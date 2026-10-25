"""
Connection Manager

Connections belong to a workspace, not directly to a user. A user can
access a connection if they're a member of the workspace it belongs to,
and -- for restricted connections -- if they're also specifically granted
access, an owner/admin, or the connection's creator.

All database-engine-specific behavior (drivers, pooling, read-only
enforcement, timeouts) lives behind app.db.dialects -- this file only
orchestrates, it never talks to psycopg2/pymysql directly. This is what
lets new database types be added without touching this file's logic.

Safety note: Phantom Query does NOT assume the credentials it's given belong
to a read-only role. It defends in depth by forcing every session into
read-only mode at connect time, per-dialect.
"""
import uuid
import datetime
import logging
import time
import ipaddress
import socket
from app.security import encrypt_value, decrypt_value
from app.db.database import SessionLocal
from app.db.models import ConnectionRecord
from app.db.workspaces import is_member, get_role
from app.db.dialects import get_dialect
from app.db.audit import log_action
from app.db.connection_access import has_grant, granted_connection_ids, delete_grants_for_connection
from app.permissions import (
    ACCESS_TEAM, VALID_ACCESS_LEVELS, can_access_connection,
)

logger = logging.getLogger(__name__)




_BLOCKED_PREFIXES = (
    "169.254.",   # link-local / cloud metadata (AWS, GCP, Azure)
    "fd",         # IPv6 ULA
    "fe80",       # IPv6 link-local
)

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _assert_safe_host(host: str) -> None:
    """Reject hosts that could be used to pivot to internal network services.

    Resolves the hostname to an IP and checks it against blocked ranges:
    loopback, RFC1918 private, link-local (including cloud metadata endpoints),
    and IPv6 equivalents. Raises ValueError with a generic message so callers
    cannot distinguish between 'blocked' and 'unresolvable'.
    """
    host = host.strip().rstrip(".")
    try:
        # getaddrinfo returns all addresses; check every one.
        results = socket.getaddrinfo(host, None)
        ips = {r[4][0] for r in results}
    except OSError:
        # Unresolvable host — let the connection attempt fail naturally.
        return

    for ip_str in ips:
        try:
            # Strip an IPv6 zone id ("fe80::1%eth0") before parsing.
            addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
        except ValueError:
            continue
        # "::ffff:10.0.0.5" is an IPv4 address in IPv6 clothing; judge it
        # as the IPv4 address it actually reaches.
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        # is_global is the allowlist view: it also rejects ranges the
        # is_private check misses, e.g. 100.64.0.0/10 (carrier-grade NAT,
        # used for some cloud-internal networking), 0.0.0.0/8 and reserved
        # blocks. Hosting platforms differ in which private ranges their
        # internal network uses, so block everything non-public.
        if not addr.is_global:
            raise ValueError(
                "Could not connect to the database. Check your host, port, credentials, and SSL setting."
            )
        if addr.is_loopback or addr.is_link_local or addr.is_private:
            raise ValueError(
                "Could not connect to the database. Check your host, port, credentials, and SSL setting."
            )
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                raise ValueError(
                    "Could not connect to the database. Check your host, port, credentials, and SSL setting."
                )
            

class ConnectionManager:
    def __init__(self):
        self._pools: dict[str, object] = {}

    def add_connection(
        self, user_id: str, workspace_id: str, name: str, host: str, port: int,
        database: str, username: str, password: str, use_ssl: bool = False,
        db_type: str = "postgres", access_level: str = ACCESS_TEAM,
    ) -> ConnectionRecord:
        if not is_member(user_id, workspace_id):
            raise PermissionError("You are not a member of this workspace.")

        if access_level not in VALID_ACCESS_LEVELS:
            raise ValueError(f"Invalid access_level: {access_level!r}")

        _assert_safe_host(host)
        self.test_connection(host, port, database, username, password, use_ssl, db_type)
        record = ConnectionRecord(
            id=str(uuid.uuid4()),
            user_id=user_id,
            workspace_id=workspace_id,
            name=name,
            host=host,
            port=port,
            database=database,
            username=username,
            encrypted_password=encrypt_value(password),
            use_ssl=use_ssl,
            db_type=db_type,
            access_level=access_level,
            created_at=datetime.datetime.utcnow().isoformat(),
        )

        db = SessionLocal()
        try:
            db.add(record)
            db.commit()
            db.refresh(record)
        finally:
            db.close()

        log_action(
            workspace_id, user_id, "connection.created", "connection", record.id,
            {"name": name, "host": host, "database": database, "db_type": db_type,
             "access_level": access_level},
        )

        return record

    def list_connections(self, user_id: str, workspace_id: str) -> list[ConnectionRecord]:
        role = get_role(user_id, workspace_id)
        if role is None:
            return []

        db = SessionLocal()
        try:
            all_records = db.query(ConnectionRecord).filter(
                ConnectionRecord.workspace_id == workspace_id
            ).all()

            # One batched lookup for this user's grants across every
            # restricted connection in the workspace, rather than a query
            # per connection -- avoids an N+1 as the connection list grows.
            restricted_ids = [r.id for r in all_records if r.access_level != ACCESS_TEAM]
            grants = granted_connection_ids(user_id, restricted_ids) if restricted_ids else set()

            return [
                r for r in all_records
                if can_access_connection(r.access_level, r.user_id, user_id, role, r.id in grants)
            ]
        finally:
            db.close()

    def get_connection(self, connection_id: str, user_id: str) -> ConnectionRecord:
        db = SessionLocal()
        try:
            record = db.query(ConnectionRecord).filter(
                ConnectionRecord.id == connection_id
            ).first()
            if record is None:
                raise KeyError(f"No connection with id {connection_id}")

            role = get_role(user_id, record.workspace_id)
            if role is None:
                raise KeyError(f"No connection with id {connection_id}")

            grant = (
                granted_connection_ids(user_id, [connection_id])
                if record.access_level != ACCESS_TEAM else set()
            )
            if not can_access_connection(record.access_level, record.user_id, user_id, role, grant):
                # Same KeyError as "doesn't exist" -- a user who can't see
                # a restricted connection shouldn't be able to distinguish
                # it from one that was never there (404, not 403).
                raise KeyError(f"No connection with id {connection_id}")

            return record
        finally:
            db.close()

    def delete_connection(self, connection_id: str, user_id: str) -> None:
        db = SessionLocal()
        try:
            record = db.query(ConnectionRecord).filter(
                ConnectionRecord.id == connection_id
            ).first()
            if record is None:
                raise KeyError(f"No connection with id {connection_id}")

            role = get_role(user_id, record.workspace_id)
            if role is None:
                raise KeyError(f"No connection with id {connection_id}")

            grant = (
                granted_connection_ids(user_id, [connection_id])
                if record.access_level != ACCESS_TEAM else set()
            )
            if not can_access_connection(record.access_level, record.user_id, user_id, role, grant):
                raise KeyError(f"No connection with id {connection_id}")

            # Capture details before deletion -- the audit log needs to
            # describe what was deleted, and the row won't exist to query
            # afterward.
            workspace_id = record.workspace_id
            name = record.name
            host = record.host

            if record.id in self._pools:
                dialect = get_dialect(record.db_type)
                dialect.close_pool(self._pools[record.id])
                del self._pools[record.id]
            db.query(ConnectionRecord).filter(ConnectionRecord.id == connection_id).delete()
            db.commit()
        finally:
            db.close()

        delete_grants_for_connection(connection_id)

        log_action(
            workspace_id, user_id, "connection.deleted", "connection", connection_id,
            {"name": name, "host": host},
        )

    def set_access_level(self, connection_id: str, user_id: str, new_level: str) -> ConnectionRecord:
        """Admin/owner-only -- enforced by the router dependency before this
        is ever called. Grants are left in place when switching back to
        "team" rather than deleted, so a round trip to "restricted" doesn't
        silently lose them.

        A no-op change is not audited, matching grant_access/revoke_access:
        an audit entry should mean something actually changed."""
        if new_level not in VALID_ACCESS_LEVELS:
            raise ValueError(f"Invalid access_level: {new_level!r}")

        db = SessionLocal()
        try:
            record = db.query(ConnectionRecord).filter(
                ConnectionRecord.id == connection_id
            ).first()
            if record is None:
                raise KeyError(f"No connection with id {connection_id}")

            old_level = record.access_level
            workspace_id = record.workspace_id
            name = record.name

            if old_level == new_level:
                return record

            record.access_level = new_level
            db.commit()
            db.refresh(record)
        finally:
            db.close()

        log_action(
            workspace_id, user_id, "connection.access_changed", "connection", connection_id,
            {"name": name, "old_level": old_level, "new_level": new_level},
        )

        return record

    def test_connection(self, host, port, database, username, password,
                         use_ssl: bool = False, db_type: str = "postgres") -> bool:
        dialect = get_dialect(db_type)
        try:
            conn = dialect.connect(host, port, database, username, password, use_ssl)
            conn.close()
            return True
        except Exception as e:
            logger.warning(f"Connection test failed for host {host} ({db_type}): {e}")
            raise ConnectionError("Could not connect to the database. Check your host, port, credentials, and SSL setting.")

    def check_health(self, connection_id: str, user_id: str) -> dict:
        """Live health check for an existing, saved connection: can we
        actually reach it right now, what's the round-trip latency, and
        what version is it running. Unlike test_connection (used before a
        connection is saved, with raw credentials), this always goes
        through get_connection() first so the same access rules apply --
        a restricted connection a user can't see raises the same 404
        upstream as everywhere else, rather than leaking a health result.

        Never raises for a reachable-but-broken database: connection
        failures are reported in the return value (healthy=False, error
        set) so the router can return a normal 200 with the health
        details, which is what the frontend's health-check panel expects
        to render either way.
        """
        record = self.get_connection(connection_id, user_id)  # access-checked
        dialect = get_dialect(record.db_type)
        password = decrypt_value(record.encrypted_password)

        start = time.monotonic()
        try:
            # Re-check on every connect, not only when the connection was
            # saved: DNS can change after creation (rebinding), and records
            # saved before the SSRF fix were never checked at all.
            _assert_safe_host(record.host)
            conn = dialect.connect(
                record.host, record.port, record.database,
                record.username, password, record.use_ssl,
            )
        except Exception as e:
            logger.warning(f"Health check failed to connect for {connection_id} ({record.db_type}): {e}")
            return {
                "healthy": False,
                "version": None,
                "latency_ms": None,
                "ssl_enabled": record.use_ssl,
                "error": "Could not connect to the database.",
            }

        try:
            cursor = dialect.dict_cursor(conn)
            cursor.execute(dialect.health_query())
            version_row = cursor.fetchone()
            latency_ms = round((time.monotonic() - start) * 1000)
            version = str(version_row.get("version", "") if isinstance(version_row, dict) else version_row[0]) if version_row else None
            return {
                "healthy": True,
                "version": version,
                "latency_ms": latency_ms,
                "ssl_enabled": record.use_ssl,
                "error": None,
            }
        except Exception as e:
            logger.warning(f"Health check query failed for {connection_id} ({record.db_type}): {e}")
            return {
                "healthy": False,
                "version": None,
                "latency_ms": None,
                "ssl_enabled": record.use_ssl,
                "error": "Connected, but the health check query failed.",
            }
        finally:
            conn.close()

    def _get_pool(self, stored: ConnectionRecord):
        if stored.id not in self._pools:
            # Same re-check as check_health: a pool is created lazily, often
            # long after the connection record was saved and validated.
            _assert_safe_host(stored.host)
            dialect = get_dialect(stored.db_type)
            password = decrypt_value(stored.encrypted_password)
            self._pools[stored.id] = dialect.create_pool(
                minconn=1, maxconn=5,
                host=stored.host, port=stored.port, database=stored.database,
                username=stored.username, password=password, use_ssl=stored.use_ssl,
            )
        return self._pools[stored.id]

    def get_live_connection(self, connection_id: str, user_id: str, read_only: bool = True):
        stored = self.get_connection(connection_id, user_id)  # already access-checked
        dialect = get_dialect(stored.db_type)
        pool = self._get_pool(stored)
        conn = dialect.get_pooled_connection(pool)
        if read_only:
            dialect.enforce_read_only(conn)
        return conn

    def release_connection(self, connection_id: str, conn) -> None:
        if connection_id in self._pools:
            record = None
            db = SessionLocal()
            try:
                record = db.query(ConnectionRecord).filter(ConnectionRecord.id == connection_id).first()
            finally:
                db.close()
            if record:
                dialect = get_dialect(record.db_type)
                dialect.return_pooled_connection(self._pools[connection_id], conn)


connection_manager = ConnectionManager()