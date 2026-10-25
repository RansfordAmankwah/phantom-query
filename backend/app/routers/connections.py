from fastapi import APIRouter, HTTPException, Depends

from app.schemas import (
    ConnectionCreate, ConnectionOut, SchemaSnapshot, ConnectionHealthOut,
    ConnectionAccessOut, ConnectionGrantOut, UpdateConnectionAccessRequest,
    GrantConnectionAccessRequest,
)
from app.db.connection_manager import connection_manager
from app.db.introspector import introspect
from app.db.connection_access import list_grants, grant_access, revoke_access
from app.db.workspaces import get_membership
from app.dependencies import get_current_user_id
from app.permissions import (
    WorkspaceContext, assert_valid_access_level, require_admin,
)

router = APIRouter(prefix="/api/connections", tags=["connections"])

MAX_CONNECTIONS_PER_WORKSPACE = 20


def _to_out(conn) -> ConnectionOut:
    return ConnectionOut(
        id=conn.id, name=conn.name, host=conn.host, port=conn.port,
        database=conn.database, created_at=conn.created_at,
        folder_id=conn.folder_id, db_type=conn.db_type,
        access_level=conn.access_level,
    )


def _require_connection_admin(connection_id: str, user_id: str):
    """Resolve a connection, then require admin on the workspace owning it.

    The order matters and mirrors the workspace routes: load first, assert
    second. get_connection() already applies the per-connection access gate,
    so a user who cannot see a restricted connection gets 404 -- as far as
    they are concerned it does not exist -- rather than a 403 that would
    confirm it does. A member who *can* see it gets 403, which correctly
    says "this exists, you just may not administer it".

    These routes cannot use the require_workspace_admin dependency because
    workspace_id is not in the path; it is derived from the connection.
    """
    try:
        record = connection_manager.get_connection(connection_id, user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connection not found")

    ctx = require_admin(user_id, record.workspace_id)
    return record, ctx


def _access_out(record, connection_id: str) -> ConnectionAccessOut:
    return ConnectionAccessOut(
        connection_id=record.id,
        access_level=record.access_level,
        grants=[ConnectionGrantOut(**g) for g in list_grants(connection_id)],
    )


@router.get("", response_model=list[ConnectionOut])
def list_connections(workspace_id: str, user_id: str = Depends(get_current_user_id)):
    # Restricted connections this user cannot reach are filtered out by the
    # manager, not here -- they never enter the response at all.
    return [_to_out(c) for c in connection_manager.list_connections(user_id, workspace_id)]


@router.post("", response_model=ConnectionOut)
def create_connection(payload: ConnectionCreate, user_id: str = Depends(get_current_user_id)):
    existing = connection_manager.list_connections(user_id, payload.workspace_id)
    if len(existing) >= MAX_CONNECTIONS_PER_WORKSPACE:
        raise HTTPException(
            status_code=400,
            detail=f"This workspace has reached the maximum of {MAX_CONNECTIONS_PER_WORKSPACE} database connections.",
        )
    assert_valid_access_level(payload.access_level)
    try:
        conn = connection_manager.add_connection(
            user_id=user_id, workspace_id=payload.workspace_id, name=payload.name,
            host=payload.host, port=payload.port, database=payload.database,
            username=payload.username, password=payload.password, use_ssl=payload.use_ssl,
            db_type=payload.db_type, access_level=payload.access_level,
        )
    except ConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_out(conn)


@router.delete("/{connection_id}")
def delete_connection(connection_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        connection_manager.delete_connection(connection_id, user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"status": "deleted"}


@router.get("/{connection_id}/health", response_model=ConnectionHealthOut)
def check_connection_health(connection_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        result = connection_manager.check_health(connection_id, user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connection not found")
    return ConnectionHealthOut(**result) 


@router.get("/{connection_id}/schema", response_model=SchemaSnapshot)
def get_schema(connection_id: str, refresh: bool = False, user_id: str = Depends(get_current_user_id)):
    try:
        return introspect(connection_id, user_id, force_refresh=refresh)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connection not found")


# --- Per-connection access management (admin or owner only) --------------

@router.get("/{connection_id}/access", response_model=ConnectionAccessOut)
def get_connection_access(connection_id: str, user_id: str = Depends(get_current_user_id)):
    """The access level plus the full grant list, for the management panel.

    Admin-only: the grant list names which colleagues can reach a given
    database, which is administrative rather than collaborative information.
    """
    record, _ctx = _require_connection_admin(connection_id, user_id)
    return _access_out(record, connection_id)


@router.patch("/{connection_id}/access", response_model=ConnectionAccessOut)
def update_connection_access(
    connection_id: str,
    payload: UpdateConnectionAccessRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Switch a connection between team access and restricted."""
    _record, ctx = _require_connection_admin(connection_id, user_id)

    new_level = payload.access_level.strip().lower()
    assert_valid_access_level(new_level)

    updated = connection_manager.set_access_level(connection_id, ctx.user_id, new_level)
    return _access_out(updated, connection_id)


@router.post("/{connection_id}/access/grants", response_model=ConnectionAccessOut)
def grant_connection_access(
    connection_id: str,
    payload: GrantConnectionAccessRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Grant one user access to a restricted connection.

    The target must already belong to the workspace that owns the
    connection. Without that check a grant could hand a database to someone
    with no business in the workspace, and it would not show up anywhere in
    the members panel.
    """
    record, ctx = _require_connection_admin(connection_id, user_id)

    if get_membership(record.workspace_id, payload.user_id) is None:
        raise HTTPException(
            status_code=404,
            detail="This user is not a member of this workspace.",
        )

    grant_access(connection_id, payload.user_id, ctx.user_id)
    return _access_out(record, connection_id)


@router.delete("/{connection_id}/access/grants/{target_user_id}", response_model=ConnectionAccessOut)
def revoke_connection_access(
    connection_id: str,
    target_user_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Revoke a grant. Takes effect immediately: the next request that user
    makes resolves the connection through get_connection(), which re-reads
    the grant rather than trusting anything cached."""
    record, ctx = _require_connection_admin(connection_id, user_id)

    revoke_access(connection_id, target_user_id, ctx.user_id)
    return _access_out(record, connection_id)
