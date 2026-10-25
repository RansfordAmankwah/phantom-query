"""
Behaviour that matters once the API runs behind a hosting proxy (Render).

1. Rate limits are per user, not per client IP. Behind a proxy every request
   arrives from the proxy's address, so an IP-keyed limiter would make all
   users share one bucket.
2. The SSRF host check blocks every non-public address, including ranges
   is_private alone misses, and IPv4-mapped IPv6 forms.
"""
import pytest

from app.db.connection_manager import _assert_safe_host
from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_limits():
    limiter.reset()
    yield
    limiter.reset()


GENERATE_LIMIT = 10  # @limiter.limit("10/minute") on /api/query/generate


def _generate(client, user):
    # The connection doesn't exist, so the endpoint answers 404 -- but the
    # request still counts against the limit, which is all this test needs.
    return client.post(
        "/api/query/generate",
        json={"connection_id": "does-not-exist", "question": "how many users?"},
        headers=user["headers"],
    )


def test_rate_limit_is_per_user_not_shared(client, make_user):
    alice, bob = make_user("Alice"), make_user("Bob")

    for _ in range(GENERATE_LIMIT):
        assert _generate(client, alice).status_code != 429

    assert _generate(client, alice).status_code == 429
    # Same client IP as Alice (TestClient always uses "testclient"), but a
    # different user: Bob must not inherit Alice's exhausted bucket.
    assert _generate(client, bob).status_code != 429


def test_invalid_token_is_rejected_before_counting(client, make_user):
    alice = make_user("Alice")
    bad = {"Authorization": "Bearer not-a-real-token"}
    for _ in range(GENERATE_LIMIT + 5):
        res = client.post(
            "/api/query/generate",
            json={"connection_id": "x", "question": "q"},
            headers=bad,
        )
        assert res.status_code == 401
    # Garbage tokens never touched any bucket, so Alice is unaffected.
    assert _generate(client, alice).status_code != 429


@pytest.mark.parametrize("host", [
    "127.0.0.1",          # loopback
    "localhost",
    "10.0.0.5",           # RFC1918
    "172.16.4.2",
    "192.168.1.10",
    "169.254.169.254",    # cloud metadata
    "100.64.0.1",         # carrier-grade NAT -- not caught by is_private
    "0.0.0.0",
    "::1",
    "fe80::1",
    "fd00::1",
    "::ffff:10.0.0.5",    # IPv4-mapped IPv6 pointing at a private address
    "::ffff:127.0.0.1",
])
def test_non_public_hosts_are_blocked(host):
    with pytest.raises(ValueError):
        _assert_safe_host(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_hosts_are_allowed(host):
    _assert_safe_host(host)  # must not raise
