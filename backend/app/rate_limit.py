"""
Rate limiting.

Limits are keyed by the authenticated user, not the client IP.

Why: behind a hosting proxy (Render, Railway, Cloudflare) request.client.host
is the proxy's address, so an IP-keyed limiter puts every user in one shared
bucket -- one busy user exhausts "10/minute" for everyone. Reading the real IP
from X-Forwarded-For instead is fragile: Render appends to any incoming value
rather than replacing it, so the leftmost entry is client-controlled and
spoofable, and which entry is trustworthy depends on how many proxies sit in
front of the app.

Every rate-limited route is authenticated, so the user id is a better key
anyway: it cannot be spoofed without a valid token, and it limits a person
rather than a network (a whole campus behind one NAT is not one user).

An invalid token never reaches this function for those routes: FastAPI
resolves the get_current_user_id dependency, which rejects it with 401,
before slowapi's wrapper runs. The IP fallback only covers a route that is
rate-limited without requiring auth.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from app.security import decode_access_token


def rate_limit_key(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        try:
            return f"user:{decode_access_token(token.strip())}"
        except Exception:
            pass
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=rate_limit_key)
