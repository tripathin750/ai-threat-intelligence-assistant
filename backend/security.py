"""Small defence-in-depth controls suitable for a single-process MVP."""

from collections import defaultdict, deque
import hmac
from time import monotonic
from uuid import uuid4

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limit; replace with shared storage at scale."""

    def __init__(self, app, requests_per_minute: int) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        if request.url.path in {"/docs", "/openapi.json", "/redoc"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = monotonic()
        window = self._requests[client]
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= self.requests_per_minute:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Try again in a minute."},
            )
        window.append(now)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", str(uuid4()))
        return response


def verify_api_key(request: Request) -> None:
    """Require an API key only when the deployment configuration sets one."""
    if settings.api_key is None:
        return
    supplied = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(supplied, settings.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds baseline OWASP-recommended response headers to every response.

    These don't replace input validation or authentication; they reduce the
    blast radius of classes of bugs (MIME sniffing, clickjacking, referrer
    leakage) even if one is later introduced elsewhere in the application.
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response
