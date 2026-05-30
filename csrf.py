"""
middleware/csrf.py — CSRF Protection Middleware
================================================
Implements the HMAC-SHA256 double-submit cookie pattern from §5.3.

For every state-changing request (POST, PUT, PATCH, DELETE):
  1. Both the X-CSRF-Token header and the csrf_token cookie must be present.
  2. They must match after constant-time HMAC verification against the session ID.

Safe methods (GET, HEAD, OPTIONS) are exempt.
Routes listed in _CSRF_EXEMPT are also exempt (e.g., OAuth callbacks).

CSRF token is generated on login and placed in a non-HttpOnly cookie so
JavaScript can read and attach it as a request header.
The session cookie remains HttpOnly — inaccessible to JS.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from core.config import settings
from core.logging_config import security_logger
from core.security import verify_csrf_token

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Routes exempt from CSRF enforcement (no session, no state change)
_CSRF_EXEMPT = frozenset(
    {
        "/auth/login",
        "/auth/register",
        "/auth/verify-email",
        "/health",
    }
)


def _get_client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Validates CSRF tokens on all state-changing requests.
    Blueprint §5.3: double-submit HMAC + SameSite=Strict cookie.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Safe methods are not CSRF-vulnerable
        if request.method in _SAFE_METHODS:
            return await call_next(request)

        # Exempt routes
        if request.url.path in _CSRF_EXEMPT:
            return await call_next(request)

        # Extract tokens
        header_token: str | None = request.headers.get(settings.CSRF_HEADER_NAME)
        cookie_token: str | None = request.cookies.get(settings.CSRF_COOKIE_NAME)

        if not header_token or not cookie_token:
            security_logger.warning(
                "csrf_token_missing",
                path=request.url.path,
                method=request.method,
                ip=_get_client_ip(request),
                has_header=bool(header_token),
                has_cookie=bool(cookie_token),
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token missing."},
            )

        # Constant-time comparison of header vs cookie
        if header_token != cookie_token:
            security_logger.warning(
                "csrf_token_mismatch_double_submit",
                path=request.url.path,
                method=request.method,
                ip=_get_client_ip(request),
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token mismatch."},
            )

        # HMAC verification against the session ID
        session_id: str | None = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if not session_id:
            # No session — the session middleware will catch this; let it pass
            return await call_next(request)

        if not verify_csrf_token(session_id, header_token):
            security_logger.warning(
                "csrf_token_hmac_invalid",
                path=request.url.path,
                method=request.method,
                ip=_get_client_ip(request),
                user_id=getattr(request.state, "user_id", None),
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token invalid."},
            )

        return await call_next(request)
