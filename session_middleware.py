"""
middleware/session_middleware.py — Session Validation Middleware
===============================================================
Implements validate_session() from §3.3.

On every request:
  1. Reads the opaque session cookie
  2. Looks up the session in Redis
  3. Enforces idle timeout and IP binding
  4. Refreshes last_active
  5. Attaches the resolved user to request.state.user

Unauthenticated requests to protected routes are rejected with 401.
Public routes (defined in UNAUTHENTICATED_PATHS) pass through freely.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

from fastapi import status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from core.config import settings
from core.logging_config import security_logger
from core.session import get_session

# ---------------------------------------------------------------------------
# Route prefixes that do NOT require an authenticated session.
# Every other route is protected.
# ---------------------------------------------------------------------------
_PUBLIC_PREFIXES = (
    "/auth/login",
    "/auth/register",
    "/auth/verify-email",
    "/auth/password-reset",
    "/public",
    "/static",
    "/assets",
    "/docs",        # Remove in production
    "/openapi.json", # Remove in production
    "/health",
)


def _is_public_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)


def _get_client_ip(request: Request) -> str:
    """Extract client IP — prefers X-Real-IP set by Nginx proxy."""
    return request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")


class SessionMiddleware(BaseHTTPMiddleware):
    """
    Validates the session cookie on every non-public request.
    Attaches resolved session data and user_id to request.state.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Public paths bypass session validation
        if _is_public_path(request.url.path):
            return await call_next(request)

        session_id: Optional[str] = request.cookies.get(settings.SESSION_COOKIE_NAME)

        if not session_id:
            security_logger.info(
                "session_missing",
                path=request.url.path,
                ip=_get_client_ip(request),
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Not authenticated."},
            )

        client_ip = _get_client_ip(request)
        session_data = await get_session(session_id, request_ip=client_ip)

        if session_data is None:
            security_logger.info(
                "session_invalid_or_expired",
                path=request.url.path,
                ip=client_ip,
                session_prefix=session_id[:8],
            )
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Session expired or invalid. Please log in again."},
            )
            # Clear the stale cookie from the client
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                httponly=True,
                secure=True,
                samesite="strict",
            )
            return response

        # Attach session context to the request for downstream handlers
        request.state.session_id = session_id
        request.state.user_id = session_data.user_id
        request.state.user_role = session_data.role
        request.state.session = session_data

        return await call_next(request)
