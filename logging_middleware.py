"""
middleware/logging_middleware.py — Request / Security Event Logging
===================================================================
Logs every inbound request and outbound response at the INFO level.
Security-relevant events (4xx, 5xx) are logged with additional context.

Rules enforced (§7.1):
  - NEVER log: request body, cookies, Authorization header
  - Log: method, path, status code, duration_ms, client IP, user_id (if authed)
  - Security events (401, 403, 422, 429, 5xx) get severity='WARNING'|'ERROR'
"""

from __future__ import annotations

import time
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from core.logging_config import security_logger, app_logger

# Headers that should never be logged
_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "x-api-key", "x-csrf-token"}
)

# Status codes that warrant a security log entry
_SECURITY_STATUS_CODES = frozenset({401, 403, 422, 429})


def _get_client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")


def _safe_headers(request: Request) -> dict:
    """Return request headers with sensitive values redacted."""
    return {
        k: "[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else v
        for k, v in request.headers.items()
    }


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured request/response logging middleware.
    All log records are emitted as structured JSON by structlog.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.perf_counter()

        # Capture identity context (populated by SessionMiddleware)
        user_id = getattr(request.state, "user_id", None)
        user_role = getattr(request.state, "user_role", None)

        response: Response = await call_next(request)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        status_code = response.status_code
        client_ip = _get_client_ip(request)

        log_payload = dict(
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            duration_ms=duration_ms,
            ip=client_ip,
            user_id=user_id,
            user_role=user_role,
            user_agent=request.headers.get("user-agent", ""),
        )

        if status_code in _SECURITY_STATUS_CODES:
            security_logger.warning("http_security_event", **log_payload)
        elif status_code >= 500:
            security_logger.error("http_server_error", **log_payload)
        else:
            app_logger.info("http_request", **log_payload)

        return response
