"""
middleware/security_headers.py — Security Headers Middleware
============================================================
Injects all security headers defined in §6 on every HTTP response.

In production, Nginx also sets these headers at the edge — this middleware
is the defence-in-depth layer that ensures they are present even if the
reverse proxy is misconfigured or bypassed in development.

Headers applied to ALL responses:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Content-Security-Policy (with per-request nonce for style-src)
  - Cache-Control (differentiated: no-store for auth'd, public for static)

Headers deliberately REMOVED:
  - Server
  - X-Powered-By
"""

from __future__ import annotations

import secrets
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from core.config import settings

# ---------------------------------------------------------------------------
# Routes that serve authenticated content — get the strictest cache headers
# ---------------------------------------------------------------------------
_AUTHENTICATED_PREFIXES = (
    "/auth/",
    "/bookings",
    "/uploads",
    "/admin",
    "/profile",
    "/files",
)

# ---------------------------------------------------------------------------
# Permitted script / style origins for CSP
# Blueprint §5.1
# ---------------------------------------------------------------------------
_SCRIPT_SRC = "'self' https://cdnjs.cloudflare.com"
_FONT_SRC = "'self' https://fonts.gstatic.com"
_STYLE_SRC_BASE = "'self' https://fonts.googleapis.com"   # nonce appended per-request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Starlette BaseHTTPMiddleware that adds security headers to every response.

    A fresh CSP nonce is generated per request so that inline style blocks
    in server-rendered pages can use the nonce without requiring 'unsafe-inline'.
    The nonce is stored in request.state so Jinja2 templates can access it.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._hsts_max_age = settings.HSTS_MAX_AGE if hasattr(settings, "HSTS_MAX_AGE") else 31536000

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Generate a per-request nonce (128-bit, URL-safe base64)
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response: Response = await call_next(request)

        # --- Remove information-disclosure headers ---
        response.headers.pop("server", None)
        response.headers.pop("x-powered-by", None)

        # --- HSTS (HTTPS only; also guards subdomains) ---
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self._hsts_max_age}; includeSubDomains; preload"
            )

        # --- Framing protection ---
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"

        # --- Referrer ---
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # --- Permissions ---
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )

        # --- Content Security Policy ---
        csp_report = (
            f"; report-uri {settings.CSP_REPORT_URI}"
            if hasattr(settings, "CSP_REPORT_URI") and getattr(settings, "CSP_REPORT_URI", "")
            else ""
        )
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src {_SCRIPT_SRC}; "
            f"style-src {_STYLE_SRC_BASE} 'nonce-{nonce}'; "
            f"font-src {_FONT_SRC}; "
            f"img-src 'self' data: https:; "
            f"connect-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self'"
            f"{csp_report}"
        )

        # Modern browsers: disable legacy XSS auditor (CSP is the control)
        response.headers["X-XSS-Protection"] = "0"

        # --- Cache-Control ---
        path = request.url.path
        is_auth_route = any(path.startswith(p) for p in _AUTHENTICATED_PREFIXES)
        if is_auth_route:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        elif path.startswith("/static/") or path.startswith("/assets/"):
            # Static assets: immutable cache (filename includes content hash)
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # Public pages: short cache, no sensitive data
            response.headers["Cache-Control"] = "public, max-age=300, must-revalidate"

        return response
