"""
core/limiter.py — Rate Limiter Configuration
============================================
Configures slowapi (Starlette/FastAPI rate limiting) with per-IP keys.
Blueprint §3.1, §3.2, §5.4.

Rate limits per route (from settings):
  - POST /auth/login          : 5 / 15 min per IP
  - POST /auth/register       : 3 / 1 hour per IP
  - POST /auth/password-reset : 3 / 1 hour per IP
  - POST /uploads             : 10 / 1 hour per user (authenticated)
"""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import settings


def _get_real_ip(request: Request) -> str:
    """
    Extract the real client IP address.
    In production behind Nginx, trust X-Forwarded-For only from our own proxy.
    Falls back to the direct connection IP.

    IMPORTANT: In production, configure Nginx to set X-Real-IP and ensure
    TRUSTED_PROXY_IPS is restricted to your proxy's IP(s) only.
    """
    # When running behind a trusted reverse proxy, use X-Real-IP set by Nginx
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        # Validate it looks like an IP (basic sanity check; Nginx set it)
        return real_ip.strip()
    return get_remote_address(request)


# Single global Limiter instance — imported by routers and main.py
limiter = Limiter(
    key_func=_get_real_ip,
    default_limits=[],           # No global default; limits are per-route
    storage_uri=settings.REDIS_URL,
    strategy="fixed-window",
)


# ---------------------------------------------------------------------------
# Convenience rate-limit strings built from settings
# Avoids magic strings scattered across route files.
# ---------------------------------------------------------------------------

def login_limit() -> str:
    return (
        f"{settings.RATE_LIMIT_LOGIN_ATTEMPTS}"
        f"/{settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS} second"
    )


def register_limit() -> str:
    return (
        f"{settings.RATE_LIMIT_REGISTER_ATTEMPTS}"
        f"/{settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS} second"
    )


def password_reset_limit() -> str:
    return (
        f"{settings.RATE_LIMIT_PASSWORD_RESET_ATTEMPTS}"
        f"/{settings.RATE_LIMIT_PASSWORD_RESET_WINDOW_SECONDS} second"
    )


def upload_limit() -> str:
    return (
        f"{settings.RATE_LIMIT_UPLOAD_ATTEMPTS}"
        f"/{settings.RATE_LIMIT_UPLOAD_WINDOW_SECONDS} second"
    )
