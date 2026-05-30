"""
middleware/cors.py — CORS Configuration
========================================
Blueprint §6.1: exact-match allowed origins, no wildcards,
credentials supported.

FastAPI's built-in CORSMiddleware is used; this module centralises the
configuration so it is imported and applied once in main.py.
"""

from __future__ import annotations

from fastapi.middleware.cors import CORSMiddleware

from core.config import settings


def get_cors_kwargs() -> dict:
    """
    Returns the kwargs dict to pass to app.add_middleware(CORSMiddleware, ...).

    Blueprint §6.1 requirements:
      - allowed_origins: exact list, no wildcards
      - allow_credentials: True (session cookie must be sent cross-origin in dev)
      - allowed_headers: only what the API actually uses
      - max_age: 600s preflight cache
    """
    return dict(
        allow_origins=settings.cors_origins_list,       # e.g. ["https://cleancare.example.com"]
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            settings.CSRF_HEADER_NAME,                  # "X-CSRF-Token"
            "Authorization",                            # Future: Bearer tokens
        ],
        expose_headers=[
            settings.CSRF_HEADER_NAME,                  # JS can read it in responses
        ],
        max_age=600,                                     # Preflight cache: 10 min
    )
