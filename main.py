"""
main.py — CleanCare Solutions API Entry Point
==============================================
Bootstraps the FastAPI application with the full security middleware stack.

Middleware is applied in REVERSE order of add_middleware() calls —
the last-added middleware runs FIRST on incoming requests.
Correct execution order (outermost → innermost):

  Request IN:
    1. CORSMiddleware          — handles preflight, sets CORS headers
    2. SecurityHeadersMiddleware — injects all §6 security headers
    3. RequestLoggingMiddleware  — structured log of every request
    4. SessionMiddleware         — validates session cookie (§3.3)
    5. CSRFMiddleware             — validates CSRF token (§5.3)
    6. Route Handler              — business logic

  Response OUT (reverse):
    6 → 5 → 4 → 3 → 2 → 1

Lifespan:
  - startup:  configure logging, verify DB, ping Redis
  - shutdown: close Redis connection pool

Blueprint coverage in this file:
  §1.1  — Communication rules (enforced at Nginx; checked here in dev)
  §2.4  — Session management (via SessionMiddleware)
  §5.1  — XSS (CSP via SecurityHeadersMiddleware)
  §5.3  — CSRF (via CSRFMiddleware)
  §6    — HTTP hardening (via SecurityHeadersMiddleware)
  §6.1  — CORS (via CORSMiddleware)
  §7.1  — Logging (via RequestLoggingMiddleware + structlog)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from core.config import settings
from core.logging_config import configure_logging, app_logger, security_logger
from core.limiter import limiter
from core.session import close_redis, get_redis
from middleware.cors import get_cors_kwargs
from middleware.csrf import CSRFMiddleware
from middleware.logging_middleware import RequestLoggingMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from middleware.session_middleware import SessionMiddleware

# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown events
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler.
    Runs setup before the server starts accepting requests,
    and teardown after the last request completes.
    """
    # --- STARTUP ---
    configure_logging()
    app_logger.info(
        "cleancare_api_starting",
        environment=settings.APP_ENV.value,
        version="1.0.0",
    )

    # Verify Redis connectivity
    try:
        redis = await get_redis()
        await redis.ping()
        app_logger.info("redis_connected", url=settings.REDIS_URL.split("@")[-1])  # Mask password
    except Exception as exc:
        app_logger.error("redis_connection_failed", error=str(exc))
        raise RuntimeError(f"Cannot connect to Redis: {exc}") from exc

    # Verify DB connectivity
    try:
        from db.database import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        app_logger.info("database_connected")
    except Exception as exc:
        app_logger.error("database_connection_failed", error=str(exc))
        raise RuntimeError(f"Cannot connect to database: {exc}") from exc

    app_logger.info("cleancare_api_ready", port=settings.APP_PORT)

    yield  # Application runs here

    # --- SHUTDOWN ---
    app_logger.info("cleancare_api_shutting_down")
    await close_redis()
    app_logger.info("cleancare_api_shutdown_complete")


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """
    Creates and configures the FastAPI application instance.
    Separating creation into a factory function makes testing easier —
    tests can call create_app() with test settings.
    """

    _app = FastAPI(
        title="CleanCare Solutions API",
        description="Secure booking and service management API.",
        version="1.0.0",
        # Disable automatic docs in production (prevents information disclosure)
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # -------------------------------------------------------------------------
    # Rate limiter state (slowapi requires this on the app instance)
    # -------------------------------------------------------------------------
    _app.state.limiter = limiter

    # -------------------------------------------------------------------------
    # Middleware stack
    # IMPORTANT: add_middleware() applies in reverse — last added = outermost.
    # Order below produces the execution sequence described at the top of file.
    # -------------------------------------------------------------------------

    # 5. CSRF — innermost protection layer (closest to route handlers)
    _app.add_middleware(CSRFMiddleware)

    # 4. Session validation
    _app.add_middleware(SessionMiddleware)

    # 3. Request / response logging
    _app.add_middleware(RequestLoggingMiddleware)

    # 2. Security headers (§6)
    _app.add_middleware(SecurityHeadersMiddleware)

    # 1. slowapi rate limiting
    _app.add_middleware(SlowAPIMiddleware)

    # 0. CORS — outermost (handles OPTIONS preflight before all other middleware)
    _app.add_middleware(CORSMiddleware, **get_cors_kwargs())

    # -------------------------------------------------------------------------
    # Exception Handlers
    # -------------------------------------------------------------------------

    @_app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        """Blueprint §3.2: 429 with generic message — no internals exposed."""
        security_logger.warning(
            "rate_limit_exceeded",
            path=request.url.path,
            ip=request.headers.get("X-Real-IP", getattr(request.client, "host", "unknown")),
            limit=str(exc.detail),
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests. Please try again later."},
            headers={"Retry-After": "900"},
        )

    @_app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """
        Pydantic validation errors → 422.
        Returns field-level error details (safe — these are schema violations,
        not raw input echoes).
        Logs the rejection without logging the invalid values.
        """
        errors = []
        for error in exc.errors():
            field = " → ".join(str(loc) for loc in error.get("loc", []))
            errors.append({"field": field, "message": error.get("msg", "Invalid value.")})
            security_logger.info(
                "pydantic_validation_rejected",
                field=field,
                reason=error.get("msg"),
                path=request.url.path,
            )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Validation failed.", "errors": errors},
        )

    @_app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Catch-all: log full error internally, return generic 500 to client.
        Blueprint §5.2: DB errors and all internals suppressed in responses.
        """
        security_logger.error(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal error occurred."},
        )

    # -------------------------------------------------------------------------
    # Routers
    # -------------------------------------------------------------------------
    from routers import auth, password, bookings, uploads, public

    _app.include_router(public.router, tags=["Public"])
    _app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
    _app.include_router(password.router, prefix="/auth", tags=["Password"])
    _app.include_router(bookings.router, prefix="/bookings", tags=["Bookings"])
    _app.include_router(uploads.router, prefix="/files", tags=["Files"])

    # -------------------------------------------------------------------------
    # Health check endpoint (no auth, no CSRF, safe for load-balancer probes)
    # -------------------------------------------------------------------------
    @_app.get("/health", include_in_schema=False)
    async def health_check() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ok", "service": "cleancare-api"},
        )

    return _app


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------
app = create_app()


# ---------------------------------------------------------------------------
# Development server entry point
# Run with: python main.py   (or: uvicorn main:app --reload)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.is_development,
        # Production: workers managed by supervisor / Docker
        workers=1 if settings.is_development else None,
        # TLS terminated by Nginx in production
        ssl_keyfile=None,
        ssl_certfile=None,
        # Access log disabled — our RequestLoggingMiddleware handles it
        access_log=False,
        # Proxy headers (X-Forwarded-For etc.) trusted from Nginx
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",  # Only trust proxy headers from localhost
    )
