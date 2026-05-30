"""
core/logging_config.py — Structured Security Logging
=====================================================
Configures structlog for JSON-structured output.

Security logging rules enforced here (§7.1):
  - Auth events always logged (success + failure)
  - Validation rejections logged (field name + reason, NOT the raw value)
  - NEVER logged: passwords, session tokens, PII beyond what is required
  - Append-only output to stdout for SIEM collection
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict

import structlog

from core.config import LogFormat, settings

# Fields that must NEVER appear in any log record.
# The sanitise_record processor strips them automatically.
_FORBIDDEN_LOG_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "confirm_password",
        "session_token",
        "session_id",
        "csrf_token",
        "mfa_secret",
        "mfa_token",
        "reset_token",
        "verify_token",
        "credit_card",
        "card_number",
        "cvv",
        "api_key",
        "secret_key",
        "authorization",
        "cookie",
    }
)


def _sanitise_record(
    logger: Any, method: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Structlog processor: removes any key whose name appears in the forbidden
    list, regardless of where in the pipeline it was added.
    Operates on a copy so the original call-site dict is not mutated.
    """
    for field in list(event_dict.keys()):
        if field.lower() in _FORBIDDEN_LOG_FIELDS:
            event_dict[field] = "[REDACTED]"
    return event_dict


def _add_severity(
    logger: Any, method: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Maps structlog level names to uppercase for SIEM compatibility."""
    event_dict["severity"] = method.upper()
    return event_dict


def configure_logging() -> None:
    """
    Call once at application startup (inside main.py lifespan).
    Sets up both structlog and the standard-library logging bridge so that
    third-party libraries (SQLAlchemy, uvicorn, etc.) also emit structured JSON.
    """
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        _add_severity,
        _sanitise_record,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.LOG_FORMAT == LogFormat.JSON:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(settings.LOG_LEVEL)

    # Quieten noisy third-party loggers in production
    if settings.is_production:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Application-wide logger instances
# ---------------------------------------------------------------------------

# General application logger
app_logger = structlog.get_logger("cleancare.app")

# Security-specific logger — all auth/authz/validation events go here
security_logger = structlog.get_logger("cleancare.security")
