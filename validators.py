"""
utils/validators.py — Whitelist Input Validation & Sanitisation
================================================================
Implements validate_input() and sanitize() from §2.2.

Every field that enters the backend passes through a named validator.
Client-side validation is UX-only; this is the authoritative security layer.

Design principles:
  - Whitelist, never blacklist
  - Reject first (fail closed)
  - Sanitise after validation (strip whitespace, normalise unicode)
  - NEVER strip HTML here — that is output encoding's job (§2.3)
  - Log rejection reason + field name; NEVER log the raw invalid value
"""

from __future__ import annotations

import re
import unicodedata
from enum import Enum
from typing import Any, Optional

from core.logging_config import security_logger


# ---------------------------------------------------------------------------
# Regex Patterns (whitelist)
# ---------------------------------------------------------------------------

# RFC 5322 simplified — Pydantic's EmailStr handles full RFC validation
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Name: letters (including accented), spaces, hyphens, apostrophes
_NAME_RE = re.compile(r"^[\w\s'\-]{1,100}$", re.UNICODE)

# UUID4 format (for resource IDs from paths)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Positive integer ID
_INT_ID_RE = re.compile(r"^\d{1,10}$")

# TOTP token: exactly 6 digits
_TOTP_RE = re.compile(r"^\d{6}$")

# Phone: optional +, digits, spaces, hyphens, parentheses
_PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")

# Date: YYYY-MM-DD
_DATE_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")

# Time: HH:MM (24-hour)
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

# Safe free-text: printable Unicode, no control characters
# Used for notes, messages — max length enforced separately
_SAFE_TEXT_RE = re.compile(r"^[\w\s.,!?'\-@#&()\n\r]{1,2000}$", re.UNICODE)


# ---------------------------------------------------------------------------
# Validation Error
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when a field fails whitelist validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        # Log the rejection — NOT the raw value
        security_logger.warning(
            "input_validation_rejected",
            field=field,
            reason=reason,
        )
        super().__init__(f"Validation failed for '{field}': {reason}")


# ---------------------------------------------------------------------------
# Sanitise (called AFTER validation)
# §2.2: strip whitespace, normalise unicode NFC
# ---------------------------------------------------------------------------

def sanitize(value: str) -> str:
    """
    Sanitise a validated string value:
      1. Strip leading/trailing whitespace
      2. Normalise unicode to NFC (canonical decomposition → composition)

    Do NOT strip HTML tags here. Output encoding (§2.3) handles that
    at the rendering layer.
    """
    value = value.strip()
    value = unicodedata.normalize("NFC", value)
    return value


# ---------------------------------------------------------------------------
# Core validate_input() — dispatches to field-specific validators
# §2.2 algorithm
# ---------------------------------------------------------------------------

def validate_input(field_name: str, raw_value: Any, required: bool = True) -> Optional[str]:
    """
    Validate and sanitise a single field value against its whitelist schema.

    Args:
        field_name: The logical field name (maps to a validator function).
        raw_value:  The raw value as received from the request.
        required:   If True, None/empty raises ValidationError.

    Returns:
        The sanitised string value, or None if the field is optional and empty.

    Raises:
        ValidationError: If validation fails (field + reason logged automatically).
    """
    # --- Null / empty check ---
    if raw_value is None or (isinstance(raw_value, str) and raw_value.strip() == ""):
        if required:
            raise ValidationError(field_name, "Field is required.")
        return None

    if not isinstance(raw_value, str):
        raw_value = str(raw_value)

    # --- Dispatch to field validator ---
    validator = _VALIDATORS.get(field_name)
    if validator is None:
        # Unknown field — reject it (whitelist: only known fields accepted)
        raise ValidationError(field_name, "Unknown field.")

    return validator(field_name, raw_value)


# ---------------------------------------------------------------------------
# Individual Field Validators
# ---------------------------------------------------------------------------

def _validate_email(field: str, value: str) -> str:
    if len(value) > 254:
        raise ValidationError(field, "Exceeds maximum length of 254 characters.")
    if not _EMAIL_RE.match(value):
        raise ValidationError(field, "Invalid email format.")
    return sanitize(value.lower())   # Normalise to lowercase


def _validate_password(field: str, value: str) -> str:
    """
    Validates raw password input for presence and max length.
    Complexity rules are enforced in auth_service.py (meets_complexity).
    We do NOT log anything about the password value — not even its length
    in a way that reveals information.
    """
    if len(value) > 256:
        raise ValidationError(field, "Password exceeds maximum allowed length.")
    if len(value) < 1:
        raise ValidationError(field, "Password is required.")
    # Return raw — sanitize() is intentionally NOT called on passwords
    # (whitespace may be intentional in a passphrase)
    return value


def _validate_name(field: str, value: str) -> str:
    if len(value) > 100:
        raise ValidationError(field, "Exceeds maximum length of 100 characters.")
    if not _NAME_RE.match(value):
        raise ValidationError(field, "Contains disallowed characters.")
    return sanitize(value)


def _validate_mfa_token(field: str, value: str) -> str:
    if not _TOTP_RE.match(value):
        raise ValidationError(field, "MFA token must be exactly 6 digits.")
    return value


def _validate_phone(field: str, value: str) -> str:
    clean = value.replace(" ", "")
    if len(clean) > 20:
        raise ValidationError(field, "Exceeds maximum length.")
    if not _PHONE_RE.match(value):
        raise ValidationError(field, "Invalid phone number format.")
    return sanitize(value)


def _validate_date(field: str, value: str) -> str:
    if not _DATE_RE.match(value):
        raise ValidationError(field, "Invalid date format. Expected YYYY-MM-DD.")
    return value


def _validate_time(field: str, value: str) -> str:
    if not _TIME_RE.match(value):
        raise ValidationError(field, "Invalid time format. Expected HH:MM.")
    return value


def _validate_safe_text(field: str, value: str) -> str:
    if len(value) > 2000:
        raise ValidationError(field, "Exceeds maximum length of 2000 characters.")
    if not _SAFE_TEXT_RE.match(value):
        raise ValidationError(field, "Contains disallowed characters.")
    return sanitize(value)


def _validate_uuid(field: str, value: str) -> str:
    if not _UUID_RE.match(value):
        raise ValidationError(field, "Invalid UUID format.")
    return value.lower()


def _validate_int_id(field: str, value: str) -> str:
    if not _INT_ID_RE.match(value):
        raise ValidationError(field, "Invalid ID format.")
    if int(value) < 1:
        raise ValidationError(field, "ID must be a positive integer.")
    return value


def _validate_service_type(field: str, value: str) -> str:
    allowed = {"standard_clean", "deep_clean", "move_in", "move_out", "office"}
    if value not in allowed:
        raise ValidationError(field, f"Must be one of: {', '.join(sorted(allowed))}.")
    return value


def _validate_booking_status(field: str, value: str) -> str:
    allowed = {"pending", "confirmed", "cancelled", "completed"}
    if value not in allowed:
        raise ValidationError(field, f"Must be one of: {', '.join(sorted(allowed))}.")
    return value


# ---------------------------------------------------------------------------
# Validator Registry — maps field_name → validator function
# Only fields in this registry are accepted. All others are rejected.
# Blueprint §2.2: whitelist approach
# ---------------------------------------------------------------------------

_VALIDATORS = {
    "email": _validate_email,
    "password": _validate_password,
    "new_password": _validate_password,
    "name": _validate_name,
    "first_name": _validate_name,
    "last_name": _validate_name,
    "mfa_token": _validate_mfa_token,
    "backup_code": _validate_mfa_token,   # Same format
    "phone": _validate_phone,
    "date": _validate_date,
    "time": _validate_time,
    "notes": _validate_safe_text,
    "message": _validate_safe_text,
    "address": _validate_safe_text,
    "uuid": _validate_uuid,
    "id": _validate_int_id,
    "service_type": _validate_service_type,
    "booking_status": _validate_booking_status,
}
