"""
core/security.py — Cryptographic Primitives & Security Helpers
==============================================================
Implements:
  - Argon2id password hashing / verification          (§3.1, §5.4)
  - CSRF token generation / constant-time verification (§5.3)
  - Cryptographically secure random token generation
  - Signed URL generation for file downloads           (§4.3)
  - Constant-time string comparison helper

All operations use the standard library or well-audited third-party libraries.
No homebrew cryptography.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.fernet import Fernet, InvalidToken

from core.config import settings
from core.logging_config import security_logger

# ---------------------------------------------------------------------------
# Argon2id — Password Hashing
# Blueprint §3.1: m=64MB, t=3, p=4
# ---------------------------------------------------------------------------

_ph = PasswordHasher(
    time_cost=3,           # t=3 iterations
    memory_cost=65_536,    # m=64 MB
    parallelism=4,         # p=4 lanes
    hash_len=32,           # 256-bit output
    salt_len=16,           # 128-bit salt (generated internally)
    encoding="utf-8",
)


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using Argon2id.
    Returns the encoded hash string (includes salt + parameters).
    """
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed: str) -> bool:
    """
    Verify a plain-text password against its Argon2id hash.
    Returns True on match, False on mismatch.
    Never raises — exceptions are caught and logged.

    argon2-cffi's verify() is constant-time by design.
    """
    try:
        return _ph.verify(hashed, plain_password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError) as exc:
        security_logger.warning("password_verify_error", error=str(exc))
        return False


def password_needs_rehash(hashed: str) -> bool:
    """
    Returns True if the stored hash was created with outdated parameters.
    Call after a successful verification and re-hash if True.
    """
    return _ph.check_needs_rehash(hashed)


# ---------------------------------------------------------------------------
# Secure Random Token Generation
# ---------------------------------------------------------------------------

def secure_random_hex(byte_length: int = 32) -> str:
    """
    Generate a cryptographically secure hex token.
    Default 32 bytes = 256-bit entropy.
    Used for: email verification tokens, password reset tokens.
    """
    return secrets.token_hex(byte_length)


def secure_random_urlsafe(byte_length: int = 32) -> str:
    """
    Generate a URL-safe base64 token.
    Used for: signed URLs.
    """
    return secrets.token_urlsafe(byte_length)


def secure_session_id() -> str:
    """
    Generate a 128-bit cryptographically secure session identifier.
    Blueprint §2.4: min 128 bits of entropy.
    """
    return secrets.token_hex(16)   # 16 bytes = 128 bits → 32 hex chars


# ---------------------------------------------------------------------------
# CSRF Token — HMAC-SHA256 Double-Submit Pattern
# Blueprint §5.3
# ---------------------------------------------------------------------------

def _current_day_stamp() -> str:
    """Returns today's date as YYYY-MM-DD (UTC).  CSRF tokens rotate daily."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _previous_day_stamp() -> str:
    """Returns yesterday's date — used for the one-window grace period."""
    from datetime import timedelta
    yesterday = datetime.now(tz=timezone.utc) - timedelta(days=1)
    return yesterday.strftime("%Y-%m-%d")


def generate_csrf_token(session_id: str) -> str:
    """
    CSRF token = HMAC-SHA256(SECRET_KEY, session_id | today_date)
    Encoded as base64url (URL-safe, no padding).
    Rotates daily; previous day's token accepted during grace window.
    """
    message = f"{session_id}|{_current_day_stamp()}".encode("utf-8")
    raw = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify_csrf_token(session_id: str, token: str) -> bool:
    """
    Verify a submitted CSRF token against today's and yesterday's expected values.
    Uses constant-time comparison to prevent timing attacks.
    Returns True if valid, False otherwise.
    """
    if not token or not session_id:
        return False

    token_bytes = token.encode("ascii") if isinstance(token, str) else token

    # Check today's token
    expected_today = generate_csrf_token(session_id)
    if hmac.compare_digest(
        token_bytes,
        expected_today.encode("ascii"),
    ):
        return True

    # Grace window: also accept yesterday's token during rotation period
    yesterday_message = f"{session_id}|{_previous_day_stamp()}".encode("utf-8")
    expected_yesterday_raw = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        yesterday_message,
        hashlib.sha256,
    ).digest()
    expected_yesterday = (
        base64.urlsafe_b64encode(expected_yesterday_raw).rstrip(b"=").decode("ascii")
    )

    return hmac.compare_digest(token_bytes, expected_yesterday.encode("ascii"))


# ---------------------------------------------------------------------------
# Signed URL Generation — File Downloads
# Blueprint §4.3: expires in 60 minutes
# ---------------------------------------------------------------------------

# We derive a Fernet key from SECRET_KEY so a single env var drives everything.
def _derive_fernet_key() -> bytes:
    """
    Derives a 32-byte key from SECRET_KEY using SHA-256 and base64-encodes it
    for Fernet.  Deterministic: same SECRET_KEY → same Fernet key.
    """
    raw = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw)


_fernet = Fernet(_derive_fernet_key())


def generate_signed_url(storage_path: str, expire_minutes: Optional[int] = None) -> str:
    """
    Creates an HMAC-signed, time-limited token for file access.
    The token encodes: storage_path + expiry_timestamp.

    Returns a URL path that the /files/download endpoint will validate.
    Blueprint §4.3: files stored outside web root, served only via signed URLs.
    """
    if expire_minutes is None:
        expire_minutes = settings.UPLOAD_SIGNED_URL_EXPIRE_MINUTES

    expiry_ts = int(time.time()) + (expire_minutes * 60)
    payload = f"{storage_path}|{expiry_ts}".encode("utf-8")
    token = _fernet.encrypt(payload).decode("ascii")
    # URL-safe: Fernet output is already base64url; wrap in our endpoint path
    return f"/files/download?token={token}"


def verify_signed_url_token(token: str) -> Optional[str]:
    """
    Validates a signed URL token.
    Returns the storage_path if valid and not expired, None otherwise.
    """
    try:
        payload = _fernet.decrypt(token.encode("ascii")).decode("utf-8")
        storage_path, expiry_str = payload.rsplit("|", 1)
        if int(time.time()) > int(expiry_str):
            security_logger.info("signed_url_expired", path=storage_path)
            return None
        return storage_path
    except (InvalidToken, ValueError, Exception) as exc:
        security_logger.warning("signed_url_invalid", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Generic Token Hashing (for DB storage of reset / verify tokens)
# Blueprint §5.4: store hash(token), not raw token
# ---------------------------------------------------------------------------

def hash_token(raw_token: str) -> str:
    """
    Returns SHA-256 hex digest of a raw token for safe DB storage.
    The raw token is sent to the user; only the hash is persisted.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.
    Wraps hmac.compare_digest for general use.
    """
    return hmac.compare_digest(
        a.encode("utf-8") if isinstance(a, str) else a,
        b.encode("utf-8") if isinstance(b, str) else b,
    )
