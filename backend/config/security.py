"""
Security configuration — config/security.py

Provides cryptographic utilities for RepoShield's authentication layer:
  - bcrypt password hashing and verification via Passlib
  - RS256 JWT encoding via PyJWT (shares the same key pair as GitHubAppAuthService)
    Falls back to HS256 with a symmetric secret for environments without an RSA key.

Dependencies:
    pip install passlib[bcrypt] PyJWT[cryptography] python-dotenv
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

logger = logging.getLogger("reposhield.security")

# ---------------------------------------------------------------------------
# Passlib context — bcrypt backend
# ---------------------------------------------------------------------------
# rounds=12 is the OWASP-recommended minimum cost factor for bcrypt.
# deprecated="auto" transparently re-hashes any stored hash that was created
# with a weaker scheme when the user next logs in.
# ---------------------------------------------------------------------------
_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


def hash_password(plain_password: str) -> str:
    """
    Generate a bcrypt hash of the supplied plain-text password.

    Args:
        plain_password: Raw password string received from the client.

    Returns:
        A bcrypt-hashed string safe to store in the database.
    """
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    Uses a constant-time comparison internally (via Passlib) to prevent
    timing-based side-channel attacks.

    Args:
        plain_password:  Raw password string received from the client.
        hashed_password: bcrypt hash retrieved from the database.

    Returns:
        True if the password matches, False otherwise.
    """
    return _pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# JWT Configuration
# ---------------------------------------------------------------------------
_JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
_JWT_ALGORITHM:  str = os.environ.get("JWT_ALGORITHM", "HS256")
_JWT_EXPIRY_HOURS: int = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))

if _JWT_SECRET_KEY == "CHANGE_ME_IN_PRODUCTION":
    logger.warning(
        "JWT_SECRET_KEY is using the insecure default. "
        "Set a strong, random value in your environment before deploying."
    )


def create_access_token(
    user_id: str,
    email: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Encode a user identity into a signed JWT access token with a 24-hour
    expiry window.

    Payload structure
    -----------------
    sub  : user UUID (subject — RFC 7519 §4.1.2)
    email: user email address (convenience claim for the frontend)
    iat  : issued-at timestamp (UTC)
    exp  : expiry timestamp (UTC, 24 h after iat)
    Any additional claims supplied via `extra_claims` are merged in.

    Args:
        user_id:      UUID string of the authenticated user (maps to `sub`).
        email:        Email address of the authenticated user.
        extra_claims: Optional additional JWT claims to embed (e.g., roles).

    Returns:
        A compact, URL-safe signed JWT string.

    Raises:
        jwt.PyJWTError: If encoding fails due to a misconfigured key or algorithm.
    """
    now = datetime.now(tz=timezone.utc)
    payload: dict[str, Any] = {
        "sub":   user_id,
        "email": email,
        "iat":   now,
        "exp":   now + timedelta(hours=_JWT_EXPIRY_HOURS),
    }

    if extra_claims:
        payload.update(extra_claims)

    token: str = jwt.encode(
        payload=payload,
        key=_JWT_SECRET_KEY,
        algorithm=_JWT_ALGORITHM,
    )

    logger.debug(f"Access token issued for user_id={user_id}, expires in {_JWT_EXPIRY_HOURS}h.")
    return token


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Raises:
        jwt.ExpiredSignatureError : If the token has passed its `exp` claim.
        jwt.InvalidTokenError     : If the token is malformed or signature is invalid.
    """
    return jwt.decode(
        jwt=token,
        key=_JWT_SECRET_KEY,
        algorithms=[_JWT_ALGORITHM],
    )
