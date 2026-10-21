import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import Settings

JWT_ALGORITHM = "HS256"
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]

_hasher = PasswordHasher()  # Argon2id with the library's RFC 9106 defaults
# Verifying against this when the user does not exist keeps login timing similar
# for unknown and known usernames (limits user enumeration).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    target = password_hash if password_hash is not None else _DUMMY_HASH
    try:
        _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_access_token(*, subject: str, settings: Settings) -> tuple[str, int]:
    now = datetime.now(UTC)
    ttl_seconds = settings.access_token_ttl_minutes * 60
    claims = {
        "sub": subject,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm=JWT_ALGORITHM)
    return token, ttl_seconds


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    """Raises jwt.PyJWTError on any invalid token.

    The algorithm list is fixed, which blocks "alg: none" and algorithm confusion attacks.
    """
    return jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[JWT_ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": REQUIRED_CLAIMS},
    )
