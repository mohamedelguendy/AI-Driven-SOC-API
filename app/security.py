import hmac
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

from .config import settings

_hasher = PasswordHash.recommended()  # Argon2




# Wrap password hashing and verification behind the application's security module.
def hash_password(password: str) -> str:
    return _hasher.hash(password)




def verify_password(password: str, hashed: str) -> bool:
    return _hasher.verify(password, hashed)




# Compare machine credentials in constant time to reduce timing leaks.
def verify_api_key(candidate: str | None, expected: str) -> bool:
    """Compare API credentials without leaking a timing signal."""
    if candidate is None:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))




# Issue and validate short-lived JWTs; roles remain sourced from the database.
def create_access_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    # The role is deliberately NOT stored in the token. It is read from the
    # database on every request, so a role change or a disabled account
    # takes effect immediately.
    return jwt.encode(
        {"sub": str(user_id), "exp": expires},
        settings.jwt_secret,
        algorithm="HS256",
    )




def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
