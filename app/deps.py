import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer

from .config import settings
from .db import pool
from .security import decode_access_token, verify_api_key

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")




# Decode the bearer token and re-check the account's current database status.
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    error = HTTPException(
        status_code=401,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = int(decode_access_token(token)["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise error

    with pool.connection() as conn:
        user = conn.execute(
            "SELECT id, username, role, is_active FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()

    if user is None or not user["is_active"]:
        raise error
    return user




# Restrict a route to the listed roles after authenticating the caller.
def require_roles(*roles: str):
    """Use as a dependency: Depends(require_roles('tier3', 'admin'))."""

    def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Not allowed for your role")
        return user

    return checker




# Authenticate the AI service independently of human users and alert feeders.
def require_ai_key(x_api_key: str | None = Header(default=None)) -> None:
    """Separate machine credential for the AI SOC Engineer. Kept apart from
    the SIEM ingest key and from user logins — three different callers,
    three different credentials.
    """
    if not verify_api_key(x_api_key, settings.ai_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
