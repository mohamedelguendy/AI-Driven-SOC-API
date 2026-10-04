from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from psycopg.types.json import Jsonb

from ..db import pool
from ..deps import get_current_user
from ..security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):  # noqa: B008
    with pool.connection() as conn:
        user = conn.execute(
            "SELECT id, password_hash, role, is_active FROM users WHERE username = %s",
            (form.username,),
        ).fetchone()

        ok = (
            user is not None
            and user["is_active"]
            and verify_password(form.password, user["password_hash"])
        )

        # Log every attempt, successful or not. This happens inside the
        # transaction and is committed when the block ends.
        conn.execute(
            """
            INSERT INTO audit_log
                (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, %s, 'user', %s, %s)
            """,
            (
                user["id"] if ok else None, # type: ignore
                "auth.login_success" if ok else "auth.login_failed",
                user["id"] if user else None,
                Jsonb({"username": form.username}),
            ),
        )

    # Raise AFTER the block: raising inside would roll the audit row back.
    if not ok:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    return {
        "access_token": create_access_token(user["id"]), # type: ignore
        "token_type": "bearer",
        "role": user["role"], # type: ignore
    }


@router.get("/me")
def me(user: dict = Depends(get_current_user)):  # noqa: B008
    return {"id": user["id"], "username": user["username"], "role": user["role"]}