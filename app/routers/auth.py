import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Request
from psycopg.types.json import Jsonb

from ..db import pool
from ..deps import get_current_user
from ..security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

LOGIN_ATTEMPT_LIMIT = 10
LOGIN_WINDOW = timedelta(minutes=15)


def _login_bucket_keys(username: str, client_ip: str) -> tuple[str, str]:
    normalized_username = username.strip().casefold()
    return (
        "ip:" + hashlib.sha256(client_ip.encode("utf-8")).hexdigest(),
        "user:" + hashlib.sha256(normalized_username.encode("utf-8")).hexdigest(),
    )


def _record_login_attempt(conn, username: str, client_ip: str) -> int | None:
    retry_after = 0
    now = datetime.now(timezone.utc)
    for bucket_key in _login_bucket_keys(username, client_ip):
        row = conn.execute(
            """
            INSERT INTO login_rate_limits (bucket_key, attempts, window_started_at)
            VALUES (%s, 1, %s)
            ON CONFLICT (bucket_key) DO UPDATE
            SET attempts = CASE
                    WHEN login_rate_limits.window_started_at <= %s - %s
                    THEN 1 ELSE login_rate_limits.attempts + 1
                END,
                window_started_at = CASE
                    WHEN login_rate_limits.window_started_at <= %s - %s
                    THEN %s ELSE login_rate_limits.window_started_at
                END
            RETURNING attempts, window_started_at
            """,
            (bucket_key, now, now, LOGIN_WINDOW, now, LOGIN_WINDOW, now),
        ).fetchone()
        if row["attempts"] > LOGIN_ATTEMPT_LIMIT:
            seconds = int(
                max(
                    1,
                    (
                        row["window_started_at"] + LOGIN_WINDOW - now
                    ).total_seconds(),
                )
            )
            retry_after = max(retry_after, seconds)

    conn.execute(
        "DELETE FROM login_rate_limits WHERE window_started_at < %s - interval '1 day'",
        (now,),
    )
    return retry_after or None

@router.post("/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):  # noqa: B008
    with pool.connection() as conn:
        client_ip = request.client.host if request.client else "unknown"
        retry_after = _record_login_attempt(conn, form.username, client_ip)
        if retry_after is not None:
            conn.execute(
                """
                INSERT INTO audit_log
                    (actor_type, event_type, entity_type, details)
                VALUES ('system', 'auth.login_rate_limited', 'user', %s)
                """,
                (Jsonb({"username": form.username}),),
            )
            user = None
            ok = False
        else:
            user = conn.execute(
                "SELECT id, password_hash, role, is_active FROM users WHERE username = %s",
                (form.username,),
            ).fetchone()

            ok = (
                user is not None
                and user["is_active"]
                and verify_password(form.password, user["password_hash"])
            )

            if ok:
                conn.execute(
                    "DELETE FROM login_rate_limits WHERE bucket_key = ANY(%s)",
                    (list(_login_bucket_keys(form.username, client_ip)),),
                )

            conn.execute(
                """
                INSERT INTO audit_log
                    (actor_type, actor_id, event_type, entity_type, entity_id, details)
                VALUES ('user', %s, %s, 'user', %s, %s)
                """,
                (
                    user["id"] if ok else None,
                    "auth.login_success" if ok else "auth.login_failed",
                    user["id"] if user else None,
                    Jsonb({"username": form.username}),
                ),
            )

    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
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