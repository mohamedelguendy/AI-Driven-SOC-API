from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb

from ..db import pool
from ..deps import get_current_user, require_roles
from ..schemas import DecisionIn

router = APIRouter(prefix="/actions", tags=["actions"])




# List action history, optionally narrowed to actions still in effect.
@router.get("")
def list_actions(active_only: bool = False, user: dict = Depends(get_current_user)):
    """active_only=true shows only actions still in effect (not reverted,
    not expired) — the 'what's currently blocked/isolated' view.
    """
    query = "SELECT * FROM actions"
    if active_only:
        query += (
            " WHERE success IS TRUE AND reverted_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > now())"
        )
    query += " ORDER BY executed_at DESC"
    with pool.connection() as conn:
        rows = conn.execute(query).fetchall()
    return rows




# Queue or retry a manual reversal and record who requested it.
@router.post("/{action_id}/revert")
def revert_action(
    action_id: int,
    decision: DecisionIn,
    user: dict = Depends(require_roles("tier2", "tier3", "admin")),
):
    """Queue a manual reversal of an action (e.g. a mistaken block).
    The background worker performs the same adapter reversal used for
    actions queued by the automatic expiry job.
    """
    with pool.connection() as conn:
        action = conn.execute(
            """
            SELECT * FROM actions
            WHERE id = %s
            FOR UPDATE
            """,
            (action_id,),
        ).fetchone()
        if action is None:
            raise HTTPException(status_code=404, detail="Action not found")
        if action["reverted_at"] is not None:
            raise HTTPException(status_code=409, detail="Already reverted")
        if not action["success"]:
            raise HTTPException(status_code=409, detail="Action never succeeded — nothing to revert")

        job = conn.execute(
            """
            SELECT id, status, last_error
            FROM action_jobs
            WHERE action_id = %s AND operation = 'revert'
            FOR UPDATE
            """,
            (action_id,),
        ).fetchone()
        if job and job["status"] in ("queued", "running"):
            raise HTTPException(status_code=409, detail="A revert is already queued or running")
        if job and job["status"] == "succeeded":
            raise HTTPException(status_code=409, detail="The revert job already succeeded")

        if job and job["status"] == "failed":
            retried_job = conn.execute(
                """
                UPDATE action_jobs
                SET status = 'queued',
                    attempts = 0,
                    next_attempt_at = now(),
                    claimed_at = NULL,
                    claim_token = NULL,
                    requested_by = %s,
                    updated_at = now()
                WHERE id = %s AND status = 'failed'
                RETURNING id
                """,
                (user["id"], job["id"]),
            ).fetchone()
            if retried_job is None:
                raise HTTPException(status_code=409, detail="Revert job state changed; retry the request")
            job_id = retried_job["id"]
            event_type = "action.revert_retry_queued"
            details = {
                "job_id": job_id,
                "previous_error": job["last_error"],
                "comment": decision.comment,
            }
        else:
            queued_job = conn.execute(
                """
                INSERT INTO action_jobs (action_id, operation, requested_by)
                VALUES (%s, 'revert', %s)
                ON CONFLICT (action_id, operation) DO NOTHING
                RETURNING id
                """,
                (action_id, user["id"]),
            ).fetchone()
            if queued_job is None:
                raise HTTPException(status_code=409, detail="A revert is already queued or has been attempted")
            job_id = queued_job["id"]
            event_type = "action.revert_queued"
            details = {"job_id": job_id, "comment": decision.comment}

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, %s, 'action', %s, %s)
            """,
            (
                user["id"],
                event_type,
                action_id,
                Jsonb(details),
            ),
        )

    return {"action_id": action_id, "reverted": False, "status": "queued", "job_id": job_id}
