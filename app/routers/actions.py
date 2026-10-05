from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb

from .. import adapters
from ..db import pool
from ..deps import get_current_user, require_roles
from ..schemas import DecisionIn

router = APIRouter(prefix="/actions", tags=["actions"])


@router.get("")
def list_actions(active_only: bool = False, user: dict = Depends(get_current_user)):
    """active_only=true shows only actions still in effect (not reverted,
    not expired) — the 'what's currently blocked/isolated' view.
    """
    query = "SELECT * FROM actions"
    if active_only:
        query += " WHERE reverted_at IS NULL AND (expires_at IS NULL OR expires_at > now())"
    query += " ORDER BY executed_at DESC"
    with pool.connection() as conn:
        rows = conn.execute(query).fetchall()
    return rows


@router.post("/{action_id}/revert")
def revert_action(
    action_id: int,
    decision: DecisionIn,
    user: dict = Depends(require_roles("tier2", "tier3", "admin")),
):
    """Manually undo an action (e.g. a mistaken block). The automatic
    expiry job (app/expiry.py) calls the same adapters.revert() — this
    is the human-triggered path for everything else: mistakes, and
    permanent actions that need to be lifted before they'd ever expire.
    """
    with pool.connection() as conn:
        action = conn.execute(
            """
            SELECT a.*, r.action_type, r.target_value
            FROM actions a JOIN recommendations r ON r.id = a.recommendation_id
            WHERE a.id = %s
            """,
            (action_id,),
        ).fetchone()
        if action is None:
            raise HTTPException(status_code=404, detail="Action not found")
        if action["reverted_at"] is not None:
            raise HTTPException(status_code=409, detail="Already reverted")
        if not action["success"]:
            raise HTTPException(status_code=409, detail="Action never succeeded — nothing to revert")

        command = {
            "action_type": action["action_type"],
            "target": action["target_value"],
            "executor": action["executor"],
        }
        success, message = adapters.revert(action["executor"], command)

        if success:
            conn.execute(
                """
                UPDATE actions
                SET reverted_at = now(), reverted_by = %s
                WHERE id = %s
                """,
                (user["id"], action_id),
            )
        event = "action.reverted" if success else "action.revert_failed"
        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, %s, 'action', %s, %s)
            """,
            (user["id"], event, action_id, Jsonb({"message": message, "comment": decision.comment})),
        )

    if not success:
        # The attempt is logged above either way (requirement: log every
        # attempt, not just successes). The adapter/device stays in its
        # current state since we couldn't confirm the revert worked.
        raise HTTPException(status_code=502, detail=f"Revert failed: {message}")

    return {"action_id": action_id, "reverted": True, "message": message}