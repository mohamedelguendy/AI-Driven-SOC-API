from datetime import datetime, timedelta, timezone
from ipaddress import ip_network

from fastapi import APIRouter, Depends, Header, HTTPException
from psycopg.types.json import Jsonb

from ..config import settings
from ..db import pool
from ..deps import get_current_user, require_roles
from ..schemas import DecisionIn, RecommendationIn

router = APIRouter(prefix="/recommendations", tags=["recommendations"])


def _check_ai_key(x_api_key: str | None = Header(default=None)):
    """Separate machine credential for the AI SOC Engineer. Kept apart from
    the SIEM ingest key and from user logins — three different callers,
    three different credentials.
    """
    if x_api_key != settings.ai_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _looks_internal(target_value: str) -> bool:
    """Return whether an IP target overlaps a configured internal network."""
    try:
        target_network = ip_network(target_value, strict=False)
    except ValueError:
        return False

    for cidr in settings.internal_network_cidrs.split(","):
        internal_network = ip_network(cidr.strip(), strict=False)
        if target_network.version == internal_network.version and target_network.overlaps(internal_network):
            return True
    return False


def determine_impact(conn, action_type: str, target_scope: str, is_internal: bool, is_permanent: bool) -> str:
    """The backend assigns impact — never trusts the AI's own labeling.
    Every matching rule is considered; the highest impact found wins.
    No match at all is treated as high (fail safe).
    """
    rules = conn.execute(
        """
        SELECT impact FROM impact_rules
        WHERE (action_type IS NULL OR action_type = %s)
          AND (target_scope IS NULL OR target_scope = %s)
          AND (is_internal IS NULL OR is_internal = %s)
          AND (is_permanent IS NULL OR is_permanent = %s)
        """,
        (action_type, target_scope, is_internal, is_permanent),
    ).fetchall()

    if not rules:
        return "high"
    return "high" if any(r["impact"] == "high" for r in rules) else "low"


def _is_protected(conn, target_value: str) -> bool:
    """True if an IP target overlaps a protected network.

    Overlap matters for subnet actions: a block range containing a protected
    host is unsafe even when the full action range is not inside that host's
    allowlisted network.
    """
    try:
        target_network = ip_network(target_value, strict=False)
    except ValueError:
        return False  # not an IP target (e.g. isolate_host by hostname) — allowlist doesn't apply

    row = conn.execute(
        "SELECT 1 FROM protected_targets WHERE %s::cidr && target LIMIT 1",
        (str(target_network),),
    ).fetchone()
    return row is not None


def _find_active_action(conn, target_value: str, action_type: str, executor: str):
    """An 'active' action: it succeeded, hasn't been reverted, and hasn't
    expired. Used to avoid double-blocking the same target — approving a
    second recommendation for something already blocked should be a safe
    no-op, not a duplicate rule or a crash.
    """
    return conn.execute(
        """
        SELECT a.* FROM actions a
        JOIN recommendations r ON r.id = a.recommendation_id
        WHERE r.target_value = %s AND r.action_type = %s AND a.executor = %s
          AND a.success = TRUE
          AND a.reverted_at IS NULL
          AND (a.expires_at IS NULL OR a.expires_at > now())
        ORDER BY a.executed_at DESC
        LIMIT 1
        """,
        (target_value, action_type, executor),
    ).fetchone()


def _find_pending_action(conn, target_value: str, action_type: str, executor: str):
    """Find an execution for this target that is queued or currently running."""
    return conn.execute(
        """
        SELECT a.id
        FROM actions a
        JOIN recommendations r ON r.id = a.recommendation_id
        JOIN action_jobs j ON j.action_id = a.id AND j.operation = 'execute'
        WHERE r.target_value = %s AND r.action_type = %s AND a.executor = %s
          AND a.success IS NULL
          AND j.status IN ('queued', 'running')
        ORDER BY a.id
        LIMIT 1
        """,
        (target_value, action_type, executor),
    ).fetchone()


@router.post("", dependencies=[Depends(_check_ai_key)])
def create_recommendation(rec: RecommendationIn):
    """The AI submits a recommendation. It is stored as pending and
    NEVER executed here — a human always decides.
    """
    is_internal = _looks_internal(rec.target_value)

    with pool.connection() as conn:
        impact = determine_impact(
            conn, rec.action_type, rec.target_scope, is_internal, rec.is_permanent
        )

        if not rec.is_permanent and rec.duration_secs is None:
            raise HTTPException(
                status_code=422, detail="duration_secs is required for non-permanent actions"
            )

        incident = conn.execute(
            "SELECT id FROM incidents WHERE id = %s", (rec.incident_id,)
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        row = conn.execute(
            """
            INSERT INTO recommendations
                (incident_id, action_type, executor, target_scope, target_value,
                 is_internal, is_permanent, duration_secs, reason, risk_score, impact)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                rec.incident_id,
                rec.action_type,
                rec.executor,
                rec.target_scope,
                rec.target_value,
                is_internal,
                rec.is_permanent,
                rec.duration_secs,
                rec.reason,
                rec.risk_score,
                impact,
            ),
        ).fetchone()

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, event_type, entity_type, entity_id, details)
            VALUES ('ai', 'recommendation.created', 'recommendation', %s, %s)
            """,
            (row["id"], Jsonb({"impact": impact, "action_type": rec.action_type})),
        )

    return row


@router.get("")
def list_recommendations(status: str | None = None, user: dict = Depends(get_current_user)):
    query = "SELECT * FROM recommendations"
    params: tuple = ()
    if status:
        query += " WHERE status = %s"
        params = (status,)
    query += " ORDER BY created_at DESC"

    with pool.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return rows


@router.post("/{rec_id}/approve")
def approve(
    rec_id: int,
    decision: DecisionIn,
    user: dict = Depends(require_roles("tier2", "tier3", "admin")),
):
    with pool.connection() as conn:
        rec = conn.execute(
            "SELECT * FROM recommendations WHERE id = %s", (rec_id,)
        ).fetchone()
        if rec is None:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        if rec["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"Already {rec['status']}")

        # The core rule: tier2 can approve low-impact only, tier3/admin can approve any.
        if rec["impact"] == "high" and user["role"] not in ("tier3", "admin"):
            raise HTTPException(
                status_code=403,
                detail="High-impact actions require tier3. Escalate the incident instead.",
            )

        if _is_protected(conn, rec["target_value"]):
            raise HTTPException(
                status_code=403,
                detail="Target is on the protected allowlist and cannot be acted on",
            )

        command = {
            "action_type": rec["action_type"],
            "target": rec["target_value"],
            "executor": rec["executor"],
        }
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{rec['executor']}:{rec['action_type']}:{rec['target_value']}",),
        )
        pending = _find_pending_action(
            conn, rec["target_value"], rec["action_type"], rec["executor"]
        )
        if pending:
            raise HTTPException(
                status_code=409,
                detail=f"An identical action is already queued or running (action #{pending['id']})",
            )

        existing = _find_active_action(
            conn, rec["target_value"], rec["action_type"], rec["executor"]
        )

        approved = conn.execute(
            """
            UPDATE recommendations
            SET status = 'approved', decided_by = %s, decided_at = now()
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (user["id"], rec_id),
        ).fetchone()
        if approved is None:
            raise HTTPException(status_code=409, detail="Recommendation is no longer pending")

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, 'recommendation.approved', 'recommendation', %s, %s)
            """,
            (user["id"], rec_id, Jsonb({"comment": decision.comment})),
        )

        if existing:
            conn.execute(
                "UPDATE recommendations SET status = 'executed' WHERE id = %s",
                (rec_id,),
            )
            conn.execute(
                """
                INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
                VALUES ('user', %s, 'recommendation.approved_existing_action', 'recommendation', %s, %s)
                """,
                (user["id"], rec_id, Jsonb({"action_id": existing["id"]})),
            )
            return {
                "recommendation_id": rec_id,
                "status": "already_active",
                "action": existing,
            }

        expires_at = None
        if not rec["is_permanent"]:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=rec["duration_secs"])

        action = conn.execute(
            """
            INSERT INTO actions
                (recommendation_id, executor, command, success, result_message,
                 executed_by, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                rec_id,
                rec["executor"],
                Jsonb(command),
                None,
                "Execution queued",
                user["id"],
                expires_at,
            ),
        ).fetchone()

        conn.execute(
            """
            INSERT INTO action_jobs (action_id, operation, requested_by)
            VALUES (%s, 'execute', %s)
            """,
            (action["id"], user["id"]),
        )

    return {
        "recommendation_id": rec_id,
        "status": "queued",
        "action": action,
    }


@router.post("/{rec_id}/reject")
def reject(
    rec_id: int,
    decision: DecisionIn,
    user: dict = Depends(require_roles("tier2", "tier3", "admin")),
):
    with pool.connection() as conn:
        rec = conn.execute(
            "SELECT id, status FROM recommendations WHERE id = %s", (rec_id,)
        ).fetchone()
        if rec is None:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        if rec["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"Already {rec['status']}")

        rejected = conn.execute(
            """
            UPDATE recommendations
            SET status = 'rejected', decided_by = %s, decided_at = now()
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (user["id"], rec_id),
        ).fetchone()
        if rejected is None:
            raise HTTPException(status_code=409, detail="Recommendation is no longer pending")

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, 'recommendation.rejected', 'recommendation', %s, %s)
            """,
            (user["id"], rec_id, Jsonb({"comment": decision.comment})),
        )

    return {"recommendation_id": rec_id, "status": "rejected"}