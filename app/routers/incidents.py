from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb

from ..db import pool
from ..deps import get_current_user, require_roles
from ..schemas import NoteIn, TriageIn

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(
    status: Literal["new", "investigating", "escalated", "in_response", "resolved", "closed"] | None = None,
    user: dict = Depends(get_current_user),
):
    """The incident queue. Tier 1 triage happens first, then tier 2/tier 3
    work the tracked incident. Incidents are ordered by risk so the most
    important case is always surfaced first.
    """
    query = "SELECT * FROM incidents"
    params: tuple = ()
    if status:
        query += " WHERE status = %s"
        params = (status,)
    query += " ORDER BY risk_score DESC NULLS LAST, created_at DESC"

    with pool.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return rows


@router.get("/{incident_id}")
def get_incident(incident_id: int, user: dict = Depends(get_current_user)):
    with pool.connection() as conn:
        incident = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        alerts = conn.execute(
            "SELECT * FROM alerts WHERE incident_id = %s ORDER BY event_time DESC",
            (incident_id,),
        ).fetchall()
        notes = conn.execute(
            """
            SELECT n.*, u.username AS author_username
            FROM incident_notes n JOIN users u ON u.id = n.author_id
            WHERE n.incident_id = %s ORDER BY n.created_at
            """,
            (incident_id,),
        ).fetchall()
        recommendations = conn.execute(
            "SELECT * FROM recommendations WHERE incident_id = %s ORDER BY created_at",
            (incident_id,),
        ).fetchall()

    return {
        "incident": incident,
        "alerts": alerts,
        "notes": notes,
        "recommendations": recommendations,
    }


@router.post("/{incident_id}/triage")
def triage_incident(
    incident_id: int,
    triage: TriageIn,
    user: dict = Depends(require_roles("tier1", "tier2", "tier3", "admin")),
):
    """Tier 1 confirms whether an incident is real or a false positive."""
    with pool.connection() as conn:
        incident = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        if incident["status"] != "new":
            raise HTTPException(
                status_code=409,
                detail=f"Incident is already in status '{incident['status']}' and cannot be triaged again",
            )

        if triage.confirmed:
            new_status = "investigating"
            assigned_tier = "tier2"
            summary = triage.reason or "Confirmed as a real incident by triage review"
        else:
            new_status = "closed"
            assigned_tier = None
            summary = triage.reason or "Dismissed as a false positive during triage"

        row = conn.execute(
            """
            UPDATE incidents
            SET status = %s,
                assigned_tier = %s,
                updated_at = now(),
                resolved_at = CASE WHEN %s = 'closed' THEN now() ELSE resolved_at END
            WHERE id = %s AND status = 'new'
            RETURNING id, status, assigned_tier, updated_at
            """,
            (new_status, assigned_tier, new_status, incident_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=409, detail="Incident was triaged by another request")

        conn.execute(
            """
            INSERT INTO incident_notes (incident_id, author_id, body)
            VALUES (%s, %s, %s)
            """,
            (incident_id, user["id"], f"Triage verdict: {'confirmed' if triage.confirmed else 'dismissed'} - {summary}"),
        )

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, %s, 'incident', %s, %s)
            """,
            (
                user["id"],
                "incident.triaged_confirmed" if triage.confirmed else "incident.triaged_dismissed",
                incident_id,
                Jsonb({"confirmed": triage.confirmed, "reason": triage.reason}),
            ),
        )

    return {
        "incident_id": incident_id,
        "status": row["status"],
        "confirmed": triage.confirmed,
        "reason": triage.reason,
    }


@router.post("/{incident_id}/notes")
def add_note(
    incident_id: int, note: NoteIn, user: dict = Depends(require_roles("tier1", "tier2", "tier3", "admin"))
):
    with pool.connection() as conn:
        incident = conn.execute(
            "SELECT id FROM incidents WHERE id = %s", (incident_id,)
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        row = conn.execute(
            """
            INSERT INTO incident_notes (incident_id, author_id, body)
            VALUES (%s, %s, %s) RETURNING id, created_at
            """,
            (incident_id, user["id"], note.body),
        ).fetchone()

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id)
            VALUES ('user', %s, 'incident.note_added', 'incident', %s)
            """,
            (user["id"], incident_id),
        )

    return row


@router.post("/{incident_id}/escalate")
def escalate(incident_id: int, user: dict = Depends(require_roles("tier2", "admin"))):
    """Tier 2 hands the incident to tier 3 for response."""
    with pool.connection() as conn:
        result = conn.execute(
            """
            UPDATE incidents
            SET status = 'escalated', assigned_tier = 'tier3', updated_at = now()
            WHERE id = %s AND status = 'investigating'
            RETURNING id, status
            """,
            (incident_id,),
        ).fetchone()
        if result is None:
            current = conn.execute(
                "SELECT status FROM incidents WHERE id = %s", (incident_id,)
            ).fetchone()
            if current is None:
                raise HTTPException(status_code=404, detail="Incident not found")
            raise HTTPException(
                status_code=409,
                detail=f"Incident cannot be escalated from status '{current['status']}'",
            )

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id)
            VALUES ('user', %s, 'incident.escalated', 'incident', %s)
            """,
            (user["id"], incident_id),
        )

    return result


@router.post("/{incident_id}/resolve")
def resolve(incident_id: int, user: dict = Depends(require_roles("tier2", "tier3", "admin"))):
    with pool.connection() as conn:
        result = conn.execute(
            """
            UPDATE incidents
            SET status = 'resolved', resolved_at = now(), updated_at = now()
            WHERE id = %s AND status IN ('investigating', 'escalated', 'in_response')
            RETURNING id, status
            """,
            (incident_id,),
        ).fetchone()
        if result is None:
            current = conn.execute(
                "SELECT status FROM incidents WHERE id = %s", (incident_id,)
            ).fetchone()
            if current is None:
                raise HTTPException(status_code=404, detail="Incident not found")
            raise HTTPException(
                status_code=409,
                detail=f"Incident cannot be resolved from status '{current['status']}'",
            )

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id)
            VALUES ('user', %s, 'incident.resolved', 'incident', %s)
            """,
            (user["id"], incident_id),
        )

    return result