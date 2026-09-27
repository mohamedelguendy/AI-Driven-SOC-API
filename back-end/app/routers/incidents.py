from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb

from ..db import pool
from ..deps import get_current_user, require_roles
from ..schemas import NoteIn

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(status: str | None = None, user: dict = Depends(get_current_user)):
    """The incident queue. No tier 1 exists, so this is the first screen
    any analyst sees — ordered by risk so the most important incident is
    always on top.
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


@router.post("/{incident_id}/notes")
def add_note(
    incident_id: int, note: NoteIn, user: dict = Depends(require_roles("tier2", "tier3", "admin"))
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

        if incident_id is not None:
            conn.execute(
                "UPDATE incidents SET status = 'investigating', updated_at = now() "
                "WHERE id = %s AND status = 'new'",
                (incident_id,),
            )

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
            WHERE id = %s
            RETURNING id, status
            """,
            (incident_id,),
        ).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")

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
            WHERE id = %s
            RETURNING id, status
            """,
            (incident_id,),
        ).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id)
            VALUES ('user', %s, 'incident.resolved', 'incident', %s)
            """,
            (user["id"], incident_id),
        )

    return result