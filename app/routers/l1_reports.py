"""L1 triage reports: the AI drafts one for a new incident, tier 1 reviews
it, and approving it is the triage decision itself. The AI agent and
analysts can append notes to a report at any time."""
import json
from ipaddress import ip_address
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from ..db import pool
from ..deps import get_current_user, require_ai_key, require_roles
from ..evidence_validation import validate_evidence
from ..intel_lookup import lookup_ip
from ..l1_report_format import render
from ..schemas import L1RejectIn, L1ReportContent, L1ReportIn, L1ReviewIn, NoteIn
from .incidents import apply_triage

router = APIRouter(prefix="/l1-reports", tags=["l1-reports"])

TRIAGE_ROLES = ("tier1", "tier2", "tier3", "admin")
MAX_REPUTATION_LOOKUPS = 5  # keeps a report submission fast even with many IPs




# Facts the AI can't make up: reputation of public IPs, when each IP was
# first seen, its recent alert volume, and how many other incidents involved it.
def _enrich(conn, incident_id: int, indicators: list[dict]) -> dict:
    enrichment = {}
    lookups = 0
    for ip in dict.fromkeys(item["value"] for item in indicators if item["type"] == "ip"):
        history = conn.execute(
            """
            SELECT min(COALESCE(event_time, ingested_at)) AS first_seen,
                   count(*) FILTER (
                       WHERE COALESCE(event_time, ingested_at) > now() - interval '7 days'
                   ) AS alerts_last_7_days,
                   count(DISTINCT incident_id) FILTER (WHERE incident_id <> %s) AS other_incidents
            FROM alerts
            WHERE src_ip = %s::inet OR dst_ip = %s::inet
            """,
            (incident_id, ip, ip),
        ).fetchone()
        internal = not ip_address(ip).is_global  # private addresses never leave the network
        threat_intel = []
        if not internal and lookups < MAX_REPUTATION_LOOKUPS:
            lookups += 1
            threat_intel = [
                {"provider": result["provider"], "status": result["status"], "verdict": result["verdict"]}
                for result in lookup_ip(conn, ip)["results"]
            ]
        enrichment[ip] = {
            "internal": internal,
            "threat_intel": threat_intel,
            "first_seen": history["first_seen"].isoformat() if history["first_seen"] else None,
            "alerts_last_7_days": history["alerts_last_7_days"],
            "other_incidents": history["other_incidents"],
        }
    return enrichment




# Load a report with its reviewer's username, or 404.
def _load(conn, report_id: int) -> dict:
    report = conn.execute(
        """
        SELECT r.*, u.username AS reviewer
        FROM l1_reports r LEFT JOIN users u ON u.id = r.reviewed_by
        WHERE r.id = %s
        """,
        (report_id,),
    ).fetchone()
    if report is None:
        raise HTTPException(status_code=404, detail="L1 report not found")
    return report




# A report's notes, oldest first, with each analyst's username and role.
def _notes(conn, report_id: int) -> list[dict]:
    return conn.execute(
        """
        SELECT n.id, n.author_type, n.body, n.created_at, u.username AS author, u.role AS author_role
        FROM l1_report_notes n LEFT JOIN users u ON u.id = n.author_id
        WHERE n.report_id = %s
        ORDER BY n.created_at, n.id
        """,
        (report_id,),
    ).fetchall()




# Append one note to a report and record it in the audit log.
def _add_note(report_id: int, author_type: str, author_id: int | None, body: str) -> dict:
    with pool.connection() as conn:
        _load(conn, report_id)
        note = conn.execute(
            """
            INSERT INTO l1_report_notes (report_id, author_type, author_id, body)
            VALUES (%s, %s, %s, %s) RETURNING *
            """,
            (report_id, author_type, author_id, body),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES (%s, %s, 'l1_report.note_added', 'l1_report', %s, %s)
            """,
            (author_type, author_id, report_id, Jsonb({"note_id": note["id"]})),
        )
    return note




# The AI submits its draft; the incident is untouched until tier 1 approves.
@router.post("", dependencies=[Depends(require_ai_key)], status_code=201)
def submit_report(report: L1ReportIn):
    content = report.model_dump(mode="json", exclude={"incident_id", "evidence_alert_ids"})
    evidence_ids = sorted(set(report.evidence_alert_ids))

    with pool.connection() as conn:
        incident = conn.execute(
            "SELECT status FROM incidents WHERE id = %s", (report.incident_id,)
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        if incident["status"] != "new":
            raise HTTPException(
                status_code=409,
                detail=f"Incident was already triaged ({incident['status']}); L1 reports are for new incidents",
            )

        evidence = validate_evidence(conn, report.incident_id, evidence_ids)
        if not evidence["valid"]:
            raise HTTPException(
                status_code=422,
                detail={"message": "Cited evidence failed validation", "errors": evidence["errors"]},
            )

        row = conn.execute(
            """
            INSERT INTO l1_reports
                (incident_id, verdict, severity, category, content, evidence_alert_ids, enrichment, ai_draft)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (incident_id) WHERE status = 'pending_review' DO NOTHING
            RETURNING *
            """,
            (
                report.incident_id,
                report.verdict,
                report.severity,
                report.category,
                Jsonb(content),
                evidence_ids,
                Jsonb(_enrich(conn, report.incident_id, content["indicators"])),
                Jsonb(content),
            ),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=409, detail="This incident already has an L1 report awaiting review")

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, event_type, entity_type, entity_id, details)
            VALUES ('ai', 'l1_report.drafted', 'l1_report', %s, %s)
            """,
            (row["id"], Jsonb({"incident_id": report.incident_id, "verdict": report.verdict})),
        )

    return row




# The review queue, newest first.
@router.get("")
def list_reports(
    status: Literal["pending_review", "approved", "rejected"] | None = None,
    user: dict = Depends(get_current_user),
):
    query = "SELECT * FROM l1_reports"
    params: tuple = ()
    if status:
        query += " WHERE status = %s"
        params = (status,)
    query += " ORDER BY created_at DESC"

    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()




# How the queue and the AI are doing: review counts, how often tier 1 kept
# the AI's verdict, and mean time to acknowledge (MTTA).
@router.get("/metrics")
def report_metrics(user: dict = Depends(get_current_user)):
    with pool.connection() as conn:
        counts = conn.execute(
            """
            SELECT count(*) FILTER (WHERE status = 'pending_review') AS pending_review,
                   count(*) FILTER (WHERE status = 'approved') AS approved,
                   count(*) FILTER (WHERE status = 'rejected') AS rejected,
                   count(*) FILTER (WHERE status = 'approved' AND verdict = ai_draft->>'verdict') AS ai_verdict_kept
            FROM l1_reports
            """
        ).fetchone()
        mtta = conn.execute(
            """
            SELECT avg(EXTRACT(EPOCH FROM triaged_at - created_at)) / 60 AS minutes,
                   count(*) AS triaged_incidents
            FROM incidents
            WHERE triaged_at IS NOT NULL
            """
        ).fetchone()

    return {
        **counts,
        "ai_verdict_agreement": round(counts["ai_verdict_kept"] / counts["approved"], 3) if counts["approved"] else None,
        "mtta_minutes": round(float(mtta["minutes"]), 1) if mtta["minutes"] is not None else None,
        "triaged_incidents": mtta["triaged_incidents"],
    }




# One report as JSON, with its notes.
@router.get("/{report_id}")
def get_report(report_id: int, user: dict = Depends(get_current_user)):
    with pool.connection() as conn:
        return {**_load(conn, report_id), "notes": _notes(conn, report_id)}




# One report as the plain-text handoff document.
@router.get("/{report_id}/text", response_class=PlainTextResponse)
def get_report_text(report_id: int, user: dict = Depends(get_current_user)) -> str:
    with pool.connection() as conn:
        report = _load(conn, report_id)
        incident = conn.execute(
            "SELECT id, created_at FROM incidents WHERE id = %s", (report["incident_id"],)
        ).fetchone()
        alerts = conn.execute(
            """
            SELECT id, source, signature, src_ip, dst_ip, COALESCE(event_time, ingested_at) AS seen_at
            FROM alerts WHERE incident_id = %s ORDER BY seen_at
            """,
            (report["incident_id"],),
        ).fetchall()
        actions = conn.execute(
            """
            SELECT r.action_type, r.target_value, a.success, a.reverted_at
            FROM actions a JOIN recommendations r ON r.id = a.recommendation_id
            WHERE r.incident_id = %s ORDER BY a.executed_at
            """,
            (report["incident_id"],),
        ).fetchall()
        notes = _notes(conn, report_id)
    return render(report, incident, alerts, actions, notes)




# Approve a draft, optionally correcting any field first. This triages the
# incident: a true positive goes to tier 2, a false positive is closed.
@router.post("/{report_id}/approve")
def approve_report(report_id: int, review: L1ReviewIn, user: dict = Depends(require_roles(*TRIAGE_ROLES))):
    with pool.connection() as conn:
        report = conn.execute(
            "SELECT * FROM l1_reports WHERE id = %s FOR UPDATE", (report_id,)
        ).fetchone()
        if report is None:
            raise HTTPException(status_code=404, detail="L1 report not found")
        if report["status"] != "pending_review":
            raise HTTPException(status_code=409, detail=f"Report is already {report['status']}")

        try:
            final = L1ReportContent.model_validate({**report["content"], **review.changes})
        except ValidationError as error:
            raise HTTPException(status_code=422, detail=json.loads(error.json(include_url=False))) from None
        content = final.model_dump(mode="json")
        changes = [
            field
            for field in L1ReportContent.model_fields
            if field in review.changes and content[field] != report["content"].get(field)
        ]
        true_positive = final.verdict == "true_positive"

        triage = apply_triage(
            conn,
            report["incident_id"],
            user["id"],
            true_positive,
            final.escalation_reason if true_positive else final.false_positive_reason,
        )
        conn.execute(
            "UPDATE incidents SET severity = %s, ai_summary = %s, updated_at = now() WHERE id = %s",
            (final.severity, final.summary, report["incident_id"]),
        )
        conn.execute(
            """
            UPDATE l1_reports
            SET status = 'approved', verdict = %s, severity = %s, category = %s, content = %s,
                reviewer_changes = %s, reviewed_by = %s, reviewed_at = now(), review_comment = %s
            WHERE id = %s
            """,
            (
                final.verdict,
                final.severity,
                final.category,
                Jsonb(content),
                changes,
                user["id"],
                review.comment,
                report_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, 'l1_report.approved', 'l1_report', %s, %s)
            """,
            (user["id"], report_id, Jsonb({"verdict": final.verdict, "reviewer_changes": changes})),
        )

    return {
        "report_id": report_id,
        "incident_id": report["incident_id"],
        "incident_status": triage["status"],
        "verdict": final.verdict,
        "reviewer_changes": changes,
    }




# Send a draft back. The incident stays new, so the AI can submit a corrected
# report or tier 1 can triage it by hand.
@router.post("/{report_id}/reject")
def reject_report(report_id: int, body: L1RejectIn, user: dict = Depends(require_roles(*TRIAGE_ROLES))):
    with pool.connection() as conn:
        row = conn.execute(
            """
            UPDATE l1_reports
            SET status = 'rejected', reviewed_by = %s, reviewed_at = now(), review_comment = %s
            WHERE id = %s AND status = 'pending_review'
            RETURNING id, incident_id
            """,
            (user["id"], body.comment, report_id),
        ).fetchone()
        if row is None:
            existing = _load(conn, report_id)
            raise HTTPException(status_code=409, detail=f"Report is already {existing['status']}")

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('user', %s, 'l1_report.rejected', 'l1_report', %s, %s)
            """,
            (user["id"], report_id, Jsonb({"comment": body.comment})),
        )

    return {"report_id": report_id, "incident_id": row["incident_id"], "status": "rejected"}




# An analyst adds a note, e.g. something found after the report was written.
@router.post("/{report_id}/notes", status_code=201)
def add_analyst_note(report_id: int, note: NoteIn, user: dict = Depends(require_roles(*TRIAGE_ROLES))):
    return _add_note(report_id, "user", user["id"], note.body)




# The AI agent adds a note, e.g. new evidence that arrived after its draft.
@router.post("/{report_id}/notes/ai", dependencies=[Depends(require_ai_key)], status_code=201)
def add_ai_note(report_id: int, note: NoteIn):
    return _add_note(report_id, "ai", None, note.body)
