"""Checks that an AI-submitted recommendation's cited evidence actually
exists — i.e. the alert IDs it points to are real, and really belong to
the incident it claims. This is the hallucination check: the AI should
never be trusted to cite evidence that doesn't exist or doesn't apply.
"""
from typing import Any




# Confirm every cited alert exists and belongs to the submitted incident.
def validate_evidence(conn, incident_id: int, evidence_alert_ids: list[int]) -> dict[str, Any]:
    if not evidence_alert_ids:
        return {"valid": False, "errors": ["No evidence cited"], "validated_count": 0}

    rows = conn.execute(
        "SELECT id FROM alerts WHERE incident_id = %s AND id = ANY(%s)",
        (incident_id, evidence_alert_ids),
    ).fetchall()
    found_ids = {r["id"] for r in rows}

    errors = [
        f"Cited alert id {aid} does not exist or does not belong to incident {incident_id}"
        for aid in evidence_alert_ids
        if aid not in found_ids
    ]

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "validated_count": len(found_ids),
    }
