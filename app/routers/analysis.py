from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..analysis import analyze_event
from ..db import pool
from ..deps import get_current_user, require_roles
from ..evidence_validation import validate_evidence

router = APIRouter(prefix="/analysis", tags=["analysis"])


class ClassifyIn(BaseModel):
    signature: str | None = None
    severity: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None


@router.post("/classify")
def classify(event: ClassifyIn, user: dict = Depends(require_roles("tier1", "admin"))):
    """A suggestion for tier1 — not an automatic decision. Tier1 still
    makes the real call via POST /incidents/{id}/triage.
    """
    return analyze_event(event.model_dump())


class ValidateEvidenceIn(BaseModel):
    incident_id: int
    evidence_alert_ids: list[int]


@router.post("/validate-evidence")
def validate_evidence_endpoint(
    body: ValidateEvidenceIn, user: dict = Depends(get_current_user)
):
    """Confirms an AI recommendation's cited evidence is real. Call this
    before trusting an AI-submitted report's claims.
    """
    with pool.connection() as conn:
        return validate_evidence(conn, body.incident_id, body.evidence_alert_ids)