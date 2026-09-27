from typing import Optional

from pydantic import BaseModel


class AlertIn(BaseModel):
    source: str
    event_time: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    hostname: Optional[str] = None
    signature: Optional[str] = None
    severity: Optional[int] = None

    class Config:
        extra = "allow"


class NoteIn(BaseModel):
    body: str


class RecommendationIn(BaseModel):
    incident_id: int
    action_type: str
    executor: str
    target_scope: str
    target_value: str
    is_permanent: bool = False
    duration_secs: Optional[int] = None
    reason: str
    risk_score: Optional[int] = None


class DecisionIn(BaseModel):
    comment: Optional[str] = None