from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertIn(BaseModel):
    """What the security team's pipeline sends us.
 
    Deliberately loose: almost everything is optional. A missing or
    malformed field must never cause a rejected event — see alerts.py.
    """
 
    model_config = ConfigDict(extra="allow")

    source: str  # 'siem', 'ids', 'edr', 'firewall', 'webapp'
    event_time: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    signature: str | None = None
    severity: int | None = None


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


class RecommendationIn(BaseModel):
    """What the AI SOC Engineer sends when it wants an action taken.
 
    The AI proposes; it never decides impact or executes anything itself.
    """

    incident_id: int = Field(gt=0)
    action_type: str = Field(min_length=1, max_length=100)  # 'block_ip', 'block_port', 'isolate_host', 'unisolate_host', ...
    executor: Literal["firewall", "edr"]
    target_scope: str = Field(min_length=1, max_length=100)  # 'single_ip', 'subnet', 'endpoint', ...
    target_value: str = Field(min_length=1, max_length=255)  # the IP, CIDR, port or hostname
    is_permanent: bool = False
    duration_secs: int | None = Field(default=None, gt=0)
    reason: str = Field(min_length=1, max_length=10_000)
    risk_score: int | None = Field(default=None, ge=0, le=100)


class DecisionIn(BaseModel):
    """Optional note when approving/rejecting a recommendation."""

    comment: str | None = Field(default=None, max_length=10_000)


class TriageIn(BaseModel):
    """Tier1's verdict on a new incident: real, or a false positive."""

    confirmed: bool
    reason: str | None = Field(default=None, max_length=10_000)  # why it's a false positive, if not confirmed
 