from typing import Literal, Optional
 
from pydantic import BaseModel
 
 
class AlertIn(BaseModel):
    """What the security team's pipeline sends us.
 
    Deliberately loose: almost everything is optional. A missing or
    malformed field must never cause a rejected event — see alerts.py.
    """
 
    source: str  # 'siem', 'ids', 'edr', 'firewall', 'webapp'
    event_time: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    hostname: Optional[str] = None
    signature: Optional[str] = None
    severity: Optional[int] = None
 
    class Config:
        extra = "allow"  # keep any extra fields the sender includes
 
 
class NoteIn(BaseModel):
    body: str
 
 
class RecommendationIn(BaseModel):
    """What the AI SOC Engineer sends when it wants an action taken.
 
    The AI proposes; it never decides impact or executes anything itself.
    """
 
    incident_id: int
    action_type: str  # 'block_ip', 'block_port', 'isolate_host', 'unisolate_host', ...
    executor: Literal["firewall", "edr"]
    target_scope: str  # 'single_ip', 'subnet', 'endpoint', ...
    target_value: str  # the IP, CIDR, port or hostname
    is_permanent: bool = False
    duration_secs: Optional[int] = None
    reason: str
    risk_score: Optional[int] = None
 
 
class DecisionIn(BaseModel):
    """Optional note when approving/rejecting a recommendation."""
 
    comment: Optional[str] = None
 
 
class TriageIn(BaseModel):
    """Tier1's verdict on a new incident: real, or a false positive."""
 
    confirmed: bool
    reason: Optional[str] = None  # why it's a false positive, if not confirmed
 