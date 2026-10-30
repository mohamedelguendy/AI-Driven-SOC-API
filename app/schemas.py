from ipaddress import ip_network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FIREWALL_ACTION_TYPES = ("block_ip", "block_port")




# Keep incoming security events flexible; route code validates extracted fields.
class AlertIn(BaseModel):
    """What the security team's pipeline sends us.

    Deliberately loose: every field is optional and untyped. A missing or
    malformed field must never cause a rejected event — alerts.py
    validates each one and records what it could not parse.
    """

    model_config = ConfigDict(extra="allow")

    source: Any = None  # 'siem', 'ids', 'edr', 'firewall', 'webapp'
    event_time: Any = None
    src_ip: Any = None
    dst_ip: Any = None
    hostname: Any = None
    signature: Any = None
    severity: Any = None




class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)




# Validate proposed response actions and derive firewall targets server-side.
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
    # Alerts the AI cites as evidence; checked against the incident before storing.
    evidence_alert_ids: list[int] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def normalize_firewall_target(self):
        """For firewall actions the backend, not the AI, decides what the
        target is and what scope it has. A target that can't be parsed is
        rejected rather than treated as external: otherwise it would skip
        the internal-network and protected-target checks.
        """
        if self.executor != "firewall":
            return self

        if self.action_type == "block_ip":
            try:
                network = ip_network(self.target_value.strip(), strict=False)
            except ValueError:
                raise ValueError("block_ip target_value must be an IP address or CIDR") from None
            if network.num_addresses == 1:
                self.target_scope, self.target_value = "single_ip", str(network.network_address)
            else:
                self.target_scope, self.target_value = "subnet", str(network)
        elif self.action_type == "block_port":
            port = self.target_value.strip()
            if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
                raise ValueError("block_port target_value must be a port number from 1 to 65535")
            self.target_scope, self.target_value = "port", str(int(port))
        else:
            raise ValueError(
                "firewall action_type must be one of: " + ", ".join(FIREWALL_ACTION_TYPES)
            )
        return self




# Shared request bodies for analyst decisions and incident triage.
class DecisionIn(BaseModel):
    """Optional note when approving/rejecting a recommendation."""

    comment: str | None = Field(default=None, max_length=10_000)




class TriageIn(BaseModel):
    """Tier1's verdict on a new incident: real, or a false positive."""

    confirmed: bool
    reason: str | None = Field(default=None, max_length=10_000)  # why it's a false positive, if not confirmed
