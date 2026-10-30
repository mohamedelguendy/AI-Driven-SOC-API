from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FIREWALL_ACTION_TYPES = ("block_ip", "block_port")
Verdict = Literal["true_positive", "false_positive"]
Confidence = Literal["low", "medium", "high"]
ReportText = Annotated[str, Field(min_length=1, max_length=2000)]
ActionText = Annotated[str, Field(min_length=1, max_length=500)]
Category = Literal[
    "malware", "ransomware", "phishing", "account_compromise", "brute_force", "reconnaissance",
    "denial_of_service", "data_exfiltration", "insider_threat", "policy_violation",
    "vulnerability_exploitation", "other",
]
Tlp = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]




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




# One observable from the incident (IP, domain, hash, port, account...) and why it matters.
class Indicator(BaseModel):
    type: Literal[
        "ip", "domain", "url", "hash", "port", "user", "hostname", "process", "file_path", "email", "registry_key"
    ]
    value: str = Field(min_length=1, max_length=500)
    context: ReportText | None = None  # e.g. "brute-force source"

    @model_validator(mode="after")
    def normalize_value(self):
        value = self.value.strip()
        if self.type == "ip":
            try:
                value = str(ip_address(value))
            except ValueError:
                raise ValueError(f"'{self.value}' is not a valid IP address") from None
        elif self.type == "port":
            if not (value.isascii() and value.isdigit() and 1 <= int(value) <= 65535):
                raise ValueError("port indicators must be a number from 1 to 65535")
            value = str(int(value))
        self.value = value
        return self




# A host or account touched by the incident, and how much it matters.
class AffectedAsset(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    ip: str | None = None
    user: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=255)  # e.g. "public web server"
    criticality: Literal["low", "medium", "high", "critical"] | None = None

    @model_validator(mode="after")
    def require_identifier(self):
        if not (self.hostname or self.ip or self.user):
            raise ValueError("an affected asset needs a hostname, ip or user")
        if self.ip:
            try:
                self.ip = str(ip_address(self.ip.strip()))
            except ValueError:
                raise ValueError(f"'{self.ip}' is not a valid IP address") from None
        return self




# A MITRE ATT&CK technique seen in the incident.
class AttackTechnique(BaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")  # e.g. T1110.001
    name: str = Field(min_length=1, max_length=200)
    tactic: str | None = Field(default=None, max_length=100)  # e.g. "Credential Access"




# One timestamped event in the incident story.
class TimelineEvent(BaseModel):
    time: datetime
    event: ReportText
    source: str | None = Field(default=None, max_length=200)  # the log or tool it came from

    @field_validator("time")
    @classmethod
    def assume_utc(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)




# Something checked during triage, and what it showed.
class Finding(BaseModel):
    check: ReportText
    result: ReportText




# The five questions every L1 report answers. Left empty, the report fills
# them from the evidence.
class FiveWs(BaseModel):
    who: ReportText | None = None
    what: ReportText | None = None
    when: ReportText | None = None
    where: ReportText | None = None
    why: ReportText | None = None




# Business and data impact (VERIS-style: which of confidentiality, integrity
# and availability were hit).
class Impact(BaseModel):
    business_impact: ReportText | None = None
    data_exposure: Literal["none", "suspected", "confirmed", "unknown"] = "unknown"
    data_types: list[Literal["pii", "financial", "credentials", "intellectual_property", "health", "other"]] = Field(
        default_factory=list, max_length=6
    )
    cia_affected: list[Literal["confidentiality", "integrity", "availability"]] = Field(
        default_factory=list, max_length=3
    )
    affected_services: list[ActionText] = Field(default_factory=list, max_length=20)




# A raw log excerpt supporting the verdict (relevant lines only).
class LogExcerpt(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    excerpt: str = Field(min_length=1, max_length=4000)




# Someone who should hear about the incident, and why.
class Notification(BaseModel):
    audience: str = Field(min_length=1, max_length=200)  # e.g. "asset owner", "SOC manager"
    reason: ReportText




# Everything in an L1 report that the AI writes and tier 1 can correct.
class L1ReportContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: Confidence
    severity: int = Field(ge=1, le=5)  # 1 = critical ... 5 = informational
    category: Category = "other"
    tlp: Tlp = "AMBER"  # who the report may be shared with
    attacker: Literal["external", "internal", "partner", "unknown"] = "unknown"
    summary: ReportText
    five_ws: FiveWs = Field(default_factory=FiveWs)
    affected_assets: list[AffectedAsset] = Field(default_factory=list, max_length=50)
    indicators: list[Indicator] = Field(default_factory=list, max_length=100)
    mitre_attack: list[AttackTechnique] = Field(default_factory=list, max_length=30)
    timeline: list[TimelineEvent] = Field(default_factory=list, max_length=100)
    investigation_steps: list[Finding] = Field(default_factory=list, max_length=50)
    context_checks: list[Finding] = Field(default_factory=list, max_length=20)
    impact: Impact = Field(default_factory=Impact)
    log_excerpts: list[LogExcerpt] = Field(default_factory=list, max_length=20)
    actions_taken: list[ActionText] = Field(default_factory=list, max_length=20)
    recommended_actions: list[ActionText] = Field(default_factory=list, max_length=20)
    open_questions: list[ReportText] = Field(default_factory=list, max_length=20)
    notifications: list[Notification] = Field(default_factory=list, max_length=20)
    escalation_reason: ReportText | None = None  # required for a true positive
    false_positive_reason: ReportText | None = None  # required for a false positive
    false_positive_pattern: ReportText | None = None  # what keeps triggering the alert
    tuning_recommendation: Literal["tune_rule", "add_exclusion", "accept_risk"] | None = None

    @model_validator(mode="after")
    def require_reason_for_verdict(self):
        if self.verdict == "true_positive" and not self.escalation_reason:
            raise ValueError("a true_positive report needs an escalation_reason")
        if self.verdict == "false_positive" and not self.false_positive_reason:
            raise ValueError("a false_positive report needs a false_positive_reason")
        return self




# The AI's draft: the report content plus which incident and alerts it is about.
class L1ReportIn(L1ReportContent):
    incident_id: int = Field(gt=0)
    evidence_alert_ids: list[int] = Field(min_length=1, max_length=100)




# Tier 1's approval. Each key in changes replaces that field of the draft,
# e.g. {"severity": 2}; the result is validated like a new draft.
class L1ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    changes: dict[str, Any] = Field(default_factory=dict)
    comment: str | None = Field(default=None, max_length=10_000)




# Sending a draft back: tier 1 must say what was wrong with it.
class L1RejectIn(BaseModel):
    comment: str = Field(min_length=1, max_length=10_000)
