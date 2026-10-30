"""Plain-text rendering of an L1 report, in the layout tier 1 hands to tier 2."""
import textwrap
from datetime import datetime, timezone

WIDTH = 78
DASH = "\u2014"
SEVERITY_LABELS = {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Informational"}
PRIORITIES = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P4"}
STATUS_LINES = {
    "pending_review": "AI draft, awaiting L1 review",
    "approved": "Approved by {reviewer}",
    "rejected": "Draft rejected by {reviewer}",
}




# Format a timestamp (datetime or ISO string) the same way everywhere.
def _time(value) -> str:
    if value is None:
        return "pending"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")




# Wrap free text to the report width.
def _wrap(text: str | None) -> list[str]:
    return textwrap.wrap(text, WIDTH) if text else []




# "- srv-web-01 (10.20.1.15), user account: deploy, public web server, criticality: high"
def _asset_line(asset: dict) -> str:
    name = asset.get("hostname") or asset.get("ip") or ""
    if asset.get("hostname") and asset.get("ip"):
        name += f" ({asset['ip']})"
    if asset.get("user"):
        name = f"{name}, user account: {asset['user']}" if name else f"user account: {asset['user']}"
    details = [asset.get("role"), asset.get("criticality") and f"criticality: {asset['criticality']}"]
    details = [detail for detail in details if detail]
    return f"- {name}" + (f" {DASH} {', '.join(details)}" if details else "")




# "- 203.0.113.45: abuseipdb: malicious; first seen ...; no other incidents"
def _enrichment_line(ip: str, info: dict) -> str:
    if info.get("internal"):
        reputation = "internal address, no reputation lookup"
    elif info["threat_intel"]:
        reputation = ", ".join(
            f"{result['provider']}: "
            + (result["verdict"] if result["status"] == "ok" else result["status"].replace("_", " "))
            for result in info["threat_intel"]
        )
    else:
        reputation = "no reputation lookup"
    seen = f"first seen {_time(info['first_seen'])}" if info["first_seen"] else "not seen in any alert"
    others = info["other_incidents"]
    history = "no other incidents" if others == 0 else f"{others} other incident(s)"
    return f"- {ip}: {reputation}; {seen}; {history}"




# "- block_ip 203.0.113.45: in effect"
def _action_line(action: dict) -> str:
    if action["reverted_at"]:
        state = "reverted"
    elif action["success"] is None:
        state = "queued"
    else:
        state = "in effect" if action["success"] else "failed"
    return f"- {action['action_type']} {action['target_value']}: {state}"




# Render one report. alerts are all of the incident's alerts; actions are
# the response actions already queued or taken for it.
def render(report: dict, incident: dict, alerts: list[dict], actions: list[dict]) -> str:
    escalated = report["verdict"] == "true_positive"
    severity = report["severity"]
    reviewer = report.get("reviewer")
    evidence_ids = set(report["evidence_alert_ids"])
    evidence = [alert for alert in alerts if alert["id"] in evidence_ids]
    title = "L1 ESCALATION REPORT" if escalated else "L1 TRIAGE: CLOSED AS FALSE POSITIVE"

    lines = [
        f"INCIDENT #{incident['id']} {DASH} {title}",
        "Status: " + STATUS_LINES[report["status"]].format(reviewer=reviewer),
        f"Detected: {_time(incident['created_at'])}      Triaged: {_time(report['reviewed_at'])}",
        f"Analyst: {reviewer or DASH}      "
        f"Severity: {severity} ({SEVERITY_LABELS[severity]})   Priority: {PRIORITIES[severity]}",
    ]

    def section(heading: str, body: list[str]) -> None:
        lines.extend(["", heading, *(body or ["None"])])

    section("SUMMARY", _wrap(report["summary"]))
    verdict = "True positive" if escalated else "False positive"
    section(
        "L1 VERDICT",
        [
            f"{verdict} {DASH} confidence {report['confidence'].upper()}",
            *([] if escalated else _wrap(report["false_positive_reason"])),
        ],
    )
    triggers = dict.fromkeys(
        f"{alert['signature'] or 'unnamed detection'} (source: {alert['source']})" for alert in evidence
    )
    section("TRIGGER", [*triggers, f"Alerts on this incident: {len(alerts)} (cited as evidence: {len(evidence)})"])
    section("AFFECTED ASSETS", [_asset_line(asset) for asset in report["affected_assets"]])
    section("INDICATORS", [f"- {item['type']}: {item['value']}" for item in report["indicators"]])
    section(
        "EVIDENCE",
        [
            f"- {alert['id']}: {alert['signature'] or 'unnamed detection'}, "
            f"{alert['src_ip'] or '?'} -> {alert['dst_ip'] or '?'} at {_time(alert['seen_at'])}"
            for alert in evidence
        ],
    )
    section("ENRICHMENT", [_enrichment_line(ip, info) for ip, info in report["enrichment"].items()])
    section("ACTIONS TAKEN", [_action_line(action) for action in actions])

    recommendations = [f"- {action}" for action in report["recommended_actions"]]
    if escalated:
        section("ESCALATION REASON / RECOMMENDATION", [*_wrap(report["escalation_reason"]), *recommendations])
    else:
        section("RECOMMENDATION", recommendations)

    notes = []
    if report["reviewer_changes"]:
        notes.append("Changed from the AI draft: " + ", ".join(report["reviewer_changes"]))
    if report["ai_draft"]["verdict"] != report["verdict"]:
        notes.append(f"The AI originally judged this a {report['ai_draft']['verdict'].replace('_', ' ')}.")
    notes += _wrap(report["review_comment"])
    if notes:
        section("L1 REVIEW NOTES", notes)
    return "\n".join(lines) + "\n"
