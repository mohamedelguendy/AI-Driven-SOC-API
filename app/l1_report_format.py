"""Plain-text rendering of an L1 report, in the layout tier 1 hands to tier 2.

The layout combines what real SOC escalation tickets have in common: the
five Ws, a UTC timeline, an impact assessment, indicators with reputation,
MITRE ATT&CK mapping, investigation steps, open questions for tier 2, and a
notes area for anything added later.
"""
import textwrap
from datetime import datetime, timezone

WIDTH = 78
DASH = "\u2014"
NONE = "None recorded."
SEVERITY_LABELS = {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Informational"}
PRIORITIES = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P4"}
STATUS_LINES = {
    "pending_review": "AI draft, awaiting L1 review",
    "approved": "Approved by {reviewer}",
    "rejected": "Draft rejected by {reviewer}",
}




# Accept a datetime or an ISO string, always returning an aware datetime.
def _as_datetime(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)




# Format a timestamp the same way everywhere.
def _time(value) -> str:
    if value is None:
        return "pending"
    return _as_datetime(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")




# Wrap a paragraph to the report width.
def _wrap(text: str | None, indent: str = "") -> list[str]:
    return textwrap.wrap(text, WIDTH, initial_indent=indent, subsequent_indent=indent) if text else []




# Wrap one list item, indenting continuation lines under its text.
def _bullet(text: str, prefix: str = "- ") -> list[str]:
    return textwrap.wrap(text, WIDTH, initial_indent=prefix, subsequent_indent=" " * len(prefix))




# "brute_force" -> "Brute force"
def _label(value: str) -> str:
    return value.replace("_", " ").capitalize()




# "abuseipdb: malicious, virustotal: not configured"
def _reputation(info: dict) -> str:
    if info.get("internal"):
        return "internal address, no reputation lookup"
    if not info["threat_intel"]:
        return "no reputation lookup"
    return ", ".join(
        f"{result['provider']}: "
        + (result["verdict"] if result["status"] == "ok" else result["status"].replace("_", " "))
        for result in info["threat_intel"]
    )




# "srv-web-01 (10.20.1.15), user account: deploy \u2014 public web server, criticality: high"
def _asset_text(asset: dict) -> str:
    name = asset.get("hostname") or asset.get("ip") or ""
    if asset.get("hostname") and asset.get("ip"):
        name += f" ({asset['ip']})"
    if asset.get("user"):
        name = f"{name}, user account: {asset['user']}" if name else f"user account: {asset['user']}"
    details = [asset.get("role"), asset.get("criticality") and f"criticality: {asset['criticality']}"]
    details = [detail for detail in details if detail]
    return name + (f" {DASH} {', '.join(details)}" if details else "")




# "block_ip 203.0.113.45: in effect"
def _action_text(action: dict) -> str:
    if action["reverted_at"]:
        state = "reverted"
    elif action["success"] is None:
        state = "queued"
    else:
        state = "in effect" if action["success"] else "failed"
    return f"{action['action_type']} {action['target_value']}: {state}"




# Render one report. alerts are all of the incident's alerts, actions the
# response actions queued or taken for it, notes the report's addenda.
def render(report: dict, incident: dict, alerts: list[dict], actions: list[dict], notes: list[dict]) -> str:
    content = report["content"]
    escalated = content["verdict"] == "true_positive"
    severity = content["severity"]
    reviewer = report.get("reviewer")
    reason = content["escalation_reason"] if escalated else content["false_positive_reason"]
    evidence_ids = set(report["evidence_alert_ids"])
    evidence = [alert for alert in alerts if alert["id"] in evidence_ids]
    seen = sorted(_as_datetime(alert["seen_at"]) for alert in evidence)
    window = f"{_time(seen[0])} to {_time(seen[-1])}" if seen else None
    assets = content["affected_assets"]
    users = list(dict.fromkeys(
        [asset["user"] for asset in assets if asset.get("user")]
        + [item["value"] for item in content["indicators"] if item["type"] == "user"]
    ))
    places = list(dict.fromkeys(asset.get("hostname") or asset.get("ip") for asset in assets if asset.get("hostname") or asset.get("ip")))
    signatures = list(dict.fromkeys(alert["signature"] or "unnamed detection" for alert in evidence))

    title = "L1 ESCALATION REPORT" if escalated else "L1 TRIAGE: CLOSED AS FALSE POSITIVE"
    lines = [
        f"INCIDENT #{incident['id']} {DASH} {title}",
        f"Report #{report['id']} | Status: "
        + STATUS_LINES[report["status"]].format(reviewer=reviewer)
        + f" | TLP:{content['tlp']}",
        f"Category: {_label(content['category'])} | Attacker: {_label(content['attacker'])} | "
        + ("Escalated to: Tier 2" if escalated else "Closed by: Tier 1"),
        f"Detected: {_time(incident['created_at'])} | Triaged: {_time(report['reviewed_at'])}",
        f"Analyst: {reviewer or DASH} | Severity: {severity} ({SEVERITY_LABELS[severity]}) | "
        f"Priority: {PRIORITIES[severity]} | Confidence: {content['confidence'].upper()}",
    ]
    number = 0

    def section(heading: str, body: list[str], empty: str = NONE) -> None:
        nonlocal number
        number += 1
        lines.extend(["", f"{number}. {heading}", *(body or [empty])])

    section("EXECUTIVE SUMMARY", _wrap(content["summary"]))

    ws = content["five_ws"]
    five_ws = [
        ("Who", ws["who"] or ", ".join(users) or "Not identified"),
        ("What", ws["what"] or ", ".join(signatures) or "Not described"),
        ("When", ws["when"] or (f"Activity window {window}" if window else "Unknown")),
        ("Where", ws["where"] or ", ".join(places) or "Not identified"),
        ("Why", ws["why"] or reason),
    ]
    section("AT A GLANCE (FIVE Ws)", [line for label, text in five_ws for line in _bullet(text, f"{label + ':':<7}")])

    section("L1 VERDICT", [
        f"{'True positive' if escalated else 'False positive'} {DASH} confidence {content['confidence'].upper()}",
        *_wrap(reason),
    ])

    section("DETECTION", [
        *(f"- {alert['signature'] or 'unnamed detection'} (source: {alert['source']})"
          for alert in {f"{a['signature']}|{a['source']}": a for a in evidence}.values()),
        f"Alerts on this incident: {len(alerts)} (cited as evidence: {len(evidence)})",
        f"Activity window: {window or 'unknown'}",
    ])

    events = [(item["time"], item["event"], item.get("source")) for item in content["timeline"]]
    events.append((incident["created_at"], "Incident opened by alert correlation", "SOC platform"))
    events.append((report["created_at"], "AI drafted this L1 report", "SOC platform"))
    if report["reviewed_at"]:
        verb = "approved" if report["status"] == "approved" else "rejected"
        events.append((report["reviewed_at"], f"Tier 1 {verb} the report ({reviewer})", "SOC platform"))
    events.sort(key=lambda event: _as_datetime(event[0]))
    section("TIMELINE (UTC)", [
        line
        for time, event, source in events
        for line in _bullet(event + (f" [{source}]" if source else ""), f"{_time(time)}  ")
    ])

    section("AFFECTED ASSETS", [line for asset in assets for line in _bullet(_asset_text(asset))])

    impact = content["impact"]
    exposure = _label(impact["data_exposure"])
    if impact["data_types"]:
        exposure += " (" + ", ".join(_label(kind) for kind in impact["data_types"]) + ")"
    section("IMPACT ASSESSMENT", [
        *_bullet(impact["business_impact"] or "Not assessed", "Business impact: "),
        f"Data exposure: {exposure}",
        "CIA affected: " + (", ".join(_label(item) for item in impact["cia_affected"]) or "Not assessed"),
        *_bullet(", ".join(impact["affected_services"]) or "None identified", "Affected services: "),
        f"Scope: {len(places)} host(s)/address(es), {len(users)} user account(s)",
    ])

    def indicator_text(item: dict) -> str:
        text = f"{item['type']}: {item['value']}"
        if item.get("context"):
            text += f" {DASH} {item['context']}"
        info = report["enrichment"].get(item["value"]) if item["type"] == "ip" else None
        return text + (f" [{_reputation(info)}]" if info else "")

    section("INDICATORS OF COMPROMISE", [line for item in content["indicators"] for line in _bullet(indicator_text(item))])

    section("MITRE ATT&CK", [
        f"- {technique['technique_id']} {technique['name']}"
        + (f" ({technique['tactic']})" if technique["tactic"] else "")
        for technique in content["mitre_attack"]
    ])

    evidence_lines = [
        line
        for alert in evidence
        for line in _bullet(
            f"{alert['id']}: {alert['signature'] or 'unnamed detection'}, "
            f"{alert['src_ip'] or '?'} -> {alert['dst_ip'] or '?'} at {_time(alert['seen_at'])}"
        )
    ]
    for excerpt in content["log_excerpts"]:
        evidence_lines += ["", f"Log excerpt [{excerpt['source']}]:", *(f"    {line}" for line in excerpt["excerpt"].splitlines())]
    section("EVIDENCE", evidence_lines)

    steps = []
    for index, step in enumerate(content["investigation_steps"], 1):
        steps += _bullet(step["check"], f"{index}. ") + _bullet(step["result"], "   Finding: ")
    section("INVESTIGATION STEPS", steps)

    section("CONTEXT CHECKS", [
        line for check in content["context_checks"] for line in _bullet(f"{check['check']}: {check['result']}")
    ])

    section("ENRICHMENT (VERIFIED BY THE BACKEND)", [
        line
        for ip, info in report["enrichment"].items()
        for line in _bullet(
            f"{ip}: {_reputation(info)}; "
            + (f"first seen {_time(info['first_seen'])}" if info["first_seen"] else "not seen in any alert")
            + f"; {info['alerts_last_7_days']} alert(s) in the last 7 days; "
            + ("no other incidents" if info["other_incidents"] == 0 else f"{info['other_incidents']} other incident(s)")
        )
    ])

    section("ACTIONS TAKEN", [
        *(line for text in content["actions_taken"] for line in _bullet(text, "- [L1] ")),
        *(line for action in actions for line in _bullet(_action_text(action), "- [response] ")),
    ], empty="None.")

    next_steps = [line for text in content["recommended_actions"] for line in _bullet(text)]
    if escalated:
        section("ESCALATION REASON AND NEXT STEPS", [*_wrap(reason), *next_steps])
    else:
        section("RECOMMENDED NEXT STEPS", next_steps)

    section(
        "OPEN QUESTIONS FOR TIER 2" if escalated else "OPEN QUESTIONS",
        [line for question in content["open_questions"] for line in _bullet(question)],
        empty="None.",
    )

    section("NOTIFICATIONS", [
        line for item in content["notifications"] for line in _bullet(f"{item['audience']}: {item['reason']}")
    ], empty="None required.")

    if not escalated:
        tuning = content["tuning_recommendation"]
        section("FALSE POSITIVE TUNING", [
            *_bullet(content["false_positive_pattern"] or "Not described", "Pattern: "),
            "Recommendation: " + (_label(tuning) if tuning else "None"),
        ])

    review = []
    if report["reviewer_changes"]:
        review += _bullet("Changed from the AI draft: " + ", ".join(report["reviewer_changes"]), "")
    if report["ai_draft"]["verdict"] != content["verdict"]:
        review.append(f"The AI originally judged this a {report['ai_draft']['verdict'].replace('_', ' ')}.")
    review += _wrap(report["review_comment"])
    if review:
        section("L1 REVIEW", review)

    note_lines = []
    for note in notes:
        author = "AI agent" if note["author_type"] == "ai" else f"{note['author']} ({note['author_role']})"
        note_lines += [f"[{_time(note['created_at'])}] {author}:", *_wrap(note["body"], "  ")]
    section("NOTES", note_lines, empty="No notes yet.")

    return "\n".join(lines) + "\n"
