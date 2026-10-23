"""Deterministic, rule-based first-pass classification of an alert.

This is NOT the AI — it's a simple, explainable rule set that gives
tier1 a starting suggestion (classification, severity, priority, risk
score) before they make the real call. Nothing in this file writes to
the database or changes anything on its own; it only suggests.
"""
from typing import Any


def analyze_event(event: dict[str, Any]) -> dict[str, Any]:
    signature = (event.get("signature") or "").lower()
    severity_hint = event.get("severity")
    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")

    evidence: list[str] = []
    recommendation = "Review the event and correlate it with related logs."
    classification = "NEEDS_REVIEW"
    severity = "LOW"
    priority = "P4"
    confidence = 0.50
    risk_score = 20

    if "port scan" in signature or "network scan" in signature:
        classification = "SUSPICIOUS_RECONNAISSANCE"
        severity, priority, confidence, risk_score = "HIGH", "P2", 0.85, 75
        evidence.append(f"Signature indicates possible reconnaissance: {event.get('signature')}")
        recommendation = (
            "Correlate source IP activity across destination ports and hosts; "
            "confirm whether the scan was authorized before taking action."
        )
    elif any(term in signature for term in ("trojan", "malware", "command and control", "c2")):
        classification = "POTENTIAL_MALWARE_ACTIVITY"
        severity, priority, confidence, risk_score = "HIGH", "P2", 0.75, 80
        evidence.append(f"Potential malware-related signature: {event.get('signature')}")
        recommendation = "Investigate the endpoint and correlate network, process, and threat-intel evidence."
    elif severity_hint == 1:
        classification = "HIGH_PRIORITY_ALERT"
        severity, priority, confidence, risk_score = "HIGH", "P2", 0.65, 70
        evidence.append("Source assigned severity 1 — this alone does not confirm a successful attack.")
        recommendation = "Prioritize analyst review and validate against additional evidence."
    elif severity_hint == 2:
        classification = "MEDIUM_PRIORITY_ALERT"
        severity, priority, confidence, risk_score = "MEDIUM", "P3", 0.60, 45
        evidence.append("Source assigned severity 2 — investigate context before confirming.")
        recommendation = "Review the signature, affected asset, and surrounding events."
    else:
        evidence.append("No specific high-risk signature pattern matched; not confirmed benign.")

    if src_ip:
        evidence.append(f"Observed source IP: {src_ip}")
    if dst_ip:
        evidence.append(f"Observed destination IP: {dst_ip}")

    return {
        "classification": classification,
        "severity": severity,
        "priority": priority,
        "confidence": confidence,
        "risk_score": risk_score,
        "evidence": evidence,
        "recommendation": recommendation,
        "analysis_type": "DETERMINISTIC_RULE_BASED",
    }