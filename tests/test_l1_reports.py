"""L1 report validation and plain-text rendering. No database needed."""
import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from app.l1_report_format import render
from app.schemas import L1ReportIn

NOW = datetime(2026, 10, 30, 14, 2, tzinfo=timezone.utc)
DRAFT = {
    "incident_id": 1042,
    "verdict": "true_positive",
    "confidence": "high",
    "severity": 2,
    "summary": "External IP made 312 failed SSH logins against srv-web-01, then logged in as deploy.",
    "evidence_alert_ids": [8812],
    "escalation_reason": "Successful login after brute force.",
}
REPORT = {
    **DRAFT,
    "status": "approved",
    "reviewer": "a.hassan",
    "false_positive_reason": None,
    "affected_assets": [
        {"hostname": "srv-web-01", "ip": "10.20.1.15", "user": None, "role": "public web server", "criticality": "high"}
    ],
    "indicators": [{"type": "ip", "value": "203.0.113.45"}],
    "enrichment": {
        "203.0.113.45": {
            "internal": False,
            "threat_intel": [{"provider": "abuseipdb", "status": "ok", "verdict": "malicious"}],
            "first_seen": NOW.isoformat(),
            "other_incidents": 0,
        }
    },
    "recommended_actions": ["Block 203.0.113.45"],
    "reviewed_at": NOW,
    "reviewer_changes": [],
    "review_comment": None,
    "ai_draft": {"verdict": "true_positive"},
}
INCIDENT = {"id": 1042, "created_at": NOW}
ALERTS = [
    {"id": 8812, "source": "ids", "signature": "BRUTE_FORCE_LOGIN", "src_ip": "203.0.113.45", "dst_ip": "10.20.1.15", "seen_at": NOW},
    {"id": 8813, "source": "ids", "signature": "BRUTE_FORCE_LOGIN", "src_ip": "203.0.113.45", "dst_ip": "10.20.1.15", "seen_at": NOW},
]
ACTIONS = [{"action_type": "block_ip", "target_value": "203.0.113.45", "success": True, "reverted_at": None}]




class L1ReportInputTests(unittest.TestCase):
    def test_each_verdict_needs_its_reason(self):
        for verdict in ("true_positive", "false_positive"):
            with self.subTest(verdict=verdict), self.assertRaises(ValidationError):
                L1ReportIn(**{**DRAFT, "verdict": verdict, "escalation_reason": None})

    def test_indicators_are_normalized_and_checked(self):
        report = L1ReportIn(
            **DRAFT, indicators=[{"type": "ip", "value": " 2001:DB8::1 "}, {"type": "port", "value": "022"}]
        )
        self.assertEqual([item.value for item in report.indicators], ["2001:db8::1", "22"])

        for bad in ({"type": "ip", "value": "not-an-ip"}, {"type": "port", "value": "70000"}):
            with self.subTest(indicator=bad), self.assertRaises(ValidationError):
                L1ReportIn(**DRAFT, indicators=[bad])

    def test_assets_need_an_identifier(self):
        with self.assertRaises(ValidationError):
            L1ReportIn(**DRAFT, affected_assets=[{"criticality": "high"}])




class L1ReportRenderingTests(unittest.TestCase):
    def test_true_positive_reads_like_an_escalation(self):
        text = render(REPORT, INCIDENT, ALERTS, ACTIONS)

        for expected in (
            "INCIDENT #1042 \u2014 L1 ESCALATION REPORT",
            "Status: Approved by a.hassan",
            "Detected: 2026-10-30 14:02 UTC      Triaged: 2026-10-30 14:02 UTC",
            "Severity: 2 (High)   Priority: P2",
            "True positive \u2014 confidence HIGH",
            "BRUTE_FORCE_LOGIN (source: ids)",
            "Alerts on this incident: 2 (cited as evidence: 1)",
            "- srv-web-01 (10.20.1.15) \u2014 public web server, criticality: high",
            "- 203.0.113.45: abuseipdb: malicious; first seen 2026-10-30 14:02 UTC; no other incidents",
            "- block_ip 203.0.113.45: in effect",
            "ESCALATION REASON / RECOMMENDATION",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("L1 REVIEW NOTES", text)

    def test_false_positive_reads_like_a_closure_and_shows_corrections(self):
        report = {
            **REPORT,
            "verdict": "false_positive",
            "false_positive_reason": "Scheduled Nessus scan from the IT scanner (CHG-5521).",
            "reviewer_changes": ["verdict", "false_positive_reason"],
            "review_comment": "Checked the change calendar.",
        }

        text = render(report, INCIDENT, ALERTS, [])

        for expected in (
            "L1 TRIAGE: CLOSED AS FALSE POSITIVE",
            "Scheduled Nessus scan from the IT scanner (CHG-5521).",
            "ACTIONS TAKEN\nNone",
            "Changed from the AI draft: verdict, false_positive_reason",
            "The AI originally judged this a true positive.",
            "Checked the change calendar.",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("ESCALATION REASON", text)




if __name__ == "__main__":
    unittest.main()
