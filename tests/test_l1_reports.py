"""L1 report validation and plain-text rendering. No database needed."""
import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from app.l1_report_format import render
from app.schemas import L1ReportContent, L1ReportIn, L1ReviewIn

NOW = datetime(2026, 10, 30, 14, 2, tzinfo=timezone.utc)
MINIMAL = {
    "verdict": "true_positive",
    "confidence": "high",
    "severity": 2,
    "summary": "External IP made 312 failed SSH logins against srv-web-01, then logged in as deploy.",
    "escalation_reason": "Successful login after brute force plus an outbound connection.",
}
CONTENT = L1ReportContent(
    **MINIMAL,
    category="brute_force",
    attacker="external",
    affected_assets=[
        {"hostname": "srv-web-01", "ip": "10.20.1.15", "user": "deploy", "role": "public web server", "criticality": "high"}
    ],
    indicators=[{"type": "ip", "value": "203.0.113.45", "context": "brute-force source"}],
    mitre_attack=[{"technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}],
    timeline=[{"time": "2026-10-30T14:02:00Z", "event": "First failed SSH login", "source": "auth.log"}],
    investigation_steps=[{"check": "Checked auth.log on srv-web-01", "result": "312 failures, then one success"}],
    context_checks=[{"check": "Known false-positive pattern", "result": "No"}],
    impact={"data_exposure": "suspected", "data_types": ["credentials"], "cia_affected": ["confidentiality"]},
    log_excerpts=[{"source": "auth.log", "excerpt": "Accepted password for deploy from 203.0.113.45 port 51122 ssh2"}],
    actions_taken=["Notified the asset owner"],
    recommended_actions=["Block 203.0.113.45"],
    open_questions=["Did the session run any commands?"],
    notifications=[{"audience": "Asset owner", "reason": "Service account may be compromised"}],
).model_dump(mode="json")
REPORT = {
    "id": 7,
    "status": "approved",
    "reviewer": "a.hassan",
    "content": CONTENT,
    "evidence_alert_ids": [8812],
    "enrichment": {
        "203.0.113.45": {
            "internal": False,
            "threat_intel": [{"provider": "abuseipdb", "status": "ok", "verdict": "malicious"}],
            "first_seen": NOW.isoformat(),
            "alerts_last_7_days": 2,
            "other_incidents": 0,
        }
    },
    "created_at": NOW,
    "reviewed_at": NOW,
    "reviewer_changes": [],
    "review_comment": None,
    "ai_draft": CONTENT,
}
INCIDENT = {"id": 1042, "created_at": NOW}
ALERTS = [
    {"id": 8812, "source": "ids", "signature": "BRUTE_FORCE_LOGIN", "src_ip": "203.0.113.45", "dst_ip": "10.20.1.15", "seen_at": NOW},
    {"id": 8813, "source": "ids", "signature": "BRUTE_FORCE_LOGIN", "src_ip": "203.0.113.45", "dst_ip": "10.20.1.15", "seen_at": NOW},
]
ACTIONS = [{"action_type": "block_ip", "target_value": "203.0.113.45", "success": True, "reverted_at": None}]
NOTES = [{"author_type": "ai", "author": None, "author_role": None, "body": "Second login at 14:20.", "created_at": NOW}]




class L1ReportInputTests(unittest.TestCase):
    def test_each_verdict_needs_its_reason(self):
        for verdict in ("true_positive", "false_positive"):
            with self.subTest(verdict=verdict), self.assertRaises(ValidationError):
                L1ReportContent(**{**MINIMAL, "verdict": verdict, "escalation_reason": None})

    def test_minimal_draft_gets_safe_defaults(self):
        report = L1ReportIn(**MINIMAL, incident_id=1, evidence_alert_ids=[1])
        self.assertEqual((report.category, report.tlp, report.attacker), ("other", "AMBER", "unknown"))
        self.assertEqual(report.impact.data_exposure, "unknown")

    def test_fields_are_normalized_and_checked(self):
        report = L1ReportContent(
            **MINIMAL,
            indicators=[{"type": "ip", "value": " 2001:DB8::1 "}, {"type": "port", "value": "022"}],
            timeline=[{"time": "2026-10-30T14:02:00", "event": "x"}],
        )
        self.assertEqual([item.value for item in report.indicators], ["2001:db8::1", "22"])
        self.assertEqual(report.timeline[0].time.tzinfo, timezone.utc)

        for bad in (
            {"indicators": [{"type": "ip", "value": "not-an-ip"}]},
            {"indicators": [{"type": "port", "value": "70000"}]},
            {"affected_assets": [{"criticality": "high"}]},
            {"mitre_attack": [{"technique_id": "TA0006", "name": "Credential Access"}]},
            {"unknown_field": "typo"},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                L1ReportContent(**MINIMAL, **bad)

    def test_review_changes_must_be_a_mapping(self):
        with self.assertRaises(ValidationError):
            L1ReviewIn(changes=["severity"])




class L1ReportRenderingTests(unittest.TestCase):
    def test_true_positive_reads_like_an_escalation(self):
        text = render(REPORT, INCIDENT, ALERTS, ACTIONS, NOTES)

        for expected in (
            "INCIDENT #1042 \u2014 L1 ESCALATION REPORT",
            "Report #7 | Status: Approved by a.hassan | TLP:AMBER",
            "Category: Brute force | Attacker: External | Escalated to: Tier 2",
            "Severity: 2 (High) | Priority: P2 | Confidence: HIGH",
            "Who:   deploy",
            "When:  Activity window 2026-10-30 14:02 UTC to 2026-10-30 14:02 UTC",
            "- BRUTE_FORCE_LOGIN (source: ids)",
            "Alerts on this incident: 2 (cited as evidence: 1)",
            "2026-10-30 14:02 UTC  First failed SSH login [auth.log]",
            "- srv-web-01 (10.20.1.15), user account: deploy \u2014 public web server,\n  criticality: high",
            "Data exposure: Suspected (Credentials)",
            "CIA affected: Confidentiality",
            "- ip: 203.0.113.45 \u2014 brute-force source [abuseipdb: malicious]",
            "- T1110.001 Password Guessing (Credential Access)",
            "    Accepted password for deploy from 203.0.113.45 port 51122 ssh2",
            "1. Checked auth.log on srv-web-01",
            "   Finding: 312 failures, then one success",
            "first seen 2026-10-30 14:02 UTC; 2\n  alert(s) in the last 7 days; no other incidents",
            "- [L1] Notified the asset owner",
            "- [response] block_ip 203.0.113.45: in effect",
            "OPEN QUESTIONS FOR TIER 2",
            "- Asset owner: Service account may be compromised",
            "AI agent:",
            "  Second login at 14:20.",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("FALSE POSITIVE TUNING", text)
        self.assertNotIn("L1 REVIEW", text)

    def test_false_positive_reads_like_a_closure_and_shows_corrections(self):
        content = {
            **CONTENT,
            "verdict": "false_positive",
            "false_positive_reason": "Scheduled Nessus scan from the IT scanner (CHG-5521).",
            "false_positive_pattern": "Weekly scan every Thursday 15:00 UTC",
            "tuning_recommendation": "add_exclusion",
        }
        report = {
            **REPORT,
            "content": content,
            "reviewer_changes": ["verdict", "false_positive_reason"],
            "review_comment": "Checked the change calendar.",
        }

        text = render(report, INCIDENT, ALERTS, [], [])

        for expected in (
            "L1 TRIAGE: CLOSED AS FALSE POSITIVE",
            "Closed by: Tier 1",
            "Scheduled Nessus scan from the IT scanner (CHG-5521).",
            "FALSE POSITIVE TUNING",
            "Pattern: Weekly scan every Thursday 15:00 UTC",
            "Recommendation: Add exclusion",
            "Changed from the AI draft: verdict, false_positive_reason",
            "The AI originally judged this a true positive.",
            "No notes yet.",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("ESCALATION REASON", text)




if __name__ == "__main__":
    unittest.main()
