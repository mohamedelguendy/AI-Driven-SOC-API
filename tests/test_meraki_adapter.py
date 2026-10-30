"""Meraki adapter and recommendation-target tests. No database or network needed."""
import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from pydantic import ValidationError

from app import adapters, db
from app.adapters import meraki
from app.config import settings
from app.schemas import RecommendationIn

DEFAULT_RULE = {
    "comment": "Default rule", "policy": "allow", "protocol": "Any",
    "srcPort": "Any", "srcCidr": "Any", "destPort": "Any", "destCidr": "Any",
}
MANUAL_RULE = {
    "comment": "manual rule", "policy": "allow", "protocol": "tcp",
    "srcPort": "Any", "srcCidr": "Any", "destPort": "443", "destCidr": "Any",
}




# Represent HTTP status, headers, and JSON without calling a real Dashboard API.
class FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self._payload = payload
        self.content = b"{}" if payload is not None else b""
        self.text = str(payload)

    def json(self):
        return self._payload




class FakeDashboard:
    """Stands in for the Meraki Dashboard API's firewall rule endpoints."""

    def __init__(self, networks, fail_put_on=None, rate_limit_once=False):
        self.rules = {
            (network, ruleset): [dict(MANUAL_RULE)]
            for network in networks
            for ruleset in (meraki.OUTBOUND, meraki.INBOUND)
        }
        self.fail_put_on = fail_put_on
        self.rate_limit_once = rate_limit_once
        self.puts = 0

    def request(self, method, url, headers, json, timeout):
        assert headers["Authorization"] == "Bearer test-key"
        network, ruleset = url.split("/networks/")[1].split("/appliance/firewall/")
        if self.rate_limit_once:
            self.rate_limit_once = False
            return FakeResponse(429, {"errors": ["Too many requests"]}, {"Retry-After": "1"})
        if method == "GET":
            return FakeResponse(
                200,
                {"rules": self.rules[(network, ruleset)] + [dict(DEFAULT_RULE)], "syslogDefaultRule": False},
            )
        if network == self.fail_put_on:
            return FakeResponse(400, {"errors": ["Invalid rule"]})
        assert all(rule["comment"] != "Default rule" for rule in json["rules"])
        assert json["syslogDefaultRule"] is False
        self.puts += 1
        self.rules[(network, ruleset)] = json["rules"]
        return FakeResponse(200, json)




class FakePool:
    """Stub the advisory-lock database connection used by the adapter."""

    @contextmanager
    def connection(self):
        class Connection:
            def execute(self, query, params=None):
                assert "pg_advisory_xact_lock" in query

        yield Connection()




# Cover Meraki rule creation, retries, duplicate prevention, and reversals.
class MerakiAdapterTests(unittest.TestCase):
    command = {"action_id": 7, "action_type": "block_ip", "target": "203.0.113.7", "executor": "firewall"}

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

    def use(self, dashboard, **overrides):
        values = {
            "meraki_api_key": "test-key",
            "meraki_network_ids": "N_1,N_2",
            "meraki_block_inbound": True,
            **overrides,
        }
        self.stack.enter_context(patch.multiple(settings, **values))
        self.stack.enter_context(patch.object(meraki.requests, "request", dashboard.request))
        self.stack.enter_context(patch.object(db, "pool", FakePool()))
        self.stack.enter_context(patch.object(meraki.time, "sleep", lambda seconds: None))

    def test_block_ip_adds_tagged_deny_rules_above_existing_rules(self):
        dashboard = FakeDashboard(["N_1", "N_2"], rate_limit_once=True)
        self.use(dashboard)

        success, message = meraki.execute(self.command)

        self.assertTrue(success, message)
        for network in ("N_1", "N_2"):
            outbound = dashboard.rules[(network, meraki.OUTBOUND)]
            inbound = dashboard.rules[(network, meraki.INBOUND)]
            self.assertEqual(outbound[0]["policy"], "deny")
            self.assertEqual(outbound[0]["destCidr"], "203.0.113.7/32")
            self.assertEqual(inbound[0]["srcCidr"], "203.0.113.7/32")
            self.assertIn("[soc-action-7]", outbound[0]["comment"])
            self.assertEqual(outbound[1], MANUAL_RULE)

    def test_retried_execute_does_not_duplicate_rules(self):
        dashboard = FakeDashboard(["N_1", "N_2"])
        self.use(dashboard)

        meraki.execute(self.command)
        puts = dashboard.puts
        success, _ = meraki.execute(self.command)

        self.assertTrue(success)
        self.assertEqual(dashboard.puts, puts)

    def test_revert_removes_only_this_actions_rules(self):
        dashboard = FakeDashboard(["N_1", "N_2"])
        self.use(dashboard)
        meraki.execute(self.command)
        meraki.execute({**self.command, "action_id": 77, "target": "198.51.100.0/24"})

        success, message = meraki.revert(self.command)

        self.assertTrue(success, message)
        for rules in dashboard.rules.values():
            comments = [rule["comment"] for rule in rules]
            self.assertFalse(any("[soc-action-7]" in comment for comment in comments))
            self.assertTrue(any("[soc-action-77]" in comment for comment in comments))
            self.assertIn(MANUAL_RULE, rules)

    def test_partial_failure_removes_rules_already_added(self):
        dashboard = FakeDashboard(["N_1", "N_2"], fail_put_on="N_2")
        self.use(dashboard, meraki_block_inbound=False)

        success, message = meraki.execute({**self.command, "action_type": "block_port", "target": "445"})

        self.assertFalse(success)
        self.assertIn("HTTP 400", message)
        self.assertEqual(dashboard.rules[("N_1", meraki.OUTBOUND)], [MANUAL_RULE])

    def test_block_port_denies_tcp_and_udp(self):
        dashboard = FakeDashboard(["N_1"])
        self.use(dashboard, meraki_network_ids="N_1", meraki_block_inbound=False)

        success, _ = meraki.execute({**self.command, "action_type": "block_port", "target": "445"})

        added = dashboard.rules[("N_1", meraki.OUTBOUND)][:2]
        self.assertTrue(success)
        self.assertEqual({rule["protocol"] for rule in added}, {"tcp", "udp"})
        self.assertTrue(all(rule["destPort"] == "445" for rule in added))

    def test_unsupported_action_is_not_sent(self):
        dashboard = FakeDashboard(["N_1"])
        self.use(dashboard, meraki_network_ids="N_1")

        success, message = meraki.execute({**self.command, "action_type": "isolate_host"})

        self.assertFalse(success)
        self.assertIn("not attempted", message)
        self.assertEqual(dashboard.puts, 0)

    def test_firewall_mode_selects_the_adapter(self):
        self.assertIs(adapters._adapter_for("firewall"), adapters.firewall)
        with patch.object(settings, "firewall_mode", "meraki"):
            self.assertIs(adapters._adapter_for("firewall"), meraki)




# Ensure backend-derived firewall target scopes override untrusted AI values.
class RecommendationTargetTests(unittest.TestCase):
    base = {
        "incident_id": 1,
        "executor": "firewall",
        "target_scope": "single_ip",
        "reason": "Regression test",
        "duration_secs": 60,
    }

    def test_backend_derives_firewall_target_scope(self):
        cases = [
            ("block_ip", " 203.0.113.7 ", "single_ip", "203.0.113.7"),
            ("block_ip", "10.0.0.5/16", "subnet", "10.0.0.0/16"),
            ("block_ip", "2001:db8::1/128", "single_ip", "2001:db8::1"),
            ("block_port", "443", "port", "443"),
        ]
        for action_type, target, scope, value in cases:
            with self.subTest(target=target):
                recommendation = RecommendationIn(**self.base, action_type=action_type, target_value=target)
                self.assertEqual((recommendation.target_scope, recommendation.target_value), (scope, value))

    def test_unparseable_firewall_targets_are_rejected(self):
        cases = [
            ("block_ip", "evil.example"),
            ("block_port", "0"),
            ("block_port", "70000"),
            ("block_port", "\u00b2"),
            ("delete_rules", "203.0.113.7"),
        ]
        for action_type, target in cases:
            with self.subTest(action_type=action_type, target=target), self.assertRaises(ValidationError):
                RecommendationIn(**self.base, action_type=action_type, target_value=target)

    def test_edr_targets_are_hostnames(self):
        recommendation = RecommendationIn(
            **{**self.base, "executor": "edr"}, action_type="isolate_host", target_value="ws-01"
        )
        self.assertEqual(recommendation.target_value, "ws-01")




if __name__ == "__main__":
    unittest.main()
