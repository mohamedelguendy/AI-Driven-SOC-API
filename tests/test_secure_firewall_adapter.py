"""Secure Firewall (FMC) adapter tests. No database or FMC needed."""
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from fastapi import HTTPException

from app import adapters
from app.adapters import secure_firewall
from app.config import settings
from app.routers import recommendations
from app.schemas import RecommendationIn

OBJECT_ID = "005056A1-0000-0ed3-0000-000000000123"




# Fake FMC responses so token and object behavior is tested without a device.
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




class FakeFMC:
    """Stands in for the FMC auth, dynamic object and mapping endpoints."""

    def __init__(self, mappings=(), expire_first_token=False, object_exists=True):
        self.mappings = list(mappings)
        self.expire_first_token = expire_first_token
        self.object_exists = object_exists
        self.logins = 0
        self.changes = []

    def login(self, url, auth, verify, timeout):
        assert url == "https://fmc.test/api/fmc_platform/v1/auth/generatetoken"
        assert auth == ("soc-api", "secret")
        self.logins += 1
        return FakeResponse(
            204, headers={"X-auth-access-token": f"token-{self.logins}", "DOMAIN_UUID": "domain-1"}
        )

    def request(self, method, url, headers, json, params, verify, timeout):
        if self.expire_first_token and headers["X-auth-access-token"] == "token-1":
            return FakeResponse(401, {"error": "token expired"})
        prefix = "https://fmc.test/api/fmc_config/v1/domain/domain-1"
        assert url.startswith(prefix)
        path = url[len(prefix):]

        if method == "GET" and path == "/object/dynamicobjects":
            items = [{"id": OBJECT_ID, "name": params["name"]}] if self.object_exists else []
            return FakeResponse(200, {"items": items, "paging": {}})
        if method == "GET" and path == f"/object/dynamicobjects/{OBJECT_ID}/mappings":
            start = params["offset"]
            page = self.mappings[start:start + params["limit"]]
            paging = {"next": ["..."]} if start + params["limit"] < len(self.mappings) else {}
            return FakeResponse(200, {"items": [{"mapping": m} for m in page], "paging": paging})
        if method == "POST" and path == "/object/dynamicobjectmappings":
            self.changes.append(json)
            for entry in json["add"]:
                assert entry["dynamicObject"]["id"] == OBJECT_ID
                self.mappings += entry["mappings"]
            for entry in json["remove"]:
                self.mappings = [m for m in self.mappings if m not in entry["mappings"]]
            return FakeResponse(201, json)
        raise AssertionError(f"unexpected {method} {path}")




# Cover secure-firewall idempotency, pagination, token refresh, and safe reverts.
class SecureFirewallAdapterTests(unittest.TestCase):
    command = {"action_id": 7, "action_type": "block_ip", "target": "203.0.113.7", "executor": "firewall"}

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        secure_firewall._session.update(token=None, domain=None, issued_at=0.0, object_id=None, object_name=None)

    def use(self, fmc, mode="live"):
        self.stack.enter_context(
            patch.multiple(
                settings,
                fmc_host="https://fmc.test/",
                fmc_username="soc-api",
                fmc_password="secret",
                fmc_dynamic_object="SOC-Blocked-IPs",
                firewall_execution_mode=mode,
            )
        )
        self.stack.enter_context(patch.object(secure_firewall.requests, "post", fmc.login))
        self.stack.enter_context(patch.object(secure_firewall.requests, "request", fmc.request))

    def test_block_adds_ip_to_dynamic_object(self):
        fmc = FakeFMC(mappings=["198.51.100.1"])
        self.use(fmc)

        success, message = secure_firewall.execute(self.command)

        self.assertTrue(success, message)
        self.assertEqual(fmc.mappings, ["198.51.100.1", "203.0.113.7"])
        self.assertEqual(fmc.changes[0]["remove"], [])

    def test_block_and_unblock_are_idempotent(self):
        fmc = FakeFMC(mappings=["203.0.113.7/32"])
        self.use(fmc)

        self.assertTrue(secure_firewall.execute(self.command)[0])
        self.assertEqual(fmc.changes, [])  # already present: nothing sent

        self.assertTrue(secure_firewall.revert(self.command)[0])
        self.assertTrue(secure_firewall.revert(self.command)[0])
        self.assertEqual(len(fmc.changes), 1)
        self.assertEqual(fmc.mappings, [])

    def test_revert_leaves_other_ips_alone(self):
        fmc = FakeFMC(mappings=["203.0.113.7", "198.51.100.0/24"])
        self.use(fmc)

        success, _ = secure_firewall.revert(self.command)

        self.assertTrue(success)
        self.assertEqual(fmc.mappings, ["198.51.100.0/24"])

    def test_large_objects_are_read_across_pages(self):
        existing = [f"10.{i // 256}.{i % 256}.1" for i in range(2500)] + ["203.0.113.7"]
        fmc = FakeFMC(mappings=existing)
        self.use(fmc)

        success, message = secure_firewall.execute(self.command)

        self.assertTrue(success)
        self.assertIn("already", message)

    def test_expired_token_is_renewed_once(self):
        fmc = FakeFMC(expire_first_token=True)
        self.use(fmc)

        success, message = secure_firewall.execute(self.command)

        self.assertTrue(success, message)
        self.assertEqual(fmc.logins, 2)

    def test_missing_dynamic_object_fails_with_setup_hint(self):
        fmc = FakeFMC(object_exists=False)
        self.use(fmc)

        success, message = secure_firewall.execute(self.command)

        self.assertFalse(success)
        self.assertIn("SOC-Blocked-IPs", message)
        self.assertIn("README", message)

    def test_only_block_ip_is_supported(self):
        fmc = FakeFMC()
        self.use(fmc)

        success, message = secure_firewall.execute({**self.command, "action_type": "block_port", "target": "445"})

        self.assertFalse(success)
        self.assertIn("not attempted", message)
        self.assertEqual(fmc.logins, 0)

    def test_dry_run_reads_but_never_writes(self):
        fmc = FakeFMC(mappings=["198.51.100.1"])
        self.use(fmc, mode="dry_run")

        with patch.object(settings, "firewall_mode", "fmc"):
            success, message = adapters.execute("firewall", self.command)

        self.assertTrue(success, message)
        self.assertTrue(message.startswith(adapters.DRY_RUN_PREFIX))
        self.assertEqual(fmc.logins, 1)  # it really talked to the FMC
        self.assertEqual(fmc.changes, [])
        self.assertEqual(fmc.mappings, ["198.51.100.1"])

    def test_firewall_mode_selects_the_adapter(self):
        with patch.object(settings, "firewall_mode", "fmc"):
            self.assertIs(adapters._adapter_for("firewall"), secure_firewall)

    def test_block_port_recommendations_are_rejected_in_fmc_mode(self):
        recommendation = RecommendationIn(
            incident_id=1,
            action_type="block_port",
            executor="firewall",
            target_scope="port",
            target_value="445",
            reason="Regression test",
            duration_secs=60,
            evidence_alert_ids=[1],
        )
        with patch.object(settings, "firewall_mode", "fmc"), self.assertRaises(HTTPException) as error:
            recommendations.create_recommendation(recommendation)
        self.assertEqual(error.exception.status_code, 422)




if __name__ == "__main__":
    unittest.main()
