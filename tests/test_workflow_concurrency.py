import atexit
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi import HTTPException
from pydantic import ValidationError

from app.alert_classifier import analyze_event
from app.schemas import AlertIn, RecommendationIn
from scripts import ingest_edr, ingest_ids_engine, ingest_suricata, ingest_zeek


TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")


class InputValidationTests(unittest.TestCase):
    def test_temporary_recommendation_requires_positive_duration(self):
        recommendation = {
            "incident_id": 1,
            "action_type": "block_ip",
            "executor": "firewall",
            "target_scope": "single_ip",
            "target_value": "203.0.113.7",
            "reason": "Regression test",
        }

        for duration in (0, -1):
            with self.subTest(duration=duration), self.assertRaises(ValidationError):
                RecommendationIn(**recommendation, duration_secs=duration)

        RecommendationIn(**recommendation, duration_secs=1)

    def test_risk_score_is_rejected_outside_database_range(self):
        recommendation = {
            "incident_id": 1,
            "action_type": "block_ip",
            "executor": "firewall",
            "target_scope": "single_ip",
            "target_value": "203.0.113.7",
            "reason": "Regression test",
            "duration_secs": 1,
        }

        for risk_score in (-1, 101):
            with self.subTest(risk_score=risk_score), self.assertRaises(ValidationError):
                RecommendationIn(**recommendation, risk_score=risk_score)

    def test_ingest_severity_mapping_keeps_low_numbers_high_priority(self):
        for normalize in (ingest_edr.normalize, ingest_ids_engine.normalize):
            with self.subTest(normalize=normalize.__module__):
                self.assertEqual(normalize({"severity": "HIGH"})["severity"], 1)
                self.assertEqual(normalize({"severity": "MEDIUM"})["severity"], 3)
                self.assertEqual(normalize({"severity": "LOW"})["severity"], 5)

        for source_level, expected in ((1, 1), (2, 3), (3, 5)):
            with self.subTest(source="suricata", severity=source_level):
                normalized = ingest_suricata.normalize(
                    {"alert": {"severity": source_level}}
                )
                self.assertEqual(normalized["severity"], expected)

        zeek_severity = ingest_zeek.normalize(
            {"conn_state": "REJ", "proto": "tcp", "id.resp_p": 443}
        )["severity"]
        self.assertEqual(zeek_severity, 3)

    def test_classifier_interprets_normalized_high_medium_low_severity(self):
        self.assertEqual(analyze_event({"severity": 1})["severity"], "HIGH")
        self.assertEqual(analyze_event({"severity": 3})["severity"], "MEDIUM")
        self.assertEqual(analyze_event({"severity": 5})["severity"], "LOW")


class ThreatIntelCacheTests(unittest.TestCase):
    def test_cached_lookup_returns_the_same_provider_list_shape(self):
        from app import intel_lookup

        class CachedResults:
            def fetchall(self):
                return [
                    {
                        "provider": "abuseipdb",
                        "status": "ok",
                        "verdict": "clean",
                        "details": {"abuseConfidenceScore": 0},
                        "queried_at": None,
                    },
                    {
                        "provider": "virustotal",
                        "status": "ok",
                        "verdict": "clean",
                        "details": {"malicious": 0},
                        "queried_at": None,
                    },
                ]

        class CachedConnection:
            def execute(self, query, params):
                self.query = query
                self.params = params
                return CachedResults()

        with patch.object(intel_lookup.settings, "abuseipdb_api_key", "test-key"), patch.object(
            intel_lookup.settings, "virustotal_api_key", "test-key"
        ):
            result = intel_lookup.lookup_ip(CachedConnection(), "203.0.113.7")

        self.assertEqual(result["ip_address"], "203.0.113.7")
        self.assertTrue(result["cached"])
        self.assertEqual(
            [provider["provider"] for provider in result["results"]],
            ["abuseipdb", "virustotal"],
        )

    def test_provider_errors_are_not_reused_from_cache(self):
        from app import intel_lookup

        class CachedResults:
            def fetchall(self):
                return [
                    {
                        "provider": "virustotal",
                        "status": "ok",
                        "verdict": "clean",
                        "details": {"malicious": 0},
                        "queried_at": None,
                    },
                ]

        class CachedConnection:
            def __init__(self):
                self.inserted = []

            def execute(self, query, params):
                if "SELECT provider" in query:
                    if "status <> 'error'" not in query:
                        raise AssertionError("Provider errors must be excluded from the cache query")
                    return CachedResults()
                self.inserted.append(params)
                return None

        connection = CachedConnection()
        with patch.object(intel_lookup.settings, "abuseipdb_api_key", "test-key"), patch.object(
            intel_lookup.settings, "virustotal_api_key", "test-key"
        ), patch.object(
            intel_lookup, "_query_abuseipdb",
            return_value={"status": "ok", "verdict": "suspicious", "details": {"score": 45}},
        ) as abuse_lookup, patch.object(intel_lookup, "_query_virustotal") as virus_lookup:
            result = intel_lookup.lookup_ip(connection, "203.0.113.7")

        abuse_lookup.assert_called_once_with("203.0.113.7")
        virus_lookup.assert_not_called()
        self.assertFalse(result["cached"])
        self.assertEqual(result["results"][0]["verdict"], "suspicious")
        self.assertEqual(len(connection.inserted), 1)


@unittest.skipUnless(TEST_DATABASE_URL, "Set TEST_DATABASE_URL to run PostgreSQL concurrency tests")
class WorkflowConcurrencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = f"soc_test_{uuid.uuid4().hex}"
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(cls.schema)))
            schema_path = Path(__file__).resolve().parents[1] / "back-end schema proto 2.sql"
            conn.execute(schema_path.read_text(encoding="utf-8"), prepare=False)
            migration_path = Path(__file__).resolve().parents[1] / "migration" / "004_add_threat_intel.sql"
            conn.execute(migration_path.read_text(encoding="utf-8"), prepare=False)

        test_conninfo = make_conninfo(
            TEST_DATABASE_URL,
            options=f"-c search_path={cls.schema},public",
        )
        cls.test_pool = ConnectionPool(
            test_conninfo,
            kwargs={"row_factory": dict_row},
            min_size=2,
            max_size=8,
            open=True,
        )

        import app.db as db_module
        from app import expiry
        from app.routers import actions, alerts, incidents, recommendations

        cls.expiry = expiry
        cls.actions = actions
        cls.alerts = alerts
        cls.incidents = incidents
        cls.recommendations = recommendations
        cls.original_pools = {
            db_module: db_module.pool,
            expiry: expiry.pool,
            actions: actions.pool,
            alerts: alerts.pool,
            incidents: incidents.pool,
            recommendations: recommendations.pool,
        }
        atexit.register(db_module.pool.close)
        db_module.pool = cls.test_pool
        expiry.pool = cls.test_pool
        actions.pool = cls.test_pool
        alerts.pool = cls.test_pool
        incidents.pool = cls.test_pool
        recommendations.pool = cls.test_pool

    @classmethod
    def tearDownClass(cls):
        for module, original_pool in cls.original_pools.items():
            module.pool = original_pool
        cls.test_pool.close()
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def setUp(self):
        with self.test_pool.connection() as conn:
            user = conn.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, 'test-hash', 'tier2') RETURNING id",
                (f"analyst-{uuid.uuid4().hex}",),
            ).fetchone()
            incident = conn.execute(
                "INSERT INTO incidents (title, severity) VALUES ('Test incident', 3) RETURNING id"
            ).fetchone()
            self.user_id = user["id"]
            self.incident_id = incident["id"]

    def _create_recommendation(self):
        with self.test_pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO recommendations
                    (incident_id, action_type, executor, target_scope, target_value,
                     is_internal, is_permanent, duration_secs, reason, impact)
                VALUES (%s, 'block_ip', 'firewall', 'single_ip', '203.0.113.7',
                        FALSE, FALSE, 60, 'Regression test', 'low')
                RETURNING id
                """,
                (self.incident_id,),
            ).fetchone()
        return row["id"]

    def test_protected_target_blocks_overlapping_subnets(self):
        with self.test_pool.connection() as conn:
            conn.execute(
                "INSERT INTO protected_targets (target, description) VALUES (%s, %s)",
                ("10.0.0.15/32", "Protected test host"),
            )
            protected = self.recommendations._is_protected(conn, "10.0.0.0/24")
            unrelated = self.recommendations._is_protected(conn, "10.0.1.0/24")
            containing_allowlist = self.recommendations._is_protected(conn, "10.0.0.15")

        self.assertTrue(protected)
        self.assertTrue(containing_allowlist)
        self.assertFalse(unrelated)

    def _sync_recommendation_read(self):
        original_pool = self.test_pool
        barrier = threading.Barrier(2)

        class QueryResult:
            def __init__(self, cursor, should_wait):
                self.cursor = cursor
                self.should_wait = should_wait

            def fetchone(self):
                row = self.cursor.fetchone()
                if self.should_wait and row is not None:
                    barrier.wait(timeout=5)
                return row

            def __getattr__(self, name):
                return getattr(self.cursor, name)

        class SynchronizedConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, query, *args, **kwargs):
                cursor = self.connection.execute(query, *args, **kwargs)
                query_text = str(query).lower()
                is_initial_read = (
                    "select" in query_text
                    and "from recommendations" in query_text
                    and "for update" not in query_text
                )
                return QueryResult(cursor, is_initial_read)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        class SynchronizedPool:
            @contextmanager
            def connection(self):
                with original_pool.connection() as connection:
                    yield SynchronizedConnection(connection)

        return SynchronizedPool()

    def _sync_incident_read(self):
        barrier = threading.Barrier(2)
        test_pool = self.test_pool

        class QueryResult:
            def __init__(self, cursor, should_wait):
                self.cursor = cursor
                self.should_wait = should_wait

            def fetchone(self):
                row = self.cursor.fetchone()
                if self.should_wait and row is not None:
                    barrier.wait(timeout=5)
                return row

            def __getattr__(self, name):
                return getattr(self.cursor, name)

        class SynchronizedConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, query, *args, **kwargs):
                cursor = self.connection.execute(query, *args, **kwargs)
                query_text = str(query).lower()
                is_initial_read = (
                    "select" in query_text
                    and "from incidents" in query_text
                    and "for update" not in query_text
                )
                return QueryResult(cursor, is_initial_read)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        class SynchronizedPool:
            @contextmanager
            def connection(self):
                with test_pool.connection() as connection:
                    yield SynchronizedConnection(connection)

        return SynchronizedPool()

    def test_concurrent_triage_records_only_one_verdict(self):
        from app.schemas import TriageIn

        self.incidents.pool = self._sync_incident_read()

        def triage(confirmed):
            return self.incidents.triage_incident(
                self.incident_id,
                TriageIn(confirmed=confirmed),
                {"id": self.user_id, "role": "tier1"},
            )

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(triage, True), executor.submit(triage, False)]
                results = []
                for future in futures:
                    try:
                        results.append(future.result(timeout=10))
                    except HTTPException as error:
                        results.append(error)
        finally:
            self.incidents.pool = self.test_pool

        successes = [result for result in results if not isinstance(result, HTTPException)]
        conflicts = [result for result in results if isinstance(result, HTTPException)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].status_code, 409)

        with self.test_pool.connection() as conn:
            note_count = conn.execute(
                "SELECT count(*) AS count FROM incident_notes WHERE incident_id = %s",
                (self.incident_id,),
            ).fetchone()["count"]
        self.assertEqual(note_count, 1)

    def test_alert_with_out_of_range_severity_is_still_ingested(self):
        result = self.alerts.ingest_alert(
            AlertIn(source="ids", severity=2**40)
        )

        with self.test_pool.connection() as conn:
            alert = conn.execute(
                "SELECT severity, parse_status, parse_notes FROM alerts WHERE id = %s",
                (result["alert_id"],),
            ).fetchone()
            incident = conn.execute(
                "SELECT severity FROM incidents WHERE id = %s",
                (result["incident_id"],),
            ).fetchone()

        self.assertIsNone(alert["severity"])
        self.assertEqual(alert["parse_status"], "failed")
        self.assertIn("outside the supported integer range", alert["parse_notes"])
        self.assertGreaterEqual(incident["severity"], 1)
        self.assertLessEqual(incident["severity"], 5)

    def test_concurrent_approve_and_reject_make_one_decision(self):
        recommendation_id = self._create_recommendation()
        self.recommendations.pool = self._sync_recommendation_read()
        execute_calls = []

        def execute_action(executor, command):
            execute_calls.append((executor, command))
            return True, "Test action completed"

        def approve():
            return self.recommendations.approve(
                recommendation_id,
                self.recommendations.DecisionIn(),
                {"id": self.user_id, "role": "tier2"},
            )

        def reject():
            return self.recommendations.reject(
                recommendation_id,
                self.recommendations.DecisionIn(),
                {"id": self.user_id, "role": "tier2"},
            )

        try:
            with patch.object(self.recommendations.adapters, "execute", side_effect=execute_action):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(approve), executor.submit(reject)]
                    results = []
                    for future in futures:
                        try:
                            results.append(future.result(timeout=10))
                        except HTTPException as error:
                            results.append(error)
        finally:
            self.recommendations.pool = self.test_pool

        successes = [result for result in results if not isinstance(result, HTTPException)]
        conflicts = [result for result in results if isinstance(result, HTTPException)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].status_code, 409)

        with self.test_pool.connection() as conn:
            final = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s",
                (recommendation_id,),
            ).fetchone()
        self.assertIn(final["status"], ("executed", "rejected"))
        self.assertEqual(len(execute_calls), 1 if final["status"] == "executed" else 0)

    def _create_expired_action(self):
        recommendation_id = self._create_recommendation()
        with self.test_pool.connection() as conn:
            conn.execute(
                "UPDATE recommendations SET status = 'executed' WHERE id = %s",
                (recommendation_id,),
            )
            action = conn.execute(
                """
                INSERT INTO actions
                    (recommendation_id, executor, command, success, executed_by, expires_at)
                VALUES (%s, 'firewall', '{"action_type":"block_ip","target":"203.0.113.7"}',
                        TRUE, %s, now() - interval '1 minute')
                RETURNING id
                """,
                (recommendation_id, self.user_id),
            ).fetchone()
        return action["id"]

    def test_manual_revert_and_expiry_worker_do_not_revert_twice(self):
        action_id = self._create_expired_action()
        revert_started = threading.Event()
        release_revert = threading.Event()
        revert_calls = []

        def revert_action(executor, command):
            revert_calls.append((executor, command))
            revert_started.set()
            if not release_revert.wait(timeout=5):
                raise TimeoutError("Test did not release the simulated revert")
            return True, "Test revert completed"

        def manual_revert():
            try:
                return self.actions.revert_action(
                    action_id,
                    self.actions.DecisionIn(),
                    {"id": self.user_id, "role": "tier2"},
                )
            except HTTPException as error:
                return error

        manual_started = threading.Event()
        original_pool = self.actions.pool

        class ManualStartConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, query, *args, **kwargs):
                if "from actions a" in str(query).lower():
                    manual_started.set()
                return self.connection.execute(query, *args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        class ManualStartPool:
            @contextmanager
            def connection(self):
                with original_pool.connection() as connection:
                    yield ManualStartConnection(connection)

        with patch.object(self.expiry.adapters, "revert", side_effect=revert_action):
            with ThreadPoolExecutor(max_workers=2) as executor:
                expiry_future = executor.submit(self.expiry._revert_expired_once)
                self.assertTrue(revert_started.wait(timeout=5))
                self.actions.pool = ManualStartPool()
                manual_future = executor.submit(manual_revert)
                try:
                    self.assertTrue(manual_started.wait(timeout=5))
                finally:
                    release_revert.set()
                    self.actions.pool = self.test_pool
                expiry_future.result(timeout=10)
                manual_result = manual_future.result(timeout=10)

        self.assertIsInstance(manual_result, HTTPException)
        self.assertEqual(manual_result.status_code, 409)
        self.assertEqual(len(revert_calls), 1)

        with self.test_pool.connection() as conn:
            row = conn.execute(
                "SELECT reverted_at FROM actions WHERE id = %s",
                (action_id,),
            ).fetchone()
        self.assertIsNotNone(row["reverted_at"])

    def test_expiry_workers_skip_actions_claimed_by_another_worker(self):
        self._create_expired_action()
        revert_started = threading.Event()
        release_revert = threading.Event()
        revert_calls = []

        def revert_action(executor, command):
            revert_calls.append((executor, command))
            revert_started.set()
            if not release_revert.wait(timeout=5):
                raise TimeoutError("Test did not release the simulated revert")
            return True, "Test revert completed"

        with patch.object(self.expiry.adapters, "revert", side_effect=revert_action):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(self.expiry._revert_expired_once)
                self.assertTrue(revert_started.wait(timeout=5))
                second = executor.submit(self.expiry._revert_expired_once)
                second.result(timeout=5)
                release_revert.set()
                first.result(timeout=10)

        self.assertEqual(len(revert_calls), 1)


if __name__ == "__main__":
    unittest.main()
