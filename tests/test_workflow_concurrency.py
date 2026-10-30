import atexit
import json
import os
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi import HTTPException
from pydantic import ValidationError

from app.alert_classifier import analyze_event
from app.config import Settings
from app.schemas import AlertIn, RecommendationIn
from scripts import ingest_edr, ingest_ids_engine, ingest_suricata, ingest_zeek
from scripts.ingest_common import follow_file, send_alert




TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")




# Check request validation and configuration rules without requiring PostgreSQL.
class InputValidationTests(unittest.TestCase):
    def test_application_secrets_must_be_strong_and_non_placeholder(self):
        required = {
            "database_url": "postgresql://localhost/soc",
            "jwt_secret": "j" * 32,
            "ingest_api_key": "i" * 32,
            "ai_api_key": "a" * 32,
        }
        Settings(**required)

        for secret_name in ("jwt_secret", "ingest_api_key", "ai_api_key"):
            with self.subTest(secret=secret_name):
                weak = {**required, secret_name: "short"}
                with self.assertRaises(ValidationError):
                    Settings(**weak)
                placeholder = {**required, secret_name: "generate-a-random-secret-at-least-64-characters-long"}
                with self.assertRaises(ValidationError):
                    Settings(**placeholder)

    def test_temporary_recommendation_requires_positive_duration(self):
        recommendation = {
            "incident_id": 1,
            "action_type": "block_ip",
            "executor": "firewall",
            "target_scope": "single_ip",
            "target_value": "203.0.113.7",
            "reason": "Regression test",
            "evidence_alert_ids": [1],
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
            "evidence_alert_ids": [1],
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




# Exercise feeder checkpoints, retry behavior, classifier output, and target scope.
class IngestHelperTests(unittest.TestCase):
    def test_checkpoint_restart_replays_unacknowledged_line_with_same_key(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            state = Path(directory) / "state.json"
            source.write_text('{"event":1}\n{"event":2}\n', encoding="utf-8")

            first_stream = follow_file(str(source), replay=True, state_file=str(state))
            first_line, _, first_key = next(first_stream)
            first_stream.close()

            self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["offset"], 0)

            restarted_stream = follow_file(
                str(source), replay=False, state_file=str(state)
            )
            replayed_line, acknowledge, replayed_key = next(restarted_stream)
            self.assertEqual(replayed_line, first_line)
            self.assertEqual(replayed_key, first_key)
            acknowledge()
            restarted_stream.close()

            final_stream = follow_file(str(source), replay=False, state_file=str(state))
            next_line, _, _ = next(final_stream)
            final_stream.close()
            self.assertEqual(next_line, '{"event":2}\n')

    def test_delivery_retries_server_error_and_preserves_idempotency_key(self):
        unavailable = Mock(status_code=503, headers={"Retry-After": "invalid"})
        unavailable.text = "temporarily unavailable"
        accepted = Mock(status_code=200, headers={})
        responses = iter((unavailable, accepted))

        with patch(
            "scripts.ingest_common.requests.post",
            side_effect=lambda *args, **kwargs: next(responses),
        ) as post, patch("scripts.ingest_common.time.sleep"):
            self.assertTrue(
                send_alert("http://localhost", "key", {"signature": "test"}, "event-key")
            )

        self.assertEqual(post.call_count, 2)
        self.assertEqual(
            [call.kwargs["headers"]["Idempotency-Key"] for call in post.call_args_list],
            ["event-key", "event-key"],
        )

    def test_delivery_does_not_retry_client_error(self):
        rejected = Mock(status_code=422, headers={})
        rejected.text = "invalid alert"
        with patch("scripts.ingest_common.requests.post", return_value=rejected) as post, patch(
            "scripts.ingest_common.time.sleep"
        ) as sleep:
            with self.assertRaisesRegex(RuntimeError, "HTTP 422"):
                send_alert("http://localhost", "key", {"signature": "test"}, "event-key")

        post.assert_called_once()
        sleep.assert_not_called()

    def test_classifier_interprets_normalized_high_medium_low_severity(self):
        self.assertEqual(analyze_event({"severity": 1})["severity"], "HIGH")
        self.assertEqual(analyze_event({"severity": 3})["severity"], "MEDIUM")
        self.assertEqual(analyze_event({"severity": 5})["severity"], "LOW")

    def test_internal_target_uses_configured_rfc1918_networks(self):
        from app.routers.recommendations import _looks_internal
        from app.db import pool

        atexit.register(pool.close)
        self.assertTrue(_looks_internal("10.23.5.4"))
        self.assertTrue(_looks_internal("172.16.0.0/12"))
        self.assertTrue(_looks_internal("192.168.1.0/24"))
        self.assertFalse(_looks_internal("8.8.8.8"))
        self.assertFalse(_looks_internal("security-host.example"))




# Verify threat-intel cache behavior and provider error handling.
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




# Run database-backed workflows against an isolated schema to test races and recovery.
class WorkflowConcurrencyTests(unittest.TestCase):
    """Exercise database-backed behavior with an isolated schema per test run."""

    @classmethod
    def setUpClass(cls):
        cls.schema = f"soc_test_{uuid.uuid4().hex}"
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(cls.schema)))
            schema_path = Path(__file__).resolve().parents[1] / "back-end schema proto 2.sql"
            conn.execute(schema_path.read_text(encoding="utf-8"), prepare=False)
            migration_dir = Path(__file__).resolve().parents[1] / "migration"
            for migration_name in (
                "004_add_threat_intel.sql",
                "005_action_jobs.sql",
                "006_login_rate_limits.sql",
                "007_alert_ingest_idempotency.sql",
                "008_action_job_leases.sql",
                "009_evidence_and_triage_time.sql",
                "010_l1_reports.sql",
            ):
                migration_path = migration_dir / migration_name
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
        from app import action_jobs, expiry
        from app.routers import actions, alerts, auth, incidents, l1_reports, recommendations

        cls.action_jobs = action_jobs
        cls.expiry = expiry
        cls.actions = actions
        cls.alerts = alerts
        cls.auth = auth
        cls.incidents = incidents
        cls.recommendations = recommendations
        cls.l1_reports = l1_reports
        cls.original_pools = {
            db_module: db_module.pool,
            action_jobs: action_jobs.pool,
            expiry: expiry.pool,
            actions: actions.pool,
            alerts: alerts.pool,
            auth: auth.pool,
            incidents: incidents.pool,
            recommendations: recommendations.pool,
            l1_reports: l1_reports.pool,
        }
        atexit.register(db_module.pool.close)
        db_module.pool = cls.test_pool
        action_jobs.pool = cls.test_pool
        expiry.pool = cls.test_pool
        actions.pool = cls.test_pool
        alerts.pool = cls.test_pool
        auth.pool = cls.test_pool
        incidents.pool = cls.test_pool
        recommendations.pool = cls.test_pool
        l1_reports.pool = cls.test_pool

    @classmethod
    def tearDownClass(cls):
        for module, original_pool in cls.original_pools.items():
            module.pool = original_pool
        cls.test_pool.close()
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    # Create independent test data so concurrency cases cannot affect one another.
    def setUp(self):
        self.target_value = f"203.0.113.{uuid.uuid4().int % 254 + 1}"
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

    # Insert a pending firewall proposal for the current test incident.
    def _create_recommendation(self, target_value=None, triaged=True):
        target_value = target_value or self.target_value
        with self.test_pool.connection() as conn:
            if triaged:
                conn.execute(
                    "UPDATE incidents SET status = 'investigating' WHERE id = %s AND status = 'new'",
                    (self.incident_id,),
                )
            row = conn.execute(
                """
                INSERT INTO recommendations
                    (incident_id, action_type, executor, target_scope, target_value,
                     is_internal, is_permanent, duration_secs, reason, impact)
                VALUES (%s, 'block_ip', 'firewall', 'single_ip', %s,
                        FALSE, FALSE, 60, 'Regression test', 'low')
                RETURNING id
                """,
                (self.incident_id, target_value),
            ).fetchone()
        return row["id"]

    # Verify allowlist overlap checks reject both contained and containing ranges.
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

    # Coordinate concurrent requests so the database race is reproducible.
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

    # Incident-state concurrency and alert-ingestion durability cases.
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
            AlertIn(source="ids", severity=2**40), None
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

    def test_retried_alert_ingest_returns_existing_alert(self):
        payload = AlertIn(source="ids", src_ip="198.51.100.44", signature="retry")
        first = self.alerts.ingest_alert(payload, "source-event-1")
        second = self.alerts.ingest_alert(payload, "source-event-1")

        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["alert_id"], second["alert_id"])
        self.assertEqual(first["incident_id"], second["incident_id"])

        with self.test_pool.connection() as conn:
            alert_count = conn.execute(
                "SELECT count(*) AS count FROM alerts WHERE source_event_id = %s",
                ("source-event-1",),
            ).fetchone()["count"]
        self.assertEqual(alert_count, 1)

    def test_reusing_alert_idempotency_key_for_different_payload_conflicts(self):
        self.alerts.ingest_alert(
            AlertIn(source="ids", src_ip="198.51.100.44", signature="first"),
            "source-event-conflict",
        )
        with self.assertRaises(HTTPException) as error:
            self.alerts.ingest_alert(
                AlertIn(source="ids", src_ip="198.51.100.45", signature="different"),
                "source-event-conflict",
            )

        self.assertEqual(error.exception.status_code, 409)

    def test_login_attempts_are_limited_by_ip_and_username(self):
        with self.test_pool.connection() as conn:
            for _ in range(self.auth.LOGIN_ATTEMPT_LIMIT):
                self.assertIsNone(
                    self.auth._record_login_attempt(conn, "limit-user", "198.51.100.9")
                )
            retry_after = self.auth._record_login_attempt(
                conn, "limit-user", "198.51.100.9"
            )

        self.assertIsNotNone(retry_after)
        self.assertGreater(retry_after, 0)
        self.assertLessEqual(retry_after, int(self.auth.LOGIN_WINDOW.total_seconds()))

    def test_concurrent_alert_ingest_for_same_source_correlates_once(self):
        barrier = threading.Barrier(2)
        original_pool = self.alerts.pool
        test_pool = self.test_pool

        class SynchronizedConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, query, *args, **kwargs):
                if "alert-correlation:" in str(query):
                    barrier.wait(timeout=5)
                return self.connection.execute(query, *args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        class SynchronizedPool:
            @contextmanager
            def connection(self):
                with test_pool.connection() as connection:
                    yield SynchronizedConnection(connection)

        self.alerts.pool = SynchronizedPool()
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        self.alerts.ingest_alert,
                        AlertIn(source="ids", src_ip="198.51.100.20", signature=f"event-{index}"),
                        None,
                    )
                    for index in range(2)
                ]
                results = [future.result(timeout=10) for future in futures]
        finally:
            self.alerts.pool = original_pool

        self.assertEqual(results[0]["incident_id"], results[1]["incident_id"])

    # Recommendation decisions must be atomic, permission-safe, and idempotent.
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
            with patch.object(self.action_jobs.adapters, "execute", side_effect=execute_action):
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

        self.assertEqual(len(execute_calls), 0)
        if successes[0]["status"] == "queued":
            self.assertTrue(self.action_jobs.process_one_job())

        with self.test_pool.connection() as conn:
            final = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s",
                (recommendation_id,),
            ).fetchone()
        self.assertIn(final["status"], ("executed", "rejected"))
        self.assertEqual(len(execute_calls), 1 if final["status"] == "executed" else 0)
        if execute_calls:
            self.assertTrue(execute_calls[0][1]["idempotency_key"].startswith("soc-action-"))

    def test_execution_job_retries_with_a_stable_idempotency_key(self):
        recommendation_id = self._create_recommendation()
        response = self.recommendations.approve(
            recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )
        action_id = response["action"]["id"]
        commands = []

        def execute_action(executor, command):
            commands.append(command)
            if len(commands) == 1:
                return False, "Temporary test failure"
            return True, "Test action completed"

        with patch.object(self.action_jobs.adapters, "execute", side_effect=execute_action):
            self.assertTrue(self.action_jobs.process_one_job())
            with self.test_pool.connection() as conn:
                conn.execute(
                    "UPDATE action_jobs SET next_attempt_at = now() WHERE action_id = %s",
                    (action_id,),
                )
            self.assertTrue(self.action_jobs.process_one_job())

        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0]["idempotency_key"], commands[1]["idempotency_key"])
        with self.test_pool.connection() as conn:
            action = conn.execute(
                "SELECT success FROM actions WHERE id = %s", (action_id,)
            ).fetchone()
            job = conn.execute(
                "SELECT status, attempts FROM action_jobs WHERE action_id = %s AND operation = 'execute'",
                (action_id,),
            ).fetchone()
            recommendation = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s",
                (recommendation_id,),
            ).fetchone()
        self.assertTrue(action["success"])
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["attempts"], 2)
        self.assertEqual(recommendation["status"], "executed")

    def test_identical_approval_is_rejected_while_execution_is_pending(self):
        target = self.target_value
        first_recommendation_id = self._create_recommendation(target)
        second_recommendation_id = self._create_recommendation(target)

        first = self.recommendations.approve(
            first_recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )
        self.assertEqual(first["status"], "queued")

        with self.assertRaises(HTTPException) as error:
            self.recommendations.approve(
                second_recommendation_id,
                self.recommendations.DecisionIn(),
                {"id": self.user_id, "role": "tier2"},
            )
        self.assertEqual(error.exception.status_code, 409)

        with self.test_pool.connection() as conn:
            count = conn.execute(
                """
                SELECT count(*) AS count
                FROM actions a
                JOIN recommendations r ON r.id = a.recommendation_id
                JOIN action_jobs j ON j.action_id = a.id AND j.operation = 'execute'
                WHERE r.target_value = %s
                  AND j.status IN ('queued', 'running')
                """,
                (target,),
            ).fetchone()["count"]
            status = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s",
                (second_recommendation_id,),
            ).fetchone()["status"]

        self.assertEqual(count, 1)
        self.assertEqual(status, "pending")
        with patch.object(
            self.action_jobs.adapters,
            "execute",
            return_value=(True, "Test action completed"),
        ):
            self.assertTrue(self.action_jobs.process_one_job())

    def test_approval_of_active_action_does_not_create_revertible_duplicate(self):
        target = self.target_value
        original_recommendation_id = self._create_recommendation(target)
        original_response = self.recommendations.approve(
            original_recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )
        action_id = original_response["action"]["id"]
        with patch.object(
            self.action_jobs.adapters,
            "execute",
            return_value=(True, "Test action completed"),
        ):
            self.assertTrue(self.action_jobs.process_one_job())

        duplicate_recommendation_id = self._create_recommendation(target)
        duplicate_response = self.recommendations.approve(
            duplicate_recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )

        self.assertEqual(duplicate_response["status"], "already_active")
        self.assertEqual(duplicate_response["action"]["id"], action_id)
        with self.test_pool.connection() as conn:
            action_count = conn.execute(
                """
                SELECT count(*) AS count
                FROM actions a JOIN recommendations r ON r.id = a.recommendation_id
                WHERE r.target_value = %s
                """,
                (target,),
            ).fetchone()["count"]
            duplicate_status = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s",
                (duplicate_recommendation_id,),
            ).fetchone()["status"]
            conn.execute(
                "UPDATE actions SET expires_at = now() - interval '1 minute' WHERE id = %s",
                (action_id,),
            )

        self.assertEqual(action_count, 1)
        self.assertEqual(duplicate_status, "executed")
        self.expiry._revert_expired_once()
        with self.test_pool.connection() as conn:
            revert_jobs = conn.execute(
                """
                SELECT count(*) AS count FROM action_jobs
                WHERE action_id = %s AND operation = 'revert'
                """,
                (action_id,),
            ).fetchone()["count"]
        self.assertEqual(revert_jobs, 1)
        with patch.object(
            self.action_jobs.adapters,
            "revert",
            return_value=(True, "Test revert completed"),
        ):
            self.assertTrue(self.action_jobs.process_one_job())

    # Worker retry, lease ownership, and expiry tests cover action recovery.
    def test_failed_revert_can_be_retried_and_audited(self):
        action_id = self._create_expired_action()
        with self.test_pool.connection() as conn:
            failed_job = conn.execute(
                """
                INSERT INTO action_jobs
                    (action_id, operation, status, attempts, last_error)
                VALUES (%s, 'revert', 'failed', 8, 'Adapter unavailable')
                RETURNING id
                """,
                (action_id,),
            ).fetchone()

        response = self.actions.revert_action(
            action_id,
            self.actions.DecisionIn(comment="Retry after checking adapter"),
            {"id": self.user_id, "role": "tier2"},
        )
        self.assertEqual(response["status"], "queued")
        self.assertEqual(response["job_id"], failed_job["id"])

        with patch.object(
            self.action_jobs.adapters,
            "revert",
            return_value=(True, "Test revert completed"),
        ):
            self.assertTrue(self.action_jobs.process_one_job())

        with self.test_pool.connection() as conn:
            job = conn.execute(
                "SELECT status, attempts FROM action_jobs WHERE id = %s",
                (failed_job["id"],),
            ).fetchone()
            audit = conn.execute(
                """
                SELECT count(*) AS count FROM audit_log
                WHERE entity_type = 'action' AND entity_id = %s
                  AND event_type = 'action.revert_retry_queued'
                """,
                (action_id,),
            ).fetchone()["count"]
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["attempts"], 1)
        self.assertEqual(audit, 1)

    def test_running_job_lease_is_renewed_while_adapter_is_active(self):
        recommendation_id = self._create_recommendation()
        self.recommendations.approve(
            recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )
        started = threading.Event()
        finish = threading.Event()

        def slow_execute(executor, command):
            started.set()
            if not finish.wait(timeout=5):
                raise TimeoutError("Test adapter was not released")
            return True, "Test action completed"

        with patch.object(self.action_jobs, "LEASE_RENEW_INTERVAL_SECONDS", 0.01), patch.object(
            self.action_jobs, "CLAIM_TIMEOUT_SECONDS", 0.04
        ), patch.object(self.action_jobs.adapters, "execute", side_effect=slow_execute):
            with ThreadPoolExecutor(max_workers=1) as executor:
                running = executor.submit(self.action_jobs.process_one_job)
                self.assertTrue(started.wait(timeout=2))
                threading.Event().wait(0.15)
                self.assertFalse(self.action_jobs.process_one_job())
                finish.set()
                self.assertTrue(running.result(timeout=5))

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
        revert_calls = []

        def revert_action(executor, command):
            revert_calls.append((executor, command))
            return True, "Test revert completed"

        self.expiry._revert_expired_once()
        with self.assertRaises(HTTPException) as error:
            self.actions.revert_action(
                action_id,
                self.actions.DecisionIn(),
                {"id": self.user_id, "role": "tier2"},
            )
        self.assertEqual(error.exception.status_code, 409)

        with patch.object(self.action_jobs.adapters, "revert", side_effect=revert_action):
            self.assertTrue(self.action_jobs.process_one_job())
        self.assertEqual(len(revert_calls), 1)

        with self.test_pool.connection() as conn:
            row = conn.execute(
                "SELECT reverted_at FROM actions WHERE id = %s",
                (action_id,),
            ).fetchone()
        self.assertIsNotNone(row["reverted_at"])

    def test_expiry_workers_skip_actions_claimed_by_another_worker(self):
        action_id = self._create_expired_action()
        with self.test_pool.connection() as conn:
            conn.execute(
                "INSERT INTO action_jobs (action_id, operation) VALUES (%s, 'revert')",
                (action_id,),
            )
        revert_started = threading.Event()
        release_revert = threading.Event()
        revert_calls = []

        def revert_action(executor, command):
            revert_calls.append((executor, command))
            revert_started.set()
            if not release_revert.wait(timeout=5):
                raise TimeoutError("Test did not release the simulated revert")
            return True, "Test revert completed"

        with patch.object(self.action_jobs.adapters, "revert", side_effect=revert_action):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(self.action_jobs.process_one_job)
                self.assertTrue(revert_started.wait(timeout=5))
                second = executor.submit(self.action_jobs.process_one_job)
                self.assertFalse(second.result(timeout=5))
                release_revert.set()
                first.result(timeout=10)

        self.assertEqual(len(revert_calls), 1)

    def _set_incident_status(self, status):
        with self.test_pool.connection() as conn:
            conn.execute(
                "UPDATE incidents SET status = %s WHERE id = %s", (status, self.incident_id)
            )

    def _incident_status(self):
        with self.test_pool.connection() as conn:
            return conn.execute(
                "SELECT status FROM incidents WHERE id = %s", (self.incident_id,)
            ).fetchone()["status"]

    # Regression cases ensure incident notes, parsing, and expiry preserve workflow semantics.
    def test_adding_a_note_does_not_skip_triage(self):
        from app.schemas import NoteIn

        self.incidents.add_note(
            self.incident_id,
            NoteIn(body="Looking into it"),
            {"id": self.user_id, "role": "tier1"},
        )

        self.assertEqual(self._incident_status(), "new")

    def test_malformed_alert_fields_are_stored_with_notes(self):
        result = self.alerts.ingest_alert(
            AlertIn(severity="high", src_ip=12345, hostname="ws-01"), None
        )

        self.assertEqual(result["parse_status"], "partial")
        self.assertEqual(len(result["parse_notes"]), 3)  # missing source, bad IP, bad severity

    def test_temporary_action_expiry_starts_when_execution_succeeds(self):
        from datetime import timedelta

        recommendation_id = self._create_recommendation()
        response = self.recommendations.approve(
            recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier2"},
        )
        action_id = response["action"]["id"]
        self.assertIsNone(response["action"]["expires_at"])

        with patch.object(
            self.action_jobs.adapters, "execute", return_value=(True, "Test action completed")
        ):
            self.assertTrue(self.action_jobs.process_one_job())

        with self.test_pool.connection() as conn:
            action = conn.execute(
                "SELECT success, expires_at - executed_at AS duration FROM actions WHERE id = %s",
                (action_id,),
            ).fetchone()
        self.assertTrue(action["success"])
        self.assertEqual(action["duration"], timedelta(seconds=60))

    def test_actions_cannot_be_approved_for_finished_incidents(self):
        recommendation_id = self._create_recommendation()
        self._set_incident_status("resolved")

        with self.assertRaises(HTTPException) as error:
            self.recommendations.approve(
                recommendation_id,
                self.recommendations.DecisionIn(),
                {"id": self.user_id, "role": "tier3"},
            )

        self.assertEqual(error.exception.status_code, 409)
        with self.test_pool.connection() as conn:
            status = conn.execute(
                "SELECT status FROM recommendations WHERE id = %s", (recommendation_id,)
            ).fetchone()["status"]
        self.assertEqual(status, "pending")

    def test_actions_cannot_be_approved_before_tier1_triage(self):
        recommendation_id = self._create_recommendation(triaged=False)

        with self.assertRaises(HTTPException) as error:
            self.recommendations.approve(
                recommendation_id,
                self.recommendations.DecisionIn(),
                {"id": self.user_id, "role": "tier3"},
            )

        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self._incident_status(), "new")

    def test_triage_records_when_it_happened(self):
        from app.schemas import TriageIn

        self.incidents.triage_incident(
            self.incident_id, TriageIn(confirmed=True), {"id": self.user_id, "role": "tier1"}
        )

        with self.test_pool.connection() as conn:
            incident = conn.execute(
                "SELECT triaged_at, created_at FROM incidents WHERE id = %s", (self.incident_id,)
            ).fetchone()
        self.assertIsNotNone(incident["triaged_at"])
        self.assertGreaterEqual(incident["triaged_at"], incident["created_at"])

    def _recommendation_citing(self, alert_ids):
        return RecommendationIn(
            incident_id=self.incident_id,
            action_type="block_ip",
            executor="firewall",
            target_scope="single_ip",
            target_value=self.target_value,
            reason="Regression test",
            duration_secs=60,
            evidence_alert_ids=alert_ids,
        )

    def test_recommendation_stores_validated_evidence(self):
        with self.test_pool.connection() as conn:
            alert_id = conn.execute(
                "INSERT INTO alerts (incident_id, source) VALUES (%s, 'ids') RETURNING id",
                (self.incident_id,),
            ).fetchone()["id"]

        row = self.recommendations.create_recommendation(self._recommendation_citing([alert_id, alert_id]))

        self.assertEqual(row["evidence_alert_ids"], [alert_id])

    def test_recommendation_citing_unrelated_alerts_is_rejected(self):
        with self.test_pool.connection() as conn:
            other_incident = conn.execute(
                "INSERT INTO incidents (title, severity) VALUES ('Other', 3) RETURNING id"
            ).fetchone()["id"]
            other_alert = conn.execute(
                "INSERT INTO alerts (incident_id, source) VALUES (%s, 'ids') RETURNING id",
                (other_incident,),
            ).fetchone()["id"]

        for cited in ([other_alert], [999_999_999]):
            with self.subTest(cited=cited), self.assertRaises(HTTPException) as error:
                self.recommendations.create_recommendation(self._recommendation_citing(cited))
            self.assertEqual(error.exception.status_code, 422)

    def _l1_report(self, verdict="true_positive"):
        from app.schemas import L1ReportIn

        with self.test_pool.connection() as conn:
            alert_id = conn.execute(
                """
                INSERT INTO alerts (incident_id, source, src_ip, signature)
                VALUES (%s, 'ids', %s, 'BRUTE_FORCE_LOGIN') RETURNING id
                """,
                (self.incident_id, self.target_value),
            ).fetchone()["id"]
        return self.l1_reports.submit_report(
            L1ReportIn(
                incident_id=self.incident_id,
                verdict=verdict,
                confidence="high",
                severity=3,
                category="brute_force",
                summary="Repeated failed SSH logins followed by a successful one.",
                indicators=[{"type": "ip", "value": self.target_value}],
                evidence_alert_ids=[alert_id],
                escalation_reason="Possible compromised account" if verdict == "true_positive" else None,
                false_positive_reason="Scheduled vulnerability scan" if verdict == "false_positive" else None,
            )
        )

    def test_approved_l1_report_escalates_true_positive(self):
        from app.schemas import L1ReviewIn

        report = self._l1_report()
        self.assertEqual(report["status"], "pending_review")
        self.assertEqual(self._incident_status(), "new")
        self.assertIn(self.target_value, report["enrichment"])

        result = self.l1_reports.approve_report(
            report["id"], L1ReviewIn(changes={"severity": 2}), {"id": self.user_id, "role": "tier1"}
        )

        self.assertEqual(result["incident_status"], "investigating")
        self.assertEqual(result["reviewer_changes"], ["severity"])
        with self.test_pool.connection() as conn:
            incident = conn.execute(
                "SELECT severity, ai_summary, triaged_at FROM incidents WHERE id = %s", (self.incident_id,)
            ).fetchone()
        self.assertEqual(incident["severity"], 2)
        self.assertEqual(incident["ai_summary"], report["content"]["summary"])
        self.assertIsNotNone(incident["triaged_at"])

    def test_approved_false_positive_l1_report_closes_incident(self):
        from app.schemas import L1ReviewIn

        report = self._l1_report("false_positive")
        result = self.l1_reports.approve_report(
            report["id"], L1ReviewIn(), {"id": self.user_id, "role": "tier1"}
        )

        self.assertEqual(result["incident_status"], "closed")
        self.assertEqual(self._incident_status(), "closed")

    def test_overriding_the_ai_verdict_needs_the_matching_reason(self):
        from app.schemas import L1ReviewIn

        report = self._l1_report()
        user = {"id": self.user_id, "role": "tier1"}
        with self.assertRaises(HTTPException) as error:
            self.l1_reports.approve_report(report["id"], L1ReviewIn(changes={"verdict": "false_positive"}), user)
        self.assertEqual(error.exception.status_code, 422)
        self.assertEqual(self._incident_status(), "new")

        result = self.l1_reports.approve_report(
            report["id"],
            L1ReviewIn(changes={"verdict": "false_positive", "false_positive_reason": "Authorized penetration test"}),
            user,
        )

        self.assertEqual(result["incident_status"], "closed")
        self.assertEqual(result["reviewer_changes"], ["verdict", "false_positive_reason"])
        text = self.l1_reports.get_report_text(report["id"], user)
        self.assertIn("L1 TRIAGE: CLOSED AS FALSE POSITIVE", text)
        self.assertIn("The AI originally judged this a true positive.", text)

    def test_only_one_l1_report_awaits_review_per_incident(self):
        from app.schemas import L1RejectIn

        first = self._l1_report()
        with self.assertRaises(HTTPException) as error:
            self._l1_report()
        self.assertEqual(error.exception.status_code, 409)

        self.l1_reports.reject_report(
            first["id"], L1RejectIn(comment="Wrong host"), {"id": self.user_id, "role": "tier1"}
        )
        self.assertEqual(self._incident_status(), "new")
        self.assertEqual(self._l1_report()["status"], "pending_review")

    def test_l1_report_text_and_metrics(self):
        report = self._l1_report()
        user = {"id": self.user_id, "role": "tier1"}

        text = self.l1_reports.get_report_text(report["id"], user)
        metrics = self.l1_reports.report_metrics(user)

        self.assertIn(f"INCIDENT #{self.incident_id} \u2014 L1 ESCALATION REPORT", text)
        self.assertIn("Status: AI draft, awaiting L1 review", text)
        self.assertIn("BRUTE_FORCE_LOGIN (source: ids)", text)
        self.assertGreaterEqual(metrics["pending_review"], 1)

    def test_ai_agent_and_analysts_can_add_notes_at_any_time(self):
        from app.schemas import L1ReviewIn, NoteIn

        report = self._l1_report()
        user = {"id": self.user_id, "role": "tier1"}
        self.l1_reports.add_ai_note(report["id"], NoteIn(body="A second login from the same IP arrived at 14:20."))
        self.l1_reports.approve_report(report["id"], L1ReviewIn(), user)
        self.l1_reports.add_analyst_note(report["id"], NoteIn(body="Asset owner confirmed the login was not theirs."), user)

        notes = self.l1_reports.get_report(report["id"], user)["notes"]
        text = self.l1_reports.get_report_text(report["id"], user)

        self.assertEqual([note["author_type"] for note in notes], ["ai", "user"])
        self.assertIn("AI agent:", text)
        self.assertIn("A second login from the same IP arrived at 14:20.", text)
        self.assertIn("(tier2):", text)
        with self.assertRaises(HTTPException) as error:
            self.l1_reports.add_ai_note(999_999_999, NoteIn(body="Lost note"))
        self.assertEqual(error.exception.status_code, 404)
        with self.assertRaises(psycopg.errors.RaiseException), self.test_pool.connection() as conn:
            conn.execute("DELETE FROM l1_report_notes WHERE report_id = %s", (report["id"],))

    def test_approved_action_moves_escalated_incident_to_in_response(self):
        recommendation_id = self._create_recommendation()
        self._set_incident_status("escalated")

        self.recommendations.approve(
            recommendation_id,
            self.recommendations.DecisionIn(),
            {"id": self.user_id, "role": "tier3"},
        )

        self.assertEqual(self._incident_status(), "in_response")
        with patch.object(
            self.action_jobs.adapters, "execute", return_value=(True, "Test action completed")
        ):
            self.assertTrue(self.action_jobs.process_one_job())




if __name__ == "__main__":
    unittest.main()
