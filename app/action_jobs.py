"""Durable, retryable execution and reversal of approved response actions."""
import threading
import uuid

from psycopg.types.json import Jsonb

from . import adapters
from .db import pool

CHECK_INTERVAL_SECONDS = 2
MAX_ATTEMPTS = 8
CLAIM_TIMEOUT_SECONDS = 120
LEASE_RENEW_INTERVAL_SECONDS = 30




# Claim one ready job at a time; expired leases make abandoned work reclaimable.
def _claim_job():
    """Atomically claim one ready job or reclaim one with an expired lease."""
    claim_token = uuid.uuid4()
    with pool.connection() as conn:
        return conn.execute(
            """
            UPDATE action_jobs
            SET status = 'running',
                attempts = attempts + 1,
                claimed_at = now(),
                claim_token = %s,
                updated_at = now()
            WHERE id = (
                SELECT id
                FROM action_jobs
                WHERE (
                    status = 'queued'
                    AND next_attempt_at <= now()
                ) OR (
                    status = 'running'
                    AND claimed_at < now() - (%s * interval '1 second')
                )
                ORDER BY next_attempt_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, action_id, operation, attempts, requested_by, claim_token
            """,
            (claim_token, CLAIM_TIMEOUT_SECONDS),
        ).fetchone()




# Refresh the claim timestamp while a provider call is still in progress.
def _renew_lease(
    job: dict,
    stop_event: threading.Event,
    lease_lost: threading.Event,
) -> None:
    while not stop_event.wait(LEASE_RENEW_INTERVAL_SECONDS):
        try:
            with pool.connection() as conn:
                result = conn.execute(
                    """
                    UPDATE action_jobs
                    SET claimed_at = now(), updated_at = now()
                    WHERE id = %s AND status = 'running' AND claim_token = %s
                    """,
                    (job["id"], job["claim_token"]),
                )
            if result.rowcount != 1:
                lease_lost.set()
                return
        except Exception as error:
            print(f"[action-jobs] lease renewal failed for job {job['id']}: {error}")




# Load the approved action and attach stable identifiers for adapter retries.
def _job_command(job: dict) -> tuple[str, dict]:
    with pool.connection() as conn:
        action = conn.execute(
            """
            SELECT a.executor, a.command, r.action_type, r.target_value
            FROM actions a
            JOIN recommendations r ON r.id = a.recommendation_id
            WHERE a.id = %s
            """,
            (job["action_id"],),
        ).fetchone()

    if action is None:
        raise RuntimeError(f"Action {job['action_id']} for job {job['id']} no longer exists")

    command = dict(action["command"])
    command.update(
        {
            "action_type": action["action_type"],
            "target": action["target_value"],
            "executor": action["executor"],
            "action_id": job["action_id"],
            "idempotency_key": f"soc-action-{job['action_id']}-{job['operation']}",
        }
    )
    return action["executor"], command




# Persist the result and audit event only while this worker still owns the job.
def _finish_job(job: dict, success: bool, message: str) -> None:
    retry = not success and job["attempts"] < MAX_ATTEMPTS
    delay_seconds = min(2 ** job["attempts"], 300)

    with pool.connection() as conn:
        status = "queued" if retry else ("succeeded" if success else "failed")
        result = conn.execute(
            """
            UPDATE action_jobs
            SET status = %s,
                next_attempt_at = CASE
                    WHEN %s THEN now() + (%s * interval '1 second')
                    ELSE next_attempt_at
                END,
                claimed_at = NULL,
                claim_token = NULL,
                last_error = %s,
                updated_at = now()
            WHERE id = %s AND status = 'running' AND claim_token = %s
            RETURNING id
            """,
            (
                status,
                retry,
                delay_seconds,
                None if success else message,
                job["id"],
                job["claim_token"],
            ),
        ).fetchone()
        if result is None:
            raise RuntimeError(f"Worker no longer owns action job {job['id']}")

        if job["operation"] == "execute":
            if success or not retry:
                # A temporary action's clock starts when it actually takes
                # effect, not at approval: retries can delay execution.
                conn.execute(
                    """
                    UPDATE actions a
                    SET success = %s,
                        result_message = %s,
                        executed_at = CASE WHEN %s THEN now() ELSE a.executed_at END,
                        expires_at = CASE
                            WHEN %s AND NOT r.is_permanent
                            THEN now() + r.duration_secs * interval '1 second'
                            ELSE a.expires_at
                        END
                    FROM recommendations r
                    WHERE a.id = %s AND r.id = a.recommendation_id
                    """,
                    (success, message, success, success, job["action_id"]),
                )
                conn.execute(
                    "UPDATE recommendations SET status = %s WHERE id = "
                    "(SELECT recommendation_id FROM actions WHERE id = %s)",
                    ("executed" if success else "failed", job["action_id"]),
                )
        elif success:
            conn.execute(
                """
                UPDATE actions
                SET reverted_at = now(), reverted_by = %s
                WHERE id = %s AND reverted_at IS NULL
                """,
                (job["requested_by"], job["action_id"]),
            )

        event = (
            f"action.{job['operation']}_succeeded"
            if success
            else f"action.{job['operation']}_{'retry' if retry else 'failed'}"
        )
        conn.execute(
            """
            INSERT INTO audit_log (actor_type, actor_id, event_type, entity_type, entity_id, details)
            VALUES ('system', NULL, %s, 'action', %s, %s)
            """,
            (
                event,
                job["action_id"],
                Jsonb(
                    {
                        "job_id": job["id"],
                        "attempt": job["attempts"],
                        "retrying": retry,
                        "message": message,
                    }
                ),
            ),
        )




# Keep a lease alive during slow adapter calls, then dispatch and record one job.
def process_one_job() -> bool:
    job = _claim_job()
    if job is None:
        return False

    heartbeat_stop = threading.Event()
    lease_lost = threading.Event()
    heartbeat = threading.Thread(
        target=_renew_lease,
        args=(job, heartbeat_stop, lease_lost),
        daemon=True,
    )
    heartbeat.start()
    try:
        executor, command = _job_command(job)
        if job["operation"] == "execute":
            success, message = adapters.execute(executor, command)
        else:
            success, message = adapters.revert(executor, command)
    except Exception as error:
        success, message = False, f"Action job error: {error}"
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=LEASE_RENEW_INTERVAL_SECONDS + 1)

    if lease_lost.is_set():
        print(f"[action-jobs] job {job['id']} lost its lease before completion")
        return True
    _finish_job(job, success, message)
    return True




# Poll continuously, but wait briefly when there is no ready work.
def _loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            processed = process_one_job()
        except Exception as error:  # one failed iteration must not stop durable work
            print(f"[action-jobs] processing failed: {error}")
            processed = False
        if not processed:
            stop_event.wait(CHECK_INTERVAL_SECONDS)




# Start the worker as a managed daemon thread for the application lifespan.
def start(stop_event: threading.Event) -> threading.Thread:
    thread = threading.Thread(target=_loop, args=(stop_event,), daemon=True)
    thread.start()
    return thread
