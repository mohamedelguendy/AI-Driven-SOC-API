"""Durable, retryable execution and reversal of approved response actions."""
import threading
import time

from psycopg.types.json import Jsonb

from . import adapters
from .db import pool

CHECK_INTERVAL_SECONDS = 2
MAX_ATTEMPTS = 8
CLAIM_TIMEOUT_SECONDS = 120


def _claim_job():
    with pool.connection() as conn:
        return conn.execute(
            """
            UPDATE action_jobs
            SET status = 'running',
                attempts = attempts + 1,
                claimed_at = now(),
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
            RETURNING id, action_id, operation, attempts, requested_by
            """,
            (CLAIM_TIMEOUT_SECONDS,),
        ).fetchone()


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
            "idempotency_key": f"soc-action-{job['action_id']}-{job['operation']}",
        }
    )
    return action["executor"], command


def _finish_job(job: dict, success: bool, message: str) -> None:
    retry = not success and job["attempts"] < MAX_ATTEMPTS
    delay_seconds = min(2 ** job["attempts"], 300)

    with pool.connection() as conn:
        if job["operation"] == "execute":
            if success or not retry:
                conn.execute(
                    """
                    UPDATE actions
                    SET success = %s, result_message = %s
                    WHERE id = %s
                    """,
                    (success, message, job["action_id"]),
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

        if retry:
            conn.execute(
                """
                UPDATE action_jobs
                SET status = 'queued',
                    next_attempt_at = now() + (%s * interval '1 second'),
                    claimed_at = NULL,
                    last_error = %s,
                    updated_at = now()
                WHERE id = %s
                """,
                (delay_seconds, message, job["id"]),
            )
        else:
            conn.execute(
                """
                UPDATE action_jobs
                SET status = %s, claimed_at = NULL, last_error = %s, updated_at = now()
                WHERE id = %s
                """,
                ("succeeded" if success else "failed", None if success else message, job["id"]),
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


def process_one_job() -> bool:
    job = _claim_job()
    if job is None:
        return False

    try:
        executor, command = _job_command(job)
        if job["operation"] == "execute":
            success, message = adapters.execute(executor, command)
        else:
            success, message = adapters.revert(executor, command)
    except Exception as error:
        success, message = False, f"Action job error: {error}"

    _finish_job(job, success, message)
    return True


def _loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            processed = process_one_job()
        except Exception as error:  # one failed iteration must not stop durable work
            print(f"[action-jobs] processing failed: {error}")
            processed = False
        if not processed:
            stop_event.wait(CHECK_INTERVAL_SECONDS)


def start(stop_event: threading.Event) -> threading.Thread:
    thread = threading.Thread(target=_loop, args=(stop_event,), daemon=True)
    thread.start()
    return thread
