"""Auto-reverts temporary actions once their expires_at has passed.
 
Runs as a background thread (started in main.py's lifespan) so a
temporary block doesn't require anyone to remember to undo it manually.
A failed revert is logged and retried on the next cycle — it is never
silently dropped, and expires_at is left untouched so it keeps trying.
"""
import threading
import time
 
from psycopg.types.json import Jsonb

from .db import pool
 
CHECK_INTERVAL_SECONDS = 30
 
 
def _revert_expired_once():
    with pool.connection() as conn:
        expired = conn.execute(
            """
            INSERT INTO action_jobs (action_id, operation)
            SELECT a.id, 'revert'
            FROM actions a
            WHERE a.reverted_at IS NULL
              AND a.expires_at IS NOT NULL
              AND a.expires_at <= now()
              AND a.success = TRUE
            ORDER BY a.expires_at, a.id
            LIMIT 100
            ON CONFLICT (action_id, operation) DO NOTHING
            RETURNING action_id
            """
        ).fetchall()

        for row in expired:
            conn.execute(
                """
                INSERT INTO audit_log (actor_type, event_type, entity_type, entity_id, details)
                VALUES ('system', 'action.auto_revert_queued', 'action', %s, %s)
                """,
                (row["action_id"], Jsonb({"operation": "revert"})),
            )
 
 
def _loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            _revert_expired_once()
        except Exception as e:  # noqa: BLE001 — one bad cycle must not kill the background thread
            print(f"[expiry] cycle failed: {e}")
        stop_event.wait(CHECK_INTERVAL_SECONDS)
 
 
def start(stop_event: threading.Event) -> threading.Thread:
    thread = threading.Thread(target=_loop, args=(stop_event,), daemon=True)
    thread.start()
    return thread