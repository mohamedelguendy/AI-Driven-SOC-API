-- Track feeder event IDs and enforce one stored alert per idempotency key.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS source_event_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_event_id
    ON alerts (source_event_id)
    WHERE source_event_id IS NOT NULL;
