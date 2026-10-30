-- Store the alert IDs each AI recommendation cites as evidence.
ALTER TABLE recommendations
    ADD COLUMN IF NOT EXISTS evidence_alert_ids BIGINT[] NOT NULL DEFAULT '{}';

-- When tier 1 triaged the incident: MTTA = triaged_at - created_at.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMPTZ;
