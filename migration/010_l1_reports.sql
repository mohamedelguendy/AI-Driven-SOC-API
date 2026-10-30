-- Tier 1 triage reports: drafted by the AI, reviewed and approved by tier 1.
CREATE TABLE IF NOT EXISTS l1_reports (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id           BIGINT NOT NULL REFERENCES incidents(id),
    status                TEXT NOT NULL DEFAULT 'pending_review'
                          CHECK (status IN ('pending_review', 'approved', 'rejected')),
    verdict               TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
    confidence            TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    severity              SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),  -- 1 = critical
    summary               TEXT NOT NULL,
    affected_assets       JSONB NOT NULL DEFAULT '[]',
    indicators            JSONB NOT NULL DEFAULT '[]',
    evidence_alert_ids    BIGINT[] NOT NULL,
    enrichment            JSONB NOT NULL DEFAULT '{}',   -- added by the backend, not the AI
    recommended_actions   JSONB NOT NULL DEFAULT '[]',
    escalation_reason     TEXT,
    false_positive_reason TEXT,
    ai_draft              JSONB NOT NULL,                -- exactly what the AI submitted
    reviewer_changes      TEXT[] NOT NULL DEFAULT '{}',  -- fields tier 1 corrected
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by           BIGINT REFERENCES users(id),
    reviewed_at           TIMESTAMPTZ,
    review_comment        TEXT,
    CHECK (verdict <> 'true_positive' OR escalation_reason IS NOT NULL),
    CHECK (verdict <> 'false_positive' OR false_positive_reason IS NOT NULL)
);

-- At most one draft per incident can await review at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_l1_reports_one_pending
    ON l1_reports (incident_id)
    WHERE status = 'pending_review';

-- The review queue.
CREATE INDEX IF NOT EXISTS idx_l1_reports_status
    ON l1_reports (status, created_at DESC);
