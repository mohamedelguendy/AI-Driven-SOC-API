-- Tier 1 triage reports: drafted by the AI, reviewed and approved by tier 1.
CREATE TABLE IF NOT EXISTS l1_reports (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id        BIGINT NOT NULL REFERENCES incidents(id),
    status             TEXT NOT NULL DEFAULT 'pending_review'
                       CHECK (status IN ('pending_review', 'approved', 'rejected')),
    verdict            TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
    severity           SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),  -- 1 = critical
    category           TEXT NOT NULL,
    content            JSONB NOT NULL,                -- the report: AI draft plus tier 1 corrections
    evidence_alert_ids BIGINT[] NOT NULL,
    enrichment         JSONB NOT NULL DEFAULT '{}',   -- added by the backend, not the AI
    ai_draft           JSONB NOT NULL,                -- exactly what the AI submitted
    reviewer_changes   TEXT[] NOT NULL DEFAULT '{}',  -- fields tier 1 corrected
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by        BIGINT REFERENCES users(id),
    reviewed_at        TIMESTAMPTZ,
    review_comment     TEXT
);

-- At most one draft per incident can await review at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_l1_reports_one_pending
    ON l1_reports (incident_id)
    WHERE status = 'pending_review';

-- The review queue.
CREATE INDEX IF NOT EXISTS idx_l1_reports_status
    ON l1_reports (status, created_at DESC);

-- Notes the AI agent or analysts append to a report at any time.
CREATE TABLE IF NOT EXISTS l1_report_notes (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_id   BIGINT NOT NULL REFERENCES l1_reports(id),
    author_type TEXT NOT NULL CHECK (author_type IN ('ai', 'user')),
    author_id   BIGINT REFERENCES users(id),  -- NULL for the AI agent
    body        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((author_type = 'ai') = (author_id IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_l1_report_notes_report
    ON l1_report_notes (report_id, created_at);

-- Notes are part of the record: they can be added, never edited or deleted.
CREATE OR REPLACE FUNCTION l1_report_notes_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'l1_report_notes is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS l1_report_notes_append_only ON l1_report_notes;
CREATE TRIGGER l1_report_notes_append_only
    BEFORE UPDATE OR DELETE ON l1_report_notes
    FOR EACH ROW EXECUTE FUNCTION l1_report_notes_immutable();
