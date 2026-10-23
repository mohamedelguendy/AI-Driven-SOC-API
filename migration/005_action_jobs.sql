CREATE TABLE IF NOT EXISTS action_jobs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_id       BIGINT NOT NULL REFERENCES actions(id),
    operation       TEXT NOT NULL CHECK (operation IN ('execute', 'revert')),
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at      TIMESTAMPTZ,
    requested_by    BIGINT REFERENCES users(id),
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (action_id, operation)
);

CREATE INDEX IF NOT EXISTS idx_action_jobs_ready
    ON action_jobs (next_attempt_at, id)
    WHERE status IN ('queued', 'running');
