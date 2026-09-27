-- =====================================================================
-- AI-Driven SOC Platform: backend database schema (PostgreSQL)
-- Covers: users/roles, alerts, incidents, AI recommendations,
-- impact rules, protected allowlist, executed actions, audit log.
-- =====================================================================

-- ---------- Enumerated types ----------

CREATE TYPE user_role AS ENUM ('tier2', 'tier3', 'admin');

CREATE TYPE alert_source AS ENUM ('siem', 'ids', 'edr', 'firewall', 'webapp');

CREATE TYPE incident_status AS ENUM (
    'new',            -- created by correlation, waiting for tier 2
    'investigating',  -- tier 2 is working on it
    'escalated',      -- sent to tier 3
    'in_response',    -- tier 3 is acting on it
    'resolved',
    'closed'
);

CREATE TYPE impact_level AS ENUM ('low', 'high');

CREATE TYPE recommendation_status AS ENUM (
    'pending',    -- waiting for a decision
    'approved',   -- approved, not yet executed
    'rejected',
    'executed',
    'failed',     -- approved but the firewall/EDR call failed
    'expired'     -- never decided within the allowed time
);

CREATE TYPE executor_type AS ENUM ('firewall', 'edr');

CREATE TYPE actor_type AS ENUM ('user', 'system', 'ai');

-- ---------- Users ----------

CREATE TABLE users (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,              -- never store plain passwords
    role           user_role NOT NULL,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Incidents and alerts ----------

CREATE TABLE incidents (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title          TEXT NOT NULL,
    status         incident_status NOT NULL DEFAULT 'new',
    severity       SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),
    risk_score     SMALLINT CHECK (risk_score BETWEEN 0 AND 100),
    assigned_tier  user_role CHECK (assigned_tier IN ('tier2', 'tier3')),
    assigned_to    BIGINT REFERENCES users(id),
    ai_summary     TEXT,                       -- AI explanation shown to analysts
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ
);

CREATE INDEX idx_incidents_queue ON incidents (status, risk_score DESC);

CREATE TABLE alerts (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id    BIGINT REFERENCES incidents(id),
    source         alert_source NOT NULL,
    event_time     TIMESTAMPTZ NOT NULL,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip         INET,
    dst_ip         INET,
    hostname       TEXT,
    signature      TEXT,                       -- rule or detection name
    severity       SMALLINT CHECK (severity BETWEEN 1 AND 5),
    raw_event      JSONB NOT NULL              -- original event from the security team
);

CREATE INDEX idx_alerts_incident ON alerts (incident_id);
CREATE INDEX idx_alerts_src_ip   ON alerts (src_ip);
CREATE INDEX idx_alerts_time     ON alerts (event_time DESC);

CREATE TABLE incident_notes (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id    BIGINT NOT NULL REFERENCES incidents(id),
    author_id      BIGINT NOT NULL REFERENCES users(id),
    body           TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Impact rules (editable, not hardcoded) ----------
-- A NULL column means "matches anything". The backend collects every rule
-- that matches a recommendation and uses the HIGHEST impact level found.
-- If no rule matches, the backend must treat the action as 'high' (fail safe).

CREATE TABLE impact_rules (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_type    TEXT,        -- e.g. 'block_ip', 'block_port', 'isolate_host'
    target_scope   TEXT,        -- e.g. 'single_ip', 'subnet', 'endpoint'
    is_internal    BOOLEAN,     -- does the target belong to the internal network?
    is_permanent   BOOLEAN,     -- is the action permanent (no expiry)?
    impact         impact_level NOT NULL,
    description    TEXT
);

INSERT INTO impact_rules (action_type, target_scope, is_internal, is_permanent, impact, description) VALUES
    ('block_ip',    'single_ip', FALSE, FALSE, 'low',  'Temporary block of one external IP'),
    ('block_port',  NULL,        FALSE, FALSE, 'low',  'Temporary block of a port for external traffic'),
    ('block_ip',    NULL,        NULL,  TRUE,  'high', 'Any permanent block'),
    ('block_ip',    'subnet',    NULL,  NULL,  'high', 'Blocking an IP range'),
    ('isolate_host', NULL,       NULL,  NULL,  'high', 'Isolating an endpoint through EDR'),
    (NULL,          NULL,        TRUE,  NULL,  'high', 'Any action touching an internal host');

-- ---------- Protected allowlist ----------
-- Targets that can never be blocked or isolated by anyone, any tier.

CREATE TABLE protected_targets (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target         CIDR NOT NULL UNIQUE,       -- single IP is stored as /32
    description    TEXT NOT NULL,
    created_by     BIGINT REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Example rows; replace with your real network before use:
-- INSERT INTO protected_targets (target, description) VALUES
--     ('192.168.1.1/32', 'Default gateway'),
--     ('192.168.1.10/32', 'SOC platform server');

-- ---------- AI recommendations ----------

CREATE TABLE recommendations (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id     BIGINT NOT NULL REFERENCES incidents(id),
    action_type     TEXT NOT NULL,             -- 'block_ip', 'block_port', 'isolate_host', ...
    executor        executor_type NOT NULL,
    target_scope    TEXT NOT NULL,
    target_value    TEXT NOT NULL,             -- IP, CIDR, port or hostname
    is_internal     BOOLEAN NOT NULL,          -- computed by the backend, not the AI
    is_permanent    BOOLEAN NOT NULL DEFAULT FALSE,
    duration_secs   INTEGER,                   -- for temporary actions
    reason          TEXT NOT NULL,             -- AI explanation
    risk_score      SMALLINT CHECK (risk_score BETWEEN 0 AND 100),
    impact          impact_level NOT NULL,     -- assigned by the backend from impact_rules
    status          recommendation_status NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by      BIGINT REFERENCES users(id),
    decided_at      TIMESTAMPTZ,
    CHECK (is_permanent OR duration_secs IS NOT NULL)
);

CREATE INDEX idx_recommendations_pending ON recommendations (status, impact);

-- ---------- Executed actions ----------

CREATE TABLE actions (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recommendation_id BIGINT NOT NULL REFERENCES recommendations(id),
    executor          executor_type NOT NULL,
    command           JSONB NOT NULL,          -- what was sent to the firewall/EDR
    success           BOOLEAN,
    result_message    TEXT,
    executed_by       BIGINT NOT NULL REFERENCES users(id),
    executed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ,             -- a background job reverts the action after this
    reverted_at       TIMESTAMPTZ,
    reverted_by       BIGINT REFERENCES users(id)  -- NULL when the system reverted it
);

CREATE INDEX idx_actions_expiry ON actions (expires_at)
    WHERE reverted_at IS NULL AND expires_at IS NOT NULL;

-- ---------- Audit log (append-only) ----------

CREATE TABLE audit_log (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type     actor_type NOT NULL,
    actor_id       BIGINT REFERENCES users(id),    -- NULL for system or AI
    event_type     TEXT NOT NULL,                  -- e.g. 'recommendation.approved'
    entity_type    TEXT NOT NULL,                  -- e.g. 'incident', 'action'
    entity_id      BIGINT,
    details        JSONB
);

CREATE INDEX idx_audit_entity ON audit_log (entity_type, entity_id);
CREATE INDEX idx_audit_ts     ON audit_log (ts DESC);

-- Block edits and deletes so the trail cannot be changed afterwards.
CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
