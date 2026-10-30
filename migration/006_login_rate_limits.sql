-- Store rolling login-attempt counters keyed by hashed username and client IP.

CREATE TABLE IF NOT EXISTS login_rate_limits (
    bucket_key        TEXT PRIMARY KEY,
    attempts          INTEGER NOT NULL CHECK (attempts > 0),
    window_started_at TIMESTAMPTZ NOT NULL
);

-- Keep old login buckets easy to clean up.
CREATE INDEX IF NOT EXISTS idx_login_rate_limits_window
    ON login_rate_limits (window_started_at);
