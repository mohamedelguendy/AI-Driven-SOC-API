-- Adds IP reputation lookups (VirusTotal / AbuseIPDB), with caching so the
-- same IP isn't re-queried on every alert.
 
CREATE TABLE IF NOT EXISTS threat_intel_lookups (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip_address  INET NOT NULL,
    provider    TEXT NOT NULL,          -- 'virustotal' or 'abuseipdb'
    status      TEXT NOT NULL,          -- 'ok', 'no_provider_configured', 'error'
    verdict     TEXT NOT NULL DEFAULT 'unknown',  -- 'clean', 'suspicious', 'malicious', 'unknown'
    details     JSONB NOT NULL DEFAULT '{}',
    queried_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
 
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel_lookups (ip_address, queried_at DESC);
