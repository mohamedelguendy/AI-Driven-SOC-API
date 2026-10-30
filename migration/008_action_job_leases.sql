-- Identify the worker currently claiming each job so stale workers cannot finish it.

ALTER TABLE action_jobs
    ADD COLUMN IF NOT EXISTS claim_token UUID;
