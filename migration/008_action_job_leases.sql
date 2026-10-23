ALTER TABLE action_jobs
    ADD COLUMN IF NOT EXISTS claim_token UUID;
