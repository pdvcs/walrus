-- Separate vulnerability feed freshness from the latest attempt outcome.
-- `last_run` remains the latest attempt for backward-compatible operational queries.

ALTER TABLE vuln_sync_state ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMPTZ;
ALTER TABLE vuln_sync_state ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMPTZ;

UPDATE vuln_sync_state
SET last_success_at = last_run
WHERE last_ok = TRUE AND last_success_at IS NULL;
