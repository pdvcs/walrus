CREATE TABLE vuln_backfill_jobs (
    id              BIGSERIAL PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    since_date      DATE,
    cpe_pairs_total INTEGER NOT NULL DEFAULT 0,
    cpe_pairs_done  INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    execution_name  TEXT,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vuln_backfill_jobs_created ON vuln_backfill_jobs(created_at DESC);
CREATE UNIQUE INDEX idx_vuln_backfill_one_active
    ON vuln_backfill_jobs ((1)) WHERE status IN ('queued', 'running');
