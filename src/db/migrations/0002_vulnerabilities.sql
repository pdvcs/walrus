-- Vulnerability intelligence schema (plan §1, ADR-001). Keyed to walrus
-- packages: no separate `products` table. Reconciled from the `[vulnerabilities]`
-- TOML section at boot. Idempotent (CREATE ... IF NOT EXISTS) even though the
-- postgres-migrations runner already applies each file once.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Human-name aliases for resolution ("npp" → notepad-plus-plus). Source of truth: TOML.
CREATE TABLE IF NOT EXISTS package_aliases (
    id            SERIAL PRIMARY KEY,
    package_name  TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
    alias         TEXT NOT NULL,          -- stored normalized (lowercase, collapsed ws)
    source        TEXT NOT NULL,          -- 'config' | 'learned'
    UNIQUE (package_name, alias)
);
CREATE INDEX IF NOT EXISTS idx_pkg_alias_trgm ON package_aliases USING gin (alias gin_trgm_ops);

-- CPE vendor:product pairs per package (a package can match several,
-- e.g. openjdk → oracle:openjdk; temurin → eclipse:temurin + oracle:openjdk).
CREATE TABLE IF NOT EXISTS package_cpes (
    id            SERIAL PRIMARY KEY,
    package_name  TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
    cpe_vendor    TEXT NOT NULL,
    cpe_product   TEXT NOT NULL,
    is_primary    BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (package_name, cpe_vendor, cpe_product)
);
CREATE INDEX IF NOT EXISTS idx_pkg_cpes_pair ON package_cpes(cpe_vendor, cpe_product);

-- OSV mapping lives on packages (nullable columns; set from TOML).
ALTER TABLE packages ADD COLUMN IF NOT EXISTS osv_ecosystem TEXT;
ALTER TABLE packages ADD COLUMN IF NOT EXISTS osv_name TEXT;

CREATE TABLE IF NOT EXISTS cves (
    id             TEXT PRIMARY KEY,       -- 'CVE-2023-40031'
    published_at   TIMESTAMPTZ,
    modified_at    TIMESTAMPTZ,
    cvss_v3_score  NUMERIC(3,1),
    cvss_v3_vector TEXT,
    severity       TEXT,                   -- CRITICAL/HIGH/MEDIUM/LOW
    description    TEXT,
    is_kev         BOOLEAN NOT NULL DEFAULT false,
    kev_added_at   DATE,
    raw            JSONB NOT NULL,
    updated_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_affects (
    id                 SERIAL PRIMARY KEY,
    cve_id             TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    package_name       TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
    version_start      TEXT,
    version_start_excl BOOLEAN NOT NULL DEFAULT false,
    version_end        TEXT,
    version_end_excl   BOOLEAN NOT NULL DEFAULT true,
    exact_version      TEXT,
    fixed_in           TEXT,
    source             TEXT NOT NULL,      -- 'nvd' | 'osv'
    raw_cpe            TEXT,
    -- NULLS NOT DISTINCT: raw_cpe is null for OSV rows; keeps re-ingestion idempotent
    CONSTRAINT cve_affects_dedupe UNIQUE NULLS NOT DISTINCT (cve_id, package_name, source, raw_cpe)
);
CREATE INDEX IF NOT EXISTS idx_cve_affects_pkg ON cve_affects(package_name);
CREATE INDEX IF NOT EXISTS idx_cve_affects_cve ON cve_affects(cve_id);

-- Ingestion cursors (per-source, not per-package — deliberately separate from sync_jobs)
CREATE TABLE IF NOT EXISTS vuln_sync_state (
    source    TEXT PRIMARY KEY,            -- 'nvd-cve' | 'kev' | 'osv'
    cursor    TEXT,
    last_run  TIMESTAMPTZ,
    last_ok   BOOLEAN
);

-- Feeds alias curation: what users asked for that we couldn't resolve
CREATE TABLE IF NOT EXISTS unresolved_queries (
    id                  SERIAL PRIMARY KEY,
    query_text          TEXT NOT NULL,
    normalized          TEXT NOT NULL,
    top_candidate_slug  TEXT,
    top_candidate_score NUMERIC(5,2),
    created_at          TIMESTAMPTZ DEFAULT now()
);
