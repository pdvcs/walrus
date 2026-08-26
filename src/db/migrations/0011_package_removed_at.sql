-- Package removal lifecycle (WAL-53): explicit tombstone marker.
--
-- Deleting a TOML previously left the package fully live: OSV-synced weekly, NVD
-- ingestion still attributed to it, versions still listed — the analyst reasonably
-- assumed "file gone" meant "package gone". Reconcile now closes that gap: a DB row
-- whose TOML no longer exists is tombstoned (disabled, vuln config cleared) rather
-- than left running.
--
-- An explicit column rather than inferring from enabled=false + missing config:
-- watch-only packages (seeded enabled=false WITH vuln config) and operator-disabled
-- packages (TOML present) must not be mistaken for removals. NULL means never
-- removed; a timestamp marks a tombstone. Hard delete of the row (and its artifacts
-- via CASCADE-free FKs) stays an explicit admin action.

ALTER TABLE packages ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ;
