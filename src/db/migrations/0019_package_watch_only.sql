-- Watch-only packages (WAL-54): explicit marker for `watchlist/*.toml` rows.
--
-- A watch-only package is vulnerability-tracked but never discovered, downloaded or served.
-- Its row is kept `enabled = false` so every serving route already excludes it, but
-- `enabled = false` alone cannot identify it: an operator-disabled served package and (since
-- WAL-53) a tombstone look the same. Tombstone revival in particular used to set
-- enabled = true unconditionally, which would have promoted a watch row into the serving
-- routes on the second boot.
--
-- Reconcile owns this column: it is rewritten from disk (watchlist/ vs packages/) on every
-- boot, so moving a TOML between the two directories flips the marker. DEFAULT false keeps
-- every existing row a served package.

ALTER TABLE packages ADD COLUMN IF NOT EXISTS watch_only BOOLEAN NOT NULL DEFAULT false;
