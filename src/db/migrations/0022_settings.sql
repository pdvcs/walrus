-- Operator-managed application settings: free-form name/text pairs (e.g. registry_public_key
-- holding a PEM public key). The value is TEXT, not a typed column, because a setting's meaning
-- belongs to whatever reads it; this table only stores and audits it.
-- Names are constrained here as well as in the API so a direct write cannot create a name the
-- admin UI could not address. The 64 KiB value cap keeps a mistaken paste from bloating a table
-- that is read on hot paths.

CREATE TABLE IF NOT EXISTS settings (
  name        TEXT PRIMARY KEY
              CHECK (name ~ '^[a-z][a-z0-9_]*$' AND length(name) <= 64),
  value       TEXT NOT NULL
              CHECK (length(btrim(value)) > 0 AND length(value) <= 65536),
  updated_by  TEXT NOT NULL CHECK (length(btrim(updated_by)) > 0),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
