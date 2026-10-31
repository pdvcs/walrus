-- Provenance split for repackaged artifacts (WAL-58, epic WAL-56).
--
-- Until a transform runs, `artifacts.checksum` has meant both "the digest the vendor
-- published" and "the digest of the bytes we serve" — the same value, because walrus only
-- ever served upstream bytes. The transform stage (src/transform/) ends that: for a
-- repackaged artifact the served zip exists nowhere upstream and its digest is walrus's own.
--
-- checksum / file_size KEEP their meaning — they always describe the bytes we serve. The
-- download route, retention and every existing API response shape rely on that and change
-- not at all. The upstream side of the split gains its own columns:
--
--   source_checksum    digest of the bytes upstream published, verified before the transform
--                      ran (WAL-57 AC3). NULL = this artifact is not a repackaging; its
--                      checksum is already the upstream digest.
--   source_file_size   byte count of those upstream bytes. NULL on the same condition.
--   transform          versioned identity of the conversion that produced the served bytes,
--                      e.g. "tar-bz2-to-zip@1". NULL = untransformed.
--
-- Deliberately NOT added: source_url. upstream_url already holds the URL the source bytes
-- were fetched from — for a transformed artifact that is exactly the provenance URL, and a
-- second column would duplicate it and invite drift between the two. upstream_url IS the
-- source URL (WAL-58 AC5).

ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS source_checksum TEXT;
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS source_file_size BIGINT;
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS transform TEXT;
