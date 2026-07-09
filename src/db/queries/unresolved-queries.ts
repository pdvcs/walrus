import { Pool } from "pg";
import { normalizeName } from "../../vuln/normalize.js";

export interface UnresolvedTopCandidate {
  slug: string;
  score: number;
}

/**
 * Record a query we couldn't resolve, to feed alias curation. Best-effort — a
 * logging failure must never fail the caller's request (plan §3, WAL-10).
 */
export async function logUnresolvedQuery(
  pool: Pool,
  queryText: string,
  topCandidate?: UnresolvedTopCandidate,
): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO unresolved_queries (query_text, normalized, top_candidate_slug, top_candidate_score)
       VALUES ($1, $2, $3, $4)`,
      [
        queryText,
        normalizeName(queryText),
        topCandidate?.slug ?? null,
        topCandidate?.score ?? null,
      ],
    );
  } catch {
    // swallow — logging is best-effort
  }
}
