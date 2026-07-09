/**
 * Package resolution pipeline (ported from vulncheck `matching/resolver.ts`),
 * keyed to walrus packages. Stop at the first confident hit:
 *   1. exact name match           → confidence 1.0,  method 'slug-exact'
 *   2. exact alias match          → confidence 0.97, method 'alias-exact'
 *      (multiple exact hits ⇒ ambiguous: return all as candidates)
 *   3. pg_trgm candidates + fuzzball token_set_ratio rerank
 *      accept if top ≥ 90 and gap to #2 ≥ 5 → method 'fuzzy'
 *   4. unresolved with top-5 candidates
 *
 * Requires pg_trgm (real Postgres) — see tests/db/resolver.test.ts.
 */
import { token_set_ratio } from "fuzzball";
import { Pool } from "pg";
import { nameVariants, normalizeName } from "./normalize.js";

export interface Candidate {
  slug: string; // walrus package name
  display_name: string;
  score: number;
}

export type ResolutionMethod = "slug-exact" | "alias-exact" | "fuzzy";

export interface Resolution {
  resolved: boolean;
  slug: string | null; // walrus package name
  displayName: string | null;
  confidence: number | null;
  method: ResolutionMethod | null;
  candidates: Candidate[];
}

const UNRESOLVED: Omit<Resolution, "candidates"> = {
  resolved: false,
  slug: null,
  displayName: null,
  confidence: null,
  method: null,
};

export async function resolvePackage(pool: Pool, query: string): Promise<Resolution> {
  const normalized = normalizeName(query);
  if (!normalized) return { ...UNRESOLVED, candidates: [] };
  const variants = nameVariants(query);
  const squashed = normalized.replace(/[\s\-_.]+/g, "");

  // 1. exact name match against tracked packages (compare squashed forms too:
  //    "open jdk" → "openjdk" == squash("openjdk")). Only packages with vuln
  //    config (an alias row exists) are resolvable.
  const nameHit = await pool.query<{ name: string; display_name: string }>(
    `SELECT p.name, p.display_name FROM packages p
     WHERE (p.name = $1 OR replace(p.name, '-', '') = $2)
       AND EXISTS (SELECT 1 FROM package_aliases pa WHERE pa.package_name = p.name)`,
    [normalized, squashed],
  );
  if (nameHit.rows.length === 1) {
    const p = nameHit.rows[0];
    return {
      resolved: true,
      slug: p.name,
      displayName: p.display_name,
      confidence: 1.0,
      method: "slug-exact",
      candidates: [],
    };
  }

  // 2. exact alias match on any variant
  const aliasHit = await pool.query<{ name: string; display_name: string }>(
    `SELECT DISTINCT p.name, p.display_name
     FROM package_aliases pa JOIN packages p ON p.name = pa.package_name
     WHERE pa.alias = ANY($1)`,
    [variants],
  );
  if (aliasHit.rows.length === 1) {
    const p = aliasHit.rows[0];
    return {
      resolved: true,
      slug: p.name,
      displayName: p.display_name,
      confidence: 0.97,
      method: "alias-exact",
      candidates: [],
    };
  }
  if (aliasHit.rows.length > 1) {
    // Deliberately ambiguous alias (e.g. "jdk" → openjdk + azuljdk):
    // surface all exact hits as high-confidence candidates.
    return {
      ...UNRESOLVED,
      candidates: aliasHit.rows.map((p) => ({
        slug: p.name,
        display_name: p.display_name,
        score: 97,
      })),
    };
  }

  // 3. trigram candidate fetch + fuzzball rerank
  const trgm = await pool.query<{
    name: string;
    display_name: string;
    alias: string;
    sim: number;
  }>(
    `SELECT p.name, p.display_name, pa.alias, similarity(pa.alias, $1) AS sim
     FROM package_aliases pa JOIN packages p ON p.name = pa.package_name
     WHERE similarity(pa.alias, $1) > 0.35
     ORDER BY sim DESC LIMIT 15`,
    [normalized],
  );

  // Rerank per package: best token_set_ratio across its candidate aliases.
  const byPackage = new Map<string, { p: (typeof trgm.rows)[number]; score: number }>();
  for (const row of trgm.rows) {
    const score = token_set_ratio(normalized, row.alias);
    const existing = byPackage.get(row.name);
    if (!existing || score > existing.score) byPackage.set(row.name, { p: row, score });
  }
  const ranked = [...byPackage.values()].sort((a, b) => b.score - a.score);

  if (ranked.length > 0) {
    const top = ranked[0];
    const runnerUp = ranked[1];
    const gap = runnerUp ? top.score - runnerUp.score : Infinity;
    if (top.score >= 90 && gap >= 5) {
      return {
        resolved: true,
        slug: top.p.name,
        displayName: top.p.display_name,
        // scale 90..100 → 0.90..0.96 (stays below alias-exact's 0.97)
        confidence: Math.round((0.9 + ((top.score - 90) / 10) * 0.06) * 100) / 100,
        method: "fuzzy",
        candidates: [],
      };
    }
  }

  // 4. unresolved: top-5 candidates
  return {
    ...UNRESOLVED,
    candidates: ranked
      .slice(0, 5)
      .map(({ p, score }) => ({ slug: p.name, display_name: p.display_name, score })),
  };
}
