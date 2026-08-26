/**
 * CISA KEV flagging (ported from vulncheck `worker/kevSync.ts`). Downloads the
 * Known Exploited Vulnerabilities catalog and sets is_kev / kev_added_at on
 * matching cves rows; clears the flag on rows that left the catalog. Entries for
 * CVEs we don't track are skipped (they'll flag on a later run once ingested).
 */
import { Pool } from "pg";
import { flagKev, clearKevExcept, knownCveIds } from "../../db/queries/cves.js";
import { setSyncState } from "../../db/queries/vuln-sync-state.js";
import { config } from "../../config/index.js";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevCatalog {
  catalogVersion: string;
  vulnerabilities: Array<{ cveID: string; dateAdded: string }>;
}

export interface KevResult {
  flagged: number;
  cleared: number;
  skippedUnknown: number;
}

/**
 * A parsed-but-empty catalog is almost always a malformed upstream (a JSON error body,
 * a truncated document) rather than reality — CISA has never published a KEV with zero
 * entries, and silently clearing every flag on one would hide confirmed-exploited CVEs
 * from badges and counts for a week. Refuse it and let the run fail instead.
 */
function assertPlausible(catalog: KevCatalog): void {
  if (!Array.isArray(catalog.vulnerabilities) || catalog.vulnerabilities.length === 0) {
    throw new Error(
      "KEV catalog contains no vulnerabilities — refusing to apply " +
        "(likely an upstream error, not an empty catalog)",
    );
  }
}

/** Apply a KEV catalog to the cves table. */
export async function applyKev(pool: Pool, catalog: KevCatalog): Promise<KevResult> {
  assertPlausible(catalog);
  const entries = catalog.vulnerabilities.map((v) => ({ id: v.cveID, added: v.dateAdded }));
  const ids = entries.map((e) => e.id);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const known = await knownCveIds(client, ids);

    let flagged = 0;
    for (const e of entries) {
      if (!known.has(e.id)) continue;
      await flagKev(client, e.id, e.added);
      flagged++;
    }

    const cleared = await clearKevExcept(client, ids);
    await client.query("COMMIT");
    return { flagged, cleared, skippedUnknown: entries.length - flagged };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function kevSync(pool: Pool, fetchFn: typeof fetch = fetch): Promise<KevResult> {
  try {
    const res = await fetchFn(KEV_URL, {
      signal: AbortSignal.timeout(config.VULN_HTTP_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`KEV download failed: HTTP ${res.status}`);
    // Validate shape before applying: `as KevCatalog` trusts nothing after this check,
    // but an array-typed hole would otherwise flow into clearKevExcept below.
    const parsed: unknown = await res.json();
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !Array.isArray((parsed as KevCatalog).vulnerabilities)
    ) {
      throw new Error("KEV download is not a recognizable catalog (missing vulnerabilities[])");
    }
    const result = await applyKev(pool, parsed as KevCatalog);
    await setSyncState(pool, "kev", (parsed as KevCatalog).catalogVersion, true);
    return result;
  } catch (err) {
    await setSyncState(pool, "kev", null, false);
    throw err;
  }
}
