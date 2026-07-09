#!/usr/bin/env tsx
/**
 * vuln-backfill.ts — one-time NVD backfill of CVE data for all tracked packages.
 *
 * Per-package-CPE backfill via the NVD virtualMatchString API. Tolerable only
 * with an NVD_API_KEY in .env.secrets (keyless pacing is ~10x slower). Writes
 * `cves` + `cve_affects` and advances the nvd-cve cursor.
 *
 * Usage:
 *   npm run vuln:backfill                       # full history for all CPE pairs
 *   npm run vuln:backfill -- --since 2015-01-01 # limit to CVEs published since a date
 */
import { Pool } from "pg";
import { config } from "../src/config/index.js";
import { runMigrations } from "../src/db/client.js";
import { NvdClient } from "../src/vuln/sync/nvd-client.js";
import { backfillNvd } from "../src/vuln/sync/nvd-sync.js";
import { listDistinctCpePairs } from "../src/db/queries/package-aliases.js";
import { loadAllPackages } from "../src/services/package-registry.js";
import { reconcileAllPackageVulns } from "../src/services/vuln-config.js";

function parseSince(args: string[]): string | undefined {
  const i = args.indexOf("--since");
  if (i >= 0 && args[i + 1]) {
    const v = args[i + 1];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) {
      console.error(`Invalid --since date (expected YYYY-MM-DD): ${v}`);
      process.exit(1);
    }
    return v;
  }
  return undefined;
}

async function main(): Promise<void> {
  const since = parseSince(process.argv.slice(2));
  const pool = new Pool({ connectionString: config.DATABASE_URL });
  await runMigrations();

  // Reconcile package configs so CPE pairs exist even on a fresh DB (the same
  // step the app runs at boot) — makes the backfill self-sufficient.
  const configs = loadAllPackages().configs.map((c) => c.config);
  await reconcileAllPackageVulns(pool, configs);

  const pairs = await listDistinctCpePairs(pool);
  if (pairs.length === 0) {
    console.log("No CPE pairs configured — add [vulnerabilities].cpes to package TOMLs first.");
    await pool.end();
    return;
  }

  if (!config.NVD_API_KEY) {
    console.warn(
      "⚠  No NVD_API_KEY set — backfill will be rate-limited to 5 req/30s and may take a long time.",
    );
  }
  console.log(
    `Backfilling ${pairs.length} CPE pair(s)${since ? ` since ${since}` : " (full history)"}...`,
  );

  const nvd = new NvdClient();
  const started = Date.now();
  try {
    const totals = await backfillNvd(pool, nvd, { since, log: (m) => console.log(m) });
    const secs = ((Date.now() - started) / 1000).toFixed(0);
    console.log(
      `\n✓ Backfill complete in ${secs}s: ${totals.cves} CVEs, ${totals.affects} affects rows ` +
        `(${totals.skippedCpes} untracked CPEs skipped).`,
    );
  } catch (err) {
    console.error("✗ Backfill failed:", err instanceof Error ? err.message : err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
