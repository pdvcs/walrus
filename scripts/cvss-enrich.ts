#!/usr/bin/env tsx
/**
 * cvss-enrich.ts — fill in CVSS/severity for CVEs that have none.
 *
 * Most such CVEs are OSV stubs. NVD holds their CVSS but files them as
 * "Deferred" with no CPE configurations, so the CPE-keyed sync paths never see
 * them; a by-id lookup does. See src/vuln/sync/cvss-enrich.ts.
 *
 * ALWAYS dry-run first. Enrichment can newly satisfy the >= 9.0 download gate,
 * which makes /download return 403 for versions that serve fine today. The dry
 * run reports exactly which versions those would be, before anything is written.
 *
 * Dev convenience only. Production has no shell, so the same capability is exposed
 * over HTTP: POST /internal/vuln-sync/cvss (or /admin/v1/...) with a JSON body of
 * {"dry_run": true, "limit": N}. Keep the two in step.
 *
 * Usage:
 *   npm run vuln:enrich -- --dry-run   # report proposals + newly-blocked versions
 *   npm run vuln:enrich                # apply
 *   npm run vuln:enrich -- --limit 20  # bound the walk (either mode)
 */
import { Pool } from "pg";
import { config } from "../src/config/index.js";
import { runMigrations } from "../src/db/client.js";
import { NvdClient } from "../src/vuln/sync/nvd-client.js";
import { enrichMissingCvss, previewGateDelta } from "../src/vuln/sync/cvss-enrich.js";
import { withVulnSyncLock } from "../src/vuln/sync/lock.js";

export function parseLimit(args: string[]): number | undefined {
  const i = args.indexOf("--limit");
  if (i < 0) return undefined;
  const value = Number(args[i + 1]);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error("--limit requires a positive integer");
  }
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const limit = parseLimit(args);
  const pool = new Pool({ connectionString: config.DATABASE_URL });
  await runMigrations();

  if (!config.NVD_API_KEY) {
    console.warn("⚠  No NVD_API_KEY set — this walks one request per CVE and will be slow.");
  }

  const nvd = new NvdClient();
  try {
    const result = await withVulnSyncLock(pool, "nvd", () =>
      enrichMissingCvss(pool, nvd, { dryRun, limit, log: (m) => console.log(m) }),
    );

    const gated = result.proposals.filter((p) => p.crosses_critical_gate);
    console.log(
      `\n${dryRun ? "Would set" : "Set"} severity on ${result.proposals.length} CVE(s); ` +
        `${gated.length} at CVSS >= 9.0.`,
    );

    if (gated.length > 0) {
      const deltas = await previewGateDelta(pool, result.proposals);
      if (deltas.length === 0) {
        console.log("No cached version changes availability as a result.");
      } else {
        const total = deltas.reduce((n, d) => n + d.newly_blocked.length, 0);
        console.log(
          `\n⚠  ${total} version(s) ${dryRun ? "would become" : "became"} download-blocked (403):`,
        );
        for (const d of deltas) {
          console.log(`   ${d.package_name}: ${d.newly_blocked.join(", ")}`);
        }
      }
    }

    if (dryRun) console.log("\nDry run — nothing was written.");
  } catch (err) {
    console.error("✗ Enrichment failed:", err instanceof Error ? err.message : err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error("Unexpected error:", err);
    process.exit(1);
  });
}
