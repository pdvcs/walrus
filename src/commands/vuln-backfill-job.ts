import { Pool } from "pg";
import { config } from "../config/index.js";
import { runMigrations } from "../db/client.js";
import { loadAllPackages } from "../services/package-registry.js";
import { reconcileAllPackageVulns } from "../services/vuln-config.js";
import { runVulnBackfillJob } from "../services/vuln-backfill.js";

async function main(): Promise<void> {
  const index = process.argv.indexOf("--job-id");
  const jobId = index >= 0 ? process.argv[index + 1] : undefined;
  if (!jobId) throw new Error("--job-id is required");
  const pool = new Pool({ connectionString: config.DATABASE_URL });
  try {
    await runMigrations();
    await reconcileAllPackageVulns(
      pool,
      loadAllPackages().configs.map((entry) => entry.config),
    );
    await runVulnBackfillJob(pool, jobId);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
