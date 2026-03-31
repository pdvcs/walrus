import path from "path";
import { Pool, types } from "pg";
import { migrate } from "postgres-migrations";
import { config } from "../config/index.js";

// BIGINT (OID 20) comes back as string by default; parse to number since file
// sizes fit comfortably within JS's safe integer range.
types.setTypeParser(20, (val) => parseInt(val, 10));

export const pool = new Pool({ connectionString: config.DATABASE_URL });

export async function runMigrations(): Promise<void> {
  const client = await pool.connect();
  try {
    await migrate({ client }, path.join(__dirname, "migrations"));
  } finally {
    client.release();
  }
}

// CLI entrypoint: tsx src/db/client.ts migrate
if (require.main === module) {
  const command = process.argv[2];
  if (command === "migrate") {
    runMigrations()
      .then(() => {
        console.log("Migrations complete");
        return pool.end();
      })
      .then(() => process.exit(0))
      .catch((err) => {
        console.error("Migration failed:", err);
        process.exit(1);
      });
  } else {
    console.error("Usage: tsx src/db/client.ts migrate");
    process.exit(1);
  }
}
