import { defineConfig } from "vitest/config";
import { configDotenv } from "dotenv";

// Load .env for non-DB config (e.g. NVD_API_KEY), but NEVER inherit the dev
// DATABASE_URL — integration tests run against a DEDICATED test database so they
// can't read or destroy real data. Override with TEST_DATABASE_URL.
configDotenv({ path: ".env.local" });
configDotenv({ path: ".env.secrets" });

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    // Integration tests share one local Postgres and the global `cves` table;
    // run test files sequentially so cleanup in one file can't race another.
    fileParallelism: false,
    // tests/setup.ts refuses to run unless this points at a *_test database.
    setupFiles: ["./tests/setup.ts"],
    env: {
      DATABASE_URL: TEST_DATABASE_URL,
    },
  },
  resolve: {
    // Allow importing .ts files with .js extension (TypeScript ESM convention)
    extensions: [".ts", ".js"],
  },
});
