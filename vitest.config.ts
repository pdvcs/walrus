import { defineConfig } from "vitest/config";
import { configDotenv } from "dotenv";

configDotenv({ path: ".env.local" });
configDotenv({ path: ".env.secrets" });

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    env: {
      DATABASE_URL: process.env.DATABASE_URL!,
    },
  },
  resolve: {
    // Allow importing .ts files with .js extension (TypeScript ESM convention)
    extensions: [".ts", ".js"],
  },
});
