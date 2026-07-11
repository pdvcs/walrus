import { z } from "zod";

const configSchema = z.object({
  PORT: z.coerce.number().default(8080),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default("info"),
  DATABASE_URL: z.string().optional(),
  GCS_BUCKET: z.string().optional(),
  GCP_PROJECT: z.string().optional(),
  GCP_REGION: z.string().default("us-central1"),
  VULN_BACKFILL_JOB: z.string().optional(),
  STORAGE_BACKEND: z.enum(["gcs", "local"]).default("local"),
  LOCAL_STORAGE_PATH: z.string().default("./data/artifacts"),
  SYNC_CONCURRENCY: z.coerce.number().default(4),
  DOWNLOAD_CONCURRENCY: z.coerce.number().default(2),
  DEFAULT_RETENTION: z.coerce.number().default(3),
  DISCOVERY_HTTP_TIMEOUT_MS: z.coerce.number().default(15000),
  DISCOVERY_HTTP_MAX_RETRIES: z.coerce.number().default(2),
  DISCOVERY_HTTP_RETRY_BASE_DELAY_MS: z.coerce.number().default(300),
  VULN_HTTP_TIMEOUT_MS: z.coerce.number().positive().default(30000),
  // Optional upstream credential for the NVD API 2.0 (raises the rate limit from
  // 5 to 50 req/30s). Unrelated to walrus authn/authz. Lives in .env.secrets.
  NVD_API_KEY: z.string().optional(),
});

export type AppConfig = z.infer<typeof configSchema>;

function loadConfig(): AppConfig {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    console.error("Invalid configuration:", result.error.format());
    process.exit(1);
  }
  return result.data;
}

export const config = loadConfig();
