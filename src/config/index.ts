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
  // How many transformed artifacts may be in flight at once, independent of
  // DOWNLOAD_CONCURRENCY (WAL-61 AC2). A download is IO-bound and eight of those on the sync
  // job have always been fine; a transform is CPU-bound — it holds live bzip2 and deflate
  // state per artifact and costs ~10-30s of core time for a ~125 MB output. The number is
  // sized for the sync job's 2 pinned vCPUs (WAL-67): two transforms saturate them without
  // starving the IO-bound downloads sharing the container, and a third only adds contention
  // that slows every artifact in flight. Do not raise DOWNLOAD_CONCURRENCY to compensate;
  // the two limits govern different resources.
  TRANSFORM_CONCURRENCY: z.coerce.number().int().min(1).default(2),
  // Resumable-upload chunk size for GCS. Setting it *at all* is what turns a single
  // unresumable PUT into a resumable multi-chunk upload: @google-cloud/storage 7.22.0 gates
  // its retry buffer on `multiChunkMode = !!chunkSize` (resumable-upload.js:504, re-verified
  // unchanged from 7.21.0 at the 7.22.0 bump). The price is
  // one buffer of this size per concurrent upload, so resident cost is
  // GCS_UPLOAD_CHUNK_BYTES x DOWNLOAD_CONCURRENCY.
  //
  // The default is deliberately the one that is safe *unpinned*: the API service can also run
  // an on-demand sync and declares no memory limit, so 8 MiB x 8 = 64 MiB fits the Cloud Run
  // 512Mi default. The sync job overrides it upward in Terraform, where the 2Gi it pins pays
  // for larger chunks. GCS requires a multiple of 256 KiB.
  GCS_UPLOAD_CHUNK_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .refine((n) => n % (256 * 1024) === 0, {
      message: "GCS_UPLOAD_CHUNK_BYTES must be a multiple of 256 KiB",
    })
    .default(8 * 1024 * 1024),
  // Whole-transfer attempts for one artifact. Two, not three: the GCS half of the transfer
  // retries its own chunks now, so an outer restart only re-covers the upstream fetch, and at
  // 1.6 GB an attempt is expensive enough that a third is worse than waiting for the next
  // scheduled sync — the same reasoning as the sync job's `max_retries = 0`.
  DOWNLOAD_MAX_ATTEMPTS: z.coerce.number().int().min(1).default(2),
  DEFAULT_RETENTION: z.coerce.number().default(3),
  // Above this size a download must be ranged, and an unranged GET is refused rather than
  // served (WAL-66). The number is arithmetic, not taste: Cloud Run caps a request at 3600s
  // and that ceiling is not negotiable, so a client sustaining 2 Mbps completes about 900 MB
  // before the request is killed with no partial result to resume from. 1 GB is the first
  // round number past that. It leaves every artifact walrus serves today — VS Code, and
  // gitwindows at ~125 MB — in the lane where a plain GET still works, and catches only the
  // IntelliJ-sized ones where "degrade gracefully" would mean an hour of doomed transfer.
  RANGE_REQUIRED_BYTES: z.coerce.number().int().positive().default(1_000_000_000),
  // Advertised to a client that has to chunk. The server is indifferent to chunk size and
  // must stay so; this is a hint in the refusal body, never a constraint on the request.
  SUGGESTED_CHUNK_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(32 * 1024 * 1024),
  DISCOVERY_HTTP_TIMEOUT_MS: z.coerce.number().default(15000),
  DISCOVERY_HTTP_MAX_RETRIES: z.coerce.number().default(2),
  DISCOVERY_HTTP_RETRY_BASE_DELAY_MS: z.coerce.number().default(300),
  VULN_HTTP_TIMEOUT_MS: z.coerce.number().positive().default(30000),
  // Optional upstream credential for the NVD API 2.0 (raises the rate limit from
  // 5 to 50 req/30s). Unrelated to walrus authn/authz. Lives in .env.secrets.
  NVD_API_KEY: z.string().optional(),
  // Autonomous per-package CVE backfill (WAL-37, ADR-003). On by default: a package added
  // without it is served with CVE history that was never ingested. Set "false" to disable
  // the autostart sweep only — scheduled NVD/KEV/OSV/CVSS ingestion is unaffected.
  // Not z.coerce.boolean(): Boolean("false") is true, which would make the off switch a no-op.
  VULN_AUTO_BACKFILL: z
    .enum(["true", "false"])
    .default("true")
    .transform((v) => v === "true"),
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
