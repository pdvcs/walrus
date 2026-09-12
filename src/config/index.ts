import { z } from "zod";
import { isValidBasePath } from "../common/base-path.js";

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
  // an on-demand sync, so 8 MiB x 8 = 64 MiB fits the Cloud Run
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
  // NVD gets its own, far longer budget. `AbortSignal.timeout` bounds the whole exchange
  // including the body read, and an NVD lastMod page runs ~14 KB per CVE typically and ~43 KB
  // at the worst measured -- so a page is megabytes, and 30s demanded ~350 KB/s sustained.
  // Three 14:20Z ticks lost that race (7, 9 and 10 Sep 2026): every attempt aborted mid-body
  // while TTFB stayed under a second, so the handshake was never the problem.
  //
  // 120s is sized against Cloud Scheduler's 1800s attempt deadline, which is the binding limit
  // (Cloud Run allows 3600s). The client makes at most 6 attempts per page, so a page that
  // fails every one of them costs 6 x 120s plus ~69s of backoff -- ~790s, leaving room for the
  // rest of the walk. Raising this without redoing that arithmetic is how a retry budget starts
  // outliving the deadline that contains it.
  //
  // Deliberately NOT folded into VULN_HTTP_TIMEOUT_MS above: KEV is one modest file and OSV is
  // a per-package loop with no retries, so a longer ceiling buys them nothing and multiplies
  // the cost of a hang across every package in the run.
  VULN_NVD_HTTP_TIMEOUT_MS: z.coerce.number().positive().default(120000),
  // Rows per NVD page request on the steady-state incremental walk. Not 2000 (the API maximum)
  // because rows are a poor proxy for bytes, and the two NVD workloads sit at opposite ends of
  // that: a *recent* lastMod window is CVEs NVD is actively re-enriching, measured at ~14.5 KB
  // each and ~43 KB at the worst. A 2-hourly window holds only a few hundred of them, so at
  // 2000 rows the whole window arrives as one 10-13 MB body on a single deadline -- which is
  // precisely what failed on 7, 9 and 10 Sep 2026. 100 rows holds a page near 1.5 MB and costs
  // ~10 requests for a 900-CVE window, nothing against the 45/30s keyed rate limit.
  //
  // Do NOT reuse this for the bootstrap; see VULN_NVD_BOOTSTRAP_PAGE_SIZE below for why.
  VULN_NVD_PAGE_SIZE: z.coerce.number().int().positive().default(100),
  // Rows per page for the fresh-DB bootstrap only -- the 119-day lookback taken when there is
  // no cursor yet. The inverse trade of the knob above, because the workload inverts: that
  // window is ~372,000 CVEs averaging ~2.1 KB (the bulk of NVD is old, sparse records, not the
  // fat recently-re-enriched ones), so bytes are cheap and request COUNT is the binding cost.
  //
  // At 2000 rows that is 187 requests, a ~125s rate-limit floor and ~4.1 MB pages -- the real
  // bootstraps on 30 Aug 2026 took 437s and 493s end to end, against Cloud Scheduler's 1800s
  // deadline. At 100 rows it would be 3,723 requests and a ~2,482s floor: over the deadline
  // before a single byte of payload, and permanently so, since the cursor is claimed only after
  // the whole window completes (see incrementalNvdSync) -- every retry would restart from zero.
  VULN_NVD_BOOTSTRAP_PAGE_SIZE: z.coerce.number().int().positive().default(2000),
  // Connections this process may hold. Explicit because it is half of a budget: every workload
  // multiplies it, and Cloud SQL's max_connections is the divisor. pg's own default is 10, which
  // on a db-f1-micro (max_connections ~25) means three instances exhaust the database and a
  // scale-up becomes the outage. Terraform sets this per workload -- see cloudrun.tf, which does
  // the arithmetic. Raising it without re-reading that comment is the way to starve the fleet.
  DB_POOL_MAX: z.coerce.number().int().positive().default(5),
  // Optional upstream credentials. Each raises a rate limit and does nothing else: NVD from 5 to
  // 50 req/30s, GitHub from 60 to 5,000 req/hour. Unrelated to walrus authn/authz; both live in
  // Secret Manager. walrus runs without either, which is what makes local work and CI possible
  // with nothing provisioned.
  //
  // `.transform(v => v || undefined)` because Secret Manager can mount a version holding an
  // empty string: "set to empty" has to mean the same as "not set", and settling that here beats
  // trusting every call site to use a truthy check. Not `.min(1)` -- that would fail the parse
  // and take the process down over a credential whose whole point is being optional.
  NVD_API_KEY: z
    .string()
    .optional()
    .transform((v) => v || undefined),
  // Read through the schema rather than `process.env` at import time, which is where this lived
  // from the first commit -- before this schema existed. That capture was never a decision, and
  // it left the value untestable and gave one fact two sources: a module-load const for the
  // request header, and a call-time read for the startup warning.
  GITHUB_TOKEN: z
    .string()
    .optional()
    .transform((v) => v || undefined),
  // Autonomous per-package CVE backfill (WAL-37, ADR-003). On by default: a package added
  // without it is served with CVE history that was never ingested. Set "false" to disable
  // the autostart sweep only — scheduled NVD/KEV/OSV/CVSS ingestion is unaffected.
  // Not z.coerce.boolean(): Boolean("false") is true, which would make the off switch a no-op.
  VULN_AUTO_BACKFILL: z
    .enum(["true", "false"])
    .default("true")
    .transform((v) => v === "true"),
  WALRUS_AUTHN_PROVIDER: z.string().default("password"),
  WALRUS_ADMIN_PASSWORD: z.string().optional(),
  WALRUS_ADMINS_FILE: z.string().default("config/admins.toml"),
  WALRUS_ADMIN_MATCH: z.enum(["fold", "exact"]).default("fold"),
  WALRUS_SESSION_SECRET: z.string().optional(),
  WALRUS_SESSION_SECRET_PREVIOUS: z.string().optional(),
  WALRUS_SESSION_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(2 * 60 * 60),
  WALRUS_SESSION_MAX_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(8 * 60 * 60),
  WALRUS_SESSION_EPOCH: z.coerce.number().int().nonnegative().default(0),
  WALRUS_INTERNAL_AUDIENCE: z.string().optional(),
  WALRUS_INTERNAL_SERVICE_ACCOUNT: z.string().optional(),
  // Enterprise egress rewriting (WAL-113). Path to a TOML rule file, same shape as
  // WALRUS_ADMINS_FILE: defaults to a file under config/ that ships empty, so out of the box
  // this changes nothing. File contents are validated separately, at boot, by
  // loadEgressConfig() in src/common/egress-rules.ts — this only names where to find it.
  WALRUS_EGRESS_RULES: z.string().default("config/egress-rules.toml"),
  // direct: today's behaviour (configured rules, if any, still apply to a matching URL).
  // rules: an unmatched URL is logged at warn and attempted anyway.
  // strict: an unmatched URL is refused rather than attempted direct.
  WALRUS_EGRESS_MODE: z.enum(["direct", "rules", "strict"]).default("direct"),
  // Adopter deployment: serve the whole app under a path prefix of the adopter's own domain
  // instead of only at root (e.g. /foo instead of /), so a team fronting walrus with their own
  // path-routed gateway doesn't need a dedicated sub-domain. Default "" is today's behaviour —
  // mounted at root, nothing prefixed. Priority is a single path segment (/foo); a multi-segment
  // prefix (/corp/walrus) is accepted for free by the same pattern, not a design goal on its own.
  // Validated at boot, same fail-fast contract as WALRUS_EGRESS_RULES: no leading-slash means a
  // typo like "foo" would silently produce paths such as "foobar" rather than "/foo/bar".
  WALRUS_BASE_PATH: z
    .string()
    .default("")
    .refine(isValidBasePath, {
      message:
        "WALRUS_BASE_PATH must be empty, or a path made of /-separated segments of letters, " +
        "digits, '-' and '_' (e.g. /foo or /corp/walrus) with no trailing slash",
    }),
  // Adopter branding: the product name on the public landing page. Defaults to the project name,
  // but a deployer presenting walrus under their own internal name overrides just this. Trimmed
  // and required non-empty, so `WALRUS_BRANDING=" "` is a startup failure rather than a blank
  // heading; everything else is free text and is HTML-escaped at render time.
  WALRUS_BRANDING: z.string().trim().min(1).default("Walrus"),
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
