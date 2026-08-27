/**
 * NVD ingestion (ported from vulncheck `worker/nvdSync.ts`), keyed to walrus
 * packages. For each CVE: upsert `cves`, parse `configurations[].nodes[].cpeMatch[]`
 * via the CPE parser, join vendor/product against `package_cpes`, and rebuild
 * that CVE's `'nvd'` `cve_affects` rows. See plan §5, WAL-7.
 */
import { Pool } from "pg";
import { NvdClient, type NvdCveItem } from "./nvd-client.js";
import { parseCpe, buildMatchString } from "../cpe.js";
import {
  upsertCveFull,
  deleteAffectsForSource,
  insertAffects,
  knownCveIds,
  AffectsInsert,
} from "../../db/queries/cves.js";
import { loadCpeLookup, listDistinctCpePairs } from "../../db/queries/package-aliases.js";
import { getSyncCursor, setSyncState } from "../../db/queries/vuln-sync-state.js";

export interface IngestCounts {
  cves: number;
  affects: number;
  skippedCpes: number;
}

/** Which CVSS version produced a row's `severity`. */
export type SeveritySource = "nvd-cvss-v3" | "nvd-cvss-v4" | "nvd-cvss-v2";

export interface ExtractedCvss {
  /** CVSS v3 base score; null when the CVE is only scored under v4 and/or v2. */
  score: number | null;
  vector: string | null;
  /** CVSS v4 base score, populated independently of v3/v2. */
  v4Score: number | null;
  v4Vector: string | null;
  /** CVSS v2 base score, populated independently of v3/v4. */
  v2Score: number | null;
  v2Vector: string | null;
  severity: string | null;
  severitySource: SeveritySource | null;
}

/** Read one metric entry, preferring the Primary provider. */
function readMetric(
  metrics: Record<string, Array<Record<string, unknown>>>,
  key: string,
): { score: number | null; vector: string | null; severity: string | null } | null {
  const list = metrics[key];
  if (!list?.length) return null;
  const primary = list.find((m) => m["type"] === "Primary") ?? list[0];
  const data = primary["cvssData"] as
    | { baseScore?: number; vectorString?: string; baseSeverity?: string }
    | undefined;
  return {
    score: data?.baseScore ?? null,
    vector: data?.vectorString ?? null,
    // v3 carries baseSeverity inside cvssData; v2 carries it on the metric
    // object one level up. Tolerate both.
    severity: data?.baseSeverity ?? (primary["baseSeverity"] as string | undefined) ?? null,
  };
}

/**
 * Pick the best CVSS metrics, tolerating NVD's variants.
 *
 * Severity precedence is v3 → v4 → v2. v3 stays primary so already-scored rows
 * do not churn; v4 sits above v2 because it shares v3's severity bands
 * (CRITICAL 9.0+), where v2 has no CRITICAL band at all (v2 HIGH spans
 * 7.0-10.0) — so a v2-derived severity is not comparable to a v3/v4 one and
 * `severitySource` records which produced it. Each version's score/vector is
 * stored in its own fields regardless of which wins the severity, so a CVE
 * scored under several keeps them all.
 */
export function extractCvss(item: NvdCveItem): ExtractedCvss {
  const metrics = (item.cve.metrics ?? {}) as Record<string, Array<Record<string, unknown>>>;
  const v3 = readMetric(metrics, "cvssMetricV31") ?? readMetric(metrics, "cvssMetricV30");
  const v4 = readMetric(metrics, "cvssMetricV40");
  const v2 = readMetric(metrics, "cvssMetricV2");

  return {
    score: v3?.score ?? null,
    vector: v3?.vector ?? null,
    v4Score: v4?.score ?? null,
    v4Vector: v4?.vector ?? null,
    v2Score: v2?.score ?? null,
    v2Vector: v2?.vector ?? null,
    severity: v3?.severity ?? v4?.severity ?? v2?.severity ?? null,
    severitySource: v3?.severity
      ? "nvd-cvss-v3"
      : v4?.severity
        ? "nvd-cvss-v4"
        : v2?.severity
          ? "nvd-cvss-v2"
          : null,
  };
}

/** Build cve_affects rows (source 'nvd') for the packages we track. */
export function extractAffects(
  item: NvdCveItem,
  lookup: Map<string, string[]>,
): { rows: AffectsInsert[]; skippedCpes: number } {
  const rows: AffectsInsert[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  for (const conf of item.cve.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const parsed = parseCpe(m.criteria);
        if (!parsed || parsed.part !== "a") continue;
        const packageNames = lookup.get(`${parsed.vendor}:${parsed.product}`);
        if (!packageNames) {
          skipped++;
          continue;
        }

        // CPE 2.3 gives the version component two logical values, and they are not synonyms:
        // `*` is ANY (the entry applies to every version) and `-` is NA (the version attribute
        // does not apply to this entry at all). Both yield no exact version to match on, but
        // only ANY may be read as "all versions" — see WAL-69 and `findBlockingCve`.
        const versionNa = parsed.version === "-";
        const exactVersion = parsed.version !== "*" && !versionNa ? parsed.version : null;
        const versionStart = m.versionStartIncluding ?? m.versionStartExcluding ?? null;
        const versionEnd = m.versionEndIncluding ?? m.versionEndExcluding ?? null;
        // Same criteria can appear in multiple nodes with different ranges, so
        // the dedupe key (and stored raw_cpe) includes the range.
        const rangeTag = [
          m.versionStartIncluding
            ? `>=${m.versionStartIncluding}`
            : m.versionStartExcluding
              ? `>${m.versionStartExcluding}`
              : "",
          m.versionEndIncluding
            ? `<=${m.versionEndIncluding}`
            : m.versionEndExcluding
              ? `<${m.versionEndExcluding}`
              : "",
        ]
          .filter(Boolean)
          .join(",");
        const rawCpe = rangeTag ? `${m.criteria}|${rangeTag}` : m.criteria;

        for (const packageName of packageNames) {
          const key = `${packageName}|${rawCpe}`;
          if (seen.has(key)) continue;
          seen.add(key);
          rows.push({
            cve_id: item.cve.id,
            package_name: packageName,
            version_start: versionStart,
            version_start_excl: Boolean(m.versionStartExcluding),
            version_end: versionEnd,
            version_end_excl: Boolean(m.versionEndExcluding),
            exact_version: exactVersion,
            fixed_in: m.versionEndExcluding ?? null,
            source: "nvd",
            raw_cpe: rawCpe,
            version_na: versionNa,
          });
        }
      }
    }
  }
  return { rows, skippedCpes: skipped };
}

/** Upsert a batch of NVD CVE items and rebuild their 'nvd' affects rows, transactionally. */
export async function ingestCveItems(
  pool: Pool,
  items: NvdCveItem[],
  lookup?: Map<string, string[]>,
): Promise<IngestCounts> {
  const cpeLookup = lookup ?? (await loadCpeLookup(pool));
  const counts: IngestCounts = { cves: 0, affects: 0, skippedCpes: 0 };
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    for (const item of items) {
      const cve = item.cve;
      const desc = cve.descriptions?.find((d) => d.lang === "en")?.value ?? null;
      const { score, vector, v4Score, v4Vector, v2Score, v2Vector, severity, severitySource } =
        extractCvss(item);

      await upsertCveFull(client, {
        id: cve.id,
        published_at: cve.published ?? null,
        modified_at: cve.lastModified ?? null,
        cvss_v3_score: score,
        cvss_v3_vector: vector,
        cvss_v4_score: v4Score,
        cvss_v4_vector: v4Vector,
        cvss_v2_score: v2Score,
        cvss_v2_vector: v2Vector,
        severity,
        severity_source: severitySource,
        description: desc,
        raw: item,
      });
      counts.cves++;

      // Rebuild NVD-sourced affects rows for this CVE (modified CVEs may have
      // changed configurations; OSV rows are left untouched).
      await deleteAffectsForSource(client, cve.id, "nvd");
      const { rows, skippedCpes } = extractAffects(item, cpeLookup);
      counts.skippedCpes += skippedCpes;
      for (const r of rows) {
        await insertAffects(client, r);
        counts.affects++;
      }
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
  return counts;
}

type Logger = (msg: string) => void;
const DAY_MS = 24 * 3600 * 1000;
/** The API caps lastMod windows at 120 days; stay under with room for margins. */
export const MAX_NVD_DATE_WINDOW_MS = 119 * DAY_MS;
/**
 * Safety margin subtracted from each incremental window's start.
 *
 * NVD's lastModStartDate index lags real time: a CVE modified just before a window's
 * end can become queryable only after the query executed, so with abutting windows it
 * falls permanently between them — silently, and (per the gate's data flow) biased
 * toward under-blocking. Starting each window a little earlier re-fetches the boundary
 * zone every run; per-CVE ingestion is idempotent (`upsertCveFull` + affects rebuild),
 * so the overlap costs a handful of re-walked records and closes the gap.
 */
export const NVD_LASTMOD_LAG_MARGIN_MS = 2 * 3600 * 1000;

export interface PublicationWindow extends Record<string, string> {
  pubStartDate: string;
  pubEndDate: string;
}

/** Build adjacent inclusive NVD publication windows (the API caps spans at 120 days). */
export function buildPublicationWindows(since: string, now = new Date()): PublicationWindow[] {
  const start = new Date(`${since}T00:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(since) || Number.isNaN(start.getTime())) {
    throw new Error(`Invalid --since date (expected YYYY-MM-DD): ${since}`);
  }
  if (start.toISOString().slice(0, 10) !== since) {
    throw new Error(`Invalid --since date: ${since}`);
  }
  if (Number.isNaN(now.getTime())) throw new Error("Invalid backfill end time");
  if (start.getTime() > now.getTime()) {
    throw new Error(`--since date must not be in the future: ${since}`);
  }

  const windows: PublicationWindow[] = [];
  let windowStart = start;
  while (windowStart.getTime() <= now.getTime()) {
    const windowEnd = new Date(
      Math.min(now.getTime(), windowStart.getTime() + MAX_NVD_DATE_WINDOW_MS),
    );
    windows.push({
      pubStartDate: windowStart.toISOString(),
      pubEndDate: windowEnd.toISOString(),
    });
    windowStart = new Date(windowEnd.getTime() + 1);
  }
  return windows;
}

/**
 * Per-pair backfill using virtualMatchString (keeps the DB scoped to tracked packages).
 *
 * `packageName` narrows the walk to one package's CPE pairs. Two deliberate
 * consequences:
 *
 *  - The CPE lookup stays UNSCOPED. A pair can be shared (oracle:openjdk is
 *    tracked by both openjdk and azuljdk), and a CVE on that pair genuinely
 *    affects every package tracking it — so ingestion still attributes rows to
 *    all of them. A targeted backfill is narrower in what it *fetches*, not in
 *    what it records.
 *  - The nvd-cve cursor is NOT advanced. That cursor means "everything modified
 *    up to T has been ingested for every tracked package"; a one-package walk
 *    has not established that, and advancing it would make the next incremental
 *    sync skip the window for all other packages.
 */
export async function backfillNvd(
  pool: Pool,
  nvd: NvdClient,
  opts: {
    since?: string;
    log?: Logger;
    now?: Date;
    packageName?: string;
    onPairComplete?: (done: number) => Promise<void>;
  } = {},
): Promise<IngestCounts> {
  const log = opts.log ?? (() => {});
  const pairs = await listDistinctCpePairs(pool, opts.packageName);
  const lookup = await loadCpeLookup(pool);
  const totals: IngestCounts = { cves: 0, affects: 0, skippedCpes: 0 };
  const now = opts.now ?? new Date();
  const windows: Array<Record<string, string>> = opts.since
    ? buildPublicationWindows(opts.since, now)
    : [{}];

  try {
    for (const [pairIndex, pair] of pairs.entries()) {
      const matchString = buildMatchString(pair.cpe_vendor, pair.cpe_product);
      log(`backfill: ${pair.cpe_vendor}:${pair.cpe_product} (${matchString})`);
      for (const window of windows) {
        const items = await nvd.cvesForCpe(matchString, window);
        const counts = await ingestCveItems(pool, items, lookup);
        log(
          `  ${items.length} CVEs → ${counts.affects} affects rows (${counts.skippedCpes} untracked CPEs skipped)`,
        );
        totals.cves += counts.cves;
        totals.affects += counts.affects;
        totals.skippedCpes += counts.skippedCpes;
      }
      await opts.onPairComplete?.(pairIndex + 1);
    }
    // Only a full backfill can claim the cursor — see the doc comment above.
    if (!opts.packageName) await setSyncState(pool, "nvd-cve", now.toISOString(), true);
  } catch (err) {
    if (!opts.packageName) await setSyncState(pool, "nvd-cve", null, false);
    throw err;
  }
  return totals;
}

/**
 * Incremental sync from the vuln_sync_state cursor. On a fresh DB (no cursor)
 * bootstraps a 119-day lookback window rather than erroring, so the /internal
 * trigger works before a full backfill (which remains the way to get history).
 * The cursor advances only on success.
 *
 * The window is `[cursor - lag margin, now]` rather than abutting the previous
 * run's end: NVD's modification index lags, and an abutting window would let a
 * late-indexed CVE fall permanently between runs. See NVD_LASTMOD_LAG_MARGIN_MS.
 */
export async function incrementalNvdSync(
  pool: Pool,
  nvd: NvdClient,
  opts: { log?: Logger; now?: Date } = {},
): Promise<IngestCounts> {
  const log = opts.log ?? (() => {});
  const cursor = await getSyncCursor(pool, "nvd-cve");
  const now = opts.now ?? new Date();
  // Overlap backwards, never forwards: the fresh-DB bootstrap keeps its full lookback
  // (there is no previous window to bridge), while an existing cursor re-fetches the
  // boundary zone ahead of it. End still bounds at `now`, so everything indexed up to
  // now stays covered by this window.
  const start = new Date(
    cursor
      ? new Date(cursor).getTime() - NVD_LASTMOD_LAG_MARGIN_MS
      : now.getTime() - MAX_NVD_DATE_WINDOW_MS,
  );
  const end = new Date(Math.min(now.getTime(), start.getTime() + MAX_NVD_DATE_WINDOW_MS));

  try {
    const items = await nvd.cvesModifiedSince(start.toISOString(), end.toISOString());
    // A lastMod window returns EVERYTHING modified; keep only CVEs that touch a
    // tracked package (or that we already know about).
    const lookup = await loadCpeLookup(pool);
    const known = await knownCveIds(
      pool,
      items.map((item) => item.cve.id),
    );
    const relevantById = new Map<string, NvdCveItem>();
    for (const item of items) {
      if (known.has(item.cve.id) || extractAffects(item, lookup).rows.length > 0) {
        relevantById.set(item.cve.id, item);
      }
    }
    const relevant = [...relevantById.values()];
    const counts = await ingestCveItems(pool, relevant, lookup);
    log(
      `incremental: ${items.length} modified CVEs in window, ${relevant.length} relevant, ${counts.affects} affects rows`,
    );
    await setSyncState(pool, "nvd-cve", end.toISOString(), true);
    return counts;
  } catch (err) {
    await setSyncState(pool, "nvd-cve", null, false);
    throw err;
  }
}
