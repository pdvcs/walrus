import { describe, expect, it, vi } from "vitest";
import type { Pool } from "pg";
import { incrementalNvdSync } from "../../../src/vuln/sync/nvd-sync.js";
import type { NvdClient, NvdCveItem, NvdCvePage } from "../../../src/vuln/sync/nvd-client.js";

/**
 * WAL-95. The incremental sync used to call `cvesModifiedSince`, which concatenates every page
 * of a lastMod window into one array. On a fresh database there is no cursor, so the first sync
 * of any new environment requests the full 119-day window — and on the first real GCP deployment
 * that aborted the service with `FATAL ERROR: Reached heap limit`, signal 6, about two minutes in.
 *
 * These tests pin the shape of the fix rather than a byte count: ingestion must happen per page,
 * so peak memory is flat in the window's size. A revert to accumulate-then-ingest collapses the
 * transaction count to one and fails here.
 */

const PAGE_SIZE = 3;
const PAGES = 5;

function page(startIndex: number, total: number): NvdCvePage {
  return {
    resultsPerPage: PAGE_SIZE,
    startIndex,
    totalResults: total,
    vulnerabilities: Array.from({ length: PAGE_SIZE }, (_, i) => ({
      cve: { id: `CVE-2026-${String(startIndex + i).padStart(4, "0")}` },
    })) as NvdCveItem[],
  };
}

/** Records the transaction boundaries and per-transaction write volume that ingestion produces. */
function fakePool() {
  const transactions: number[] = [];
  let open: number | null = null;

  const record = (sql: string) => {
    if (sql.startsWith("BEGIN")) open = 0;
    else if (sql.startsWith("COMMIT")) {
      transactions.push(open ?? 0);
      open = null;
    } else if (open !== null && sql.includes("INSERT INTO cves")) open++;
  };

  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    record(sql);
    // Everything in the window counts as already-known, so every item is relevant and reaches
    // ingestion — otherwise the filter would empty each page and prove nothing.
    if (sql.includes("SELECT id FROM cves WHERE id = ANY")) {
      return { rows: ((params?.[0] as string[]) ?? []).map((id) => ({ id })), rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });

  const pool = {
    query,
    connect: async () => ({ query, release: () => {} }),
  } as unknown as Pool;

  return { pool, transactions, query };
}

function fakeNvd(pageCount: number) {
  const total = pageCount * PAGE_SIZE;
  const cvesModifiedSince = vi.fn();
  return {
    cvesModifiedSince,
    async *cvePages(): AsyncGenerator<NvdCvePage> {
      for (let i = 0; i < pageCount; i++) yield page(i * PAGE_SIZE, total);
    },
  } as unknown as NvdClient & { cvesModifiedSince: ReturnType<typeof vi.fn> };
}

describe("incremental NVD sync streams pages (WAL-95)", () => {
  it("ingests once per page instead of once for the whole window", async () => {
    const { pool, transactions } = fakePool();
    const nvd = fakeNvd(PAGES);

    await incrementalNvdSync(pool, nvd, { now: new Date("2026-08-30T12:00:00Z") });

    // One transaction per page — the property that bounds peak memory.
    expect(transactions).toHaveLength(PAGES);
    // And each one carries only that page's rows, never the accumulated window.
    for (const writes of transactions) expect(writes).toBe(PAGE_SIZE);
  });

  it("never calls the accumulating cvesModifiedSince path", async () => {
    const { pool } = fakePool();
    const nvd = fakeNvd(PAGES);

    await incrementalNvdSync(pool, nvd, { now: new Date("2026-08-30T12:00:00Z") });

    expect(nvd.cvesModifiedSince).not.toHaveBeenCalled();
  });

  it("still ingests every CVE in the window, and counts them once", async () => {
    const { pool, transactions } = fakePool();
    const counts = await incrementalNvdSync(pool, fakeNvd(PAGES), {
      now: new Date("2026-08-30T12:00:00Z"),
    });

    expect(counts.cves).toBe(PAGES * PAGE_SIZE);
    expect(transactions.reduce((a, b) => a + b, 0)).toBe(PAGES * PAGE_SIZE);
  });

  it("advances the cursor only after the last page", async () => {
    const { pool, query } = fakePool();
    await incrementalNvdSync(pool, fakeNvd(PAGES), { now: new Date("2026-08-30T12:00:00Z") });

    const calls = query.mock.calls.map((c) => String(c[0]));
    const lastIngest = calls.lastIndexOf("COMMIT");
    const cursorWrite = calls.findIndex((sql) => sql.includes("INSERT INTO vuln_sync_state"));
    expect(cursorWrite).toBeGreaterThan(lastIngest);
  });
});
