import { Router } from "express";
import { renderSharedHtml, escHtml } from "./admin.js";
import { VulnQueryResult, DataFreshness } from "../services/vuln-query.js";
import { isVulnSyncSource, runVulnSync, SourceOutcome, VulnSyncImpls } from "../vuln/sync/index.js";
import type { VulnSourceStatus, VulnSyncStatus } from "../db/queries/vuln-sync-state.js";
import type { VulnBackfillJobRow } from "../db/queries/vuln-backfill-jobs.js";
import { buildPublicationWindows } from "../vuln/sync/nvd-sync.js";

export interface AdminVulnsRouteDeps {
  /** Bound /vulns query (same code path as the public API). */
  queryVulns: (product: string, version?: string) => Promise<VulnQueryResult>;
  getDataFreshness: () => Promise<DataFreshness>;
  getSyncStatus: () => Promise<VulnSyncStatus>;
  vulnSyncImpls: VulnSyncImpls;
  logAdminAction: (details: Record<string, unknown>) => Promise<void>;
  /** Operator hints (e.g. "run vuln:backfill") shown above the freshness panel. */
  getHints?: () => Promise<string[]>;
  startVulnBackfill: (
    since?: string,
  ) => Promise<{ job?: VulnBackfillJobRow; alreadyRunning?: boolean }>;
  getVulnBackfill: (id: string) => Promise<VulnBackfillJobRow | null>;
}

/**
 * Admin vulnerability explorer (plan §6, WAL-15). Server-rendered in the existing
 * /admin/v1 style. Data flows through the shared query service (no duplicate SQL);
 * autocomplete calls the public search endpoint client-side.
 */
export function createAdminVulnsRouter(deps: AdminVulnsRouteDeps): Router {
  const router = Router();

  router.get("/vulns", async (req, res, next) => {
    try {
      const product = optionalString(req.query.product);
      const version = optionalString(req.query.version);
      const synced = optionalString(req.query.synced);
      const syncError = optionalString(req.query.sync_error);

      const [freshness, syncStatus] = await Promise.all([
        deps.getDataFreshness(),
        deps.getSyncStatus(),
      ]);
      const hints = deps.getHints ? await deps.getHints() : [];
      const result = product ? await deps.queryVulns(product, version) : null;

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(
        renderExplorer({
          product,
          version,
          synced,
          syncError,
          freshness,
          syncStatus,
          hints,
          result,
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  router.post("/vuln-sync/:source", async (req, res, next) => {
    try {
      const source = req.params.source;
      if (!isVulnSyncSource(source)) {
        res.status(400).json({ error: `Unknown vuln sync source: ${source}` });
        return;
      }
      const outcomes = await runVulnSync(source, deps.vulnSyncImpls);
      await deps.logAdminAction({ action: "vuln-sync", source, outcomes });
      const wantsHtml = req.headers.accept?.includes("text/html");
      const alreadyRunning = source !== "all" && outcomes[0]?.code === "already_running";
      if (wantsHtml) {
        res.redirect(
          alreadyRunning
            ? `/admin/v1/vulns?sync_error=${encodeURIComponent(`${source} sync is already running`)}`
            : `/admin/v1/vulns?synced=${encodeURIComponent(source)}`,
        );
        return;
      }
      const allOk = outcomes.every((o: SourceOutcome) => o.ok);
      res.status(allOk ? 200 : alreadyRunning ? 409 : 207).json({ source, outcomes });
    } catch (err) {
      next(err);
    }
  });

  router.post("/vuln-backfill", async (req, res, next) => {
    try {
      const body = (req.body ?? {}) as { since?: unknown };
      const since = optionalString(body.since);
      if (since) buildPublicationWindows(since);
      const result = await deps.startVulnBackfill(since);
      if (result.alreadyRunning)
        return void res
          .status(409)
          .json({ code: "already_running", ...(result.job ? { job: result.job } : {}) });
      if (!result.job) throw new Error("Backfill launcher did not return a job");
      await deps.logAdminAction({ action: "vuln-backfill", since, job_id: result.job.id });
      res
        .status(202)
        .json({ job: result.job, status_url: `/admin/v1/vuln-backfill/${result.job.id}` });
    } catch (error) {
      if (error instanceof Error && error.message.includes("since"))
        return void res.status(400).json({ error: error.message });
      next(error);
    }
  });

  router.get("/vuln-backfill/:id", async (req, res, next) => {
    try {
      const job = await deps.getVulnBackfill(req.params.id);
      if (!job) return void res.status(404).json({ error: "Backfill job not found" });
      res.json({ job });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

function renderExplorer(ctx: {
  product?: string;
  version?: string;
  synced?: string;
  syncError?: string;
  freshness: DataFreshness;
  syncStatus: VulnSyncStatus;
  hints: string[];
  result: VulnQueryResult | null;
}): string {
  const esc = escHtml;
  const product = ctx.product ?? "";
  const version = ctx.version ?? "";

  const hintsBanner = ctx.hints
    .map((h) => `<div class="note note-warn">${renderHint(h)}</div>`)
    .join("");

  const freshnessPanel = `
    <div class="freshness">
      <strong>Data freshness</strong>
      <span>NVD: ${fmtTs(ctx.freshness.nvd_last_sync)} ${fmtSourceStatus(ctx.syncStatus.nvd)}</span>
      <span>KEV: ${fmtTs(ctx.freshness.kev_last_sync)} ${fmtSourceStatus(ctx.syncStatus.kev)}</span>
      <span>OSV: ${fmtTs(ctx.freshness.osv_last_sync)} ${fmtSourceStatus(ctx.syncStatus.osv)}</span>
      <form method="post" action="/admin/v1/vuln-sync/nvd" style="display:inline"><button class="btn btn-sm btn-secondary">Sync NVD now</button></form>
      <form method="post" action="/admin/v1/vuln-sync/kev" style="display:inline"><button class="btn btn-sm btn-secondary">Sync KEV now</button></form>
      <form method="post" action="/admin/v1/vuln-sync/osv" style="display:inline"><button class="btn btn-sm btn-secondary">Sync OSV now</button></form>
      <form method="post" action="/admin/v1/vuln-backfill" style="display:inline"><button class="btn btn-sm btn-secondary">Start NVD backfill</button></form>
    </div>`;

  const syncedBanner = ctx.synced
    ? `<div class="note note-ok">Triggered ${esc(ctx.synced)} sync. Freshness updates once ingestion completes.</div>`
    : "";
  const syncErrorBanner = ctx.syncError
    ? `<div class="note note-warn">${esc(ctx.syncError)}</div>`
    : "";

  const form = `
    <form method="get" action="/admin/v1/vulns" class="vform" autocomplete="off">
      <div style="position:relative">
        <input id="product" name="product" value="${esc(product)}" placeholder="Product or alias (e.g. openjdk, npp)" required>
        <div id="ac" class="ac"></div>
      </div>
      <input name="version" value="${esc(version)}" placeholder="Version (optional)">
      <button class="btn btn-primary" type="submit">Look up</button>
    </form>`;

  const results = ctx.result
    ? renderResult(ctx.result)
    : `<p class="empty">Enter a product to look up known CVEs.</p>`;

  const body = `
    <h1>Vulnerability explorer</h1>
    ${hintsBanner}
    ${freshnessPanel}
    ${syncedBanner}
    ${syncErrorBanner}
    ${form}
    ${results}`;

  const scripts = `
    const input = document.getElementById('product');
    const ac = document.getElementById('ac');
    let timer;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 2) { ac.innerHTML=''; return; }
      timer = setTimeout(async () => {
        try {
          const r = await fetch('/api/v1/vulns/products/search?q=' + encodeURIComponent(q));
          if (!r.ok) return;
          const d = await r.json();
          ac.innerHTML = d.results.map(x =>
            '<div class="ac-item" data-slug="' + x.slug + '">' + x.display_name + ' <span class="ac-slug">' + x.slug + '</span></div>'
          ).join('');
          ac.querySelectorAll('.ac-item').forEach(el => el.addEventListener('mousedown', () => {
            input.value = el.getAttribute('data-slug'); ac.innerHTML='';
          }));
        } catch(e) {}
      }, 150);
    });
    input.addEventListener('blur', () => setTimeout(() => ac.innerHTML='', 150));`;

  const styleTail = `<style>
    .vform { display:flex; gap:8px; margin:16px 0; flex-wrap:wrap; }
    .vform input { padding:8px 10px; border:1px solid #d1d5db; border-radius:6px; font-size:0.9rem; min-width:280px; }
    .ac { position:absolute; top:100%; left:0; right:0; background:#fff; border:1px solid #e5e7eb; border-radius:6px; z-index:10; box-shadow:0 4px 12px rgba(0,0,0,0.08); }
    .ac-item { padding:6px 10px; cursor:pointer; font-size:0.85rem; }
    .ac-item:hover { background:#f3f4f6; }
    .ac-slug { color:#9ca3af; font-size:0.75rem; }
    .freshness { display:flex; gap:16px; align-items:center; flex-wrap:wrap; background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:10px 14px; font-size:0.82rem; color:#6b7280; }
    .freshness strong { color:#111; }
    .note { padding:10px 14px; border-radius:8px; margin:12px 0; font-size:0.85rem; }
    .note-ok { background:#dcfce7; color:#15803d; }
    .note-warn { background:#fef3c7; color:#92400e; }
    .note-info { background:#f3f4f6; color:#374151; }
    .sev-CRITICAL { color:#b91c1c; font-weight:700; }
    .sev-HIGH { color:#c2410c; font-weight:700; }
    .sev-MEDIUM { color:#a16207; }
    .sev-LOW { color:#6b7280; }
  </style>`;

  return renderSharedHtml("Vulnerabilities", "vulns", body, scripts, styleTail);
}

function renderResult(r: VulnQueryResult): string {
  const esc = escHtml;
  const m = r.match;

  if (!m.resolved) {
    const cands = m.candidates.length
      ? `<p>Did you mean:</p><ul>${m.candidates
          .map(
            (c) =>
              `<li><a href="/admin/v1/vulns?product=${encodeURIComponent(c.slug)}">${esc(c.display_name)}</a> <span class="ac-slug">${esc(c.slug)}</span></li>`,
          )
          .join("")}</ul>`
      : "<p>No similar products found.</p>";
    return `<div class="note note-warn"><strong>Not matched:</strong> “${esc(r.query.product)}” did not resolve to a tracked package.</div>${cands}`;
  }

  const header = `<p class="meta">Resolved to <strong>${esc(m.display_name ?? m.product_slug ?? "")}</strong>
    (<code>${esc(m.product_slug ?? "")}</code>, ${esc(m.method ?? "")}, confidence ${m.confidence ?? "—"})
    · ${r.counts.total} CVE(s)${r.counts.kev > 0 ? ` · <span class="badge badge-kev">${r.counts.kev} KEV</span>` : ""}</p>`;

  const warn = r.version_parse_warning
    ? `<div class="note note-warn">${esc(r.version_parse_warning)}</div>`
    : "";

  if (r.vulns.length === 0) {
    return `${header}${warn}<div class="note note-info">No known CVEs for this product${r.query.version ? ` at version ${esc(r.query.version)}` : ""}. (Absence of results does not imply safety.)</div>`;
  }

  const rows = r.vulns
    .map((v) => {
      const kev = v.is_kev ? ` <span class="badge badge-kev">KEV</span>` : "";
      const unc =
        v.affected.matched_because === "range-uncomparable"
          ? ` <span class="badge badge-vuln-high">uncomparable</span>`
          : "";
      return `<tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve_id)}" target="_blank" rel="noopener">${esc(v.cve_id)}</a></td>
        <td class="sev-${esc(v.severity ?? "")}">${esc(v.severity ?? "—")}${v.cvss_v3_score !== null ? ` (${v.cvss_v3_score})` : ""}</td>
        <td>${esc(v.affected.range)}${unc}</td>
        <td>${v.fixed_in ? esc(v.fixed_in) : "—"}</td>
        <td>${kev || "—"}</td>
        <td>${v.sources.map((s) => esc(s)).join(", ")}</td>
      </tr>`;
    })
    .join("");

  return `${header}${warn}
    <table>
      <thead><tr><th>CVE</th><th>Severity</th><th>Affected range</th><th>Fixed in</th><th>KEV</th><th>Sources</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

/** Escape a hint string, then render `backtick code` spans as <code>. */
function renderHint(hint: string): string {
  return escHtml(hint).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function fmtTs(ts: string | null): string {
  if (!ts) return "never";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "never" : d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function fmtSourceStatus(status: VulnSourceStatus): string {
  if (status.last_ok === null) return "(never attempted)";
  if (status.last_ok) return "(last attempt succeeded)";
  return `(last attempt failed ${fmtTs(status.last_failure)})`;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}
