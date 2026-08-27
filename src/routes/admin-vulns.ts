import { Router } from "express";
import { renderSharedHtml, escHtml } from "./admin.js";
import { VulnQueryResult, DataFreshness } from "../services/vuln-query.js";
import {
  isVulnSyncSource,
  parseVulnSyncOptions,
  runVulnSync,
  SourceOutcome,
  VulnSyncImpls,
} from "../vuln/sync/index.js";
import { VulnSyncAlreadyRunningError } from "../vuln/sync/lock.js";
import type { VulnSourceStatus, VulnSyncStatus } from "../db/queries/vuln-sync-state.js";
import type { VulnBackfillJobRow } from "../db/queries/vuln-backfill-jobs.js";
import { buildPublicationWindows } from "../vuln/sync/nvd-sync.js";
import { VERSION_NA } from "../vuln/version-ranges.js";
import { CRITICAL_SCORE } from "../services/vuln-service.js";

export interface AdminVulnsRouteDeps {
  /** Bound /vulns query (same code path as the public API). */
  queryVulns: (product: string, version?: string) => Promise<VulnQueryResult>;
  getDataFreshness: () => Promise<DataFreshness>;
  getSyncStatus: () => Promise<VulnSyncStatus>;
  vulnSyncImpls: VulnSyncImpls;
  logAdminAction: (details: Record<string, unknown>) => Promise<void>;
  /** Record gate transitions after an admin-triggered sync, exactly as /internal does. */
  recordAvailability?: (source: string) => Promise<{
    newlyBlocked: Array<{ package_name: string; version: string; cve_id: string | null }>;
    newlyAvailable: Array<{ package_name: string; version: string }>;
  }>;
  /** Operator hints (e.g. "run vuln:backfill") shown above the freshness panel. */
  getHints?: () => Promise<string[]>;
  startVulnBackfill: (
    since?: string,
    packageName?: string,
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
      const backfillStarted = optionalString(req.query.backfill_started);

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
          backfillStarted,
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
      const parsed = parseVulnSyncOptions(source, req.body);
      if (!parsed.ok) {
        res.status(400).json({ error: parsed.error });
        return;
      }

      if (parsed.opts.dryRun) {
        const preview = deps.vulnSyncImpls.cvssPreview;
        if (!preview) {
          res.status(503).json({ error: "cvss preview is not available" });
          return;
        }
        let result;
        try {
          result = await preview({ limit: parsed.opts.limit });
        } catch (err) {
          if (err instanceof VulnSyncAlreadyRunningError) {
            res.status(409).json({ code: "already_running", error: err.message });
            return;
          }
          throw err;
        }
        // Logged like any other admin action even though nothing was written — who
        // previewed a gate change, and when, is part of the audit trail.
        await deps.logAdminAction({
          action: "vuln-sync-preview",
          source,
          proposals: result.proposals.length,
          newly_blocked: result.newly_blocked.reduce((n, d) => n + d.newly_blocked.length, 0),
        });
        res.status(200).json({ source, dry_run: true, preview: result });
        return;
      }

      const outcomes = await runVulnSync(source, deps.vulnSyncImpls, parsed.opts);
      const availability = outcomes.some((o: SourceOutcome) => o.ok)
        ? await deps.recordAvailability?.(source).catch(() => undefined)
        : undefined;
      await deps.logAdminAction({
        action: "vuln-sync",
        source,
        outcomes,
        ...(availability
          ? {
              newly_blocked: availability.newlyBlocked.length,
              newly_available: availability.newlyAvailable.length,
            }
          : {}),
      });
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
      const body = (req.body ?? {}) as {
        since?: unknown;
        package?: unknown;
        return_version?: unknown;
      };
      const since = optionalString(body.since);
      const packageName = optionalString(body.package);
      if (since) buildPublicationWindows(since);
      const result = await deps.startVulnBackfill(since, packageName);
      // Browser form posts get a redirect back to the explorer with a status message —
      // navigating to a JSON body was a dead end for operators. API clients keep JSON.
      const wantsHtml = req.headers.accept?.includes("text/html");
      if (wantsHtml) {
        // A package-scoped backfill is started from a package's own view, so the redirect has
        // to land back on it — dropping the operator on an empty explorer would make them
        // retype the lookup to see what the run they just started did.
        const context = new URLSearchParams();
        if (packageName) context.set("product", packageName);
        const returnVersion = optionalString(body.return_version);
        if (returnVersion) context.set("version", returnVersion);

        if (result.alreadyRunning) {
          context.set("sync_error", "A vulnerability backfill is already running");
          res.redirect(303, `/admin/v1/vulns?${context.toString()}`);
          return;
        }
        context.set("backfill_started", String(result.job?.id ?? ""));
        if (since) context.set("backfill_since", since);
        res.redirect(303, `/admin/v1/vulns?${context.toString()}`);
        return;
      }
      if (result.alreadyRunning)
        return void res
          .status(409)
          .json({ code: "already_running", ...(result.job ? { job: result.job } : {}) });
      if (!result.job) throw new Error("Backfill launcher did not return a job");
      await deps.logAdminAction({
        action: "vuln-backfill",
        since,
        package: packageName,
        job_id: result.job.id,
      });
      res
        .status(202)
        .json({ job: result.job, status_url: `/admin/v1/vuln-backfill/${result.job.id}` });
    } catch (error) {
      if (
        error instanceof Error &&
        (error.message.includes("since") || error.message.includes("No CPE pairs"))
      ) {
        if (req.headers.accept?.includes("text/html")) {
          return void res.redirect(
            303,
            `/admin/v1/vulns?sync_error=${encodeURIComponent(error.message)}`,
          );
        }
        return void res.status(400).json({ error: error.message });
      }
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
  backfillStarted?: string;
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

  // ── Status strip: state chips left, actions right. Two fixed rows — the old single
  // flex-wrap mixed readouts and buttons at one level and re-wrapped arbitrarily as
  // timestamps changed length.
  const sources: Array<{
    key: string;
    label: string;
    ts: string | null;
    status: VulnSourceStatus;
  }> = [
    { key: "nvd", label: "NVD", ts: ctx.freshness.nvd_last_sync, status: ctx.syncStatus.nvd },
    { key: "kev", label: "KEV", ts: ctx.freshness.kev_last_sync, status: ctx.syncStatus.kev },
    { key: "osv", label: "OSV", ts: ctx.freshness.osv_last_sync, status: ctx.syncStatus.osv },
    { key: "cvss", label: "CVSS", ts: ctx.freshness.cvss_last_sync, status: ctx.syncStatus.cvss },
  ];
  const sourceChips = sources
    .map((s) => {
      const state = chipState(s.status);
      const tooltip = chipTooltip(s);
      return `<span class="src-chip src-${state}" title="${esc(tooltip)}">
        <span class="dot"></span>${esc(s.label)}
        <span class="src-ts" data-ts="${esc(s.ts ?? "")}">${esc(s.ts ? "…" : "never")}</span>
      </span>`;
    })
    .join("");
  const statusStrip = `
    <div class="status-strip">
      <div class="status-row">
        <strong>Data sources</strong>
        <span class="src-chips">${sourceChips}</span>
        <span class="strip-actions">
          <form method="post" action="/admin/v1/vuln-sync/nvd"><button class="btn btn-sm btn-secondary">Sync NVD</button></form>
          <form method="post" action="/admin/v1/vuln-sync/kev"><button class="btn btn-sm btn-secondary">Sync KEV</button></form>
          <form method="post" action="/admin/v1/vuln-sync/osv"><button class="btn btn-sm btn-secondary">Sync OSV</button></form>
          <form method="post" action="/admin/v1/vuln-backfill"><button class="btn btn-sm btn-secondary">NVD backfill</button></form>
        </span>
      </div>
    </div>`;

  // CVSS enrichment is triggerable below rather than by a sync button, because it is the
  // one write that can change what /download serves -- the preview is not a convenience
  // here, it is the step that makes applying safe. Collapsed by default: rarely used,
  // and its explanation is long.
  const enrichPanel = `
    <details class="enrich-wrap">
      <summary>CVSS enrichment <span class="summary-hint">fills missing severities; can block versions — preview first</span></summary>
      <div class="enrich">
        <div class="enrich-head">
          <span>Fills in severity for CVEs that have none (mostly OSV stubs). Applying can newly
          satisfy the &ge; 9.0 gate, which makes versions that serve today return 403.
          Preview first.</span>
        </div>
        <div class="enrich-actions">
          <label for="cvss-limit">Limit</label>
          <input id="cvss-limit" type="number" min="1" placeholder="all">
          <button id="cvss-preview" class="btn btn-sm btn-secondary" type="button">Preview</button>
          <button id="cvss-apply" class="btn btn-sm btn-danger" type="button" disabled
            title="Run a preview first">Apply</button>
        </div>
        <div id="cvss-out"></div>
      </div>
    </details>`;

  const syncedBanner = ctx.synced
    ? `<div class="note note-ok">Triggered ${esc(ctx.synced)} sync. Freshness updates once ingestion completes.</div>`
    : "";
  const backfillBanner = ctx.backfillStarted
    ? `<div class="note note-ok">NVD backfill job <a href="/admin/v1/vuln-backfill/${esc(ctx.backfillStarted)}">#${esc(ctx.backfillStarted)}</a> queued — it runs in the background; this page's NVD chip updates when it finishes.</div>`
    : "";
  const syncErrorBanner = ctx.syncError
    ? `<div class="note note-warn">${esc(ctx.syncError)}</div>`
    : "";

  // ── Lookup first: it is the page's primary task; ops panels sit below the fold.
  const form = `
    <form method="get" action="/admin/v1/vulns" class="vform" autocomplete="off">
      <div style="position:relative">
        <input id="product" name="product" value="${esc(product)}" placeholder="Product or alias (e.g. openjdk, npp)" required autofocus>
        <div id="ac" class="ac"></div>
      </div>
      <input name="version" value="${esc(version)}" placeholder="Version (optional)">
      <button class="btn btn-primary" type="submit">Look up</button>
    </form>`;

  const results = ctx.result
    ? renderResult(ctx.result)
    : `<p class="empty">Enter a product to look up known CVEs.</p>`;

  const body = `
    <h1>Vulnerability Explorer</h1>
    ${syncErrorBanner}
    ${syncedBanner}
    ${backfillBanner}
    ${form}
    <div id="results-anchor">${results}</div>
    ${hintsBanner}
    ${statusStrip}
    ${enrichPanel}`;

  const scripts = `
    // ── Relative timestamps for the source chips ──
    function relTime(iso) {
      const then = new Date(iso).getTime();
      if (isNaN(then)) return null;
      const mins = Math.round((Date.now() - then) / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return mins + 'm ago';
      const hours = Math.round(mins / 60);
      if (hours < 48) return hours + 'h ago';
      return Math.round(hours / 24) + 'd ago';
    }
    document.querySelectorAll('.src-ts').forEach(el => {
      const iso = el.getAttribute('data-ts');
      if (!iso) return;
      const rel = relTime(iso);
      if (rel) el.textContent = rel;
      el.parentElement.title = el.parentElement.title + ' — last success ' + new Date(iso).toISOString();
    });

    // ── Autocomplete with keyboard navigation ──
    const input = document.getElementById('product');
    const ac = document.getElementById('ac');
    let acItems = [];
    let acIndex = -1;
    function clearAc() { ac.innerHTML = ''; acItems = []; acIndex = -1; }
    function highlightAc() {
      acItems.forEach((el, i) => el.classList.toggle('ac-active', i === acIndex));
    }
    function chooseAc(el) {
      input.value = el.getAttribute('data-slug');
      clearAc();
      input.form.submit();
    }
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 2) { clearAc(); return; }
      timer = setTimeout(async () => {
        try {
          const r = await fetch('/api/v1/vulns/products/search?q=' + encodeURIComponent(q));
          if (!r.ok) return;
          const d = await r.json();
          ac.innerHTML = d.results.map(x =>
            '<div class="ac-item" data-slug="' + x.slug + '">' + x.display_name + ' <span class="ac-slug">' + x.slug + '</span></div>'
          ).join('');
          acItems = [...ac.querySelectorAll('.ac-item')];
          acIndex = -1;
          acItems.forEach(el => el.addEventListener('mousedown', (ev) => { ev.preventDefault(); chooseAc(el); }));
        } catch(e) {}
      }, 150);
    });
    input.addEventListener('keydown', (e) => {
      if (!acItems.length) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); acIndex = Math.min(acIndex + 1, acItems.length - 1); highlightAc(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); acIndex = Math.max(acIndex - 1, 0); highlightAc(); }
      else if (e.key === 'Enter' && acIndex >= 0) { e.preventDefault(); chooseAc(acItems[acIndex]); }
      else if (e.key === 'Escape') { clearAc(); }
    });
    input.addEventListener('blur', () => setTimeout(() => clearAc(), 150));
    let timer;

    // ── Results filter chips (client-side; no pagination machinery) ──
    const resultsEl = document.getElementById('results-anchor');
    const resultsTable = resultsEl ? resultsEl.querySelector('table') : null;
    if (resultsTable) {
      const rows = [...resultsTable.querySelectorAll('tbody tr')];
      const total = rows.length;
      const counts = { all: total, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, kev: 0 };
      rows.forEach(tr => {
        const sevEl = tr.querySelector('[class*="sev-"]');
        const cls = sevEl ? sevEl.className : '';
        const m = cls.match(/sev-([A-Z]+)/);
        if (m && counts[m[1]] !== undefined) counts[m[1]]++;
        if (tr.querySelector('.badge-kev')) counts.kev++;
      });
      if (total > 12) {
        const bar = document.createElement('div');
        bar.className = 'filter-bar';
        const chips = [
          ['all', 'All (' + total + ')'],
          ['CRITICAL', 'Critical (' + counts.CRITICAL + ')'],
          ['HIGH', 'High (' + counts.HIGH + ')'],
          ['MEDIUM', 'Medium (' + counts.MEDIUM + ')'],
          ['LOW', 'Low (' + counts.LOW + ')'],
          ['kev', 'KEV (' + counts.kev + ')'],
        ];
        bar.innerHTML = '<span class="filter-label">Show:</span>' + chips.map(([k, label], i) =>
          '<button type="button" class="filter-chip' + (i === 0 ? ' filter-on' : '') + '" data-filter="' + k + '">' + label + '</button>'
        ).join('');
        resultsTable.parentNode.insertBefore(bar, resultsTable);
        const counter = document.createElement('p');
        counter.className = 'meta filter-count';
        bar.parentNode.insertBefore(counter, bar.nextSibling);
        const shown = document.createElement('span');
        shown.textContent = 'Showing ' + total + ' of ' + total + ' CVE(s).';
        counter.appendChild(shown);
        let active = 'all';
        bar.addEventListener('click', (e) => {
          const btn = e.target.closest('.filter-chip');
          if (!btn) return;
          active = btn.getAttribute('data-filter');
          bar.querySelectorAll('.filter-chip').forEach(c => c.classList.toggle('filter-on', c === btn));
          let visible = 0;
          rows.forEach(tr => {
            const sevEl = tr.querySelector('[class*="sev-"]');
            const m = sevEl ? sevEl.className.match(/sev-([A-Z]+)/) : null;
            const sev = m ? m[1] : '';
            const isKev = Boolean(tr.querySelector('.badge-kev'));
            const show = active === 'all'
              || (active === 'kev' ? isKev : sev === active);
            tr.style.display = show ? '' : 'none';
            if (show) visible++;
          });
          shown.textContent = 'Showing ' + visible + ' of ' + total + ' CVE(s)'
            + (active !== 'all' ? ' — ' + active + ' only' : '') + '.';
        });
      }
    }

    // ── CVSS enrichment preview/apply ──
    const limitEl = document.getElementById('cvss-limit');
    const previewBtn = document.getElementById('cvss-preview');
    const applyBtn = document.getElementById('cvss-apply');
    const out = document.getElementById('cvss-out');
    // Apply stays locked to the limit the preview was computed for: applying with a
    // different bound would write a change set nobody looked at.
    let previewedLimit;
    let previewedBlocked = 0;

    function esc(v) {
      const d = document.createElement('div');
      d.textContent = v == null ? '' : String(v);
      return d.innerHTML;
    }

    function currentLimit() {
      const raw = limitEl.value.trim();
      return raw === '' ? undefined : Number(raw);
    }

    function lockApply(why) {
      applyBtn.disabled = true;
      applyBtn.title = why;
      previewedLimit = undefined;
    }

    limitEl.addEventListener('input', () => lockApply('Limit changed — preview again'));

    async function post(payload) {
      const r = await fetch('/admin/v1/vuln-sync/cvss', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      let data = {};
      try { data = await r.json(); } catch (e) {}
      return { status: r.status, data: data };
    }

    function renderError(status, data) {
      const msg = data && data.error ? data.error : 'Request failed (HTTP ' + status + ')';
      out.innerHTML = '<div class="note note-warn">' + esc(msg) + '</div>';
    }

    function renderPreview(d) {
      const p = d.preview || {};
      const proposals = p.proposals || [];
      const blocked = p.newly_blocked || [];
      previewedBlocked = blocked.reduce((n, x) => n + x.newly_blocked.length, 0);

      let html = '<div class="note note-info">Dry run — nothing was written. '
        + esc(p.candidates) + ' candidate(s), ' + esc(p.fetched) + ' fetched, '
        + proposals.length + ' proposal(s).</div>';

      if (previewedBlocked > 0) {
        html += '<div class="note note-warn"><strong>' + previewedBlocked
          + ' version(s) would start returning 403:</strong><ul class="blocked">'
          + blocked.map(b => '<li>' + esc(b.package_name) + ': '
              + b.newly_blocked.map(esc).join(', ') + '</li>').join('')
          + '</ul></div>';
      } else if (proposals.length > 0) {
        html += '<div class="note note-ok">No cached version changes availability.</div>';
      }

      if (proposals.length > 0) {
        html += '<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS v3</th>'
          + '<th>CVSS v4</th><th>CVSS v2</th><th>Source</th><th>Crosses gate</th></tr></thead><tbody>'
          + proposals.map(x =>
              '<tr><td>' + esc(x.cve_id) + '</td>'
              + '<td class="sev-' + esc(x.severity) + '">' + esc(x.severity) + '</td>'
              + '<td>' + esc(x.cvss_v3_score == null ? '—' : x.cvss_v3_score) + '</td>'
              + '<td>' + esc(x.cvss_v4_score == null ? '—' : x.cvss_v4_score) + '</td>'
              + '<td>' + esc(x.cvss_v2_score == null ? '—' : x.cvss_v2_score) + '</td>'
              + '<td>' + esc(x.severity_source) + '</td>'
              + '<td>' + (x.crosses_critical_gate ? 'yes' : 'no') + '</td></tr>'
            ).join('')
          + '</tbody></table>';
      } else {
        html += '<p class="empty">Nothing to enrich — no CVE is missing a severity.</p>';
      }
      out.innerHTML = html;
    }

    previewBtn.addEventListener('click', async () => {
      previewBtn.disabled = true;
      out.innerHTML = '<p class="empty">Previewing…</p>';
      try {
        const limit = currentLimit();
        const payload = { dry_run: true };
        if (limit !== undefined) payload.limit = limit;
        const r = await post(payload);
        if (r.status !== 200) { renderError(r.status, r.data); lockApply('Preview failed'); return; }
        renderPreview(r.data);
        previewedLimit = limit;
        applyBtn.disabled = false;
        applyBtn.title = 'Apply the previewed changes';
      } catch (e) {
        renderError(0, { error: String(e) });
        lockApply('Preview failed');
      } finally {
        previewBtn.disabled = false;
      }
    });

    applyBtn.addEventListener('click', async () => {
      const warning = previewedBlocked > 0
        ? previewedBlocked + ' version(s) will start returning 403 from /download.\\n\\n'
        : '';
      if (!confirm(warning + 'Apply the previewed CVSS enrichment?')) return;
      applyBtn.disabled = true;
      out.innerHTML = '<p class="empty">Applying…</p>';
      try {
        const payload = {};
        if (previewedLimit !== undefined) payload.limit = previewedLimit;
        const r = await post(payload);
        if (r.status !== 200 && r.status !== 207) { renderError(r.status, r.data); return; }
        const s = (r.data.outcomes && r.data.outcomes[0] && r.data.outcomes[0].summary) || {};
        out.innerHTML = '<div class="note note-ok">Applied: ' + esc(s.updated) + ' updated, '
          + esc(s.fetched) + ' fetched of ' + esc(s.candidates) + ' candidate(s). '
          + 'Re-run the lookup to see the new severities.</div>';
      } catch (e) {
        renderError(0, { error: String(e) });
      } finally {
        lockApply('Preview again before applying');
      }
    });`;

  const styleTail = `<style>
    .vform { display:flex; gap:8px; margin:16px 0; flex-wrap:wrap; }
    .vform input { padding:8px 10px; border:1px solid #d1d5db; border-radius:6px; font-size:0.9rem; min-width:280px; }
    .ac { position:absolute; top:100%; left:0; right:0; background:#fff; border:1px solid #e5e7eb; border-radius:6px; z-index:10; box-shadow:0 4px 12px rgba(0,0,0,0.08); }
    .ac-item { padding:6px 10px; cursor:pointer; font-size:0.85rem; }
    .ac-item:hover, .ac-item.ac-active { background:#f3f4f6; }
    .ac-slug { color:#9ca3af; font-size:0.75rem; }
    .status-strip { background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:10px 14px; margin-top:16px; }
    .status-row { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
    .status-row strong { font-size:0.82rem; color:#111; }
    .src-chips { display:flex; gap:8px; flex-wrap:wrap; flex:1; }
    .src-chip { display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:12px; font-size:0.8rem; background:#f3f4f6; color:#374151; }
    .src-chip .dot { width:8px; height:8px; border-radius:50%; background:#9ca3af; }
    .src-ok { background:#f0fdf4; color:#166534; }
    .src-ok .dot { background:#22c55e; }
    .src-fail { background:#fef2f2; color:#b91c1c; }
    .src-fail .dot { background:#ef4444; }
    .src-never { background:#f3f4f6; color:#6b7280; }
    .src-never .dot { background:#9ca3af; }
    .src-ts { color:inherit; opacity:0.75; font-size:0.75rem; }
    .strip-actions { display:flex; gap:8px; flex-wrap:wrap; margin-left:auto; }
    .enrich-wrap { margin-top:12px; background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:10px 14px; }
    .enrich-wrap summary { cursor:pointer; font-size:0.85rem; font-weight:700; color:#111; }
    .enrich-wrap .summary-hint { font-weight:400; color:#6b7280; font-size:0.8rem; margin-left:6px; }
    .enrich { margin-top:10px; }
    .enrich-head span { font-size:0.8rem; color:#6b7280; max-width:70ch; }
    .enrich-actions { display:flex; align-items:center; gap:8px; margin-top:10px; flex-wrap:wrap; }
    .enrich-actions label { font-size:0.8rem; color:#6b7280; }
    .enrich-actions input { padding:4px 8px; border:1px solid #d1d5db; border-radius:6px; font-size:0.8rem; width:90px; }
    .enrich .btn:disabled { opacity:0.5; cursor:not-allowed; }
    .note { padding:10px 14px; border-radius:8px; margin:12px 0; font-size:0.85rem; }
    .note-ok { background:#dcfce7; color:#15803d; }
    .note-warn { background:#fef3c7; color:#92400e; }
    .note-info { background:#f3f4f6; color:#374151; }
    .blocked { margin:6px 0 0 18px; }
    .blocked li { font-size:0.82rem; }
    .sev-CRITICAL { color:#b91c1c; font-weight:700; }
    .sev-HIGH { color:#c2410c; font-weight:700; }
    .sev-MEDIUM { color:#a16207; }
    .sev-LOW { color:#6b7280; }
    .filter-bar { display:flex; gap:6px; align-items:center; flex-wrap:wrap; margin-top:12px; }
    .filter-label { font-size:0.8rem; color:#6b7280; }
    .filter-chip { padding:3px 10px; border-radius:12px; border:1px solid #d1d5db; background:#fff; font-size:0.78rem; cursor:pointer; color:#374151; }
    .filter-chip:hover { background:#f3f4f6; }
    .filter-chip.filter-on { background:#1d4ed8; border-color:#1d4ed8; color:#fff; }
    .filter-count { margin:6px 0 0; }
    .hist-link { font-size:0.8rem; }
    .badge-blocked-gate { background:#b91c1c; color:#fff; margin-left:6px; }
    .pkg-backfill { display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin:0 0 14px; }
    .pkg-backfill label { font-size:0.8rem; color:#4b5563; }
    .pkg-backfill input[type=date] { font-size:0.8rem; padding:3px 6px; }
    .pkg-backfill-hint { font-size:0.75rem; color:#6b7280; }
  </style>`;

  return renderSharedHtml("Vulnerabilities", "vulns", body, scripts, styleTail);
}

/**
 * Per-package NVD backfill, offered where the operator already is: looking at one package.
 *
 * The strip's "NVD backfill" walks every CPE pair of every package, which is the wrong tool for
 * "this package's history is missing" — the case that actually arises, since incremental sync is
 * cursor-based and can never reach a newly tracked package's older CVEs. The API has taken a
 * `package` scope since WAL-37; only the UI was missing it (ADR-007).
 */
function renderPackageBackfill(slug: string, displayName: string, version?: string | null): string {
  if (!slug) return "";
  return `<form class="pkg-backfill" method="post" action="/admin/v1/vuln-backfill">
    <input type="hidden" name="package" value="${escHtml(slug)}">
    ${version ? `<input type="hidden" name="return_version" value="${escHtml(version)}">` : ""}
    <label for="pkg-backfill-since">Backfill ${escHtml(displayName)} from</label>
    <input id="pkg-backfill-since" type="date" name="since" max="${new Date().toISOString().slice(0, 10)}">
    <button class="btn btn-sm btn-secondary" type="submit">Backfill this package</button>
    <span class="pkg-backfill-hint">Walks this package's CPE pairs only. Leave the date empty for all history.</span>
  </form>`;
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
    · ${r.counts.total} CVE(s)${r.counts.kev > 0 ? ` · <span class="badge badge-kev">${r.counts.kev} KEV</span>` : ""}
    · <a class="hist-link" href="/api/v1/packages/${esc(m.product_slug ?? "")}/availability${
      r.query.version ? `?version=${encodeURIComponent(r.query.version)}` : ""
    }">availability history</a></p>
    ${renderPackageBackfill(m.product_slug ?? "", m.display_name ?? m.product_slug ?? "", r.query.version)}`;

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
      // The gate (ADR-005) blocks on ANY CVSS base score >= 9.0, so a HIGH-labeled CVE
      // can still block: its v4 or v2 score may cross the threshold where v3 does not
      // (live example: CVE-2026-6100, v3 8.1 / v4 9.1, blocks python 3.12.13). Show the
      // max score and mark gate-crossers explicitly, rather than displaying one
      // sub-threshold number and leaving the block unexplained.
      const scores = [v.cvss_v3_score, v.cvss_v4_score, v.cvss_v2_score].filter((s) => s !== null);
      const maxScore = scores.length > 0 ? Math.max(...scores) : null;
      // Crossing the threshold is necessary but not sufficient: the row must also gate. A CPE
      // naming no version (WAL-69) and a fail-open match are both excluded from the gate, so
      // badging them "blocks at 9.8" told operators the opposite of what /download does — the
      // explorer went on calling CVE-2024-43488 a blocker after the fix had unblocked vscode.
      const gateable =
        v.affected.matched_because !== VERSION_NA &&
        v.affected.matched_because !== "range-uncomparable";
      const gates =
        gateable && maxScore !== null && maxScore >= CRITICAL_SCORE
          ? ` <span class="badge badge-blocked-gate">blocks at ${maxScore}</span>`
          : "";
      const scoreLabel = maxScore !== null ? ` (${maxScore})` : "";
      return `<tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve_id)}" target="_blank" rel="noopener">${esc(v.cve_id)}</a></td>
        <td class="sev-${esc(v.severity ?? "")}">${esc(v.severity ?? "—")}${scoreLabel}${gates}</td>
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

function optionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

/** Chip state class for one source: ok / fail / never drives the strip's color coding. */
function chipState(status: VulnSourceStatus): "ok" | "fail" | "never" {
  if (status.last_ok === null) return "never";
  return status.last_ok ? "ok" : "fail";
}

/** Tooltip text: absolute times, because the chip itself stays compact. */
function chipTooltip(s: { label: string; ts: string | null; status: VulnSourceStatus }): string {
  if (s.status.last_ok === null) {
    return `${s.label}: never attempted`;
  }
  if (!s.status.last_ok) {
    return `${s.label}: last attempt FAILED ${fmtTs(s.status.last_failure)} (last success ${fmtTs(s.ts)})`;
  }
  return `${s.label}: last sync succeeded ${fmtTs(s.ts)}`;
}
