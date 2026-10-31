import { readFileSync } from "fs";
import { join } from "path";
import { Router, Request, Response } from "express";
import { withBase } from "../common/base-path.js";
import { BASE_PAGE_STYLES, escapeHtml, renderPublicNav } from "./page-shell.js";

const API_DOCS_MARKDOWN = readFileSync(join(__dirname, "api-docs.md"), "utf8");

// GitHub-style heading slug, so in-page #anchors written in the markdown resolve.
const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");

/** Renders a chunk of markdown (no h1-h3 headings expected) to HTML. */
export function renderMarkdownToHtml(md: string, basePath: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let inCodeBlock = false;
  let inTable = false;
  let tableHeaderDone = false;
  let inList = false;
  let paraLines: string[] = [];
  let quoteLines: string[] = [];
  let itemLines: string[] | null = null;
  let fenceIndent = 0;

  // Code spans are lifted out into placeholders first, so emphasis (which may legitimately
  // wrap a code span: **`x`**) never touches `snake_case_names` inside them.
  const inline = (s: string) => {
    const spans: string[] = [];
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/`([^`]+)`/g, (_m, code: string) => `\uE000${spans.push(code) - 1}\uE000`)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[^\w])_([^_\s](?:[^_]*[^_\s])?)_(?!\w)/g, "$1<em>$2</em>")
      .replace(/(^|[^\w*])\*([^*\s](?:[^*]*[^*\s])?)\*(?![\w*])/g, "$1<em>$2</em>")
      .replace(/\uE000(\d+)\uE000/g, (_m, i: string) => `<code>${spans[Number(i)]}</code>`)
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, text: string, href: string) => {
        // Site-relative links (the docs' own examples) must carry the base path so
        // they work when this page is reached through an adopter's prefixed proxy; in-page
        // anchors and external links are untouched.
        if (href.startsWith("#") || /^[a-z][a-z0-9+.-]*:/i.test(href)) {
          const external = !href.startsWith("#");
          return external
            ? `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`
            : `<a href="${href}">${text}</a>`;
        }
        return `<a href="${withBase(basePath, href)}">${text}</a>`;
      });
  };

  const flushPara = () => {
    if (paraLines.length > 0) {
      out.push(`<p>${inline(paraLines.join(" "))}</p>`);
      paraLines = [];
    }
  };

  const flushQuote = () => {
    if (quoteLines.length > 0) {
      out.push(`<blockquote><p>${inline(quoteLines.join(" "))}</p></blockquote>`);
      quoteLines = [];
    }
  };

  // A list item stays open across indented continuation lines, so it is emitted lazily.
  const closeList = () => {
    if (itemLines) {
      out.push(`<li>${inline(itemLines.join(" "))}</li>`);
      itemLines = null;
    }
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
  };

  const flushBlock = () => {
    flushPara();
    flushQuote();
    closeList();
    if (inTable) {
      out.push("</tbody></table>");
      inTable = false;
      tableHeaderDone = false;
    }
  };

  for (const line of lines) {
    // A fence may be indented (a code sample nested under a list item).
    if (/^\s*```/.test(line)) {
      flushBlock();
      inCodeBlock = !inCodeBlock;
      if (inCodeBlock) fenceIndent = line.length - line.trimStart().length;
      out.push(inCodeBlock ? "<pre><code>" : "</code></pre>");
      continue;
    }

    if (inCodeBlock) {
      const code = line.replace(new RegExp(`^ {0,${fenceIndent}}`), "");
      out.push(code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      continue;
    }

    if (quoteLines.length > 0 && !line.startsWith(">")) flushQuote();

    if (line.startsWith("##### ")) {
      flushBlock();
      out.push(`<h5 id="${slug(line.slice(6))}">${inline(line.slice(6))}</h5>`);
      continue;
    }
    if (line.startsWith("#### ")) {
      flushBlock();
      out.push(`<h4 id="${slug(line.slice(5))}">${inline(line.slice(5))}</h4>`);
      continue;
    }

    if (line.trim() === "---") {
      flushBlock();
      out.push("<hr>");
      continue;
    }

    if (line.startsWith(">")) {
      flushPara();
      quoteLines.push(line.replace(/^>\s?/, ""));
      continue;
    }

    if (line.startsWith("|")) {
      flushPara();
      closeList();
      if (!inTable) {
        out.push("<table><thead>");
        inTable = true;
        tableHeaderDone = false;
      }
      if (line.replace(/\|/g, "").trim().replace(/-/g, "").trim() === "") {
        out.push("</thead><tbody>");
        tableHeaderDone = true;
        continue;
      }
      const cells = line
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim());
      const tag = tableHeaderDone ? "td" : "th";
      out.push("<tr>" + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join("") + "</tr>");
      continue;
    }

    if (inTable) {
      out.push("</tbody></table>");
      inTable = false;
      tableHeaderDone = false;
    }

    if (line.startsWith("- ")) {
      flushPara();
      if (itemLines) out.push(`<li>${inline(itemLines.join(" "))}</li>`);
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      itemLines = [line.slice(2)];
      continue;
    }

    // An indented line directly under a list item continues that item.
    if (itemLines && /^\s+\S/.test(line)) {
      itemLines.push(line.trim());
      continue;
    }

    closeList();

    if (line.trim() === "") {
      flushPara();
      continue;
    }

    paraLines.push(line);
  }

  flushBlock();

  return out.join("\n").replace(/<pre><code>\n/g, "<pre><code>");
}

// ---------------------------------------------------------------------------
// Section model
// ---------------------------------------------------------------------------

export interface DocSection {
  id: string;
  title: string;
  method?: string;
  /** Path without query string, e.g. `/api/v1/packages/:name/groups`. */
  path?: string;
  /** Query parameter names declared in the heading (`?product=&version=`). */
  headingQuery: string[];
  /** Raw markdown body, kept for deriving Try It defaults. */
  body: string;
}

export interface DocGroup {
  title: string;
  sections: DocSection[];
}

const METHOD_RE = /^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/;

/** Drops leading/trailing blank lines and `---` rules from a chunk of lines. */
function trimChunk(lines: string[]): string {
  let start = 0;
  let end = lines.length;
  const skippable = (l: string) => l.trim() === "" || l.trim() === "---";
  while (start < end && skippable(lines[start])) start++;
  while (end > start && skippable(lines[end - 1])) end--;
  return lines.slice(start, end).join("\n");
}

/**
 * Splits the markdown into sidebar groups (`##`) of sections (`###`). Prose before the first
 * `##` becomes an Overview section; prose directly under a `##` becomes "<group> overview".
 * Headings inside code fences are ignored.
 */
export function parseApiDocs(md: string): DocGroup[] {
  const groups: DocGroup[] = [];
  const intro: DocGroup = { title: "Introduction", sections: [] };

  let groupTitle: string | null = null;
  let current: { section: Omit<DocSection, "body">; lines: string[] } | null = null;
  let inFence = false;
  let seenH1 = false;

  const groupFor = (title: string | null): DocGroup => {
    if (title === null) return intro;
    return groups[groups.length - 1];
  };

  const close = () => {
    if (!current) return;
    const body = trimChunk(current.lines);
    if (body !== "" || current.section.method) {
      groupFor(groupTitle).sections.push({ ...current.section, body });
    }
    current = null;
  };

  for (const line of md.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;

    if (!inFence && line.startsWith("# ") && !seenH1) {
      seenH1 = true;
      current = {
        section: { id: "overview", title: "Overview", headingQuery: [] },
        lines: [],
      };
      continue;
    }
    if (!inFence && line.startsWith("## ")) {
      close();
      groupTitle = line.slice(3).trim();
      groups.push({ title: groupTitle, sections: [] });
      current = {
        section: { id: slug(groupTitle), title: `${groupTitle} overview`, headingQuery: [] },
        lines: [],
      };
      continue;
    }
    if (!inFence && line.startsWith("### ")) {
      close();
      const raw = line.slice(4).trim();
      const sep = raw.indexOf(" | ");
      const left = sep === -1 ? raw : raw.slice(0, sep).trim();
      const title = sep === -1 ? raw : raw.slice(sep + 3).trim();
      const m = METHOD_RE.exec(left);
      const section: Omit<DocSection, "body"> = {
        id: slug(left),
        title,
        headingQuery: [],
      };
      if (m) {
        const [pathOnly, query = ""] = m[2].split("?");
        section.method = m[1];
        section.path = pathOnly;
        section.headingQuery = query
          .split("&")
          .map((p) => p.split("=")[0])
          .filter(Boolean);
      }
      current = { section, lines: [] };
      continue;
    }
    current?.lines.push(line);
  }
  close();

  return [intro, ...groups].filter((g) => g.sections.length > 0);
}

// ---------------------------------------------------------------------------
// Try It
// ---------------------------------------------------------------------------

export function isTryable(section: DocSection): boolean {
  if (section.method !== "GET" || !section.path) return false;
  return (
    section.path.startsWith("/api/v1/") ||
    section.path === "/health" ||
    section.path === "/openapi.json"
  );
}

/** Names from the first column of the section's "Query parameters" table. */
function tableQueryParams(body: string): string[] {
  const lines = body.split("\n");
  const at = lines.findIndex((l) => l.trim() === "**Query parameters**");
  if (at === -1) return [];
  const names: string[] = [];
  let rows = 0;
  for (const line of lines.slice(at + 1)) {
    if (line.trim() === "" && rows === 0) continue;
    if (!line.startsWith("|")) break;
    rows++;
    if (rows <= 2) continue; // header + separator
    const first = line.split("|")[1]?.trim().replace(/`/g, "");
    if (first) names.push(first);
  }
  return names;
}

/**
 * Example values for the form, taken from the first in-section link that matches the route
 * (e.g. `[openjdk](/api/v1/packages/openjdk/groups)` supplies `name=openjdk`).
 */
function exampleDefaults(section: DocSection): {
  path: Record<string, string>;
  query: Record<string, string>;
} {
  const result = { path: {} as Record<string, string>, query: {} as Record<string, string> };
  if (!section.path) return result;
  const names: string[] = [];
  const pattern = new RegExp(
    "^" +
      section.path
        .split(/(:\w+)/)
        .map((part) => {
          if (part.startsWith(":")) {
            names.push(part.slice(1));
            return "([^/?]+)";
          }
          return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        })
        .join("") +
      "$",
  );
  for (const m of section.body.matchAll(/\]\((\/[^)\s]*)\)/g)) {
    const [hrefPath, hrefQuery = ""] = m[1].split("?");
    const hit = pattern.exec(hrefPath);
    if (!hit) continue;
    names.forEach((n, i) => (result.path[n] = decodeURIComponent(hit[i + 1])));
    for (const [k, v] of new URLSearchParams(hrefQuery)) result.query[k] = v;
    break;
  }
  return result;
}

function renderTryIt(section: DocSection): string {
  const path = section.path as string;
  const pathParams = [...path.matchAll(/:(\w+)/g)].map((m) => m[1]);
  const queryParams = [...new Set([...section.headingQuery, ...tableQueryParams(section.body)])];
  const defaults = exampleDefaults(section);

  const field = (kind: "path" | "query", name: string, value: string) =>
    `<label class="tryit-field"><span>${escapeHtml(name)}${kind === "query" ? " <em>(optional)</em>" : ""}</span>` +
    `<input data-kind="${kind}" name="${escapeHtml(name)}" value="${escapeHtml(value)}" autocomplete="off" spellcheck="false"></label>`;

  const fields = [
    ...pathParams.map((n) => field("path", n, defaults.path[n] ?? "")),
    ...queryParams.map((n) => field("query", n, defaults.query[n] ?? "")),
  ].join("");

  return `<form class="tryit" data-path="${escapeHtml(path)}" hidden>
  ${fields ? `<div class="tryit-fields">${fields}</div>` : ""}
  <div class="tryit-actions"><button class="btn btn-primary" type="submit">Send request</button></div>
  <div class="tryit-out" hidden>
    <div class="tryit-status" role="status"></div>
    <div class="tryit-links"><code class="tryit-curl"></code> <a class="tryit-open" target="_blank" rel="noopener noreferrer">Open in new tab</a></div>
    <pre class="tryit-body"></pre>
  </div>
</form>`;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function renderSection(section: DocSection, basePath: string): string {
  const tryable = isTryable(section);
  const header = section.method
    ? `<div class="endpoint"><span class="method method-${section.method.toLowerCase()}">${section.method}</span>` +
      `<code class="endpoint-path">${escapeHtml(section.path ?? "")}</code>` +
      (tryable
        ? `<button type="button" class="btn btn-secondary tryit-toggle">Try It</button>`
        : "") +
      `</div>`
    : "";
  return `<section class="doc-section" id="${escapeHtml(section.id)}">
  <h2 class="doc-title">${escapeHtml(section.title)}</h2>
  ${header}
  ${tryable ? renderTryIt(section) : ""}
  <div class="doc-body">${renderMarkdownToHtml(section.body, basePath)}</div>
</section>`;
}

function renderSidebar(groups: DocGroup[]): string {
  const items = groups
    .map((g) => {
      const links = g.sections
        .map((s) => {
          const tag = s.method
            ? `<span class="method method-${s.method.toLowerCase()} method-sm">${s.method}</span>`
            : "";
          return `<li><a class="side-link" href="#${escapeHtml(s.id)}" data-search="${escapeHtml(`${s.title} ${s.path ?? ""}`.toLowerCase())}">${tag}<span>${escapeHtml(s.title)}</span></a></li>`;
        })
        .join("\n");
      return `<div class="side-group"><h3>${escapeHtml(g.title)}</h3><ul>${links}</ul></div>`;
    })
    .join("\n");
  return `<aside class="sidebar">
  <input id="side-filter" type="search" placeholder="Filter endpoints…" aria-label="Filter endpoints">
  <nav aria-label="API sections">${items}</nav>
</aside>`;
}

const STYLES = String.raw`
  body { font-size: 14px; line-height: 1.6; }
  .nav { margin-bottom: 0; }
  .docs-layout { display: grid; grid-template-columns: 290px minmax(0, 1fr); gap: 32px; max-width: 1280px; margin: 0 auto; padding: 24px; align-items: start; }
  .sidebar { position: sticky; top: 16px; max-height: calc(100vh - 32px); overflow-y: auto; padding-right: 4px; }
  .sidebar input { margin-bottom: 14px; }
  .side-group { margin-bottom: 16px; }
  .side-group h3 { margin: 0 0 6px; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; }
  .side-group ul { list-style: none; margin: 0; padding: 0; }
  .side-link { display: flex; align-items: center; gap: 8px; padding: 5px 8px; border-radius: 6px; color: #374151; font-size: 0.86rem; line-height: 1.35; }
  .side-link:hover { background: #e5e7eb; text-decoration: none; }
  .side-link.active { background: #dbeafe; color: #1e3a8a; font-weight: 600; }
  .pane { min-width: 0; background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 28px 32px; max-width: 900px; }
  .js .doc-section:not(.active) { display: none; }
  .doc-section + .doc-section { margin-top: 40px; padding-top: 24px; border-top: 1px solid #e5e7eb; }
  .js .doc-section + .doc-section { margin-top: 0; padding-top: 0; border-top: 0; }
  .doc-title { font-size: 1.35rem; margin: 0 0 14px; color: #111; }
  .endpoint { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; padding: 10px 14px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; }
  .endpoint-path { font-size: 14px; font-weight: 600; word-break: break-all; }
  .endpoint .tryit-toggle { margin-left: auto; padding: 5px 12px; }
  .method { display: inline-block; min-width: 3.4em; text-align: center; padding: 2px 8px; border-radius: 4px; font: 700 11px ui-monospace, SFMono-Regular, Menlo, monospace; color: #fff; background: #6b7280; }
  .method-sm { min-width: 2.9em; padding: 1px 5px; font-size: 10px; }
  .method-get { background: #15803d; }
  .method-post { background: #b45309; }
  .method-put, .method-patch { background: #1d4ed8; }
  .method-delete { background: #b91c1c; }
  .tryit { margin: -6px 0 20px; padding: 14px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; }
  .tryit[hidden], .tryit-out[hidden] { display: none; }
  .tryit-fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-bottom: 12px; }
  .tryit-field { display: grid; gap: 4px; font-size: 0.78rem; font-weight: 700; color: #374151; }
  .tryit-field em { font-weight: 400; color: #6b7280; font-style: normal; }
  .tryit-field input { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; font-weight: 400; }
  .tryit-actions { display: flex; gap: 10px; }
  .tryit-out { margin-top: 14px; }
  .tryit-status { font-weight: 700; font-size: 0.85rem; margin-bottom: 6px; }
  .tryit-status.ok { color: #15803d; }
  .tryit-status.err { color: #b91c1c; }
  .tryit-links { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; font-size: 0.8rem; color: #6b7280; }
  .tryit-body { max-height: 420px; overflow: auto; }
  h3, h4, h5 { margin: 24px 0 8px; color: #111; }
  h4 { font-size: 0.95rem; }
  h5 { font-size: 0.88rem; }
  .doc-body p { margin: 8px 0; }
  .doc-body hr { border: none; border-top: 1px solid #e5e7eb; margin: 24px 0; }
  pre { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; overflow-x: auto; margin: 10px 0; }
  code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }
  p code, li code, td code { background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }
  blockquote { margin: 12px 0; padding: 4px 16px; border-left: 3px solid #d1d5db; background: #f9fafb; color: #4b5563; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; margin: 10px 0; font-size: 13px; }
  th { background: #f9fafb; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; padding: 9px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  td { padding: 8px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
  ul { margin: 8px 0 8px 20px; }
  li { margin: 3px 0; }
  .doc-body p a, .doc-body li a { background: #eff6ff; border: 1px solid #bfdbfe; padding: 0 6px; border-radius: 4px; font-size: 12.5px; }
  .doc-body p a:hover, .doc-body li a:hover { background: #dbeafe; text-decoration: none; }
  .doc-body a code { background: none; padding: 0; color: inherit; }
  @media (max-width: 800px) {
    .docs-layout { grid-template-columns: 1fr; gap: 16px; padding: 16px; }
    .sidebar { position: static; max-height: 260px; }
    .pane { padding: 20px 16px; }
  }
`;

// Plain browser JS (String.raw keeps the regex backslashes). The only server-injected value
// is BASE, the deployment base path, JSON-encoded.
const CLIENT_SCRIPT = String.raw`
(function () {
  var BASE = __BASE__;
  document.documentElement.classList.add("js");
  var sections = Array.prototype.slice.call(document.querySelectorAll(".doc-section"));
  var links = Array.prototype.slice.call(document.querySelectorAll(".side-link"));

  function show() {
    var id = "";
    try { id = decodeURIComponent(location.hash.slice(1)); } catch (e) {}
    var target = id ? document.getElementById(id) : null;
    var sec = target ? target.closest(".doc-section") : null;
    if (!sec) { sec = sections[0]; target = null; }
    sections.forEach(function (s) { s.classList.toggle("active", s === sec); });
    links.forEach(function (l) {
      var on = l.getAttribute("href") === "#" + sec.id;
      l.classList.toggle("active", on);
      if (on) l.setAttribute("aria-current", "page"); else l.removeAttribute("aria-current");
    });
    if (target && target !== sec) target.scrollIntoView(); else window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", show);
  show();

  var filter = document.getElementById("side-filter");
  filter.addEventListener("input", function () {
    var q = filter.value.trim().toLowerCase();
    links.forEach(function (l) {
      l.parentNode.hidden = q !== "" && l.getAttribute("data-search").indexOf(q) === -1;
    });
    Array.prototype.forEach.call(document.querySelectorAll(".side-group"), function (g) {
      g.hidden = !g.querySelector("li:not([hidden])");
    });
  });

  function build(form) {
    var missing = [];
    var path = form.getAttribute("data-path").replace(/:(\w+)/g, function (_m, n) {
      var input = form.querySelector('[data-kind="path"][name="' + n + '"]');
      var v = input ? input.value.trim() : "";
      if (!v) missing.push(n);
      return encodeURIComponent(v);
    });
    var qs = new URLSearchParams();
    Array.prototype.forEach.call(form.querySelectorAll('[data-kind="query"]'), function (i) {
      if (i.value.trim()) qs.append(i.name, i.value.trim());
    });
    var q = qs.toString();
    return { url: BASE + path + (q ? "?" + q : ""), missing: missing };
  }

  function send(form) {
    var out = form.querySelector(".tryit-out");
    var status = form.querySelector(".tryit-status");
    var pre = form.querySelector(".tryit-body");
    var built = build(form);
    out.hidden = false;
    status.className = "tryit-status";
    if (built.missing.length) {
      status.className = "tryit-status err";
      status.textContent = "Missing: " + built.missing.join(", ");
      pre.textContent = "";
      return;
    }
    form.querySelector(".tryit-curl").textContent = 'curl "' + location.origin + built.url + '"';
    form.querySelector(".tryit-open").setAttribute("href", built.url);
    status.textContent = "Sending…";
    pre.textContent = "";
    var t0 = performance.now();
    fetch(built.url, { headers: { Accept: "application/json" } })
      .then(function (r) { return r.text().then(function (t) { return { r: r, t: t }; }); })
      .then(function (x) {
        var ms = Math.round(performance.now() - t0);
        status.className = "tryit-status " + (x.r.ok ? "ok" : "err");
        status.textContent = x.r.status + " " + x.r.statusText + " · " + ms + " ms";
        var body = x.t;
        try { body = JSON.stringify(JSON.parse(x.t), null, 2); } catch (e) {}
        pre.textContent = body;
      })
      .catch(function (err) {
        status.className = "tryit-status err";
        status.textContent = "Request failed: " + err.message;
      });
  }

  Array.prototype.forEach.call(document.querySelectorAll(".tryit"), function (form) {
    form.addEventListener("submit", function (e) { e.preventDefault(); send(form); });
  });
  Array.prototype.forEach.call(document.querySelectorAll(".tryit-toggle"), function (btn) {
    btn.addEventListener("click", function () {
      var form = btn.closest(".doc-section").querySelector(".tryit");
      var input = form.querySelector("input");
      form.hidden = false;
      if (input) input.focus(); else send(form);
    });
  });
})();
`;

export function renderApiDocsHtml(markdown: string, basePath: string): string {
  const groups = parseApiDocs(markdown);
  const sections = groups.flatMap((g) => g.sections);
  const base = JSON.stringify(withBase(basePath, "")).replace(/</g, "\\u003c");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Walrus API Docs</title>
  <style>${BASE_PAGE_STYLES}${STYLES}</style>
</head>
<body>
  ${renderPublicNav(basePath, "api")}
  <div class="docs-layout">
    ${renderSidebar(groups)}
    <main class="pane">
      ${sections.map((s) => renderSection(s, basePath)).join("\n")}
    </main>
  </div>
  <script>${CLIENT_SCRIPT.replace("__BASE__", () => base)}</script>
</body>
</html>`;
}

export function createApiDocsRouter(basePath: string): Router {
  const router = Router();
  router.get("/", (req: Request, res: Response) => {
    if (req.headers.accept?.includes("text/html")) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderApiDocsHtml(API_DOCS_MARKDOWN, basePath));
    } else {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.send(API_DOCS_MARKDOWN);
    }
  });
  return router;
}
