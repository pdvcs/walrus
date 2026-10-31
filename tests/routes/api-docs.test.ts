import { readFileSync } from "fs";
import { join } from "path";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createApiDocsRouter,
  isTryable,
  parseApiDocs,
  renderMarkdownToHtml,
  renderApiDocsHtml,
} from "../../src/routes/api-docs.js";

const MD = readFileSync(join(__dirname, "../../src/routes/api-docs.md"), "utf8");
const sections = parseApiDocs(MD).flatMap((g) => g.sections);
const byId = (id: string) => sections.find((s) => s.id === id);
const html = renderApiDocsHtml(MD, "");

function sectionHtml(id: string, source = html): string {
  const start = source.indexOf(`<section class="doc-section" id="${id}">`);
  expect(start).toBeGreaterThan(-1);
  return source.slice(start, source.indexOf("</section>", start));
}

describe("api docs structure", () => {
  it("emits one titled section and sidebar link per ### heading", () => {
    const slug = (x: string) =>
      x
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, "")
        .trim()
        .replace(/\s+/g, "-");
    const headings = MD.split("\n")
      .filter((l) => l.startsWith("### "))
      .map((l) => l.slice(4).split(" | ")[0].trim());
    for (const h of headings) expect(byId(slug(h)), h).toBeDefined();
    for (const s of sections) expect(s.title.trim()).not.toBe("");
    expect(html.match(/class="side-link"/g)?.length).toBe(sections.length);
    expect(new Set(sections.map((s) => s.id)).size).toBe(sections.length);
  });

  it("keeps slugs derived from the endpoint, not the human title", () => {
    expect(byId("get-apiv1packagesnameversions")?.title).toBe("All versions for a package");
    expect(byId("get-apiv1packagesnamevulns")).toBeDefined();
  });

  it("resolves every in-page anchor link to an id in the rendered page", () => {
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    const anchors = [...MD.matchAll(/\]\(#([^)]+)\)/g)].map((m) => m[1]);
    expect(anchors.length).toBeGreaterThan(0);
    for (const a of anchors) expect(ids, `#${a}`).toContain(a);
  });

  it("renders #### as h4 and > as blockquote with no literal markers", () => {
    expect(html).toContain('<h4 id="range-requests">');
    expect(html).toContain("<blockquote>");
    expect(html).not.toMatch(/<p>#{4,5} /);
    expect(html).not.toMatch(/<p>&gt; /);
  });
});

describe("api docs markdown rendering", () => {
  const render = (md: string) => renderMarkdownToHtml(md, "");

  it("renders _italics_ but leaves snake_case and code spans alone", () => {
    expect(render("narrower in what it _fetches_, not in what it _records_.")).toBe(
      "<p>narrower in what it <em>fetches</em>, not in what it <em>records</em>.</p>",
    );
    const literal = render("use `_not_italic_` and my_var_name here");
    expect(literal).not.toContain("<em>");
    expect(literal).toContain("<code>_not_italic_</code>");
  });

  it("renders *italics*, alone and alongside **bold**", () => {
    expect(render("an *emphasised* word")).toBe("<p>an <em>emphasised</em> word</p>");
    expect(render("**bold** then *it* then _it2_")).toBe(
      "<p><strong>bold</strong> then <em>it</em> then <em>it2</em></p>",
    );
    expect(render("***both***")).not.toMatch(/\*/);
    expect(render("2 * 3 * 4")).toBe("<p>2 * 3 * 4</p>");
    expect(render("see `a*b*c` literal")).toContain("<code>a*b*c</code>");
    expect(render("an *it\nalic* span")).toBe("<p>an <em>it alic</em> span</p>");
  });

  it("applies emphasis across a source line break", () => {
    expect(render("a **bold\nphrase** and _it\nalic_")).toBe(
      "<p>a <strong>bold phrase</strong> and <em>it alic</em></p>",
    );
  });

  it("lets bold wrap a code span", () => {
    expect(render("**Resolved + `vulns: []`** ok")).toBe(
      "<p><strong>Resolved + <code>vulns: []</code></strong> ok</p>",
    );
  });

  it("keeps indented continuation lines inside their list item", () => {
    const html = render("- first line\n  second line\n- next\n\nafter");
    expect(html).toBe("<ul>\n<li>first line second line</li>\n<li>next</li>\n</ul>\n<p>after</p>");
  });

  it("renders a fenced block indented under a list item as code", () => {
    const html = render("- item\n  ```bash\n  curl <x>\n  ```\n- other");
    expect(html).toContain("<pre><code>curl &lt;x&gt;\n</code></pre>");
    expect(html).not.toContain("```");
  });

  it("renders the NVD backfill section with no raw markdown markers", () => {
    const nvd = sectionHtml("start-an-nvd-backfill-operator-api");
    expect(nvd).toContain("<em>fetches</em>");
    expect(nvd).not.toMatch(/_fetches_|_records_/);
    // Both bullets stay in one list rather than splitting around a stray paragraph.
    expect(nvd.match(/<ul>/g)?.length).toBe(1);
  });
});

describe("api docs Try It", () => {
  it("builds a prefilled form for the groups endpoint", () => {
    const s = sectionHtml("get-apiv1packagesnamegroups");
    expect(s).toContain('data-path="/api/v1/packages/:name/groups"');
    expect(s).toMatch(/name="name" value="openjdk"/);
    expect(s).toContain('name="os"');
    expect(s).toContain('name="arch"');
  });

  it("has a button but no inputs for the parameterless list endpoint", () => {
    const s = sectionHtml("get-apiv1packages");
    expect(s).toContain("tryit-toggle");
    expect(s).not.toContain("<input");
  });

  it("offers Try It only for public JSON GETs", () => {
    for (const s of sections) {
      if (s.path?.startsWith("/download/") || s.path?.startsWith("/admin/") || s.method !== "GET") {
        expect(isTryable(s), s.id).toBe(false);
      }
    }
    expect(sectionHtml("get-downloadpackageversionosarch")).not.toContain("tryit-toggle");
    expect(sectionHtml("get-adminv1transitions")).not.toContain("tryit-toggle");
  });
});

describe("api docs routing", () => {
  it("carries the base path into links and the fetch prefix", () => {
    const prefixed = renderApiDocsHtml(MD, "/walrus");
    expect(prefixed).toContain('var BASE = "/walrus";');
    expect(prefixed).toContain('href="/walrus/api/v1/packages/openjdk/groups"');
  });

  it("serves HTML to browsers and raw markdown otherwise", async () => {
    const app = express();
    app.use("/api", createApiDocsRouter(""));
    const page = await request(app).get("/api/").set("Accept", "text/html");
    expect(page.status).toBe(200);
    expect(page.text).toContain("docs-layout");
    const md = await request(app).get("/api/").set("Accept", "text/markdown");
    expect(md.text).toBe(MD);
  });
});
