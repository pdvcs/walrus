import { describe, it, expect, vi } from "vitest";
import { runInNewContext } from "node:vm";
import { renderAdminNav } from "../../src/routes/page-shell.js";

/** The chip's script is an async IIFE; let its fetch and json() settle. */
const flush = () => new Promise((resolve) => setImmediate(resolve));

function navChipScript(): string {
  const nav = renderAdminNav();
  const start = nav.indexOf("// nav-suppression-chip:start");
  const end = nav.indexOf("// nav-suppression-chip:end");
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return nav.slice(start, end);
}

async function runChip(response: { ok: boolean; body?: unknown } | Error) {
  const el = { textContent: "", title: "", hidden: true };
  const fetchMock = vi.fn(async () => {
    if (response instanceof Error) throw response;
    return { ok: response.ok, json: async () => response.body };
  });
  runInNewContext(navChipScript(), {
    document: { getElementById: (id: string) => (id === "nav-suppressions" ? el : null) },
    fetch: fetchMock,
  });
  await flush();
  return { el, fetchMock };
}

describe("admin nav suppression chip", () => {
  it("renders hidden and links to the explorer's suppression list", () => {
    const nav = renderAdminNav();
    expect(nav).toContain(
      '<a class="nav-chip" id="nav-suppressions" href="/admin/v1/vulns#active-suppressions" hidden></a>',
    );
  });

  it("shows the count as a glyph and spells it out in the tooltip", async () => {
    const { el, fetchMock } = await runChip({ ok: true, body: { active_count: 3 } });
    expect(fetchMock).toHaveBeenCalledWith("/admin/v1/vuln-suppressions/active-count");
    expect(el.hidden).toBe(false);
    expect(el.textContent).toBe("\u{1F515} 3");
    expect(el.title).toContain("3 active suppressions");
    expect(el.title).toContain("critical-CVE gate");
  });

  it("singularises a lone suppression in the tooltip", async () => {
    const { el } = await runChip({ ok: true, body: { active_count: 1 } });
    expect(el.textContent).toBe("\u{1F515} 1");
    expect(el.title).toContain("1 active suppression —");
  });

  it("stays hidden when nothing is suppressed", async () => {
    const { el } = await runChip({ ok: true, body: { active_count: 0 } });
    expect(el.hidden).toBe(true);
    expect(el.textContent).toBe("");
  });

  // The chip is decoration on every admin page: a logged-out session (401) or a network
  // failure must leave the page working rather than throw into the console.
  it("stays hidden and silent when the count cannot be fetched", async () => {
    expect((await runChip({ ok: false })).el.hidden).toBe(true);
    expect((await runChip(new Error("offline"))).el.hidden).toBe(true);
  });
});
