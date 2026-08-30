import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

/**
 * WAL-48. The scheduled cvss run had no body at all, so it walked the entire un-scored backlog
 * and was cut off mid-walk on a large one. The bound must stay on the *scheduled* job only —
 * `/vuln-sync/all` and the admin trigger are deliberately unbounded (AC5).
 */
describe("scheduled cvss run is bounded", () => {
  const scheduler = read("infra/terraform/scheduler.tf");
  const variables = read("infra/terraform/variables.tf");

  it("sends a limit, sized by a documented variable rather than a buried literal", () => {
    expect(scheduler).toContain("body     = jsonencode({ limit = var.vuln_sync_cvss_limit })");
    const m = variables.match(/variable "vuln_sync_cvss_limit"[\s\S]*?default\s+=\s+(\d+)/);
    expect(m, "vuln_sync_cvss_limit has no numeric default").not.toBeNull();
    const limit = Number(m![1]);
    // Sized for the keyless NVD rate: 4 req/30s over the job's 1800s deadline is ~240 requests,
    // one per candidate. The default must stay under that, since NVD_API_KEY is optional.
    expect(limit).toBeGreaterThan(0);
    expect(limit).toBeLessThan(240);
  });

  it("bounds only cvss — the other three sources send no body", () => {
    // Each source's first `body =` after its map key opens. Comment lines may sit between them.
    const bodyFor = (source: string) => {
      const start = scheduler.indexOf(`    ${source} = {`);
      expect(start, `no map entry for ${source}`).toBeGreaterThan(-1);
      return scheduler
        .slice(start)
        .match(/body\s+= ([^\n]+)/)![1]
        .trim();
    };
    const bodies = ["nvd", "kev", "osv", "cvss"].map((s) => [s, bodyFor(s)]);
    expect(Object.fromEntries(bodies)).toEqual({
      nvd: "null",
      kev: "null",
      osv: "null",
      cvss: "jsonencode({ limit = var.vuln_sync_cvss_limit })",
    });
  });

  it("declares the content type, without which the route cannot parse the body", () => {
    expect(scheduler).toContain(
      'headers = each.value.body == null ? {} : { "Content-Type" = "application/json" }',
    );
    expect(scheduler).toContain("body    = each.value.body == null ? null : base64encode(");
  });
});
