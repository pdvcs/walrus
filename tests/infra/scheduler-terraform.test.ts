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

/**
 * WAL-106, on top of WAL-105.
 *
 * A Cloud Run 429 — `no available instance` — is a request that never reached walrus: nothing ran,
 * no advisory lock was taken, no cursor was read. Every vuln-sync job must therefore be able to
 * try again, or a tick landing while the service is between instances is silently lost and shows
 * up only as an alert email.
 *
 * `nvd` was the one job with `retries = 0`, and it is also the only source **not** on a shortened
 * cadence in GCP Dev, so it is exactly the one the "dev runs more often anyway" argument does not
 * protect. It is pinned here because the value is one character and the reasoning behind it is a
 * paragraph: the next person to read the comment should not be able to quietly revert the value
 * without the test noticing.
 */
describe("every vuln-sync job can retry a refused tick (WAL-105, WAL-106)", () => {
  const scheduler = read("infra/terraform/scheduler.tf");

  const retriesFor = (source: string) => {
    const start = scheduler.indexOf(`    ${source} = {`);
    expect(start, `no map entry for ${source}`).toBeGreaterThan(-1);
    const m = scheduler.slice(start).match(/retries\s+= (\d+)/);
    expect(m, `no retries for ${source}`).not.toBeNull();
    return Number(m![1]);
  };

  it("gives every source at least one retry", () => {
    for (const source of ["nvd", "kev", "osv", "cvss"]) {
      expect(retriesFor(source), `${source} cannot retry a 429`).toBeGreaterThanOrEqual(1);
    }
  });

  it("keeps osv's larger allowance, since a lost weekly run is stale for seven days", () => {
    expect(retriesFor("osv")).toBeGreaterThanOrEqual(2);
  });

  it("keeps the backoff long enough to clear a min-instance replacement gap", () => {
    // Replacement was observed at 6-16 minutes on 2026-09-01 (WAL-105). The same gap is what lets
    // cvss retry into the nvd lock safely, so shortening it would trade one problem for another.
    const m = scheduler.match(/min_backoff_duration = "(\d+)s"[\s\S]{0,400}?each\.value/);
    const backoff = Number(
      (scheduler.match(/for_each = local\.vuln_sync_jobs[\s\S]*?min_backoff_duration = "(\d+)s"/) ??
        m)![1],
    );
    expect(backoff).toBeGreaterThanOrEqual(600);
  });
});
