import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const iam = readFileSync(path.join(root, "infra/terraform/iam.tf"), "utf8");

/**
 * WAL-99. `walrus-api` launches the backfill job with `overrides.containerOverrides`, which needs
 * `run.jobs.runWithOverrides`. `roles/run.invoker` grants only `run.jobs.run`, so every launch
 * failed 403 — invisibly, because per-package launch failures are logged and swallowed. The role
 * only evaluates against the real API, so what a test can pin is the shape of the binding.
 */
describe("Cloud Run Job launch permissions", () => {
  it("gives walrus-api a role that permits overrides, not bare invoker", () => {
    const block = iam.slice(iam.indexOf('"walrus_api_backfill_runner"'));
    expect(block).toContain("role     = google_project_iam_custom_role.job_runner.id");
    // The regression: roles/run.invoker on this binding cannot launch with overrides.
    expect(block.slice(0, block.indexOf("}"))).not.toContain("roles/run.invoker");
  });

  it("keeps that role least-privilege rather than reaching for roles/run.developer", () => {
    expect(iam).toMatch(
      /google_project_iam_custom_role" "job_runner"[\s\S]*?permissions = \[\s*"run\.jobs\.run",\s*"run\.jobs\.runWithOverrides",\s*\]/,
    );
    // run.developer would also carry create/update/delete over every Cloud Run resource. Check
    // role *assignments*, not the whole file — the custom role's description names it as the
    // thing being avoided.
    const assigned = [...iam.matchAll(/^\s*role\s*=\s*"([^"]+)"/gm)].map((m) => m[1]);
    expect(assigned).not.toContain("roles/run.developer");
    expect(assigned.length).toBeGreaterThan(0);
  });

  it("leaves the scheduler on plain invoker, which its override-free :run does allow", () => {
    const sched = iam.slice(iam.indexOf('"walrus_scheduler_job_runner"'));
    expect(sched.slice(0, sched.indexOf("}"))).toContain('role     = "roles/run.invoker"');
  });
});
