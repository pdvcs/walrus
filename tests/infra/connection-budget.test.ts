import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

/**
 * WAL-96. Cloud Run's default ceiling is 100 instances and pg's default pool is 10, so untouched
 * defaults ask a db-f1-micro for ~1,000 connections against a max_connections of ~25 — a spike
 * makes Cloud Run scale up and every new instance then fails to reach Postgres, so scaling itself
 * becomes the outage.
 *
 * The budget is enforced for real by a `precondition` on the Cloud Run service, which fails
 * `terraform plan` outright. These assertions are the CI-side copy for runs with no terraform
 * binary, and they check the *invariant* rather than today's numbers: raising the Cloud SQL tier
 * and all four variables together for UAT/production must keep passing, while raising the ceiling
 * alone must not.
 */
const tfVarDefault = (src: string, name: string): number => {
  const m = src.match(new RegExp(`variable "${name}"[\\s\\S]*?default\\s+=\\s+(\\d+)`));
  expect(m, `variable "${name}" has no numeric default`).not.toBeNull();
  return Number(m![1]);
};

describe("Cloud SQL connection budget", () => {
  const variables = read("infra/terraform/variables.tf");
  const cloudRun = read("infra/terraform/cloudrun.tf");

  it("declares the budget rather than inheriting Cloud Run's and pg's defaults", () => {
    expect(cloudRun).toContain("max_instance_count = var.cloud_run_max_instances");
    expect(read("src/db/client.ts")).toContain("max: config.DB_POOL_MAX");
    for (const v of [
      "db_usable_connections",
      "service_db_pool_max",
      "job_db_pool_max",
      "cloud_run_max_instances",
    ]) {
      expect(tfVarDefault(variables, v)).toBeGreaterThan(0);
    }
    // A default is still needed for local dev and tests, but it must not be pg's 10.
    const m = read("src/config/index.ts").match(/DB_POOL_MAX: z[\s\S]*?default\((\d+)\)/);
    expect(Number(m![1])).toBeLessThan(10);
  });

  it("wires every workload to the variables, leaving no literal pool size behind", () => {
    const refs = [...cloudRun.matchAll(/name {2}= "DB_POOL_MAX"\n\s*value = ([^\n]+)/g)].map((m) =>
      m[1].trim(),
    );
    // The service and both Cloud Run Jobs.
    expect(refs).toHaveLength(3);
    expect(refs.filter((r) => r.includes("var.service_db_pool_max"))).toHaveLength(1);
    expect(refs.filter((r) => r.includes("var.job_db_pool_max"))).toHaveLength(2);
    expect(refs.filter((r) => /^"\d+"$/.test(r))).toHaveLength(0);
  });

  it("keeps the declared defaults inside the declared budget", () => {
    const worstCase =
      tfVarDefault(variables, "service_db_pool_max") *
        tfVarDefault(variables, "cloud_run_max_instances") +
      tfVarDefault(variables, "job_db_pool_max") * 2;
    expect(worstCase).toBeLessThanOrEqual(tfVarDefault(variables, "db_usable_connections"));
  });

  it("enforces the invariant at plan time, not merely in this suite", () => {
    // A `check` block would only warn; a precondition refuses the plan. Verified live: raising
    // cloud_run_max_instances alone exits 1, while raising the tier and all four together plans.
    expect(cloudRun).toMatch(/precondition\s*\{[\s\S]*?var\.db_usable_connections/);
    expect(cloudRun).toMatch(
      /condition\s+=\s+\(\(var\.service_db_pool_max \* var\.cloud_run_max_instances\) \+ \(var\.job_db_pool_max \* 2\)\) <= var\.db_usable_connections/,
    );
  });
});
