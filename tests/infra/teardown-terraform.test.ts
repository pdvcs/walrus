import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

// WAL-40, found by the first real `terraform plan` (2026-08-30): both Cloud Run Jobs planned with
// the provider's default `deletion_protection = true`, which only the service had opted out of.
// `teardown.sh` lowered the Cloud SQL and bucket protections but not the Jobs', so `destroy`
// aborted on them — after the targeted apply had already stripped the other two. Half-torn-down
// is worse than either outcome, so the three overrides have to stay in lockstep.
describe("teardown deployment wiring", () => {
  it("keeps every deletion guard behind a variable that defaults to protected", () => {
    const variables = read("infra/terraform/variables.tf");
    for (const [name, dflt] of [
      ["sql_deletion_protection", "true"],
      ["job_deletion_protection", "true"],
      ["gcs_force_destroy", "false"],
    ]) {
      expect(variables).toMatch(new RegExp(`variable "${name}"[\\s\\S]*?default {5}= ${dflt}`));
    }
  });

  it("protects both Cloud Run Jobs, not just the service", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    // The Jobs go through the variable; the service opts out outright, as it always has.
    expect(cloudRun.match(/deletion_protection = var\.job_deletion_protection/g)).toHaveLength(2);
    expect(cloudRun.match(/resource "google_cloud_run_v2_job"/g)).toHaveLength(2);
  });

  it("lowers all three guards in teardown, on both the targeted apply and the destroy", () => {
    const teardown = read("infra/scripts/teardown.sh");
    for (const override of [
      "sql_deletion_protection=false",
      "job_deletion_protection=false",
      "gcs_force_destroy=true",
    ]) {
      // Once in the targeted apply that lowers them, once in the destroy that relies on it.
      expect(
        teardown.match(new RegExp(override.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")),
      ).toHaveLength(2);
    }
    // The targeted apply must actually reach the Jobs, or the variable never lands on them.
    expect(teardown).toContain("-target=google_cloud_run_v2_job.sync");
    expect(teardown).toContain("-target=google_cloud_run_v2_job.vuln_backfill");
  });

  it("versions the Terraform state bucket it creates", () => {
    // The state is the only record of the deployment; a truncated write is otherwise final.
    expect(read("infra/scripts/deploy.sh")).toMatch(
      /buckets create "gs:\/\/\$\{TERRAFORM_STATE_BUCKET\}"[\s\S]*?buckets update "gs:\/\/\$\{TERRAFORM_STATE_BUCKET\}"[\s\S]*?--versioning/,
    );
  });
});
