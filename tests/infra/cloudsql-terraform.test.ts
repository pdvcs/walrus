import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

// WAL-94, found by the first real `terraform apply` (2026-08-30): all three compute resources
// built the Cloud SQL connection name as a literal from var.project_id/var.region, so Terraform's
// graph had no edge to the database at all. The apply created the service alongside a still-
// initialising instance, the container fails fast on an unreachable database, and the failure
// surfaced as an opaque "failed the configured startup probe checks".
describe("Cloud SQL dependency wiring", () => {
  it("references the instance instead of reconstructing its connection name", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    // The service and both Jobs.
    expect(
      cloudRun.match(/instances = \[google_sql_database_instance\.walrus\.connection_name\]/g),
    ).toHaveLength(3);
    // The literal form is what removed the edge; it must not come back.
    expect(cloudRun).not.toMatch(/instances = \["\$\{var\.project_id\}/);
  });

  it("waits for the database and user the container connects as", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    // A RUNNABLE instance is not enough — an in-flight user or database operation leaves it
    // unable to issue an ephemeral cert (409 invalidState).
    expect(
      cloudRun.match(
        /depends_on = \[\s*google_sql_database\.walrus,\s*google_sql_user\.walrus,\s*\]/g,
      ),
    ).toHaveLength(3);
  });
});
