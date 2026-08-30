import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

// WAL-92. The gap this covers was found by hand (`rg NVD_API_KEY infra/` returning nothing)
// after the runbook had promised a production key for months. These are static wiring checks,
// not behaviour: the live rate-limit proof is the ticket's MANUAL_TEST.
describe("NVD API key deployment wiring", () => {
  it("declares the secret without committing its value", () => {
    const secrets = read("infra/terraform/secrets.tf");
    expect(secrets).toContain('secret_id = "walrus-nvd-api-key"');
    expect(secrets).not.toMatch(/secret_data|google_secret_manager_secret_version/);
  });

  it("mounts NVD_API_KEY on every workload that can reach NVD", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    // The walrus-api service, the walrus-vuln-backfill job, and the walrus-sync job.
    expect(cloudRun.match(/name = "NVD_API_KEY"/g)).toHaveLength(3);
    expect(
      cloudRun.match(/secret {2}= google_secret_manager_secret\.nvd_api_key\.secret_id/g),
    ).toHaveLength(3);
    // Never a literal: the key reaches the container through Secret Manager or not at all.
    expect(cloudRun).not.toMatch(/NVD_API_KEY"[\s\S]{0,80}?\n\s*value\s*=/);
  });

  it("keeps the mount conditional so a keyless project can still deploy", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    const variables = read("infra/terraform/variables.tf");
    // Cloud Run refuses to start a revision referencing a secret with no versions, so an
    // unconditional secret_key_ref would turn "no key supplied" into a failed deploy.
    expect(cloudRun.match(/for_each = var\.nvd_api_key_configured \? \[1\] : \[\]/g)).toHaveLength(
      3,
    );
    expect(variables).toContain('variable "nvd_api_key_configured"');
    expect(variables).toMatch(/variable "nvd_api_key_configured"[\s\S]*?default {5}= false/);
  });

  it("grants secretAccessor for the key to the account the workloads run as", () => {
    const iam = read("infra/terraform/iam.tf");
    const cloudRun = read("infra/terraform/cloudrun.tf");
    expect(iam).toMatch(
      /secret_id = google_secret_manager_secret\.nvd_api_key\.secret_id\n\s*role\s*= "roles\/secretmanager\.secretAccessor"\n\s*member\s*= "serviceAccount:\$\{google_service_account\.walrus_api\.email\}"/,
    );
    // One binding only covers all three workloads because they share the service account.
    expect(
      cloudRun.match(/service_account = google_service_account\.walrus_api\.email/g),
    ).toHaveLength(3);
  });

  it("treats the key as optional in deploy.sh and derives the Terraform flag from it", () => {
    const deploy = read("infra/scripts/deploy.sh");
    // Not in the hard-required list — a fresh project bootstraps keyless (WAL-92 AC4).
    expect(deploy).toMatch(/^for var in (?!.*NVD_API_KEY).*$/m);
    expect(deploy).toContain('export TF_VAR_nvd_api_key_configured="true"');
    expect(deploy).toContain('export TF_VAR_nvd_api_key_configured="false"');
    // Populated before the apply that wires the reference, like every other runtime secret.
    const populate = deploy.indexOf("populate_secret walrus-nvd-api-key");
    const apply = deploy.indexOf('terraform -chdir="${TF_DIR}" apply -auto-approve', populate);
    expect(populate).toBeGreaterThan(0);
    expect(apply).toBeGreaterThan(populate);
    // Never a Terraform variable value — it would land in plan output and in state.
    expect(deploy).not.toContain("TF_VAR_nvd_api_key=");
  });
});
