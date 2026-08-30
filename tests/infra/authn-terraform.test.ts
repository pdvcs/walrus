import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

describe("authentication deployment wiring", () => {
  it("declares and mounts each runtime secret with least-privilege access", () => {
    const secrets = read("infra/terraform/secrets.tf");
    const cloudRun = read("infra/terraform/cloudrun.tf");
    const iam = read("infra/terraform/iam.tf");
    for (const secret of [
      "walrus-session-secret",
      "walrus-session-secret-previous",
      "walrus-admin-password",
    ]) {
      expect(secrets).toContain(`secret_id = "${secret}"`);
    }
    for (const variable of [
      "WALRUS_SESSION_SECRET",
      "WALRUS_SESSION_SECRET_PREVIOUS",
      "WALRUS_ADMIN_PASSWORD",
    ]) {
      expect(cloudRun).toContain(`name = "${variable}"`);
    }
    expect(secrets).not.toMatch(/secret_data|google_secret_manager_secret_version/);
    expect(cloudRun).not.toMatch(
      /value\s*=\s*"[^\n]+"[^\n]*WALRUS_(?:SESSION_SECRET|ADMIN_PASSWORD)/,
    );
    expect(iam.match(/roles\/secretmanager\.secretAccessor/g)).toHaveLength(4);
  });

  it("uses one exact audience and scheduler principal on both sides of machine auth", () => {
    const cloudRun = read("infra/terraform/cloudrun.tf");
    const scheduler = read("infra/terraform/scheduler.tf");
    expect(cloudRun).toContain('name  = "WALRUS_INTERNAL_AUDIENCE"');
    expect(cloudRun).toContain("value = var.internal_oidc_audience");
    expect(cloudRun).toContain('name  = "WALRUS_INTERNAL_SERVICE_ACCOUNT"');
    expect(cloudRun).toContain("value = google_service_account.walrus_scheduler.email");
    expect(scheduler.match(/audience\s+= var\.internal_oidc_audience/g)).toHaveLength(2);
  });

  it("populates and imports secrets before rolling out the boot-validating image", () => {
    const deploy = read("infra/scripts/deploy.sh");
    const populate = deploy.indexOf("populate_secret walrus-session-secret");
    const apply = deploy.indexOf('terraform -chdir="${TF_DIR}" apply -auto-approve', populate);
    const rollout = deploy.indexOf("gcloud run services update walrus-api");
    expect(populate).toBeGreaterThan(0);
    expect(apply).toBeGreaterThan(populate);
    expect(rollout).toBeGreaterThan(apply);
    expect(deploy).not.toContain("TF_VAR_session_secret");
    expect(deploy).not.toContain("TF_VAR_admin_password");
    expect(deploy).toContain("${#WALRUS_SESSION_SECRET} < 32");
    expect(deploy).toContain("${#WALRUS_ADMIN_PASSWORD} < 16");
    expect(deploy).not.toMatch(/set -[^\n]*x/);
  });
});
