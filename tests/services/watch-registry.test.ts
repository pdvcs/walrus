import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { loadWatchConfig, loadAllWatchConfigs } from "../../src/services/watch-registry.js";
import { computeVulnInput } from "../../src/services/vuln-config.js";

const FIXTURES_DIR = path.join(os.tmpdir(), "walrus-test-watchlist");

const VALID_TERRAFORM_TOML = `
name = "terraform"
display_name = "Terraform"
vendor = "HashiCorp (IBM)"
website = "https://developer.hashicorp.com/terraform"
description = "Infrastructure-as-code provisioning tool"

[vulnerabilities]
cpes = ["hashicorp:terraform"]
osv = { ecosystem = "Go", name = "github.com/hashicorp/terraform" }
aliases = ["terraform", "tf", "hashicorp terraform"]
`;

// A watch entry exists only to be vuln-tracked, so [vulnerabilities] is required
// here even though it is optional on a served package config.
const NO_VULN_SECTION_TOML = `
name = "consul"
display_name = "Consul"
vendor = "HashiCorp (IBM)"
`;

const BAD_CPE_TOML = `
name = "vault"
display_name = "Vault"
vendor = "HashiCorp (IBM)"

[vulnerabilities]
cpes = ["cpe:2.3:a:hashicorp:vault"]
`;

describe("loadWatchConfig", () => {
  beforeAll(() => {
    fs.mkdirSync(FIXTURES_DIR, { recursive: true });
    fs.writeFileSync(path.join(FIXTURES_DIR, "terraform.toml"), VALID_TERRAFORM_TOML);
    fs.writeFileSync(path.join(FIXTURES_DIR, "consul.toml"), NO_VULN_SECTION_TOML);
    fs.writeFileSync(path.join(FIXTURES_DIR, "vault.toml"), BAD_CPE_TOML);
  });

  afterAll(() => {
    fs.rmSync(FIXTURES_DIR, { recursive: true, force: true });
  });

  it("parses a valid watch config", () => {
    const config = loadWatchConfig(path.join(FIXTURES_DIR, "terraform.toml"));
    expect(config.name).toBe("terraform");
    expect(config.vulnerabilities.cpes).toEqual(["hashicorp:terraform"]);
    expect(config.vulnerabilities.osv).toEqual({
      ecosystem: "Go",
      name: "github.com/hashicorp/terraform",
    });
  });

  it("rejects a watch config without a [vulnerabilities] section", () => {
    expect(() => loadWatchConfig(path.join(FIXTURES_DIR, "consul.toml"))).toThrow(
      /vulnerabilities/,
    );
  });

  it("rejects a full CPE 2.3 string where a vendor:product pair is expected", () => {
    expect(() => loadWatchConfig(path.join(FIXTURES_DIR, "vault.toml"))).toThrow(
      /vendor.*product.*pair/i,
    );
  });

  it("collects successes and errors separately", () => {
    const { configs, errors } = loadAllWatchConfigs(FIXTURES_DIR);
    expect(configs.map((c) => c.config.name)).toEqual(["terraform"]);
    expect(errors.map((e) => path.basename(e.filePath)).sort()).toEqual([
      "consul.toml",
      "vault.toml",
    ]);
  });

  it("treats a missing watchlist directory as empty, not an error", () => {
    const result = loadAllWatchConfigs(path.join(os.tmpdir(), "walrus-no-such-watchlist"));
    expect(result).toEqual({ configs: [], errors: [] });
  });
});

describe("computeVulnInput on a watch config", () => {
  it("derives the same shape as a served package config", () => {
    const config = {
      name: "terraform",
      display_name: "Terraform",
      vendor: "HashiCorp (IBM)",
      vulnerabilities: {
        cpes: ["hashicorp:terraform"],
        osv: { ecosystem: "Go", name: "github.com/hashicorp/terraform" },
        aliases: ["terraform", "tf", "HashiCorp Terraform"],
      },
    };

    const input = computeVulnInput(config);
    expect(input).not.toBeNull();
    expect(input!.packageName).toBe("terraform");
    // Own name + display name are always resolvable, aliases are normalized.
    expect(input!.aliases.sort()).toEqual(["hashicorp terraform", "terraform", "tf"]);
    expect(input!.cpes).toEqual([
      { cpe_vendor: "hashicorp", cpe_product: "terraform", is_primary: true },
    ]);
    expect(input!.osvEcosystem).toBe("Go");
    expect(input!.osvName).toBe("github.com/hashicorp/terraform");
  });
});
