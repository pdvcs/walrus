import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  configureEgress,
  getEgressState,
  loadEgressConfig,
  loadEgressRulesFromFile,
  matchEgressRule,
  parseEgressRules,
} from "../../src/common/egress-rules.js";

describe("parseEgressRules", () => {
  it("parses a rule with no headers or purpose", () => {
    const rules = parseEgressRules(`
[[rule]]
match = "https://github.com/"
rewrite = "https://artifactory.corp/artifactory/github-remote/"
`);
    expect(rules).toEqual([
      {
        match: "https://github.com/",
        rewrite: "https://artifactory.corp/artifactory/github-remote/",
        headers: undefined,
        purpose: undefined,
      },
    ]);
  });

  it("parses the catch-all case from WAL-113 with no special handling", () => {
    const rules = parseEgressRules(`
[[rule]]
match = "https://"
rewrite = "https://my-rewriting-proxy/url/https://"
`);
    expect(rules).toHaveLength(1);
    expect(rules[0].match).toBe("https://");
    expect(rules[0].rewrite).toBe("https://my-rewriting-proxy/url/https://");
  });

  it("interpolates ${VAR} in header values from the environment at load time", () => {
    const rules = parseEgressRules(
      `
[[rule]]
match = "https://github.com/"
rewrite = "https://artifactory.corp/github-remote/"
headers = { Authorization = "Bearer \${ARTIFACTORY_TOKEN}" }
`,
      { ARTIFACTORY_TOKEN: "s3cr3t" },
    );
    expect(rules[0].headers).toEqual({ Authorization: "Bearer s3cr3t" });
  });

  it("throws on an unresolvable ${VAR} rather than shipping the literal placeholder", () => {
    expect(() =>
      parseEgressRules(
        `
[[rule]]
match = "https://github.com/"
rewrite = "https://artifactory.corp/github-remote/"
headers = { Authorization = "Bearer \${MISSING_TOKEN}" }
`,
        {},
      ),
    ).toThrow(/MISSING_TOKEN/);
  });

  it("parses an optional purpose restriction", () => {
    const rules = parseEgressRules(`
[[rule]]
match = "https://services.nvd.nist.gov/"
purpose = "vuln-feed"
rewrite = "https://egress.corp/nvd/"
`);
    expect(rules[0].purpose).toBe("vuln-feed");
  });

  it("rejects an invalid purpose value at load time", () => {
    expect(() =>
      parseEgressRules(`
[[rule]]
match = "https://x/"
rewrite = "https://y/"
purpose = "not-a-real-purpose"
`),
    ).toThrow();
  });

  it("rejects malformed TOML", () => {
    expect(() => parseEgressRules("this is not [ valid toml")).toThrow(/Invalid egress rules TOML/);
  });

  it("rejects an unknown top-level key (schema is strict)", () => {
    expect(() =>
      parseEgressRules(`
surprise = "field"
[[rule]]
match = "https://x/"
rewrite = "https://y/"
`),
    ).toThrow(/Invalid egress rules/);
  });

  it("an empty rule file parses to zero rules", () => {
    expect(parseEgressRules("")).toEqual([]);
  });
});

describe("loadEgressRulesFromFile", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-egress-rules-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads and parses a real file", () => {
    const filePath = path.join(tmpDir, "rules.toml");
    fs.writeFileSync(
      filePath,
      `[[rule]]
match = "https://"
rewrite = "https://my-rewriting-proxy/url/https://"
`,
    );
    const rules = loadEgressRulesFromFile(filePath);
    expect(rules).toHaveLength(1);
  });

  it("fails fast with a clear error when the file is missing", () => {
    expect(() => loadEgressRulesFromFile(path.join(tmpDir, "does-not-exist.toml"))).toThrow(
      /Unable to read egress rules/,
    );
  });
});

describe("matchEgressRule", () => {
  it("implements the WAL-113 catch-all wrap: any https URL wrapped, no special-casing", () => {
    const rules = [{ match: "https://", rewrite: "https://my-rewriting-proxy/url/https://" }];
    const result = matchEgressRule("https://example.test/pkg/v1/x.tar.gz", "artifact", rules);
    expect(result?.rewrittenUrl).toBe(
      "https://my-rewriting-proxy/url/https://example.test/pkg/v1/x.tar.gz",
    );
  });

  it("replaces only the matched prefix, preserving the remainder verbatim", () => {
    const rules = [
      { match: "https://github.com/", rewrite: "https://artifactory.corp/github-remote/" },
    ];
    const result = matchEgressRule(
      "https://github.com/foo/bar/releases/download/v1/x.tar.gz",
      "artifact",
      rules,
    );
    expect(result?.rewrittenUrl).toBe(
      "https://artifactory.corp/github-remote/foo/bar/releases/download/v1/x.tar.gz",
    );
  });

  it("returns null when nothing matches", () => {
    const rules = [{ match: "https://github.com/", rewrite: "https://x/" }];
    expect(matchEgressRule("https://example.test/y", "artifact", rules)).toBeNull();
  });

  it("longest prefix wins regardless of array order", () => {
    const rules = [
      { match: "https://", rewrite: "https://catch-all/" },
      { match: "https://github.com/", rewrite: "https://specific/" },
    ];
    expect(matchEgressRule("https://github.com/x", "artifact", rules)?.rewrittenUrl).toBe(
      "https://specific/x",
    );
    expect(matchEgressRule("https://gitlab.test/x", "artifact", rules)?.rewrittenUrl).toBe(
      "https://catch-all/gitlab.test/x",
    );
  });

  it("a rule with no purpose applies to every traffic class", () => {
    const rules = [{ match: "https://x/", rewrite: "https://y/" }];
    for (const purpose of ["discovery", "artifact", "checksum", "vuln-feed", "auth"] as const) {
      expect(matchEgressRule("https://x/z", purpose, rules)).not.toBeNull();
    }
  });

  it("a rule scoped to one purpose does not match a different one", () => {
    const rules = [{ match: "https://x/", rewrite: "https://y/", purpose: "vuln-feed" as const }];
    expect(matchEgressRule("https://x/z", "vuln-feed", rules)).not.toBeNull();
    expect(matchEgressRule("https://x/z", "artifact", rules)).toBeNull();
  });

  it("exposes matched headers, defaulting to an empty object", () => {
    const withHeaders = [
      { match: "https://x/", rewrite: "https://y/", headers: { Authorization: "Bearer t" } },
    ];
    expect(matchEgressRule("https://x/z", "artifact", withHeaders)?.headers).toEqual({
      Authorization: "Bearer t",
    });

    const withoutHeaders = [{ match: "https://x/", rewrite: "https://y/" }];
    expect(matchEgressRule("https://x/z", "artifact", withoutHeaders)?.headers).toEqual({});
  });
});

describe("loadEgressConfig / configureEgress / getEgressState", () => {
  afterEach(() => {
    configureEgress({ mode: "direct", rules: [] });
  });

  it("defaults to direct mode with zero rules when no file is configured", () => {
    const state = loadEgressConfig({ mode: "direct" });
    expect(state).toEqual({ mode: "direct", rules: [] });
    expect(getEgressState()).toEqual({ mode: "direct", rules: [] });
  });

  it("loads and applies a rules file, and getEgressState reflects it", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-egress-config-"));
    try {
      const filePath = path.join(tmpDir, "rules.toml");
      fs.writeFileSync(
        filePath,
        `[[rule]]
match = "https://x/"
rewrite = "https://y/"
`,
      );
      const state = loadEgressConfig({ rulesFile: filePath, mode: "strict" });
      expect(state.mode).toBe("strict");
      expect(state.rules).toHaveLength(1);
      expect(getEgressState()).toEqual(state);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("throws — fail-fast, same contract as loadConfig() — on a malformed rules file", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-egress-config-bad-"));
    try {
      const filePath = path.join(tmpDir, "rules.toml");
      fs.writeFileSync(filePath, "not [ valid toml");
      expect(() => loadEgressConfig({ rulesFile: filePath, mode: "direct" })).toThrow();
      // A failed load must not silently leave a partial/previous config active as "current" —
      // configureEgress is only called after loadEgressRulesFromFile succeeds.
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
