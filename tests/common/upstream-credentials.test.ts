import { describe, expect, it, afterEach } from "vitest";
import { config } from "../../src/config/index.js";
import {
  GITHUB_ANONYMOUS_WARNING,
  NVD_KEYLESS_WARNING,
  getUpstreamCredentialStatus,
  warnIfGithubAnonymous,
  warnIfNvdKeyless,
} from "../../src/common/upstream-credentials.js";

function collect(): { warn: (msg: string) => void; msgs: string[] } {
  const msgs: string[] = [];
  return { warn: (msg) => msgs.push(msg), msgs };
}

describe("upstream credentials", () => {
  const originalNvd = config.NVD_API_KEY;
  const originalGithub = process.env.GITHUB_TOKEN;

  afterEach(() => {
    config.NVD_API_KEY = originalNvd;
    if (originalGithub === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = originalGithub;
  });

  it("reports presence only, never the credential", () => {
    config.NVD_API_KEY = "super-secret-key";
    const status = getUpstreamCredentialStatus();

    expect(status).toEqual({ nvd_api_key: true });
    // /app/status is public: a leak here would be a leak to anyone.
    expect(JSON.stringify(status)).not.toContain("super-secret");
  });

  it("treats an empty value as absent", () => {
    // Secret Manager can mount a version holding an empty string, and every consumer of these
    // reads falsy-or-not. A status saying "configured" over an empty key would be worse than
    // saying nothing, because it argues against the operator's own suspicion.
    config.NVD_API_KEY = "";
    process.env.GITHUB_TOKEN = "";

    expect(getUpstreamCredentialStatus().nvd_api_key).toBe(false);
    const nvd = collect();
    warnIfNvdKeyless(nvd);
    expect(nvd.msgs).toEqual([NVD_KEYLESS_WARNING]);
    const github = collect();
    warnIfGithubAnonymous(github);
    expect(github.msgs).toEqual([GITHUB_ANONYMOUS_WARNING]);
  });

  it("warns at boot only when the credential this process needs is missing", () => {
    config.NVD_API_KEY = undefined;
    delete process.env.GITHUB_TOKEN;
    const missing = collect();
    warnIfNvdKeyless(missing);
    warnIfGithubAnonymous(missing);
    expect(missing.msgs).toEqual([NVD_KEYLESS_WARNING, GITHUB_ANONYMOUS_WARNING]);

    config.NVD_API_KEY = "k";
    process.env.GITHUB_TOKEN = "t";
    const configured = collect();
    warnIfNvdKeyless(configured);
    warnIfGithubAnonymous(configured);
    expect(configured.msgs).toEqual([]);
  });

  it("keeps GITHUB_TOKEN out of the reported status", () => {
    // Not an oversight: the token is mounted only into the walrus-sync job, so the API service
    // answering /app/status legitimately lacks it. Reporting it here would read as a fault on a
    // correctly configured deployment, which is the cry-wolf this whole surface exists to avoid.
    process.env.GITHUB_TOKEN = "t";
    expect(getUpstreamCredentialStatus()).not.toHaveProperty("github_token");
    delete process.env.GITHUB_TOKEN;
    expect(getUpstreamCredentialStatus()).not.toHaveProperty("github_token");
  });

  it("names the variable and the consequence in each warning", () => {
    // The message is the entire feature on a developer's terminal: a warning that does not say
    // what to set, or what it costs not to, gets scrolled past.
    expect(NVD_KEYLESS_WARNING).toContain("NVD_API_KEY");
    expect(NVD_KEYLESS_WARNING).toMatch(/4 per 30s .* 45/);
    expect(GITHUB_ANONYMOUS_WARNING).toContain("GITHUB_TOKEN");
    expect(GITHUB_ANONYMOUS_WARNING).toMatch(/60 requests\/hour .* 5,000/);
  });
});
