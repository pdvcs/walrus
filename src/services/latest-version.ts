import { JSONPath } from "jsonpath-plus";
import { Pool } from "pg";
import { fetchJsonWithRetry } from "../common/http.js";
import { applyTagPattern } from "../common/version-utils.js";
import { log } from "../common/log.js";
import { config as appConfig } from "../config/index.js";
import { recordLatestVersion } from "../db/queries/packages.js";
import type { LatestVersionConfig, WatchConfig } from "../types/watch-config.js";

const GITHUB_API_BASE = "https://api.github.com";
/** A version string longer than this is a wrong field (a changelog, a URL), not a version. */
const MAX_VERSION_LENGTH = 64;

/**
 * Resolve the current release of a watch-only package from its `[latest]` block (WAL-54).
 * Throws with a message fit to store and show an operator; never returns an empty string.
 */
export async function resolveLatestVersion(latest: LatestVersionConfig): Promise<string> {
  const raw = latest.type === "json" ? await readJson(latest) : await readGithubRelease(latest);

  // GitHub tags conventionally carry a "v"; strip it unless the TOML says how to read the tag.
  const pattern = latest.tag_pattern ?? (latest.type === "github-release" ? "^v?(.+)$" : undefined);
  const version = pattern ? applyTagPattern(raw, pattern) : raw;
  if (!version) {
    throw new Error(`tag_pattern ${pattern} did not match "${raw}"`);
  }
  if (version.length > MAX_VERSION_LENGTH || !/\d/.test(version)) {
    throw new Error(`"${version.slice(0, 40)}" does not look like a version`);
  }
  return version;
}

async function readJson(latest: Extract<LatestVersionConfig, { type: "json" }>): Promise<string> {
  const doc = await fetchJsonWithRetry<unknown>(latest.url, {
    headers: { Accept: "application/json", "User-Agent": "walrus/1.0" },
  });
  const hits: unknown[] = JSONPath({ path: latest.version_path, json: doc as object, wrap: true });
  const value = hits[0];
  if (typeof value !== "string" && typeof value !== "number") {
    throw new Error(`${latest.version_path} found no string or number in ${latest.url}`);
  }
  return String(value).trim();
}

async function readGithubRelease(
  latest: Extract<LatestVersionConfig, { type: "github-release" }>,
): Promise<string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "walrus/1.0",
  };
  // Read per call, not at import: the schema normalises an empty secret to undefined.
  if (appConfig.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${appConfig.GITHUB_TOKEN}`;
  // /releases/latest already excludes drafts and prereleases.
  const release = await fetchJsonWithRetry<{ tag_name?: unknown }>(
    `${GITHUB_API_BASE}/repos/${latest.repo}/releases/latest`,
    { headers },
  );
  if (typeof release.tag_name !== "string" || release.tag_name === "") {
    throw new Error(`${latest.repo} has no latest release`);
  }
  return release.tag_name;
}

export interface LatestRefreshResult {
  /** Watch packages that declare a [latest] block. */
  checked: number;
  updated: number;
  failures: Array<{ package: string; error: string }>;
}

/**
 * Refresh `packages.latest_version` for every watch entry that declares `[latest]`. Per-package
 * tolerance: one dead upstream must not stop the rest, and a failure keeps the previous good
 * value (see `recordLatestVersion`). `resolve` is injectable so tests need no network.
 */
export async function refreshWatchLatestVersions(
  pool: Pool,
  watched: WatchConfig[],
  resolve: (latest: LatestVersionConfig) => Promise<string> = resolveLatestVersion,
): Promise<LatestRefreshResult> {
  const result: LatestRefreshResult = { checked: 0, updated: 0, failures: [] };
  for (const w of watched) {
    if (!w.latest) continue;
    result.checked++;
    try {
      const version = await resolve(w.latest);
      await recordLatestVersion(pool, w.name, { version });
      result.updated++;
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      result.failures.push({ package: w.name, error });
      log.warn({ package: w.name, reason: error }, "Latest-version lookup failed");
      await recordLatestVersion(pool, w.name, { error: error.slice(0, 500) }).catch(
        (dbErr: unknown) => log.error({ err: dbErr }, "Failed to record latest-version error"),
      );
    }
  }
  return result;
}
