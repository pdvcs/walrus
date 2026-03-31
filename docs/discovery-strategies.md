# Discovery Strategies — Developer Guide

This document explains how Walrus discovers package versions: the architecture, each strategy's implementation, and the real packages that exercise each code path. Read this when you're working on the discovery layer itself, adding a new strategy type, or debugging why a particular upstream isn't behaving as expected.

For the operator-facing reference (how to *write* a TOML config), see `docs/package-config.md`.

---

## Architecture overview

All discovery lives in `src/discovery/`. The entry point is `getStrategy()` in `src/discovery/index.ts`, which reads `config.discovery.type` and returns the appropriate strategy instance.

Every strategy implements a single interface:

```typescript
// src/discovery/types.ts
interface DiscoveryStrategy {
  discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]>;
}
```

The return type is always `DiscoveredVersion[]`:

```typescript
interface DiscoveredVersion {
  version: string;          // Full version string after tag_pattern applied
  versionGroup: string;     // Extracted retention bucket (from version_group_extract)
  isLts: boolean;
  artifacts: Map<PlatformKey, ArtifactInfo>; // keyed "linux/x86-64", "macos/arm64", etc.
  releasedAt?: Date;        // Upstream publish timestamp, when the API provides it
}

interface ArtifactInfo {
  url: string;
  filename: string;
  checksum?: string;        // Hex digest if known at discovery time
  checksumUrl?: string;     // URL to fetch the digest from later
  checksumType?: string;
}
```

The rest of the system — sync orchestration, DB writes, retention enforcement — only ever sees this output. Strategies are entirely self-contained.

---

## `github-releases`

**Implementation:** `src/discovery/github-releases.ts`

**Packages:** `uv`, `ripgrep`, `python`

Calls `https://api.github.com/repos/{owner}/releases` with `per_page` (default 100, configurable via `max_releases`). For each release:

1. Skips releases flagged `prerelease: true` if `include_prereleases = false`.
2. Applies `tag_pattern` to `tag_name`. If the pattern doesn't match, the release is silently skipped. If it matches, capture group 1 becomes the version string. If no `tag_pattern` is set, a leading `v` is stripped automatically.
3. For each `[[platforms]]` block, constructs the expected filename from `filename_template` and looks for an asset with that exact name in `release.assets`.
4. Release date comes from `published_at` on the release object — no config needed, it's always present.

**Standard case — uv and ripgrep**

These are textbook GitHub Releases packages. Each release has per-platform binary assets and a matching `.sha256` sidecar for each.

```
uv 0.6.14 release assets:
  uv-x86_64-unknown-linux-gnu.tar.gz
  uv-x86_64-unknown-linux-gnu.tar.gz.sha256
  uv-aarch64-apple-darwin.tar.gz
  uv-aarch64-apple-darwin.tar.gz.sha256
  uv-x86_64-pc-windows-msvc.zip
  uv-x86_64-pc-windows-msvc.zip.sha256
  ...
```

The `filename_template = "uv-{arch}-{os}.{ext}"` pattern constructs the asset name; the `[checksum]` block with `type = "github-asset"` and `asset_suffix = ".sha256"` finds the matching sidecar.

**High-asset-count variant — python**

`python-build-standalone` ships roughly 853 assets per release. The release tags are dates (`20260325`), not version numbers — the Python version is embedded in each asset filename (`cpython-3.12.9+20260325-...`). Fetching 100 releases × 853 assets × pagination would exceed GitHub's API limits and cause 504 errors.

Two config options address this:

- `max_releases = 10` limits the `per_page` parameter, reducing the asset payload from ~85,300 to ~8,500 entries.
- `asset_version_pattern = "^cpython-(3\\.(?:11|12|13|14)\\.\\d+)\\+"` extracts the Python version from each asset filename. This transforms the repository's date-based release model into Walrus's version-based model: one `DiscoveredVersion` per Python version, not per release date. Assets from the same Python version across multiple release dates are deduplicated — the most recent wins.

The `[checksum]` type is `github-asset-digest`, which reads the `digest` field directly from the GitHub asset object (GitHub populates this with a `sha256:hex` string) rather than fetching a sidecar file.

---

## `json-api`

**Implementation:** `src/discovery/json-api.ts`

**Packages:** `golang`, `nodejs`, `gradle`, `openjdk`, `azuljdk`

This is the most flexible strategy, covering four distinct API shapes through sub-modes selected by the presence or absence of certain config fields.

### Sub-mode 1: Two-step with `explicit_versions`

**Packages:** `openjdk`, `azuljdk`

When `explicit_versions` is set (and `release_url_template` is present), the strategy skips version discovery entirely and instead polls a fixed list of major version numbers. For each version number, it substitutes `{major_version}`, `{os}`, `{arch}`, and `{page_size}` into `release_url_template` and makes one API call per (version, platform) combination.

```
openjdk config:
  explicit_versions = [11, 17, 21, 25]
  release_url_template = "https://api.adoptium.net/v3/assets/feature_releases/{major_version}/ga?architecture={arch}&image_type=jdk&os={os}&..."

Calls made:
  GET .../feature_releases/21/ga?architecture=aarch64&image_type=jdk&os=mac&...
  → [ { "version": { "semver": "21.0.7+6" }, "binaries": [ { "package": { "link": "...", "checksum": "abc..." } } ] } ]
```

The strategy reads the binary URL from `binaries[0].package.link` and the SHA256 from `binaries[0].package.checksum` — this is hardcoded for Adoptium's API shape and paired with `[checksum] type = "inline-api"` and `response_path = "$.checksum"` in the TOML.

Azul uses the same sub-mode (`explicit_versions` + `release_url_template`) but its API returns a flat array of package objects. The download URL comes from `release_download_url_field = "download_url"` and the filename from `release_filename_field = "name"`. Azul's API exposes no checksum at the listing level (it would require a second call to `/packages/{uuid}`), so `[checksum] type = "none"`. The `name_must_contain` field on each platform narrows results when the OS/arch combination alone isn't selective enough — for example, Linux x86-64 results include both `linux_x64` and `linux_musl_x64` variants, and `name_must_contain = "linux_x64.tar.gz"` picks the right one.

**LTS for `openjdk`:** The `lts_source = "api"` + `lts_api_url` + `lts_api_path` fields cause the strategy to make one extra call to Adoptium's `/v3/info/available_releases` endpoint at startup to fetch the list of LTS major versions. This list is stored and used to set `isLts` on each discovered version.

**LTS for `azuljdk`:** No API support; `lts_source = "explicit"` with `lts_groups = ["8", "11", "17", "21", "25"]` is a static list maintained in the config.

### Sub-mode 2: Inline with file-objects array

**Package:** `golang`

When `release_url_template` is absent and `files_field` is set to a field that contains an array of file objects, the strategy reads all versions and their files in a single API call.

```
GET https://go.dev/dl/?mode=json&include=all
→ [
    { "version": "go1.24.2", "stable": true, "files": [
        { "filename": "go1.24.2.darwin-arm64.tar.gz", "os": "darwin", "arch": "arm64",
          "kind": "archive", "sha256": "abc..." },
        ...
      ]
    },
    ...
  ]
```

The `releases_path = "$[?(@.stable==true)]"` JSONPath filter selects stable releases. `tag_pattern = "^go(\\d+.*)"` strips the `go` prefix from the version string. `file_kind_field` + `file_kind_value` filter to `kind == "archive"`, excluding source tarballs and installers.

Platform matching in this mode works by comparing `file_os_field` against `os_upstream` and `file_arch_field` against `arch_upstream` — there is no filename construction step. The `os_upstream = "darwin"` and `arch_upstream = "arm64"` values in the `[[platforms]]` block must exactly match what Go's API returns.

Checksums are inline (`file_checksum_field = "sha256"`), so no `[checksum]` section is needed.

Go's `[[platforms]]` blocks have no `filename_template` or `url_template` — in file-objects inline mode, the strategy reads `file_filename_field` from the API response and combines it with `file_url_base` to form the download URL. The platform blocks only need `os`, `arch`, `os_upstream`, `arch_upstream`, and `extension`.

### Sub-mode 3: Inline with string-list files

**Package:** `nodejs`

Node.js uses the same single-call inline shape as Go, but `files_field` contains platform identifier *strings* rather than file objects:

```
GET https://nodejs.org/dist/index.json
→ [ { "version": "v22.14.0", "lts": "Jod",
      "files": ["linux-x64", "osx-arm64-tar", "osx-x64-tar", "win-x64-zip", ...] } ]
```

There are no per-file OS/arch fields to match against — just a string token per platform. The strategy checks whether `os_upstream` appears in the `files` array (exact string equality). If it does, the download URL is constructed from `url_template` on the platform block using `{version}` substitution.

This is also the only package currently using `release_lts_field = "lts"`. The Node.js API sets this field to `false` for current releases and a codename string (e.g. `"Jod"`, `"Iron"`) for LTS releases. The strategy treats any truthy string value as LTS.

The `releases_path` filter uses a JavaScript regex test expression (`/^v(20|22|24|25)\\./.test(@.version)`) rather than a simple comparison — this is JSONPath Plus syntax and is the mechanism for filtering to specific major version lines.

Checksums come from a separate `SHASUMS256.txt` file per release, using `[checksum] type = "separate-file"` with `parse_pattern` to extract the matching line.

### Sub-mode 4: Inline flat (no files array)

**Package:** `gradle`

Gradle's API puts the download URL directly on each release object rather than in a nested files array:

```
GET https://services.gradle.org/versions/all
→ [ { "version": "8.13", "downloadUrl": "https://services.gradle.org/distributions/gradle-8.13-bin.zip",
      "checksum": "abc...", "snapshot": false, "broken": false, "rcFor": "", ... } ]
```

Omitting `files_field` and setting `release_download_url_field = "downloadUrl"` activates flat mode. The strategy reads the URL directly from the release object and assigns the same URL to all platforms (Gradle is a pure-Java tool with a platform-neutral ZIP). Checksum is also inline via `file_checksum_field = "checksum"`.

The `releases_path` filter is the most complex of any current package, excluding snapshots, nightlies, release-nightlies, release candidates, milestones, and broken builds in a single JSONPath expression.

---

## `xml-api`

**Implementation:** `src/discovery/xml-api.ts`

**Packages:** `maven3`, `maven4`

Used when the version list is served as XML — specifically Maven Central's `maven-metadata.xml`. The strategy fetches the XML, parses it to a JavaScript object, and applies a JSONPath expression to extract version strings.

```
GET https://repo.maven.apache.org/maven2/org/apache/maven/maven/maven-metadata.xml
→ <metadata>
    <versioning>
      <versions>
        <version>3.9.9</version>
        <version>3.9.8</version>
        <version>3.9.7-alpha-1</version>   ← excluded by version_filter
        <version>4.0.0-rc-3</version>      ← captured by maven4 config
        ...
      </versions>
    </versioning>
  </metadata>
```

`version_filter` is a regex applied after the JSONPath extraction. `maven3` keeps `^3\\.9\\.\\d+$` (stable 3.9.x only), while `maven4` keeps `^4\\.0\\.0-rc-\\d+$` (release candidates only, until 4.0.0 GA ships).

Maven doesn't embed release dates in `maven-metadata.xml`. The optional `release_date_url_template` + `release_date_path` pair triggers a separate call per version to Maven Central's Solr search API to fetch the publish timestamp in milliseconds.

Maven binaries are platform-neutral (pure Java), so all `[[platforms]]` blocks point at the same `url_template` — only the file extension differs between the Linux/macOS tar.gz and the Windows zip. The sync service stores one artifact entry per platform block, even when the underlying file is identical.

Checksums use `[checksum] type = "separate-file"` with SHA1 (`.sha1` sidecar files alongside every Maven Central artifact). Since the sidecar contains only the raw hash with no filename, `parse_pattern` is omitted.

---

## `directory-listing`

**Implementation:** `src/discovery/directory-listing.ts`

**Packages:** none currently

Last-resort strategy for servers that expose a browsable HTTP directory with no structured API. Fetches the listing page, extracts `href` values matching the configured `pattern` regex, and derives version strings from the filenames. Only use this when no structured API exists — the strategy is fragile to HTML changes.

---

## Checksum strategies

Checksums are resolved separately from discovery, but the discovery strategy sets up how they'll be fetched by populating `ArtifactInfo.checksum` (known now) or `ArtifactInfo.checksumUrl` (fetch later).

| TOML type              | Mechanism                                                                         | Used by                     |
| ---------------------- | --------------------------------------------------------------------------------- | --------------------------- |
| `github-asset`         | Sidecar file attached to the same GitHub Release (`{filename}{asset_suffix}`)     | `uv`, `ripgrep`             |
| `github-asset-digest`  | `digest` field on the GitHub asset object (GitHub-native SHA256, no extra fetch)  | `python`                    |
| `inline-api`           | JSONPath into the per-version API response (`response_path`)                      | `openjdk`                   |
| `separate-file`        | Sidecar at a predictable URL; optional `parse_pattern` to extract hash from file  | `maven3`, `maven4`, `nodejs`|
| *(inline via field)*   | `file_checksum_field` on the discovery config — hash read during discovery itself | `golang`, `gradle`          |
| `none`                 | No checksum available from upstream                                               | `azuljdk`                   |

When `file_checksum_field` is set on the discovery config, no `[checksum]` section is needed — the hash is already in `ArtifactInfo.checksum` by the time the sync service picks up the result.

---

## Adding a new strategy

1. Create `src/discovery/my-strategy.ts` implementing `DiscoveryStrategy`.
2. Add a new `type` value to the discriminated union in `src/types/package-config.ts` and extend the Zod schema with whatever config fields the strategy needs.
3. Add a `case` to `getStrategy()` in `src/discovery/index.ts`.
4. Add unit tests in `tests/discovery/` using `msw` to mock HTTP — no real network calls in tests.

The strategy only needs to produce `DiscoveredVersion[]`. Everything downstream (sync, DB, retention, downloads) is unchanged.
