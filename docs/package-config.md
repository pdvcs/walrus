# Walrus TOML Configuration Guide

Each package managed by Walrus is described by a single TOML file in `packages/`. Adding a new package means adding one file; no code changes are needed.

This guide walks through how to write that file: what to investigate about the upstream, how each field maps to what you find, and how to verify the result works before committing.

---

## Before you open an editor

Spend a few minutes answering these questions about the package. The answers map directly to the TOML fields.

**Version discovery**

- Does the project publish GitHub Releases? If so, what is the `owner/repo` slug?
- If not, does it have a JSON API that lists versions? What does the response look like?
- If not, is there a Maven/XML-based metadata endpoint?
- As a last resort, is there a directory listing with predictable filenames?
- What do the version tags look like? Do they have a `v` prefix or other text that needs stripping?
- Are pre-release versions mixed in with stable ones? How do you tell them apart?

**Platform matrix**

- Which OS/arch combinations are shipped: Windows x86-64, macOS x86-64, macOS ARM64, Linux x86-64, Linux ARM64?
- For each combination, what does the download filename look like? What does the upstream call each OS and arch?
- Is there a single platform-neutral archive (e.g. a Java `.jar`-based tool), or per-platform binaries?

**Checksums**

- Does the upstream provide a checksum? In what form — a sidecar file, an API field, a GitHub release asset?
- What algorithm — SHA256, SHA1, SHA512?

**Versioning**

- What version scheme does the project use — semver, major.minor only, or calendar-based (e.g. `2024.1`)?
- How is the "release series" defined? For most tools it is the major version (`21` for Java 21.x.x). For Go it is major.minor (`1.24` for Go 1.24.x). This determines how Walrus groups versions for retention.
- Does the project have an LTS concept? If so, how are LTS releases identified?
- Is there a minimum version below which you don't want to sync (e.g. EOL releases)?

---

## File naming and location

Create the file at `packages/walrus-{name}.toml`. The `walrus-` prefix is a convention to make the files easy to identify; the `name` field inside the file does not need this prefix and is usually just the tool name.

```
packages/
  walrus-uv.toml
  walrus-openjdk.toml
  walrus-golang.toml
  ...
```

---

## Top-level metadata

```toml
name = "uv"                                        # unique identifier, lowercase alphanumeric + hyphens
display_name = "uv"                                # human-readable name shown in API responses
vendor = "Astral"                                  # who makes it
website = "https://github.com/astral-sh/uv"       # optional, informational
description = "Fast Python package installer and resolver"  # optional, one sentence
```

`name` is the primary key. It must be lowercase alphanumeric with hyphens (`^[a-z][a-z0-9-]*$`). It appears in every API URL and in the GCS path, so keep it short and stable.

---

## `[discovery]` — where and how to find versions

Choose one `type`. The strategies in preference order:

1. `github-releases` — the package publishes to GitHub Releases
2. `json-api` — there is a structured JSON API
3. `xml-api` — there is a Maven/XML metadata endpoint
4. `directory-listing` — there is a browsable directory of files (rarely needed)

### `github-releases`

**When to use:** The package publishes releases on GitHub and attaches binary assets to them.

**What to gather:**

- The `owner/repo` slug (e.g. `astral-sh/uv`)
- What the version tags look like — do they have a `v` prefix? Are there non-version tags to exclude?
- Whether pre-release tags should be included

Browse `https://api.github.com/repos/{owner}/{repo}/releases` (or `?per_page=5` for a quick sample) and look at the `tag_name`, `prerelease`, and `assets[].name` fields.

```toml
[discovery]
type = "github-releases"
repo = "astral-sh/uv"
include_prereleases = false

# tag_pattern captures the version string from the tag name.
# The regex must have exactly one capture group.
# Omit if tags are already clean version strings (or have only a leading "v").
tag_pattern = "^(\\d+\\.\\d+\\.\\d+)$"  # excludes tags like "0.6.2-pre.1"
```

`tag_pattern` serves two purposes: stripping prefixes (e.g. `v0.6.2` → `0.6.2`) and filtering out tags that aren't version releases. A tag that doesn't match is silently skipped. If the only prefix is a `v`, you can omit `tag_pattern` — the strategy strips `v` automatically.

**`max_releases`** — limits the number of releases fetched from GitHub (maps to the `per_page` query parameter, capped at 100). Omit for most packages; set it when a repo attaches hundreds of assets to each release and the default of 100 releases causes a GitHub API timeout (504). For example, `python-build-standalone` ships ~853 assets per release, so `max_releases = 10` reduces the payload from ~85,300 to ~8,500 assets.

**Asset matching** happens via `filename_template` in each `[[platforms]]` block. The strategy looks for a GitHub release asset whose name matches the constructed filename exactly. See [Platforms](#platforms) below.

---

### `json-api` — two-step submode

**When to use:** The upstream has a JSON API that lists versions, and a separate per-version API endpoint for artifact details.

**What to gather:**

- The URL that returns a list of version strings (or objects you can navigate to version strings)
- A [JSONPath](https://goessner.net/articles/JsonPath/) expression that extracts the array of versions from that response
- The URL pattern for per-version artifact details — usually contains `{major_version}`, `{os}`, `{arch}` placeholders

**Example: Adoptium OpenJDK**

```
GET https://api.adoptium.net/v3/info/available_releases
→ { "available_releases": [21, 17, 11], "available_lts_releases": [21, 17, 11] }

GET https://api.adoptium.net/v3/assets/feature_releases/21/ga?architecture=x64&image_type=jdk&os=linux&...
→ [ { "version": { "semver": "21.0.3+9", ... }, "binaries": [ { "package": { "link": "...", "checksum": "..." } } ] } ]
```

```toml
[discovery]
type = "json-api"
url = "https://api.adoptium.net/v3/info/available_releases"
versions_path = "$.available_releases"               # JSONPath → [21, 17, 11]
release_url_template = "https://api.adoptium.net/v3/assets/feature_releases/{major_version}/ga?architecture={arch}&image_type=jdk&os={os}&page=0&page_size={page_size}&sort_method=DEFAULT&sort_order=DESC"
release_date_field = "timestamp"                     # optional: field on each release for cooling-off
```

`{major_version}`, `{os}`, and `{arch}` in `release_url_template` are replaced with the version integer and each platform's `os_upstream`/`arch_upstream` values. `{page_size}` becomes the number of platforms configured.

For the Adoptium two-step case, checksum is extracted from the API response and handled automatically by the strategy (no `[checksum]` section needed — use `type = "inline-api"` with `response_path = "$.checksum"`).

**Alternative: `explicit_versions`** — if the upstream doesn't have a version-list endpoint but you know the versions to poll:

```toml
[discovery]
type = "json-api"
explicit_versions = [8, 11, 17, 21, 25]      # polled as major version numbers
release_url_template = "https://api.azul.com/metadata/v1/zulu/packages/?java_version={major_version}&os={os}&arch={arch}&..."
release_download_url_field = "download_url"  # field in each result that holds the download URL
release_filename_field = "name"              # field in each result that holds the filename
```

---

### `json-api` — inline submode

**When to use:** A single API call returns both the list of versions and all their artifact files in one response (no per-version follow-up call needed). Activated by omitting `release_url_template`.

**What to gather:**

- The single API endpoint URL
- A JSONPath filter expression that selects the stable/wanted releases from the array
- The field name within each release object that holds the version string
- The field name that holds the nested array of files (`files_field`)
- The field names within each file object for OS, arch, filename, and (optionally) checksum
- A base URL that prefixes each filename to form the download URL (or the field that holds the full URL directly)

**Example: Go downloads API**

```
GET https://go.dev/dl/?mode=json&include=all
→ [
    {
      "version": "go1.24.1",
      "stable": true,
      "files": [
        { "filename": "go1.24.1.linux-amd64.tar.gz", "os": "linux", "arch": "amd64",
          "kind": "archive", "sha256": "abc123..." },
        ...
      ]
    },
    ...
  ]
```

```toml
[discovery]
type = "json-api"
url = "https://go.dev/dl/?mode=json&include=all"

releases_path = "$[?(@.stable==true)]"    # JSONPath filter — stable releases only
release_version_field = "version"         # field on each release object
tag_pattern = "^go(\\d+.*)"              # strip "go" prefix: "go1.24.1" → "1.24.1"

files_field = "files"                     # nested array field within each release
file_os_field = "os"                      # matched against os_upstream in [[platforms]]
file_arch_field = "arch"                  # matched against arch_upstream in [[platforms]]
file_kind_field = "kind"                  # optional: field to filter artifact type
file_kind_value = "archive"              # only files where kind == "archive"
file_filename_field = "filename"          # filename to record
file_url_base = "https://dl.google.com/go/"  # download URL = base + filename
file_checksum_field = "sha256"           # inline checksum field (skips [checksum] section)
```

File matching in inline mode works differently from GitHub releases: instead of constructing a filename and searching for it, the strategy walks `files_field` and matches each file against the configured platform by comparing `file_os_field` with `os_upstream` and `file_arch_field` with `arch_upstream`. Make sure `os_upstream` and `arch_upstream` in your `[[platforms]]` blocks exactly match the values the API returns.

**`release_lts_field`** — for APIs where each release object carries a per-release LTS indicator (a field that is a non-empty string when LTS, `false` or absent otherwise). Set this in `[discovery]` alongside `release_version_field`. Pair with `lts_source = "api"` and `lts_support = true` in `[versioning]`.

**`release_date_field`** — optional field on each release object that holds the upstream release date (ISO 8601 or Unix ms). When set, this date is used as the cooling-off anchor for new artifacts, regardless of bootstrap mode.

**String-list files mode (Node.js)** — some APIs return `files_field` as a flat array of platform identifier strings rather than an array of file objects (e.g. `["linux-x64", "osx-arm64-tar", ...]`). In this case each `[[platforms]]` block must supply a `url_template`; the strategy checks whether `os_upstream` appears in the `files` array and builds the URL from the template.

**Example: Node.js**

```
GET https://nodejs.org/dist/index.json
→ [
    {
      "version": "v22.14.0",
      "date": "2025-02-11",
      "lts": "Jod",
      "files": ["linux-x64", "osx-arm64-tar", "osx-x64-tar", "win-x64-zip", ...],
      ...
    },
    ...
  ]
```

```toml
[discovery]
type = "json-api"
url = "https://nodejs.org/dist/index.json"

# JS expression filter (jsonpath-plus syntax; =~ operator is not supported)
releases_path = "$[?(/^v(20|22|24|25)\\./.test(@.version))]"
release_version_field = "version"
tag_pattern = "^v(\\d+.*)"          # strip "v" prefix: "v22.14.0" → "22.14.0"
release_date_field = "date"          # ISO 8601 release date for cooling-off
release_lts_field = "lts"           # "Jod", "Iron" = LTS; false = not LTS
files_field = "files"               # string identifiers, not file objects

[versioning]
type = "semver"
version_group_extract = "^(\\d+)"   # group by major version
lts_support = true
lts_source = "api"                  # release_lts_field drives this in inline mode

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux-x64"           # string to look for in the files array
url_template = "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz"
extension = "tar.xz"
```

When `files_field` contains strings, `os_upstream` is matched against the string values in the array (exact string equality). There is no `arch_upstream` or `file_os_field`/`file_arch_field` — the `url_template` encodes the full URL directly.

---

**Flat inline mode** — some APIs return the download URL directly on the release object, not in a nested files array (e.g. Gradle). Omit `files_field` and use `release_download_url_field` instead:

```toml
releases_path = "$[?(@.snapshot==false && @.broken==false && @.rcFor=='' && @.milestoneFor=='')]"
release_version_field = "version"
release_download_url_field = "downloadUrl"    # URL is directly on the release object
file_checksum_field = "checksum"              # also directly on the release object
release_date_field = "buildTime"              # optional: for cooling-off calculation
```

---

### `xml-api`

**When to use:** The version list is served as XML (e.g. Maven Central's `maven-metadata.xml`).

**What to gather:**

- The URL of the XML metadata file
- A JSONPath expression applied to the XML-parsed-as-JSON structure to extract version strings
- An optional regex to filter the version list (e.g. exclude alpha/RC versions)
- Optionally, a per-version URL template for fetching release dates

```toml
[discovery]
type = "xml-api"
url = "https://repo.maven.apache.org/maven2/org/apache/maven/maven/maven-metadata.xml"
versions_path = "$.metadata.versioning.versions.version"    # JSONPath into parsed XML
version_filter = "^3\\.9\\.\\d+$"                          # keep only 3.9.x stable releases

# Optional: per-version API call to get release date for cooling-off
release_date_url_template = "https://search.maven.org/solrsearch/select?q=g:org.apache.maven+AND+a:apache-maven+AND+v:{version}&rows=1&wt=json"
release_date_path = "$.response.docs[0].timestamp"         # JSONPath → Unix ms timestamp or ISO 8601
```

---

### `directory-listing`

**When to use:** Files are served from a browsable HTTP directory and there is no structured API. Use this only when no API exists.

```toml
[discovery]
type = "directory-listing"
url = "https://example.com/downloads/"
pattern = "mytool-\\d+\\.\\d+\\.\\d+-linux-amd64\\.tar\\.gz"  # regex matching filenames to consider
```

---

## `[versioning]`

Controls how version strings are parsed, grouped, and compared.

```toml
[versioning]
type = "semver"               # "semver" | "major-minor" | "calver"
version_group_extract = "^(\\d+\\.\\d+)"   # regex with one capture group
min_version = "1.21"          # optional: ignore versions older than this
lts_support = false           # whether this package has LTS releases
```

### `version_group_extract`

This is the most important field to get right. It defines the _release series_ bucket — what Walrus uses when enforcing retention limits and when the API returns `version_groups`.

The regex must have exactly one capture group. What it captures depends on how the project defines its maintenance series:

| Package        | Pattern            | Captures | Why                                              |
| -------------- | ------------------ | -------- | ------------------------------------------------ |
| Java (openjdk) | `"^(\\d+)"`        | `"21"`   | Java 21.x.x is a single series                   |
| Go             | `"^(\\d+\\.\\d+)"` | `"1.24"` | Go's series is major.minor; Go 2.x doesn't exist |
| Node.js        | `"^(\\d+)"`        | `"22"`   | Same as Java — major version is the series       |
| uv (pre-1.0)   | `"^(\\d+\\.\\d+)"` | `"0.6"`  | Pre-1.0; group by minor version                  |
| ripgrep        | `"^(\\d+)"`        | `"14"`   | Standard semver major                            |

### `min_version`

Prevents syncing EOL or very old releases. Versions whose full version string sorts below `min_version` are discarded after discovery. For Go this is `"1.21"`; for OpenJDK this is `"21"`.

### LTS support

Set `lts_support = true` only if the project has a meaningful LTS concept. Then set `lts_source`:

| `lts_source`   | When to use                                                   | Additional fields                                                                                                                                                                                                  |
| -------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `"none"`       | No LTS (default)                                              | —                                                                                                                                                                                                                  |
| `"api"`        | The discovery API indicates which releases are LTS            | Two-step mode: `lts_api_path` — JSONPath into the version-list response. Inline mode: `release_lts_field` in `[discovery]` — field on each release object whose truthy string value (e.g. `"Jod"`) marks it as LTS |
| `"even_major"` | LTS = even-numbered major versions (older Node.js convention) | `lts_min_group` — lowest qualifying major                                                                                                                                                                          |
| `"explicit"`   | Fixed list of LTS groups                                      | `lts_groups = ["21", "17", "11"]`                                                                                                                                                                                  |

**Examples:**

```toml
# Adoptium (two-step): API version-list response includes available LTS groups
lts_support = true
lts_source = "api"
lts_api_path = "$.available_lts_releases"

# Node.js (inline): each release has an "lts" field — a codename string or false
lts_support = true
lts_source = "api"
# release_lts_field = "lts" goes in [discovery], not [versioning]

# Azul: static list, no API support
lts_support = true
lts_source = "explicit"
lts_groups = ["8", "11", "17", "21"]
```

---

## `[retention]`

Controls how many versions Walrus keeps in storage.

```toml
[retention]
versions_per_group = 3    # keep the N most recent versions within each version group
groups_to_keep = 3        # optional: keep only the N most recent groups; prune older ones entirely
cooling_off_days = 3      # optional: new artifacts wait this many days before being served
```

**`versions_per_group`** — within each release series (as defined by `version_group_extract`), keep the most recent N versions. Older ones have their artifacts deleted from storage. For most packages, 2–3 is appropriate. For Go, 1 or 2 is enough (only patch releases within a series differ).

**`groups_to_keep`** — prune entire old release series. For example, `groups_to_keep = 3` with Java means Walrus keeps the three most recent major versions (e.g. 21, 17, 11) and discards Java 8 entirely. Omit if you want to keep all groups.

**`cooling_off_days`** — newly discovered artifacts are marked `pending` and wait this many days (relative to the upstream release date, or the discovery timestamp if no release date is available) before being promoted to `available`. This provides a buffer to catch upstream release mistakes before they are served to users. 3 days is a reasonable default.

---

## `[checksum]`

Declares how to obtain the checksum for each artifact. This section is optional only when checksums come from within the API response itself (via `file_checksum_field` in inline json-api mode).

```toml
[checksum]
type = "..."        # "github-asset" | "separate-file" | "inline-api" | "none"
algorithm = "sha256"  # "sha256" | "sha1" | "sha512" — default: sha256
```

### `github-asset`

The checksum is a separate file attached to the same GitHub Release, named `{filename}{suffix}`.

```toml
[checksum]
type = "github-asset"
algorithm = "sha256"
asset_suffix = ".sha256"   # e.g. "uv-aarch64-apple-darwin.tar.gz.sha256"
```

Look at a GitHub Release page for the project. If there are `.sha256` files alongside the binary downloads, this is the right type.

### `separate-file`

The checksum is a sidecar file at a predictable URL, possibly containing checksums for multiple files. Use `parse_pattern` (a regex with one capture group) to extract the hash for the specific file.

```toml
[checksum]
type = "separate-file"
algorithm = "sha1"
url_template = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{version}/apache-maven-{version}-bin.{ext}.sha1"
# parse_pattern is optional — omit if the file contains only the raw hash
```

The `{version}` and `{ext}` placeholders are substituted per artifact. If the sidecar file contains only the raw hash (no filename), omit `parse_pattern`. If it's a `SHA256SUMS`-style file with `hash  filename` lines, provide a regex:

```toml
parse_pattern = "([a-f0-9]{64})\\s+apache-maven-{version}-bin\\.{ext}"
```

### `inline-api`

The checksum appears in the API response from the discovery call. Use a JSONPath expression to locate it.

```toml
[checksum]
type = "inline-api"
algorithm = "sha256"
response_path = "$.checksum"    # JSONPath into the per-version API response
```

This applies to `json-api` two-step mode where the per-version call returns a checksum field.

### `none`

The upstream provides no checksum. Walrus will store the artifact without verifying integrity.

```toml
[checksum]
type = "none"
```

Use this only as a last resort. Note it in a comment explaining why.

---

## `[[platforms]]`

One block per supported OS/arch combination. Use TOML's array-of-tables syntax (`[[platforms]]`).

```toml
[[platforms]]
os = "linux"               # "linux" | "macos" | "windows" — Walrus's canonical name
arch = "x86-64"            # "x86-64" | "arm64" — Walrus's canonical name
os_upstream = "linux"      # the word the upstream uses for this OS
arch_upstream = "amd64"    # the word the upstream uses for this arch
extension = "tar.gz"       # file extension (without leading dot)
filename_template = "..."  # how to construct the filename (see below)
url_template = "..."       # alternative to filename_template: full URL
```

`os` and `arch` are Walrus's fixed canonical names and must be one of the values above. `os_upstream` and `arch_upstream` are whatever strings the upstream project actually uses in filenames or API fields — look these up from the real download URLs or API responses.

### Filename vs URL template

Use `filename_template` when the download URL is `{base}/{filename}` and only the filename varies. Use `url_template` when the full URL needs templating (e.g. Maven, where the version appears in the path).

**Available template variables:**

| Variable    | Replaced with                       |
| ----------- | ----------------------------------- |
| `{version}` | Full version string (e.g. `1.24.1`) |
| `{os}`      | `os_upstream` value                 |
| `{arch}`    | `arch_upstream` value               |
| `{ext}`     | `extension` value                   |

**`filename_template` example** (GitHub Releases style):

```toml
filename_template = "uv-{arch}-{os}.{ext}"
# → "uv-aarch64-apple-darwin.tar.gz"
```

**`url_template` example** (Maven style — version in path):

```toml
url_template = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{version}/apache-maven-{version}-bin.{ext}"
```

### `name_must_contain`

For APIs that return multiple candidate files and need an extra filter beyond OS/arch matching:

```toml
[[platforms]]
os = "macos"
arch = "arm64"
os_upstream = "macos"
arch_upstream = "aarch64"
extension = "tar.gz"
name_must_contain = "macosx_aarch64.tar.gz"   # excludes musl or other variants
```

Use this when `os_upstream` and `arch_upstream` alone aren't selective enough to pick the right file from the API response.

### Platform-neutral packages

For tools that ship a single archive for all platforms (e.g. pure-Java build tools like Maven and Gradle), create one `[[platforms]]` block per OS/arch combination you want to support but point them all at the same URL template. The sync service will store one artifact per platform entry, even if the files are identical.

```toml
[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "x86_64"
extension = "zip"
url_template = "https://services.gradle.org/distributions/gradle-{version}-bin.{ext}"

[[platforms]]
os = "macos"
arch = "arm64"
os_upstream = "darwin"
arch_upstream = "aarch64"
extension = "zip"
url_template = "https://services.gradle.org/distributions/gradle-{version}-bin.{ext}"
```

---

## Checking schema compliance

Before running against real upstream APIs, verify the file parses and passes Zod schema validation:

```bash
npm run validate -- packages/walrus-mytool.toml
```

If the schema check fails, the first output line will be:

```
  ✗ Schema validation failed: [field path]: [error message]
```

Common schema errors and what they mean:

| Error                                                    | Fix                                                                          |
| -------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `name: Name must be lowercase alphanumeric with hyphens` | Rename — no uppercase, no underscores                                        |
| `discovery.type: Invalid discriminator value`            | Must be one of `github-releases`, `json-api`, `xml-api`, `directory-listing` |
| `platforms: Array must contain at least 1 element(s)`    | Need at least one `[[platforms]]` block                                      |
| `versioning.type: Invalid enum value`                    | Must be `semver`, `major-minor`, or `calver`                                 |

---

## Validating against the real upstream

Once the schema is clean, run the full validation which makes real HTTP calls:

```bash
npm run validate -- packages/walrus-mytool.toml
```

A passing run looks like:

```
Validating packages/walrus-mytool.toml...
  ✓ TOML parses and validates against schema
  ✓ Discovery: github-releases
    Found 42 version(s): 1.2.3, 1.2.2, 1.2.1, 1.2.0, 1.1.5, 1.1.4 ... (+36 more)
  ✓ Artifact URL resolution (spot-check: 1.2.3 linux/x86-64)
    URL: https://github.com/example/mytool/releases/download/1.2.3/mytool-x86_64-unknown-linux-gnu.tar.gz
    HEAD request: 200 OK  8.2 MB
  ✓ Retention: would keep 9 version(s), prune 33
    Would keep: 1.2.3, 1.2.2, 1.2.1, 1.1.5 ...
    Would prune: 1.0.4, 1.0.3, 1.0.2, 1.0.1 ...
```

**What this checks:**

1. TOML parses and passes schema validation
2. The discovery strategy contacts the real upstream API and lists found versions
3. The artifact URL for the newest version on `linux/x86-64` is constructed and a `HEAD` request confirms the file exists
4. The retention plan shows which versions would be kept and pruned

**What to watch for:**

- If discovery finds 0 versions, the API call likely failed or the JSONPath/filter is wrong. Run the API URL in a browser or `curl` and check the response.
- If the HEAD request returns 404, the `filename_template` or `url_template` is constructing the wrong filename. Compare the generated URL against a real download URL from the project's release page.
- Warnings about specific versions returning 404 are usually harmless — upstream may have renamed or removed those assets.
- If you see far more versions than expected, check `tag_pattern` (github-releases) or `version_filter` (xml-api) to filter more aggressively.

---

## Quick reference: which fields are required vs optional

| Field                                | Required?   | Notes                                                                                   |
| ------------------------------------ | ----------- | --------------------------------------------------------------------------------------- |
| `name`                               | Yes         |                                                                                         |
| `display_name`                       | Yes         |                                                                                         |
| `vendor`                             | Yes         |                                                                                         |
| `website`                            | No          |                                                                                         |
| `description`                        | No          |                                                                                         |
| `[discovery]`                        | Yes         | All sub-fields depend on `type`                                                         |
| `[versioning].type`                  | Yes         |                                                                                         |
| `[versioning].version_group_extract` | Yes         |                                                                                         |
| `[versioning].min_version`           | No          | Recommended for packages with many EOL releases                                         |
| `[versioning].lts_support`           | No          | Default: `false`                                                                        |
| `[retention].versions_per_group`     | No          | Default: `3`                                                                            |
| `[retention].groups_to_keep`         | No          | Default: unlimited                                                                      |
| `[retention].cooling_off_days`       | No          | Default: no cooling-off period                                                          |
| `[checksum]`                         | No          | Omit only when `file_checksum_field` provides the checksum inline                       |
| `[[platforms]]`                      | Yes         | At least one block required                                                             |
| `[[platforms]].filename_template`    | Conditional | Required if not using `url_template` or inline json-api                                 |
| `[[platforms]].url_template`         | Conditional | Required in string-list files inline mode; alternative to `filename_template` elsewhere |
| `[[platforms]].name_must_contain`    | No          | Extra filter when OS/arch matching isn't selective enough                               |
| `[discovery].release_date_field`     | No          | Field on each release object holding the upstream release date (cooling-off anchor)     |
| `[discovery].release_lts_field`      | No          | Inline json-api only: field on each release whose truthy string value marks it as LTS   |
