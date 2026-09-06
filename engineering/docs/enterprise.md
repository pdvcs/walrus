# Running walrus as an enterprise ingress

Walrus is MIT-licensed and meant to be run by enterprise teams as their own package ingress,
often behind a corporate proxy or an Artifactory-style remote repository. Two things such a
team needs — rewriting upstream URLs onto that proxy, and their own configuration variables —
have a seam in core walrus so a fork is never required for either. See
[plans/enterprise-extension-points.md](../plans/enterprise-extension-points.md) for the full
design and rationale; this doc is the operational reference.

Status: the chokepoint and declarative rewrite rules below are shipped (WAL-112, WAL-113,
WAL-115). CONNECT proxying and an adopter extension module are designed but not yet built —
see [WAL-72](../tasks/WAL-72.md), still deferred.

## The egress chokepoint

Every outbound request walrus makes to the public internet — package discovery, artifact
downloads, checksum sidecars, the NVD/OSV/KEV vulnerability feeds, and Google OIDC/JWKS
verification for machine-tier auth — goes through one function, `createEgressFetch()`
(`src/common/http.ts`). Traffic to GCP itself (Cloud Storage, Cloud SQL, the Cloud Run control
plane) never passes through it and is never affected by anything in this document — it's reached
over Google's own network, not the public internet a corporate proxy sits in front of.

## Declarative rewrite rules (`WALRUS_EGRESS_RULES`)

Point `WALRUS_EGRESS_RULES` at a TOML file and walrus rewrites matching outbound URLs before
issuing the request:

```toml
[[rule]]
match   = "https://github.com/"
rewrite = "https://artifactory.corp/artifactory/github-remote/"
headers = { Authorization = "Bearer ${ARTIFACTORY_TOKEN}" }

[[rule]]
match   = "https://services.nvd.nist.gov/"
purpose = "vuln-feed"
rewrite = "https://egress.corp/nvd/"
```

**The simplest possible rule** — wrap every HTTPS URL through a rewriting proxy that expects the
original URL appended to its own path — needs no special syntax, just the same prefix-match
mechanism as any other rule:

```toml
[[rule]]
match   = "https://"
rewrite = "https://my-rewriting-proxy/url/https://"
```

`https://github.com/foo/bar` becomes `https://my-rewriting-proxy/url/https://github.com/foo/bar`.

### Where the rules file lives

`config/egress-rules.toml` — same directory as `WALRUS_ADMINS_FILE`'s `config/admins.toml`, and
`WALRUS_EGRESS_RULES` defaults to it the same way `WALRUS_ADMINS_FILE` defaults to
`config/admins.toml`. It ships **empty** (comments only, no `[[rule]]` entries), so out of the
box this changes nothing — walrus has no opinion about any enterprise's proxy. It's baked into
every image by the `Dockerfile`'s existing `COPY config ./config`, no Dockerfile change needed.

Deliberately _not_ reserved the way `WALRUS_EXT_*` or `packages/*.toml` are: this file is
adopter-owned deployment data from the moment it's created, exactly like `admins.toml` already
is, so editing it in a fork is expected, not a sign the design has a gap. Three ways to populate
it without a shell (ADR-004):

- **Edit it directly** in a fork that builds its own image from this source — the same way an
  adopter already maintains their own `config/admins.toml`.
- **A downstream Dockerfile**, if you'd rather not touch anything in this repo at all:
  ```dockerfile
  FROM ghcr.io/<org>/walrus:0.2.0
  COPY egress-rules.toml /app/config/egress-rules.toml
  ```
  (Overriding `WALRUS_EGRESS_RULES` to point elsewhere works too, but isn't necessary — this
  overwrites the same path the default already points at.)
- **A runtime mount** — e.g. a Cloud Run secret or volume mount at `config/egress-rules.toml`,
  or `WALRUS_EGRESS_RULES` pointed at a different mount path — so a rule change is a config
  update, not an image rebuild. Preferable when the file embeds environment-specific hostnames.

### Semantics

- **Prefix match, longest wins.** The matched `match` prefix is replaced by `rewrite` and the
  untouched remainder of the URL is appended. If more than one rule matches, the one with the
  longer `match` string wins — regardless of the order rules appear in the file, so a catch-all
  and a more specific rule can coexist without careful ordering.
- **`headers`** are attached to the rewritten request. `${VAR}` in a header value interpolates
  from the process environment at load time, so a credential never sits in the rule file itself.
  An unresolvable `${VAR}` fails boot rather than shipping a literal `${VAR}` string upstream.
- **`purpose`** (optional) restricts a rule to one class of traffic: `"discovery"`, `"artifact"`,
  `"checksum"`, `"vuln-feed"`, or `"auth"` (Google OIDC/JWKS verification). A rule with no
  `purpose` applies to everything. Artifact bytes and the vulnerability feeds are commonly routed
  to entirely different places, which is what `purpose` is for.
- **Validated at boot.** A malformed rules file — bad TOML, a schema violation, an unresolvable
  `${VAR}` — fails startup with a clear error, the same fail-fast contract as every other walrus
  config problem. It does not start serving with the rules silently ignored.

### `WALRUS_EGRESS_MODE`

Governs what happens when a request matches **no** rule. A match always applies regardless of
mode — this only controls the fallback:

| Mode               | Behaviour on no match                                |
| ------------------ | ---------------------------------------------------- |
| `direct` (default) | Proceed with a direct connection, no log line.       |
| `rules`            | Log a `warn` and proceed with a direct connection.   |
| `strict`           | Refuse the request rather than attempting it direct. |

`strict` exists for an environment where every bit of public-internet egress is required to
traverse the proxy — there, an un-rewritten direct connection is a security event, not a
transient failure to retry. It is never the implicit default just because rules are configured;
an adopter opts into it explicitly.

All three modes — like rule matching itself — only ever apply to chokepoint (public-internet)
traffic. GCP-internal calls are out of scope for every mode, including `strict`.

## Reserved configuration namespace: `WALRUS_EXT_*`

Upstream (this repository) promises never to define an environment variable under the
`WALRUS_EXT_*` prefix. That's the whole mechanism: it's the one sentence that keeps a future
`git pull` from colliding with whatever config an adopter's own extension needs, since name
collision is the only real hazard in two parties sharing one process environment.

Nothing reads `WALRUS_EXT_*` today — the extension-module loader that will (Layer 2, see
[WAL-72](../tasks/WAL-72.md)) hasn't landed. Setting one is safe in the meantime: core's config
loader (`src/config/index.ts`) parses `process.env` with a non-strict Zod object, which quietly
drops any key it doesn't recognize rather than failing boot. An adopter can start naming their
future config vars under this prefix today without waiting for the loader.

**Illustrative only** — none of these exist yet, there's no code to consume them, and they are
not a preview of the real names Layer 2 will use. They're here only to show the _shape_ of thing
this namespace is for: config a rule table can't express, read by an adopter's own extension
module once `WALRUS_EXTENSION` exists.

```bash
# A credential the extension mints short-lived Artifactory tokens with, instead of the one
# static bearer token a WALRUS_EGRESS_RULES header can express.
WALRUS_EXT_ARTIFACTORY_SERVICE_ACCOUNT=walrus-egress@corp.iam
WALRUS_EXT_ARTIFACTORY_SIGNING_KEY_PATH=/app/ext/artifactory-signing-key.pem

# Per-package routing a prefix rule can't express: gradle and nodejs need different mirrors,
# picked by package name rather than by URL shape.
WALRUS_EXT_ROUTING_TABLE_PATH=/app/ext/routing.toml

# Where the extension posts its own audit trail — the enterprise's SIEM, not walrus's admin_actions.
WALRUS_EXT_AUDIT_WEBHOOK_URL=https://siem.corp/ingest/walrus-egress
```

Each is just an ordinary env var an extension module's own `configSchema` would declare and
parse — core never learns these names, so adding or renaming one is never a walrus change.

## Observability: `GET /admin/v1/egress`

There's no shell in the deployed container (see ADR-004), so "is my rewrite rule actually
working?" has to be answerable over HTTP rather than by exec-ing in and grepping logs (ADR-007).

```
GET /admin/v1/egress
{"mode": "rules", "ruleCount": 2}

GET /admin/v1/egress?url=https://github.com/foo/bar/x.tar.gz
{
  "mode": "rules",
  "ruleCount": 2,
  "dryRun": {
    "url": "https://github.com/foo/bar/x.tar.gz",
    "matched": true,
    "rewrittenUrl": "https://artifactory.corp/artifactory/github-remote/foo/bar/x.tar.gz",
    "headerNames": ["Authorization"]
  }
}
```

The dry-run never issues the request and never returns header _values_ — only the names of any
headers a matching rule would set — so this endpoint can't be used to exfiltrate a credential a
rule injects. It also never restricts by `purpose`: it reports whether a URL would be rewritten
under _any_ configured rule, which is enough to answer "is this working at all" without asking
the caller to also know which traffic class they're debugging.

Walrus also logs its effective egress configuration (mode and rule count) once at boot.

## What's not here yet

- **CONNECT proxying** (`WALRUS_EGRESS_MODE` plus an `undici` `ProxyAgent`, for an environment
  that's a conventional corporate proxy rather than URL rewriting) — designed, not built. See
  [WAL-72](../tasks/WAL-72.md).
- **An extension module** (`WALRUS_EXTENSION`, for what a rule table can't express — token
  minting, signed URLs, per-package routing) — same ticket, same status.
- **Forking `packages/*.toml`.** An enterprise should track upstream package configs unchanged
  and redirect them at the egress layer above. If you find yourself editing a package TOML to
  point at a mirror, that's a sign this design has a gap — please report it rather than
  forking further.
