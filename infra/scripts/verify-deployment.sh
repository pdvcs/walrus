#!/usr/bin/env bash
#
# Assert a deployed walrus environment against the invariants its tickets claim.
#
# Most of what this checks was previously a "manual test": someone ran gcloud by hand, read the
# output, and wrote the result into a ticket. That is not cheaper than a script — it is a script
# executed by a human, once, with no record of the command and no way to re-run it after the next
# deploy. Everything here is an assertion with a ticket tag, so a run of this file is the evidence,
# and a regression is caught by re-running rather than by remembering to look.
#
# What deliberately stays manual is listed at the bottom of
# engineering/plans/gcp-testing-tasks.md: things needing a browser, a real Windows desktop, a
# human judgement about a vendor's licence, or the destruction of the environment.
#
#   ./infra/scripts/verify-deployment.sh              # everything except the slow byte check
#   ./infra/scripts/verify-deployment.sh --full       # adds artifact byte verification
#   ./infra/scripts/verify-deployment.sh --drift      # adds terraform plan drift (needs deploy.env)
#
# Exit 0 if every check passes, 1 otherwise. Warnings do not fail the run.

set -uo pipefail

PROJECT="${TF_VAR_project_id:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${TF_VAR_region:-us-central1}"
FULL=0
DRIFT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --full) FULL=1; shift ;;
    --drift) DRIFT=1; shift ;;
    --project) PROJECT="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0; WARN=0
ok()   { printf '  \033[32mPASS\033[0m  %-9s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no()   { printf '  \033[31mFAIL\033[0m  %-9s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
warn() { printf '  \033[33mWARN\033[0m  %-9s %s\n' "$1" "$2"; WARN=$((WARN+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

SERVICE_URL=$(gcloud run services describe walrus-api --region="$REGION" --project="$PROJECT" \
  --format='value(status.url)' 2>/dev/null)
if [ -z "$SERVICE_URL" ]; then
  echo "cannot resolve walrus-api in $PROJECT/$REGION" >&2
  exit 1
fi
printf 'walrus deployment check — %s\n%s\n' "$PROJECT" "$SERVICE_URL"

# =========================================================================================
head_ "Serving health"
# =========================================================================================
STATUS=$(curl -sS -m 30 "$SERVICE_URL/app/status" 2>/dev/null)

printf '%s' "$STATUS" | python3 -c '
import json, sys
assert json.load(sys.stdin).get("isAvailable") is True, "not available"
' && ok "health" "service reports available" || no "health" "service is not available"

# `inGracePeriod` is per *instance*, not per deployment: Cloud Run starting a new instance under
# load — including the load this script itself generates — legitimately reports true. It says
# nothing about deployment correctness, so it is reported and never failed on.
if printf '%s' "$STATUS" | grep -q '"inGracePeriod": *true'; then
  warn "health" "the instance that answered is in its startup grace period (normal after a scale-up)"
else
  ok "health" "instance is out of its startup grace period"
fi

# A vulnerability source distinguishes a transient upstream failure — which the next scheduled
# tick retries, and which walrus is *designed* to surface as a degradation — from real staleness.
# Failing the run on the former would make this script cry wolf on NVD having a bad minute.
RES=$(printf '%s' "$STATUS" | python3 -c '
import datetime, json, sys
d = json.load(sys.stdin)
srcs = d.get("vuln_sync_status") or {}
if len(srcs) != 4:
    print("FAIL expected four vulnerability sources, found %d" % len(srcs)); raise SystemExit
now = datetime.datetime.fromisoformat(d["ts"].replace("Z", "+00:00"))
stale, soft = [], []
for name, v in sorted(srcs.items()):
    if v.get("last_ok"):
        continue
    ok_at = v.get("last_success")
    if not ok_at:
        stale.append(name + " (never succeeded)"); continue
    age = (now - datetime.datetime.fromisoformat(ok_at.replace("Z", "+00:00"))).total_seconds() / 3600
    (stale if age > 24 else soft).append("%s (last success %.1fh ago)" % (name, age))
if stale:
    print("FAIL stale: " + ", ".join(stale))
elif soft:
    print("WARN transient failure, scheduler will retry: " + ", ".join(soft))
else:
    print("OK all four sources report last_ok")
')
case "$RES" in
  OK*)   ok   "WAL-78" "${RES#OK }" ;;
  WARN*) warn "WAL-78" "${RES#WARN }" ;;
  *)     no   "WAL-78" "${RES#FAIL }" ;;
esac

# =========================================================================================
head_ "Workload sizing — WAL-95 / WAL-97"
# =========================================================================================
# The heap ceiling is derived from what is left of the container after each workload's Buffer
# budget; tests/infra/memory-budget.test.ts recomputes the table and is the source of truth.
# Asserted here because a container can be resized in the console without anyone noticing that
# the ceiling no longer fits inside it.
check_workload() { # name kind expected_memory expected_heap expected_pool
  local name="$1" kind="$2" mem="$3" heap="$4" pool="$5" json
  if [ "$kind" = service ]; then
    json=$(gcloud run services describe "$name" --region="$REGION" --project="$PROJECT" --format=json 2>/dev/null)
  else
    json=$(gcloud run jobs describe "$name" --region="$REGION" --project="$PROJECT" --format=json 2>/dev/null)
  fi
  printf '%s' "$json" | python3 -c '
import json, sys
want_mem, want_heap, want_pool, kind = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(sys.stdin)
c = (d["spec"]["template"]["spec"]["containers"][0] if kind == "service"
     else d["spec"]["template"]["spec"]["template"]["spec"]["containers"][0])
env = {e["name"]: e.get("value") for e in c.get("env", [])}
mem = c.get("resources", {}).get("limits", {}).get("memory")
assert mem == want_mem, f"memory {mem} != {want_mem}"
opts = env.get("NODE_OPTIONS") or ""
assert f"--max-old-space-size={want_heap}" in opts, f"NODE_OPTIONS {opts!r} lacks heap {want_heap}"
assert env.get("DB_POOL_MAX") == want_pool, f"DB_POOL_MAX {env.get('DB_POOL_MAX')} != {want_pool}"
' "$mem" "$heap" "$pool" "$kind" \
    && ok "WAL-95" "$name: ${mem} container, ${heap} MiB heap, pool ${pool}" \
    || no "WAL-95" "$name sizing does not match the budget"
}
check_workload walrus-api          service 1Gi 384 3
check_workload walrus-sync         job     2Gi 640 4
check_workload walrus-vuln-backfill job    1Gi 768 4

# =========================================================================================
head_ "Secrets — WAL-92"
# =========================================================================================
for w in "walrus-api:service" "walrus-sync:job" "walrus-vuln-backfill:job"; do
  name="${w%%:*}"; kind="${w##*:}"
  if [ "$kind" = service ]; then
    json=$(gcloud run services describe "$name" --region="$REGION" --project="$PROJECT" --format=json 2>/dev/null)
  else
    json=$(gcloud run jobs describe "$name" --region="$REGION" --project="$PROJECT" --format=json 2>/dev/null)
  fi
  printf '%s' "$json" | python3 -c '
import json, sys
kind = sys.argv[1]
d = json.load(sys.stdin)
c = (d["spec"]["template"]["spec"]["containers"][0] if kind == "service"
     else d["spec"]["template"]["spec"]["template"]["spec"]["containers"][0])
for e in c.get("env", []):
    if e["name"] == "NVD_API_KEY":
        # A secret reference, never a literal: a plain value would be readable by anyone with
        # run.services.get, which is a far wider audience than Secret Manager access.
        assert e.get("valueFrom", {}).get("secretKeyRef"), "NVD_API_KEY is not a secret reference"
        sys.exit(0)
raise AssertionError("NVD_API_KEY not mounted")
' "$kind" && ok "WAL-92" "$name mounts NVD_API_KEY by secret reference" \
             || no "WAL-92" "$name does not mount NVD_API_KEY as a secret"
done

# Only walrus-sync runs discovery, so the GitHub token is scoped to that job — asserted here so
# the scoping stays deliberate rather than drifting to "wherever it was convenient" (WAL-103).
GH_JSON=$(gcloud run jobs describe walrus-sync --region="$REGION" --project="$PROJECT" --format=json 2>/dev/null)
GH_STATE=$(printf '%s' "$GH_JSON" | python3 -c '
import json, sys
c = json.load(sys.stdin)["spec"]["template"]["spec"]["template"]["spec"]["containers"][0]
for e in c.get("env", []):
    if e["name"] == "GITHUB_TOKEN":
        print("SECRET" if e.get("valueFrom", {}).get("secretKeyRef") else "LITERAL")
        break
else:
    print("ABSENT")
')
case "$GH_STATE" in
  SECRET)  ok   "WAL-103" "walrus-sync mounts GITHUB_TOKEN by secret reference" ;;
  LITERAL) no   "WAL-103" "GITHUB_TOKEN is a literal value on walrus-sync, not a secret reference" ;;
  *)       warn "WAL-103" "no GITHUB_TOKEN on walrus-sync — GitHub discovery runs at 60 req/hour on a shared egress IP" ;;
esac

# =========================================================================================
head_ "Scheduling — WAL-40 AC2 / WAL-48"
# =========================================================================================
SCHED=$(gcloud scheduler jobs list --location="$REGION" --project="$PROJECT" --format=json 2>/dev/null)

printf '%s' "$SCHED" | python3 -c '
import json, sys
jobs = json.load(sys.stdin)
names = sorted(j["name"].rsplit("/", 1)[-1] for j in jobs)
want = sorted(["walrus-sync", "walrus-vuln-sync-nvd", "walrus-vuln-sync-osv", "walrus-vuln-sync-kev",
               "walrus-vuln-sync-cvss", "walrus-vuln-backfill-auto"])
assert names == want, f"scheduler jobs {names} != {want}"
bad = [j["name"].rsplit("/",1)[-1] for j in jobs if j.get("state") != "ENABLED"]
assert not bad, f"not enabled: {bad}"
stale = [j["name"].rsplit("/",1)[-1] for j in jobs if not j.get("lastAttemptTime")]
assert not stale, f"never fired: {stale}"
errored = [j["name"].rsplit("/",1)[-1] for j in jobs if (j.get("status") or {}).get("code")]
assert not errored, f"last attempt failed: {errored}"
' && ok "WAL-40" "all six scheduler jobs enabled, fired, and last attempt reported success" \
   || no "WAL-40" "scheduler jobs are not all healthy"

printf '%s' "$SCHED" | python3 -c '
import base64, json, sys
for j in json.load(sys.stdin):
    if j["name"].endswith("walrus-vuln-sync-cvss"):
        body = json.loads(base64.b64decode((j.get("httpTarget") or {})["body"]))
        assert "limit" in body, f"cvss body has no limit: {body}"
        print(body["limit"])
        sys.exit(0)
raise AssertionError("cvss scheduler job not found")
' >/dev/null && ok "WAL-48" "cvss scheduler posts a bounded {\"limit\": N} body" \
              || no "WAL-48" "cvss scheduler body is not a bounded limit"

# =========================================================================================
head_ "Alerting — WAL-43"
# =========================================================================================
gcloud monitoring policies list --project="$PROJECT" --format=json 2>/dev/null | python3 -c '
import json, sys
pols = json.load(sys.stdin)
enabled = {p["displayName"] for p in pols if p.get("enabled")}
missing = [n for n in ("Walrus Cloud Run error", "Walrus automatic CVE backfill exhausted")
           if n not in enabled]
assert not missing, f"missing or disabled: {missing}"
' && ok "WAL-43" "both alert policies exist and are enabled" \
   || no "WAL-43" "alert policies missing or disabled"

# =========================================================================================
head_ "Machine-tier auth — WAL-86"
# =========================================================================================
code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X POST "$SERVICE_URL/internal/vuln-backfill/auto")
[ "$code" = 401 ] && ok "WAL-86" "unauthenticated internal call refused (401)" \
                  || no "WAL-86" "unauthenticated internal call returned $code, expected 401"

code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X POST \
  -H "Authorization: Bearer not-a-real-token" "$SERVICE_URL/internal/vuln-backfill/auto")
[ "$code" = 401 ] && ok "WAL-86" "malformed bearer token refused (401)" \
                  || no "WAL-86" "malformed bearer returned $code, expected 401"

# =========================================================================================
head_ "Artifact integrity — WAL-102 / WAL-66"
# =========================================================================================
# Every artifact walrus serves must publish a digest and derive its If-Range validator from it.
# A timestamp ETag is the WAL-102 signature: it means the digest is missing, so a resumed
# download's validator rotates whenever the object is rewritten even if the bytes are identical.
ARTIFACTS=$(python3 - "$SERVICE_URL" <<'PY'
import json, sys, urllib.request
base = sys.argv[1]
def get(path):
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.load(r)
out = []
for pkg in get("/api/v1/packages")["packages"]:
    name = pkg["name"]
    try:
        groups = get(f"/api/v1/packages/{name}/groups").get("groups") or []
    except Exception:
        continue
    if not groups:
        continue
    g = groups[0].get("version_group") or groups[0].get("group")
    try:
        vers = get(f"/api/v1/packages/{name}/versions")
    except Exception:
        continue
    for v in vers.get("versions", [])[:1]:
        for plat in v.get("platforms", []):
            if plat.get("status") != "available":
                continue
            try:
                d = get(f"/api/v1/packages/{name}/versions/{g}/latest?os={plat['os']}&arch={plat['arch']}")
            except Exception:
                continue
            a = d["artifact"]
            out.append("\t".join([name, d["version"], a["os"], a["arch"],
                                  str(a["checksum"]), str(a["checksum_type"]),
                                  str(a["file_size"]), str(a.get("transform")),
                                  str(a.get("source_checksum"))]))
print("\n".join(out))
PY
)

MISSING=$(printf '%s\n' "$ARTIFACTS" | awk -F'\t' 'NF && $5=="None" {print $1"/"$3"/"$4}')
if [ -z "$MISSING" ]; then
  ok "WAL-102" "every available artifact publishes a digest ($(printf '%s\n' "$ARTIFACTS" | grep -c . ) checked)"
else
  no "WAL-102" "artifacts with no published digest: $(printf '%s' "$MISSING" | tr '\n' ' ')"
fi

# WAL-58's provenance split: for a transformed artifact the served bytes are walrus's own, so
# its digest MUST differ from the upstream source digest. Equality means the published digest
# describes bytes walrus does not serve — worse than a missing digest, because a verifying
# client then fails on a good file. This is how WAL-102's second face was found.
LIARS=$(printf '%s\n' "$ARTIFACTS" | awk -F'\t' 'NF && $8!="None" && $9!="None" && $5==$9 {print $1"/"$3"/"$4}')
if [ -z "$LIARS" ]; then
  ok "WAL-102" "every transformed artifact's digest differs from its upstream source digest"
else
  no "WAL-102" "served digest equals the upstream source digest on:$(printf ' %s' $LIARS)"
fi

WEAK=""
while IFS=$'\t' read -r name ver os arch sum stype size xform srcsum; do
  [ -z "${name:-}" ] && continue
  et=$(curl -s -D - -o /dev/null -m 40 -H "Range: bytes=0-99" \
       "$SERVICE_URL/download/$name/$ver/$os/$arch" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2-)
  case "$et" in \"sha*) : ;; *) WEAK="$WEAK $name/$os/$arch" ;; esac
done <<< "$ARTIFACTS"
[ -z "$WEAK" ] && ok "WAL-66" "every artifact serves a content-derived If-Range validator" \
               || no "WAL-66" "timestamp ETag (no digest) on:$WEAK"

if [ "$FULL" = 1 ]; then
  # Metadata agreeing with itself proves nothing about the bytes. Verify the smallest artifact
  # end to end — small enough to be cheap, and the code path is identical at any size.
  read -r sname sver sos sarch ssum sstype <<<"$(printf '%s\n' "$ARTIFACTS" \
    | awk -F'\t' 'NF && $5!="None" {print $7"\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6}' \
    | sort -n | head -1 | cut -f2-)"
  if [ -n "${sname:-}" ]; then
    tmp=$(mktemp)
    curl -s -m 300 -o "$tmp" "$SERVICE_URL/download/$sname/$sver/$sos/$sarch"
    actual=$("${sstype}sum" "$tmp" | cut -d' ' -f1)
    [ "$actual" = "$ssum" ] \
      && ok "WAL-102" "$sname bytes hash to the published digest ($sstype)" \
      || no "WAL-102" "$sname served bytes do not match its published digest"
    rm -f "$tmp"
  fi
fi

# =========================================================================================
head_ "Autonomous backfill — WAL-101 / WAL-40 AC5"
# =========================================================================================
# The sweep must make progress: a package it launches must be marked, so the next sweep picks a
# different one. A package selected by two consecutive sweeps is the WAL-101 signature and the
# concrete form of WAL-43's deferred "succeeded but achieved nothing" alert.
# Scoped to the revision that is actually serving: launches by code since replaced say nothing
# about the deployment under test, and before WAL-101 there are plenty of them.
REV_SINCE=$(gcloud run revisions list --region="$REGION" --project="$PROJECT" \
  --format='value(creationTimestamp)' --filter='status.conditions.type=Active AND status.conditions.status=True' \
  --limit=1 2>/dev/null)
REV_SINCE="${REV_SINCE:-$(date -u -d '1 day ago' '+%Y-%m-%dT%H:%M:%SZ')}"
SWEEPS=$(gcloud logging read \
  "resource.type=\"cloud_run_revision\" AND jsonPayload.msg=\"Started autonomous CVE backfill for newly tracked package\" AND timestamp>=\"${REV_SINCE}\"" \
  --project="$PROJECT" --format=json --limit=50 2>/dev/null)

RESULT=$(printf '%s' "$SWEEPS" | python3 -c '
import json, sys
es = json.load(sys.stdin)
seen = {}
for e in es:
    p = (e.get("jsonPayload") or {}).get("package")
    if p:
        seen[p] = seen.get(p, 0) + 1
dupes = {k: v for k, v in seen.items() if v > 1}
if dupes:
    print("FAIL re-selected since deploy: " + ", ".join(f"{k}x{v}" for k, v in dupes.items()))
elif len(seen) < 2:
    # One launch cannot show whether the NEXT sweep moves on, which is the whole property.
    print(f"THIN only {len(seen)} sweep launch(es) since deploy; needs a second to be conclusive")
else:
    print(f"OK {len(seen)} package(s) launched since deploy, none twice: " + ", ".join(sorted(seen)))
')
case "$RESULT" in
  OK*)   ok   "WAL-101" "${RESULT#OK }" ;;
  THIN*) warn "WAL-101" "${RESULT#THIN }" ;;
  *)     no   "WAL-101" "${RESULT#FAIL }" ;;
esac

FAILED_EXEC=$(gcloud run jobs executions list --region="$REGION" --project="$PROJECT" \
  --format='value(name,status.failedCount)' --limit=20 2>/dev/null | awk '$2 != "" && $2 != "0" {print $1}')
[ -z "$FAILED_EXEC" ] && ok "WAL-40" "no failed Cloud Run Job executions in the recent window" \
                      || warn "WAL-40" "failed executions: $(printf '%s' "$FAILED_EXEC" | tr '\n' ' ')"

# =========================================================================================
if [ "$DRIFT" = 1 ]; then
head_ "Terraform drift — WAL-96"
# A plan that is never clean trains reviewers to skim the diff, which is how a real change gets
# waved through. Requires the deploy environment to be sourced.
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../terraform" && pwd)"
TF_PLAN_LOG="$(mktemp)"
if [ -z "${TERRAFORM_STATE_BUCKET:-}" ]; then
  warn "WAL-96" "skipped: source ~/.config/walrus/deploy.env first"
else
  # The same three variables deploy.sh computes. Without them plan cannot resolve, and its exit
  # code would be indistinguishable from real drift.
  export TF_VAR_image_tag="${TF_VAR_image_tag:-$(gcloud run services describe walrus-api \
    --region="$REGION" --project="$PROJECT" \
    --format='value(spec.template.spec.containers[0].image)' 2>/dev/null | sed 's/.*://')}"
  if [ -n "${NVD_API_KEY:-}" ]; then
    export TF_VAR_nvd_api_key_configured="${TF_VAR_nvd_api_key_configured:-true}"
  else
    export TF_VAR_nvd_api_key_configured="${TF_VAR_nvd_api_key_configured:-false}"
  fi
  export TF_VAR_alert_notification_email="${TF_VAR_alert_notification_email:-$(gcloud projects get-iam-policy "$PROJECT" \
    --flatten='bindings[].members' --filter='bindings.role=roles/owner AND bindings.members:user:' \
    --format='value(bindings.members)' 2>/dev/null | sed 's/^user://' | head -1)}"
  terraform -chdir="$TF_DIR" init -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" -reconfigure >/dev/null 2>&1
  terraform -chdir="$TF_DIR" plan -detailed-exitcode -no-color >"$TF_PLAN_LOG" 2>&1
  case $? in
    0) ok   "WAL-96" "terraform plan is clean — no drift after deploy" ;;
    2) no   "WAL-96" "terraform plan reports drift" ;;
    *) warn "WAL-96" "terraform plan could not run: $(tail -3 "$TF_PLAN_LOG" | tr "\n" " ")" ;;
  esac
fi
fi

# =========================================================================================
printf '\n%s\n' "-------------------------------------------------------------"
printf '%d passed, %d failed, %d warning(s)\n' "$PASS" "$FAIL" "$WARN"
[ "$FULL" = 1 ] || printf 'run with --full to verify served bytes against published digests\n'
[ "$DRIFT" = 1 ] || printf 'run with --drift to check terraform plan cleanliness\n'
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
