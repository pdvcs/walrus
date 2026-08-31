#!/usr/bin/env bash
#
# WAL-66 manual test step 2: kill a ranged transfer mid-flight, resume it, prove the resumed
# download refetched only what was missing and still assembled correct bytes.
#
# Step 1 (the full slow-link endurance run, examples/slow-dl.sh) already established that no
# single chunk request approaches Cloud Run's 3600s timeout. That is not what this exercises,
# so it does not repeat the 1h17m: the variable here is the interruption, not the link speed.
# --rate is exposed anyway for anyone who wants both at once.
#
# RUN THIS AGAINST A DEPLOYMENT CARRYING WAL-101 AND WAL-102. Before WAL-102 the artifact has
# no published digest, so the final verification below cannot run and the ETag is a timestamp
# rather than a content digest — which is precisely the validator this test leans on.
#
#   ./examples/wal66-resume-test.sh
#   ./examples/wal66-resume-test.sh --rate 350320 --kill-after 300   # at step 1's link speed
#
set -uo pipefail

WALRUS_URL="${WALRUS_URL:-https://walrus-api-lh3bh3olnq-uc.a.run.app}"
PACKAGE="${PACKAGE:-intellij}"
GROUP="${GROUP:-2026.2}"
OS="${OS:-windows}"
ARCH="${ARCH:-x86-64}"

# Defaults sized so the whole test takes ~4 minutes. The chunk is small enough that several
# complete before the kill, so the resume point is a real mid-transfer boundary rather than 0.
RATE=8388608          # bytes/sec
CHUNK=8388608         # 8 MiB
KILL_AFTER=45         # seconds into phase 1
WORKDIR="${WORKDIR:-/tmp/wal66-resume}"

while [ $# -gt 0 ]; do
  case "$1" in
    --rate) RATE="$2"; shift 2 ;;
    --chunk) CHUNK="$2"; shift 2 ;;
    --kill-after) KILL_AFTER="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT="$SCRIPT_DIR/download_artifact.py"
OUT="$WORKDIR/${PACKAGE}-resume-test.bin"
PART="$OUT.part"
LOG1="$WORKDIR/phase1.log"
LOG2="$WORKDIR/phase2.log"

FAILURES=0
say()  { printf '[%s] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*"; }
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

# ---------------------------------------------------------------------------------------
# Artifact metadata. `requires_range` must be true or this tests nothing: below the
# threshold the server serves a plain 200 and there is no resume path to exercise.
# ---------------------------------------------------------------------------------------
say "WAL-66 step 2 — interrupt and resume"
say "target $WALRUS_URL/$PACKAGE/$GROUP $OS/$ARCH"

META=$(curl -sS -m 30 "$WALRUS_URL/api/v1/packages/$PACKAGE/versions/$GROUP/latest?os=$OS&arch=$ARCH")
read -r VERSION TOTAL REQUIRES_RANGE PUBLISHED_SUM SUM_TYPE <<EOF
$(printf '%s' "$META" | python3 -c '
import json, sys
d = json.load(sys.stdin)
a = d["artifact"]
print(d["version"], a["file_size"], str(a["requires_range"]).lower(),
      a["checksum"] or "-", a["checksum_type"] or "-")
')
EOF

if [ -z "${TOTAL:-}" ]; then
  echo "could not read artifact metadata from $WALRUS_URL" >&2
  exit 1
fi
say "$PACKAGE $VERSION — $TOTAL bytes, requires_range=$REQUIRES_RANGE, checksum=${PUBLISHED_SUM:0:16}"

[ "$REQUIRES_RANGE" = "true" ] \
  && pass "artifact is above the range threshold, so the resume path is the one under test" \
  || fail "requires_range is false — this artifact never takes the ranged path"

# ---------------------------------------------------------------------------------------
# Phase 1 — start, then kill mid-transfer. SIGKILL, not SIGINT: the client traps SIGINT and
# exits cleanly, and a clean exit is not the scenario. This is the process dying.
# ---------------------------------------------------------------------------------------
say "phase 1: downloading, will SIGKILL after ${KILL_AFTER}s"
PYTHONUNBUFFERED=1 python3 "$CLIENT" "$PACKAGE" "$GROUP" \
  --os "$OS" --arch "$ARCH" --output "$OUT" \
  --chunk-bytes "$CHUNK" --max-bytes-per-second "$RATE" >"$LOG1" 2>&1 &
DL_PID=$!

sleep "$KILL_AFTER"
if ! kill -0 "$DL_PID" 2>/dev/null; then
  fail "phase 1 finished within ${KILL_AFTER}s — lower --kill-after or --rate; nothing was interrupted"
  wait "$DL_PID" 2>/dev/null
  exit 1
fi
kill -9 "$DL_PID" 2>/dev/null
wait "$DL_PID" 2>/dev/null
say "phase 1 killed"

[ -f "$PART" ] || { fail "no .part file after the kill; cannot resume"; exit 1; }
HAVE=$(stat -c %s "$PART")
say "partial file holds $HAVE bytes"

if [ "$HAVE" -gt 0 ] && [ "$HAVE" -lt "$TOTAL" ]; then
  pass "interrupted mid-transfer ($HAVE of $TOTAL bytes on disk)"
else
  fail "partial file is $HAVE bytes against a total of $TOTAL — not a mid-transfer interruption"
fi

# Every chunk is appended only once received in full, so a partial file that is not a chunk
# multiple would mean a torn write survived the kill.
[ $((HAVE % CHUNK)) -eq 0 ] \
  && pass "partial file is a whole number of chunks — no torn chunk was kept" \
  || fail "partial file is not a chunk multiple ($HAVE % $CHUNK = $((HAVE % CHUNK)))"

[ -s "$PART.etag" ] \
  && pass "range validator persisted for the next process: $(cat "$PART.etag")" \
  || fail "no saved .etag beside the partial file — a later process cannot send If-Range"

# ---------------------------------------------------------------------------------------
# Phase 2 — a fresh process resumes. This is the real scenario: the first run's memory is
# gone, and everything the resume needs has to come off disk.
# ---------------------------------------------------------------------------------------
say "phase 2: resuming in a new process"
START2=$(date +%s)
PYTHONUNBUFFERED=1 python3 "$CLIENT" "$PACKAGE" "$GROUP" \
  --os "$OS" --arch "$ARCH" --output "$OUT" \
  --chunk-bytes "$CHUNK" --max-bytes-per-second "$RATE" >"$LOG2" 2>&1
RC=$?
ELAPSED2=$(( $(date +%s) - START2 ))
say "phase 2 exited $RC after ${ELAPSED2}s"

[ "$RC" -eq 0 ] || fail "resumed download exited $RC — see $LOG2"

grep -q '^resuming at' "$LOG2" \
  && pass "resumed rather than restarting: $(grep -m1 '^resuming at' "$LOG2")" \
  || fail "no resume line in phase 2 — it started over from zero"

grep -qi 'discarding' "$LOG2" \
  && fail "phase 2 discarded the partial data: $(grep -m1 -i 'discarding' "$LOG2")" \
  || pass "the bytes already on disk were kept, not refetched"

# Only the missing ranges should cross the wire. At a known rate, refetching the whole
# artifact would take at least TOTAL/RATE seconds; resuming should take about
# (TOTAL-HAVE)/RATE. Allow generous slack for TLS setup and per-chunk overhead.
REMAINING=$((TOTAL - HAVE))
FLOOR=$((REMAINING / RATE))
FULL=$((TOTAL / RATE))
if [ "$ELAPSED2" -lt "$FULL" ]; then
  pass "phase 2 took ${ELAPSED2}s against ${FULL}s for a full refetch — only the missing ${REMAINING} bytes were fetched (floor ${FLOOR}s)"
else
  fail "phase 2 took ${ELAPSED2}s, at or above the ${FULL}s a full refetch would need"
fi

# ---------------------------------------------------------------------------------------
# The assembled artifact. Size alone would pass for a file spliced from two different
# builds, which is the failure the If-Range validator exists to prevent — so the digest is
# the assertion that matters.
# ---------------------------------------------------------------------------------------
[ -f "$OUT" ] || { fail "no output file after phase 2"; exit 1; }
FINAL=$(stat -c %s "$OUT")
[ "$FINAL" -eq "$TOTAL" ] \
  && pass "assembled size is exact ($FINAL bytes)" \
  || fail "assembled size is $FINAL, expected $TOTAL"

if [ "$PUBLISHED_SUM" = "-" ]; then
  fail "walrus published no checksum for this artifact (WAL-102) — the assembled bytes cannot be verified against the server"
else
  ALGO=${SUM_TYPE:-sha256}
  ACTUAL=$("${ALGO}sum" "$OUT" | cut -d' ' -f1)
  if [ "$ACTUAL" = "$PUBLISHED_SUM" ]; then
    pass "assembled $ALGO matches the published digest ($ACTUAL)"
  else
    fail "$ALGO mismatch: published $PUBLISHED_SUM, assembled $ACTUAL"
  fi
fi

[ -f "$PART" ] \
  && fail "the .part file survived a completed download" \
  || pass "partial file cleaned up on completion"

echo
if [ "$FAILURES" -eq 0 ]; then
  say "WAL-66 step 2 PASSED — interrupted at $HAVE/$TOTAL bytes, resumed in a new process, assembled bytes verified"
  say "logs: $LOG1 $LOG2"
  exit 0
fi
say "WAL-66 step 2 FAILED — $FAILURES check(s) failed; logs: $LOG1 $LOG2"
exit 1
