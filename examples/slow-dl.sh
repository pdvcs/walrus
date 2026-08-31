#!/usr/bin/env bash
#
# WAL-66 manual test step 1: a full 1.6 GB ranged transfer over a deliberately slow link.
#
# The question is whether any single chunk request approaches Cloud Run's 3600s timeout when
# the client is slow. 32 MiB at ~350 KB/s is ~99s per request, so the answer is visible in the
# timestamps rather than argued from the code. Companion to wal66-resume-test.sh, which covers
# step 2 (interrupt and resume); this one is endurance, that one is correctness.
#
# Ran 2026-08-31 03:25:18Z → 04:42:36Z: 4637.4s, 340.1 KB/s sustained, 49 chunks, 1,614,981,679
# bytes, SHA-256 matching JetBrains' upstream sidecar. Log kept as wal66-slow-transfer.log.
#
# Takes over an hour by design — run it from somewhere that will not be suspended.

set -uo pipefail

WALRUS_URL="${WALRUS_URL:-https://walrus-api-lh3bh3olnq-uc.a.run.app}"
export WALRUS_URL

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${WORKDIR:-/tmp/wal66}"

mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit 1

PYTHONUNBUFFERED=1 python3 "$SCRIPT_DIR/download_artifact.py" \
   intellij 2026.2 \
   --os windows --arch x86-64 \
   --output intellij-2026.2.1.win.zip \
   --chunk-bytes 33554432 \
   --max-bytes-per-second 350320 \
   2>&1 | awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }' \
   | tee wal66-slow-transfer.log
