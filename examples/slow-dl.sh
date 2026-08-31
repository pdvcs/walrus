mkdir -p /tmp/wal66
cd /tmp/wal66
export WALRUS_URL=https://walrus-api-lh3bh3olnq-uc.a.run.app

PYTHONUNBUFFERED=1 python3 /home/pd/repos/github/walrus/examples/download_artifact.py \
   intellij 2026.2 \
   --os windows --arch x86-64 \
   --output intellij-2026.2.1.win.zip \
   --chunk-bytes 33554432 \
   --max-bytes-per-second 440320 \
   2>&1 | tee wal66-slow-transfer.log
