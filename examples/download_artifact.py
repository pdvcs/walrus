#!/usr/bin/env python3
"""Download an artifact from walrus, with resume and a progress bar.

A worked example of the download protocol for downstream consumers. Standard library only —
no pip install — so it runs as-is on a developer laptop.

    ./download_artifact.py intellij 2026.2 --os windows --arch x86-64

The four things a correct client does, all of which this script demonstrates:

  1. Fetches metadata first, and reads `requires_range`. Above the server's threshold
     (1 GB by default) an unranged GET is REFUSED with 400 `range_required`, not served —
     a single request cannot finish inside the server's 3600s deadline at that size, so
     "degrading gracefully" would mean an hour of doomed transfer and no partial result.

  2. Downloads in chunks with `Range: bytes=<start>-<end>`, so an interrupted transfer
     resumes from what is already on disk instead of starting over.

  3. Sends `If-Range: <etag>` on every ranged request after the first. If the artifact has
     been re-synced since the download began, the server answers `200` with the whole
     representation rather than `206` — its way of saying "this is not the file you started".
     Splicing the old bytes and the new ones together would produce a corrupt archive that
     still looks plausible, so the only safe response is to discard and restart.

  4. Verifies the checksum ONCE, over the reassembled file. `X-Checksum-Sha256` always
     describes the whole artifact, never the chunk in front of you.

Exit codes: 0 success, 1 usage/HTTP error, 2 checksum mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Big enough that per-request overhead is noise against the transfer, small enough that an
# interruption costs little and a stalled chunk is noticed quickly. The server does not care:
# it answers whatever range you ask for, so this is purely the client's retry granularity.
CHUNK_BYTES = 32 * 1024 * 1024

MAX_ATTEMPTS_PER_CHUNK = 5
BACKOFF_SECONDS = 2


class DownloadError(Exception):
    """Anything that should stop the download with a message rather than a traceback."""


class ArtifactChanged(DownloadError):
    """The artifact was re-synced mid-download; partial bytes are unusable."""


def http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        raise DownloadError(describe_http_error(err)) from err
    except urllib.error.URLError as err:
        raise DownloadError(f"cannot reach {url}: {err.reason}") from err


def error_body(err: urllib.error.HTTPError) -> dict:
    """Read and cache the JSON body of an error response; the stream can only be read once."""
    cached = getattr(err, "_walrus_body", None)
    if cached is None:
        try:
            cached = json.loads(err.read().decode("utf-8", "replace"))
        except Exception:
            cached = {}
        err._walrus_body = cached
    return cached


def describe_http_error(err: urllib.error.HTTPError) -> str:
    """Turn walrus's JSON error bodies into something worth printing.

    The status codes carry meaning here and are worth handling rather than retrying blindly:
    403 is the critical-CVE gate refusing a version — its body names the advisory and the
    comparison that matched — 423 is a release still inside its cooling-off embargo (with
    `Retry-After`), and 400 `range_required` means the artifact is too large to fetch in one
    request.
    """
    body = error_body(err)
    detail = body.get("error") or err.reason

    if err.code == 403:
        # The gate names the advisory and the comparison that matched it, so there is something
        # to check rather than just a refusal. `fixed_in`, when the advisory has one, is already
        # in the message.
        blocked = body.get("blocked_by") or {}
        why = blocked.get("matched_because")
        return f"blocked: {detail}" + (f" [matched: {why}]" if why else "")
    if err.code == 423:
        retry_after = err.headers.get("Retry-After")
        available = body.get("available_at")
        when = f" until {available}" if available else ""
        wait = f", retry after {retry_after}s" if retry_after else ""
        return f"embargoed: {detail}{when}{wait}"
    if err.code == 400 and body.get("code") == "stale_range_validator":
        return str(body.get("error"))
    if err.code == 400 and body.get("code") == "range_required":
        above = body.get("range_required_above_bytes")
        return (
            f"this artifact must be fetched with Range requests"
            f"{f' (over {human(above)})' if above else ''} — "
            "the unranged path is refused, not merely discouraged"
        )
    return f"HTTP {err.code}: {detail}"


def host_platform() -> tuple[str, str]:
    """This machine in walrus's vocabulary, as the default for --os/--arch.

    A fixed default would be wrong for most people running this, and the failure it produces —
    a 404 for a platform they never asked about — reads like the package is missing rather than
    like a flag needs setting.
    """
    system = {"windows": "windows", "darwin": "macos", "linux": "linux"}.get(
        platform.system().lower(), "linux"
    )
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86-64"
    return system, arch


def available_platforms(base: str, package: str, group: str) -> str:
    """A human-readable summary of what this package does offer, for a 404 message."""
    try:
        payload = http_json(f"{base}/api/v1/packages/{package}/versions")
    except DownloadError:
        return ""

    groups = payload.get("version_groups", [])
    if group not in groups:
        return f"\n       groups for {package}: {', '.join(groups) or '(none)'}"

    combos = sorted(
        {
            f"{p['os']}/{p['arch']}"
            for v in payload.get("versions", [])
            if v.get("version_group") == group
            for p in v.get("platforms", [])
            if p.get("status") == "available"
        }
    )
    if not combos:
        return f"\n       {package} {group} has no available artifacts yet — has it synced?"
    return f"\n       available for {package} {group}: {', '.join(combos)}"


def fetch_metadata(base: str, package: str, group: str, os_name: str, arch: str) -> dict:
    query = urllib.parse.urlencode({"os": os_name, "arch": arch})
    # Catalog reads live under /api/v1; the download route is at /download, which is why the
    # metadata URL is built here and the artifact URL is taken from the response rather than
    # assembled a second time.
    url = (
        f"{base}/api/v1/packages/{package}/versions/{urllib.parse.quote(group)}/latest?{query}"
    )
    try:
        payload = http_json(url)
    except DownloadError as err:
        # A bare 404 here is ambiguous between an unknown package, an unknown group, and a
        # platform this package does not publish. Say which.
        if "404" in str(err):
            raise DownloadError(f"{err}{available_platforms(base, package, group)}") from err
        raise
    artifact = payload["artifact"]
    return {
        "version": payload["version"],
        "filename": artifact["filename"],
        "size": artifact["file_size"],
        "checksum": artifact["checksum"],
        "checksum_type": artifact["checksum_type"],
        "requires_range": artifact["requires_range"],
        "url": base + artifact["download_url"],
    }


def fetch_chunk(url: str, start: int, end: int, etag: str | None) -> tuple[bytes, str | None]:
    """One ranged GET. Returns the bytes and the artifact's current ETag.

    Raises ArtifactChanged when the server answers 200 — under `If-Range` that is the
    documented signal that the entity no longer matches what we started downloading.
    """
    headers = {"Range": f"bytes={start}-{end}"}
    if etag:
        headers["If-Range"] = etag

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200 and start > 0:
                raise ArtifactChanged(
                    "walrus returned the whole artifact instead of the requested range — "
                    "it has been re-synced since this download started"
                )
            return resp.read(), resp.headers.get("ETag")
    except urllib.error.HTTPError as err:
        if err.code == 416:
            raise DownloadError(
                "requested range is not satisfiable — the local partial file is longer than "
                "the artifact, so delete it and start again"
            ) from err
        # Above the server's range-required threshold a stale `If-Range` cannot be answered
        # the way RFC 9110 asks — the whole representation is precisely what the server has
        # refused to send at this size — so the mismatch arrives as a refusal carrying its own
        # code rather than as a `200`.
        if err.code == 400 and error_body(err).get("code") == "stale_range_validator":
            raise ArtifactChanged(error_body(err).get("error", "the artifact has changed")) from err
        raise DownloadError(describe_http_error(err)) from err


def download(meta: dict, dest: str, resume: bool, chunk_bytes: int = CHUNK_BYTES) -> None:
    total = meta["size"]
    part = dest + ".part"
    etag_file = part + ".etag"

    # A .part file is the resume point. Its length is how many bytes are already correct,
    # because every chunk is appended only after it has been received in full.
    have = os.path.getsize(part) if (resume and os.path.exists(part)) else 0
    if have > total:
        raise DownloadError(f"{part} is larger than the artifact; delete it and retry")

    # The ETag is saved next to the partial file, because resuming is mostly something you do
    # in a LATER process — the first run was interrupted. Without it the first request of a
    # resumed download cannot carry `If-Range`, and the one moment the protection is needed
    # most (bytes on disk from an unknown earlier time) is the one moment it would be missing.
    etag: str | None = None
    if have:
        try:
            etag = open(etag_file).read().strip() or None
        except OSError:
            etag = None
        if etag is None:
            # Correctness over convenience: unverifiable partial bytes are worth less than the
            # bandwidth to refetch them.
            print(
                f"discarding {human(have)} of partial data: no saved ETag, so it cannot be "
                "proven to belong to the current artifact",
                file=sys.stderr,
            )
            have = 0
        else:
            print(f"resuming at {human(have)} of {human(total)}", file=sys.stderr)

    started = time.monotonic()
    bar = ProgressBar(total, already=have)

    with open(part, "ab" if have else "wb") as out:
        while have < total:
            end = min(have + chunk_bytes, total) - 1
            for attempt in range(1, MAX_ATTEMPTS_PER_CHUNK + 1):
                try:
                    body, seen_etag = fetch_chunk(meta["url"], have, end, etag)
                    break
                except ArtifactChanged:
                    raise
                except DownloadError:
                    if attempt == MAX_ATTEMPTS_PER_CHUNK:
                        raise
                    # Only the failed chunk is retried: the bytes already on disk stay put.
                    time.sleep(BACKOFF_SECONDS * attempt)

            # Pin the identity on the first response and hold it for the rest of the transfer.
            if etag is None and seen_etag:
                etag = seen_etag
                with open(etag_file, "w") as handle:
                    handle.write(etag)
            out.write(body)
            out.flush()
            have += len(body)
            bar.update(have)

    bar.finish()
    elapsed = max(time.monotonic() - started, 1e-9)
    print(f"transferred in {elapsed:.1f}s ({human(total / elapsed)}/s)", file=sys.stderr)
    os.replace(part, dest)
    # Rename first, then drop the sidecar: a crash between the two leaves a stray .etag, which
    # is harmless, where the reverse order could orphan a .part with no identity.
    try:
        os.remove(etag_file)
    except OSError:
        pass


def verify(path: str, expected: str | None, algorithm: str | None) -> bool:
    """Hash the reassembled file. Never per chunk — the header describes the whole artifact."""
    if not expected:
        print("no checksum published for this artifact; skipping verification", file=sys.stderr)
        return True

    digest = hashlib.new(algorithm or "sha256")
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    actual = digest.hexdigest()
    if actual != expected:
        print(f"CHECKSUM MISMATCH\n  expected {expected}\n  actual   {actual}", file=sys.stderr)
        return False
    print(f"{algorithm or 'sha256'} verified", file=sys.stderr)
    return True


class ProgressBar:
    """A single rewritten line on a TTY; periodic plain lines when redirected to a file."""

    def __init__(self, total: int, already: int = 0) -> None:
        self.total = total
        self.start = time.monotonic()
        self.start_bytes = already
        self.tty = sys.stderr.isatty()
        self.last_render = 0.0
        self.width = min(shutil.get_terminal_size((80, 20)).columns, 100)

    def update(self, done: int) -> None:
        now = time.monotonic()
        if now - self.last_render < (0.1 if self.tty else 5.0) and done < self.total:
            return
        self.last_render = now

        fraction = done / self.total if self.total else 1.0
        elapsed = max(now - self.start, 1e-9)
        rate = (done - self.start_bytes) / elapsed
        eta = (self.total - done) / rate if rate > 0 else 0

        if self.tty:
            # 30 chars of bar plus the numbers, kept inside the terminal width.
            filled = int(30 * fraction)
            bar = "#" * filled + "-" * (30 - filled)
            line = (
                f"\r[{bar}] {fraction * 100:5.1f}%  "
                f"{human(done)}/{human(self.total)}  {human(rate)}/s  ETA {clock(eta)}"
            )
            sys.stderr.write(line[: self.width].ljust(self.width))
        else:
            sys.stderr.write(
                f"{fraction * 100:5.1f}%  {human(done)}/{human(self.total)}  {human(rate)}/s\n"
            )
        sys.stderr.flush()

    def finish(self) -> None:
        if self.tty:
            sys.stderr.write("\n")
            sys.stderr.flush()


def human(n: float | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def clock(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds}s"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download an artifact from walrus, resumably, with a progress bar.",
        epilog="Example: %(prog)s intellij 2026.2 --os windows --arch x86-64",
    )
    parser.add_argument("package", help="package name, e.g. intellij")
    parser.add_argument("group", help="version group, e.g. 2026.2")
    default_os, default_arch = host_platform()
    parser.add_argument(
        "--os",
        default=default_os,
        choices=["windows", "macos", "linux"],
        help=f"default: this machine ({default_os})",
    )
    parser.add_argument(
        "--arch",
        default=default_arch,
        choices=["x86-64", "arm64"],
        help=f"default: this machine ({default_arch})",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("WALRUS_URL", "http://localhost:8080"),
        help="walrus base URL (env: WALRUS_URL, default http://localhost:8080)",
    )
    parser.add_argument("-o", "--output", help="output path (default: the artifact's filename)")
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="ignore any existing .part file and start over",
    )
    parser.add_argument(
        "--chunk-bytes",
        type=int,
        default=CHUNK_BYTES,
        help=f"bytes per ranged request (default {CHUNK_BYTES}); the server answers any size, "
        "so this is only how much a failed chunk costs you",
    )
    args = parser.parse_args()

    try:
        meta = fetch_metadata(
            args.base_url.rstrip("/"), args.package, args.group, args.os, args.arch
        )
    except DownloadError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    dest = args.output or meta["filename"]
    print(
        f"{args.package} {meta['version']} {args.os}/{args.arch}\n"
        f"  {meta['filename']}  {human(meta['size'])}"
        f"{'  (range required)' if meta['requires_range'] else ''}\n"
        f"  -> {dest}",
        file=sys.stderr,
    )

    if meta["size"] is None:
        print("error: walrus published no size for this artifact", file=sys.stderr)
        return 1

    try:
        download(meta, dest, resume=not args.no_resume, chunk_bytes=args.chunk_bytes)
    except ArtifactChanged as err:
        # Deliberately not automatic: restarting silently would hide that the artifact moved
        # under a running download, which is worth a human noticing.
        print(f"error: {err}\n       re-run with --no-resume to fetch it fresh", file=sys.stderr)
        return 1
    except DownloadError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted — re-run to resume from the .part file", file=sys.stderr)
        return 1

    return 0 if verify(dest, meta["checksum"], meta["checksum_type"]) else 2


if __name__ == "__main__":
    sys.exit(main())
