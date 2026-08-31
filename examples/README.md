# Examples

Worked client code for consuming walrus. These are samples to read and adapt, not a supported
client library — they use only their language's standard library so they run with no install
step.

## `download_artifact.py`

Downloads an artifact with resume and a progress bar. Python 3.9+, no dependencies.

```bash
# --os/--arch default to the machine you are on
./download_artifact.py golang 1.27

# or name a platform explicitly
./download_artifact.py intellij 2026.2 --os windows --arch x86-64

# against a deployment
WALRUS_URL=https://walrus.example.internal ./download_artifact.py golang 1.27

# WAL-66 slow-link validation: 430 KiB/s = about 3.44 Mbit/s, below the 3.6 Mbit/s target
WALRUS_URL=https://walrus.example.internal ./download_artifact.py intellij 2026.2 \
  --os windows --arch x86-64 --chunk-bytes 33554432 --max-bytes-per-second 440320
```

Interrupt it and run it again: it resumes from the `.part` file.

Catalog reads live under `/api/v1/packages/...` while the download route is `/download/...`. The
script builds only the first, and takes the artifact URL from the metadata response rather than
assembling it a second time.

A 404 reports what _is_ available — the package's groups if the group is wrong, or the group's
platforms if the platform is.

### What it demonstrates

Walrus's download protocol has four properties a naive `curl -O` will get wrong, and the script
exists to show each one:

**Large artifacts must be fetched with `Range`.** Above the server's threshold (1 GB by
default) an unranged `GET` is refused with `400 range_required` rather than served. At that
size a single request cannot finish inside the server's 3600s deadline for any client under a
few Mbps, so serving it would mean an hour of doomed transfer and no partial result. The
artifact metadata carries `requires_range`, so a client can tell before it starts.

**Resume is per chunk, not per file.** Each `Range` request covers one chunk, appended to a
`.part` file only once received in full — so the file's length is always exactly how many bytes
are known good, and a failure costs one chunk rather than the whole transfer. `--chunk-bytes`
tunes that granularity; the server answers whatever you ask for and has no opinion.

**`If-Range` is what stops two builds being spliced together.** If the artifact is re-synced
mid-download, the bytes on disk and the bytes still to come belong to different files. Splicing
across that boundary produces a corrupt archive that still looks plausible, which is the worst
available outcome, so the script stops and says so rather than silently restarting.

A stale validator is reported two different ways, and a client has to handle both:

- **below the range-required threshold**, walrus does what RFC 9110 asks — ignores the `Range`
  and answers `200` with the whole representation, which is itself the "start over" signal;
- **above it**, that answer is impossible: the whole representation is exactly what the server
  refuses to send at this size. The mismatch surfaces as `400 stale_range_validator` instead,
  with explicit discard-and-restart guidance.

The second case is the one that matters in practice, since large artifacts are the ones actually
resumed across processes — see the note in `download_artifact.py`.

The ETag is saved next to the `.part` file, because resuming is usually something a _later
process_ does — the first run was interrupted. Without persisting it, the first request of a
resumed download could not carry `If-Range` at all, and the protection would be missing at
exactly the moment it matters most. A `.part` file with no saved ETag is discarded rather than
trusted.

**Verify the checksum once, over the reassembled file.** `X-Checksum-Sha256` always describes
the whole artifact, never the chunk in front of you. The script hashes after reassembly and
exits `2` on a mismatch.

### Errors worth handling

The status codes carry meaning; retrying blindly is wrong for three of them.

| Status                 | Meaning                                              | What to do                                                 |
| ---------------------- | ---------------------------------------------------- | ---------------------------------------------------------- |
| `403`                  | The version is blocked by walrus's critical-CVE gate | Do not retry — the body names the CVE and its `fixed_in`   |
| `423`                  | The release is inside its cooling-off embargo        | Retry after `Retry-After`; the body carries `available_at` |
| `400` `range_required` | Artifact is too large for an unranged GET            | Re-request with `Range`                                    |
| `416`                  | Requested range lies outside the artifact            | The local `.part` is stale — delete and restart            |

### Porting it

The protocol is the interesting part, and it is plain HTTP: nothing here needs a Python
runtime. A Node or Go port is a direct translation — the ordering that matters is metadata
first, then ranged chunks carrying `If-Range`, then one checksum over the result.
