import express from "express";
import request from "supertest";
import { Readable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { createDownloadRouter, DownloadRouteDeps } from "../../src/routes/download.js";

function createTestApp(deps: Parameters<typeof createDownloadRouter>[0]): express.Express {
  const app = express();
  app.use("/download", createDownloadRouter(deps));
  return app;
}

function baseDeps(): DownloadRouteDeps {
  return {
    getVersion: vi.fn().mockResolvedValue(null),
    listAffectsForPackage: vi.fn().mockResolvedValue([]),
    getArtifact: vi.fn().mockResolvedValue(null),
    streamFromStorage: vi.fn().mockReturnValue(Readable.from(Buffer.from(""))),
  };
}

function makeAvailableArtifact(overrides: Partial<{ cooling_off_until: Date | null }> = {}) {
  return {
    id: 10,
    version_id: 1,
    os: "linux",
    arch: "x86-64",
    filename: "uv.tar.gz",
    gcs_path: "uv/0.10.10/linux/x86-64/uv.tar.gz",
    file_size: 5,
    checksum: "abc",
    checksum_type: "sha256",
    upstream_url: "https://example.test/uv.tar.gz",
    status: "available" as const,
    error_message: null,
    download_started_at: null,
    download_completed_at: null,
    removed_at: null,
    sync_job_id: null,
    created_at: new Date(Date.now() - 4 * 86_400_000),
    cooling_off_until: null,
    ...overrides,
  };
}

/**
 * The state the sync service actually leaves an embargoed artifact in: `pending` with no gcs_path,
 * because it skips queueing the download until the cooling-off window elapses.
 */
function makeCoolingOffArtifact(coolingOffUntil: Date) {
  return {
    ...makeAvailableArtifact(),
    gcs_path: null,
    file_size: null,
    checksum: null,
    checksum_type: null,
    status: "pending" as const,
    cooling_off_until: coolingOffUntil,
  };
}

/**
 * A concretely-matching critical affects row for version 0.10.10 — the shape the gate refuses on.
 * Scores are strings because that is how pg hands back NUMERIC.
 */
function criticalAffects(overrides: Record<string, unknown> = {}) {
  return {
    cve_id: "CVE-2026-0001",
    version_start: null,
    version_start_excl: false,
    version_end: null,
    version_end_excl: false,
    exact_version: "0.10.10",
    fixed_in: null,
    source: "nvd",
    version_na: false,
    severity: "CRITICAL",
    severity_source: "nvd-cvss-v3",
    cvss_v3_score: "9.8",
    cvss_v4_score: null,
    cvss_v2_score: null,
    description: null,
    is_kev: false,
    raw: null,
    ...overrides,
  };
}

function makeVersionRow() {
  return {
    id: 1,
    package_name: "uv",
    version: "0.10.10",
    version_group: "0.10",
    is_lts: false,
    discovered_at: new Date(),
    version_sort: "0000.0010.0010",
  };
}

describe("download routes", () => {
  // WAL-53: a disabled package (operator disable or TOML-removed tombstone) must not
  // serve binaries via direct URL. 404 rather than 403 — that is reserved for the
  // critical-CVE gate's "dangerous" semantics.
  it("returns 404 for a disabled/tombstoned package even with an available artifact", async () => {
    const deps = baseDeps();
    deps.getPackageRow = vi.fn().mockResolvedValue({ enabled: false });
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue(makeAvailableArtifact());
    const app = createTestApp(deps);

    const res = await request(app).get("/download/uv/0.10.10/linux/x86-64");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not available/);
    expect(deps.getArtifact).not.toHaveBeenCalled();
  });

  it("serves normally when the package row reports enabled", async () => {
    const deps = baseDeps();
    deps.getPackageRow = vi.fn().mockResolvedValue({ enabled: true });
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue(makeAvailableArtifact());
    deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
    const app = createTestApp(deps);

    const res = await request(app).get("/download/uv/0.10.10/linux/x86-64");
    expect(res.status).toBe(200);
  });

  it("streams an available artifact with headers", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue(makeAvailableArtifact());
    deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("application/octet-stream");
    expect(response.headers["x-checksum-sha256"]).toBe("abc");
    const body = response.body as Buffer;
    expect(Buffer.isBuffer(body)).toBe(true);
    expect(body.toString("utf8")).toBe("hello");
  });

  it("returns 404 when version is missing", async () => {
    const deps = baseDeps();
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(404);
    const body = response.body as { error: string };
    expect(body.error).toBe("Version not found");
  });

  it("returns 404 when artifact is unavailable", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue({
      ...makeAvailableArtifact(),
      gcs_path: null,
      status: "failed" as const,
      error_message: "boom",
    });
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(404);
    const body = response.body as { error: string };
    expect(body.error).toBe("Artifact not found");
  });

  it("returns 403 without reading storage when the version has a critical CVE", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([criticalAffects()]);
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(403);
    expect(deps.getArtifact).not.toHaveBeenCalled();
    expect(deps.streamFromStorage).not.toHaveBeenCalled();
  });

  // WAL-79. The old body was the fixed string "Version blocked due to a critical vulnerability":
  // a developer whose build just failed learned that something was wrong and had no thread to
  // pull. The explanation was already computed one call below the response and thrown away.
  describe("the 403 explains itself (WAL-79)", () => {
    async function get403(rows: unknown[]) {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      deps.listAffectsForPackage = vi.fn().mockResolvedValue(rows);
      return request(createTestApp(deps)).get("/download/uv/0.10.10/linux/x86-64");
    }

    /** Everything the gate lets through reaches an artifact that really streams. */
    function servingDeps(rows: unknown[]): DownloadRouteDeps {
      return {
        ...baseDeps(),
        getVersion: vi.fn().mockResolvedValue(makeVersionRow()),
        listAffectsForPackage: vi.fn().mockResolvedValue(rows),
        getArtifact: vi.fn().mockResolvedValue(makeAvailableArtifact()),
        streamFromStorage: vi.fn().mockReturnValue(Readable.from(Buffer.from("bytes"))),
      };
    }

    it("names the CVE, the comparison that matched, and where to go instead", async () => {
      const response = await get403([criticalAffects({ fixed_in: "0.10.11" })]);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({
        // The one-line form has to stand alone: a build tool that prints one field prints this.
        error: "Version 0.10.10 is blocked by CVE-2026-0001 (CVSS 9.8) — fixed in 0.10.11",
        blocked_by: {
          cve_id: "CVE-2026-0001",
          matched_because: "0.10.10 == 0.10.10",
          severity: "CRITICAL",
          severity_source: "nvd-cvss-v3",
          cvss_v3_score: 9.8,
          cvss_v4_score: null,
          cvss_v2_score: null,
          is_kev: false,
          fixed_in: "0.10.11",
        },
      });
    });

    it("omits the remedy from the message when the advisory names no fixed version", async () => {
      const response = await get403([criticalAffects()]);

      expect(response.body.error).toBe("Version 0.10.10 is blocked by CVE-2026-0001 (CVSS 9.8)");
      expect(response.body.blocked_by.fixed_in).toBeNull();
    });

    // The gate is any-of across CVSS versions (ADR-005), so a body naming only v3 would
    // misdescribe a v4-caused refusal — the same mistake availability history already corrected.
    it("reports every score, not just v3", async () => {
      const response = await get403([
        criticalAffects({
          cvss_v3_score: null,
          cvss_v4_score: "9.9",
          cvss_v2_score: "10.0",
          severity_source: "nvd-cvss-v4",
        }),
      ]);

      expect(response.body.error).toContain("CVSS 9.9");
      expect(response.body.blocked_by).toMatchObject({
        severity_source: "nvd-cvss-v4",
        cvss_v3_score: null,
        cvss_v4_score: 9.9,
        cvss_v2_score: 10,
      });
    });

    // AC6: two callers holding the same rows in a different order get the same answer.
    it("names the worst CVE, whatever order the rows arrive in", async () => {
      const rows = [
        criticalAffects({ cve_id: "CVE-2026-0002", cvss_v3_score: "9.1" }),
        criticalAffects({ cve_id: "CVE-2026-0009", cvss_v3_score: "9.9" }),
        criticalAffects({ cve_id: "CVE-2026-0005", cvss_v3_score: "9.4" }),
      ];
      const forward = await get403(rows);
      const reversed = await get403([...rows].reverse());

      expect(forward.body.blocked_by.cve_id).toBe("CVE-2026-0009");
      expect(reversed.body).toEqual(forward.body);
    });

    // AC7. A suppression is an operator's assertion that the CVE does not apply here (WAL-70);
    // the version is not blocked, so the 403 that would have named the CVE never happens.
    it("serves the artifact when the only critical CVE is suppressed — no 403 to name it in", async () => {
      const deps = servingDeps([
        criticalAffects({
          suppressed: true,
          suppression_id: 3,
          suppression_reason: "not shipped in this build",
        }),
      ]);

      const response = await request(createTestApp(deps)).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
      expect((response.body as Buffer).toString()).toBe("bytes");
    });

    // A nullable field's schema rejects `undefined`, so a row that merely omits a key must not
    // cost the whole explanation — it would fall back on rows that are perfectly describable.
    it("still explains the block when the row omits an optional key entirely", async () => {
      const sparse: Record<string, unknown> = criticalAffects();
      delete sparse.fixed_in;
      delete sparse.severity_source;
      const response = await get403([sparse]);

      expect(response.body.blocked_by).toMatchObject({
        cve_id: "CVE-2026-0001",
        matched_because: "0.10.10 == 0.10.10",
        fixed_in: null,
        severity_source: null,
      });
    });

    // Explaining a refusal must not be able to prevent one. Response schemas are parsed so a
    // mismatch surfaces as a 500 in dev and tests — deliberate everywhere except here, where a
    // 500 would tell a client to retry a version walrus withheld on purpose.
    it("still refuses with a generic message when the detail cannot be described", async () => {
      // A row whose cve_id drifted to a non-string: still blocks, cannot be described.
      const response = await get403([criticalAffects({ cve_id: 12345 })]);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ error: "Version blocked due to a critical vulnerability" });
      expect(response.body.blocked_by).toBeUndefined();
    });

    // A non-critical CVE is listed, never gated — the gate's threshold is unchanged by WAL-79.
    it("serves a version whose only CVE is below the critical threshold", async () => {
      const deps = servingDeps([criticalAffects({ severity: "HIGH", cvss_v3_score: "8.9" })]);

      const response = await request(createTestApp(deps)).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
    });
  });

  describe("cooling off period", () => {
    it("returns 423 with Retry-After when artifact has a future cooling_off_until", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is ~2.75 days from now (3 days - 6 hours elapsed)
      const coolingOffUntil = new Date(Date.now() + (3 * 86_400_000 - 6 * 3600_000));
      deps.getArtifact = vi.fn().mockResolvedValue(makeCoolingOffArtifact(coolingOffUntil));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(423);
      const body = response.body as { error: string; available_at: string };
      expect(body.error).toBe("Artifact is in cooling off period");
      expect(new Date(body.available_at).getTime()).toBeGreaterThan(Date.now());
      const retryAfter = Number(response.headers["retry-after"]);
      expect(retryAfter).toBeGreaterThan(0);
      // Should be roughly 2.75 days away, within 60s tolerance
      expect(retryAfter).toBeCloseTo(3 * 86400 - 6 * 3600, -3);
    });

    it("returns 423 rather than 404 for a pending artifact with no gcs_path", async () => {
      // Regression: the availability check used to run first, so every embargoed artifact -- which
      // is pending by design -- surfaced as "Artifact not found" and the 423 branch was dead code.
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeCoolingOffArtifact(new Date(Date.now() + 86_400_000)));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(423);
      expect(deps.streamFromStorage).not.toHaveBeenCalled();
    });

    it("returns 423 when an already-available artifact is re-embargoed", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(
          makeAvailableArtifact({ cooling_off_until: new Date(Date.now() + 86_400_000) }),
        );
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(423);
      expect(deps.streamFromStorage).not.toHaveBeenCalled();
    });

    it("serves the artifact once cooling_off_until has passed", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is 1 day in the past
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(
          makeAvailableArtifact({ cooling_off_until: new Date(Date.now() - 86_400_000) }),
        );
      deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
    });

    it("returns 404 when the embargo has lapsed but the download has not run yet", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeCoolingOffArtifact(new Date(Date.now() - 86_400_000)));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(404);
      const body = response.body as { error: string };
      expect(body.error).toBe("Artifact not found");
    });

    it("serves the artifact when cooling_off_until is null (no cooling off applied)", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is null — bootstrapped artifact, no cooling off
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeAvailableArtifact({ cooling_off_until: null }));
      deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
    });
  });
});

describe("ranged downloads (WAL-66)", () => {
  const BODY = Buffer.from("0123456789");

  /** Storage that honours the range it is handed, so a test can see what was actually read. */
  function rangedStorage(body = BODY) {
    return vi
      .fn()
      .mockImplementation((_key: string, range?: { start: number; end: number }) =>
        Readable.from(range ? body.subarray(range.start, range.end + 1) : body),
      );
  }

  function depsForArtifact(
    overrides: Partial<ReturnType<typeof makeAvailableArtifact>> = {},
    extra: Partial<DownloadRouteDeps> = {},
  ): DownloadRouteDeps {
    const artifact = { ...makeAvailableArtifact(), file_size: BODY.length, ...overrides };
    return {
      ...baseDeps(),
      getVersion: vi.fn().mockResolvedValue({ id: 1, version: "0.10.10" }),
      getArtifact: vi.fn().mockResolvedValue(artifact),
      streamFromStorage: rangedStorage(),
      ...extra,
    };
  }

  it("advertises Accept-Ranges and an ETag on a full response", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(200);
    expect(response.headers["accept-ranges"]).toBe("bytes");
    expect(response.headers.etag).toBe('"sha256-abc"');
  });

  it("returns 206 with Content-Range for an explicit range", async () => {
    const streamFromStorage = rangedStorage();
    const app = createTestApp(depsForArtifact({}, { streamFromStorage }));

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=2-5")
      .buffer()
      .parse((res, cb) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => cb(null, Buffer.concat(chunks)));
      });

    expect(response.status).toBe(206);
    expect(response.headers["content-range"]).toBe("bytes 2-5/10");
    expect((response.body as Buffer).toString()).toBe("2345");
    // Only the requested bytes are read from storage — not the whole object with a prefix
    // thrown away.
    expect(streamFromStorage).toHaveBeenCalledWith("uv/0.10.10/linux/x86-64/uv.tar.gz", {
      start: 2,
      end: 5,
    });
  });

  it("handles an open-ended range", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=7-");

    expect(response.status).toBe(206);
    expect(response.headers["content-range"]).toBe("bytes 7-9/10");
  });

  it("handles a suffix range", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=-3");

    expect(response.status).toBe(206);
    expect(response.headers["content-range"]).toBe("bytes 7-9/10");
  });

  it("clamps a last-byte position past the end rather than failing", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=8-999");

    expect(response.status).toBe(206);
    expect(response.headers["content-range"]).toBe("bytes 8-9/10");
  });

  it("omits Content-Length on a 206, as it does on a 200", async () => {
    // Cloud Run buffers a response that declares Content-Length and caps it at 32 MB, which
    // would silently limit the chunk size a client may ask for. Content-Range already states
    // the length.
    const app = createTestApp(depsForArtifact());

    const ranged = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=0-1");
    const full = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(ranged.headers["content-length"]).toBeUndefined();
    expect(full.headers["content-length"]).toBeUndefined();
  });

  it("carries the whole-object size and checksum on a 206", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=2-3");

    expect(response.headers["x-content-length"]).toBe("10");
    expect(response.headers["x-checksum-sha256"]).toBe("abc");
  });

  it("returns 416 with Content-Range for a range beyond the object", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=100-200");

    expect(response.status).toBe(416);
    expect(response.headers["content-range"]).toBe("bytes */10");
  });

  it("returns 416 for a zero-length suffix range", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=-0");

    expect(response.status).toBe(416);
  });

  it("answers a multi-range request with the full representation", async () => {
    // RFC 9110 permits this, and it is documented in api-docs.md. Silent mishandling is what
    // breaks clients; a full 200 does not.
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "bytes=0-1,4-5");

    expect(response.status).toBe(200);
  });

  it("ignores a range unit it does not recognise", async () => {
    const app = createTestApp(depsForArtifact());

    const response = await request(app)
      .get("/download/uv/0.10.10/linux/x86-64")
      .set("Range", "items=0-1");

    expect(response.status).toBe(200);
  });

  describe("If-Range", () => {
    it("honours the range when the validator matches", async () => {
      const app = createTestApp(depsForArtifact());

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=2-5")
        .set("If-Range", '"sha256-abc"');

      expect(response.status).toBe(206);
    });

    it("falls back to a full 200 when the artifact has been replaced", async () => {
      // The reachable case: a re-synced artifact overwrites the same key, and a client
      // resuming across that would splice two different builds into one corrupt archive.
      const app = createTestApp(depsForArtifact());

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=2-5")
        .set("If-Range", '"sha256-an-older-build"');

      expect(response.status).toBe(200);
      expect(response.headers["content-range"]).toBeUndefined();
    });

    it("names a stale validator when the artifact is too large to send whole", async () => {
      // The RFC answer to an If-Range mismatch — 200 with the whole representation — is
      // exactly what the size policy refuses above the threshold, so the two collide. Answering
      // `range_required` there tells a client that DID send a range to send one, which it can
      // only respond to by repeating the identical request forever, never learning that the
      // bytes on its disk are the problem (WAL-66 AC16).
      const limits = { rangeRequiredBytes: 8, suggestedChunkBytes: 4 };
      const streamFromStorage = rangedStorage();
      const app = createTestApp(
        depsForArtifact({ file_size: 9 }, { transferLimits: limits, streamFromStorage }),
      );

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=2-5")
        .set("If-Range", '"sha256-an-older-build"');
      const body = response.body as { code: string; error: string; file_size: number };

      expect(response.status).toBe(400);
      expect(body.code).toBe("stale_range_validator");
      expect(body.error).toMatch(/changed since this download began/);
      expect(body.file_size).toBe(9);
      // The current validator rides on the refusal, so restarting needs no extra round trip.
      expect(response.headers.etag).toBe('"sha256-abc"');
      expect(streamFromStorage).not.toHaveBeenCalled();
    });

    it("still reports range_required when no range was sent at all", async () => {
      // An If-Range without a Range is meaningless, and must not be mistaken for a mismatch:
      // the client's obligation here really is "send a range".
      const limits = { rangeRequiredBytes: 8, suggestedChunkBytes: 4 };
      const app = createTestApp(depsForArtifact({ file_size: 9 }, { transferLimits: limits }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("If-Range", '"sha256-an-older-build"');

      expect(response.status).toBe(400);
      expect((response.body as { code: string }).code).toBe("range_required");
    });

    it("keeps answering a stale validator with 200 below the threshold", async () => {
      // Where walrus CAN send the whole representation it does, exactly as RFC 9110 asks.
      // The refusal above is a consequence of the size policy, not a reinterpretation of
      // If-Range.
      const app = createTestApp(depsForArtifact({ file_size: 10 }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=2-5")
        .set("If-Range", '"sha256-an-older-build"');

      expect(response.status).toBe(200);
      expect(response.headers["content-range"]).toBeUndefined();
    });

    it("derives a validator from the write timestamp when there is no checksum", async () => {
      const completedAt = new Date("2026-08-27T10:00:00Z");
      const app = createTestApp(
        depsForArtifact({
          checksum: null,
          checksum_type: null,
          download_completed_at: completedAt,
        }),
      );

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.headers.etag).toBe(`"10-10-${completedAt.getTime()}"`);
    });
  });

  describe("the two-tier size policy", () => {
    const limits = { rangeRequiredBytes: 8, suggestedChunkBytes: 4 };

    it("serves an unranged GET below the threshold exactly as before", async () => {
      const app = createTestApp(depsForArtifact({ file_size: 8 }, { transferLimits: limits }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .buffer()
        .parse((res, cb) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => cb(null, Buffer.concat(chunks)));
        });

      expect(response.status).toBe(200);
      expect((response.body as Buffer).toString()).toBe("0123456789");
      expect(response.headers["content-disposition"]).toBe('attachment; filename="uv.tar.gz"');
      expect(response.headers["content-length"]).toBeUndefined();
    });

    it("refuses an unranged GET above the threshold instead of serving it", async () => {
      const streamFromStorage = rangedStorage();
      const app = createTestApp(
        depsForArtifact({ file_size: 9 }, { transferLimits: limits, streamFromStorage }),
      );

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");
      const body = response.body as {
        code: string;
        file_size: number;
        range_required_above_bytes: number;
        suggested_chunk_bytes: number;
      };

      expect(response.status).toBe(400);
      expect(body.code).toBe("range_required");
      expect(body.file_size).toBe(9);
      expect(body.range_required_above_bytes).toBe(8);
      expect(body.suggested_chunk_bytes).toBe(4);
      // Refused before a byte is read, not after an hour of doomed transfer.
      expect(streamFromStorage).not.toHaveBeenCalled();
      expect(response.headers["accept-ranges"]).toBe("bytes");
    });

    it("serves a ranged GET above the threshold", async () => {
      const app = createTestApp(depsForArtifact({ file_size: 9 }, { transferLimits: limits }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=0-3");

      expect(response.status).toBe(206);
      expect(response.headers["content-range"]).toBe("bytes 0-3/9");
    });

    it("keys on the request, never on who is asking", async () => {
      // A User-Agent allowlist would make our own package manager a privileged client and
      // leave the next consumer — a CI job with plain curl — silently broken.
      const app = createTestApp(depsForArtifact({ file_size: 9 }, { transferLimits: limits }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("User-Agent", "walrus-package-manager/1.0");

      expect(response.status).toBe(400);
    });

    it("refuses a multi-range request above the threshold too", async () => {
      // It resolves to a whole-object transfer, and the ceiling applies to those whatever
      // header asked for it.
      const app = createTestApp(depsForArtifact({ file_size: 9 }, { transferLimits: limits }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=0-1,4-5");

      expect(response.status).toBe(400);
    });
  });

  describe("gates apply to ranged requests (AC13)", () => {
    it("refuses a range for a version blocked by a critical CVE", async () => {
      const streamFromStorage = rangedStorage();
      const deps: DownloadRouteDeps = {
        ...depsForArtifact({}, { streamFromStorage }),
        listAffectsForPackage: vi.fn().mockResolvedValue([
          {
            cve_id: "CVE-2026-0001",
            package_name: "uv",
            version_start_including: null,
            version_end_excluding: null,
            version_start_excluding: null,
            version_end_including: null,
            exact_version: "0.10.10",
            version_is_na: false,
            source: "nvd",
            severity: "CRITICAL",
            cvss_v3_score: "9.8",
            description: null,
            is_kev: false,
            raw: null,
          },
        ]),
      };
      const app = createTestApp(deps);

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=0-1");

      expect(response.status).toBe(403);
      expect(streamFromStorage).not.toHaveBeenCalled();
    });

    it("refuses a range for an artifact that is not available", async () => {
      const app = createTestApp(depsForArtifact({ status: "failed" }));

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=0-1");

      expect(response.status).toBe(404);
    });

    it("refuses a range for an artifact inside its cooling-off window", async () => {
      const deps = depsForArtifact();
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeCoolingOffArtifact(new Date(Date.now() + 86_400_000)));
      const app = createTestApp(deps);

      const response = await request(app)
        .get("/download/uv/0.10.10/linux/x86-64")
        .set("Range", "bytes=0-1");

      expect(response.status).toBe(423);
    });
  });
});
