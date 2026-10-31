import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion } from "../../src/db/queries/versions.js";
import {
  insertArtifact,
  getArtifact,
  getArtifactById,
  updateArtifactStatus,
  listArtifactsByStatus,
  listArtifactsForVersion,
} from "../../src/db/queries/artifacts.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-artifacts-pkg";

describe("artifacts queries", () => {
  let pool: Pool;
  let versionId: number;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM sync_jobs WHERE package_name = $1`, [PKG]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = $1)`,
      [PKG],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);

    await upsertPackage(pool, {
      name: PKG,
      display_name: "Test",
      vendor: "Acme",
      description: null,
      website: null,
      config_hash: "abc",
      enabled: true,
    });
    const v = await insertVersion(pool, {
      package_name: PKG,
      version: "1.0.0",
      version_group: "1.0",
      is_lts: false,
      version_sort: "0001.0000.0000",
    });
    versionId = v.id;
  });

  it("inserts and retrieves an artifact", async () => {
    const a = await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "pkg-1.0.0-linux-x64.tar.gz",
      upstream_url: "https://example.com/pkg-1.0.0-linux-x64.tar.gz",
    });
    expect(a.id).toBeGreaterThan(0);
    expect(a.status).toBe("pending");

    const fetched = await getArtifact(pool, versionId, "linux", "x86-64");
    expect(fetched).not.toBeNull();
    expect(fetched!.filename).toBe("pkg-1.0.0-linux-x64.tar.gz");
  });

  it("insert is idempotent on conflict", async () => {
    const a1 = await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "pkg.tar.gz",
      upstream_url: "https://example.com/pkg.tar.gz",
    });
    const a2 = await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "pkg.tar.gz",
      upstream_url: "https://example.com/pkg.tar.gz",
    });
    expect(a1.id).toBe(a2.id);
  });

  it("getArtifactById retrieves by id", async () => {
    const a = await insertArtifact(pool, {
      version_id: versionId,
      os: "macos",
      arch: "arm64",
      filename: "pkg-macos-arm64.tar.gz",
      upstream_url: "https://example.com/pkg-macos-arm64.tar.gz",
    });
    const fetched = await getArtifactById(pool, a.id);
    expect(fetched!.os).toBe("macos");
    expect(fetched!.arch).toBe("arm64");
  });

  it("status transition: pending → downloading → available", async () => {
    const a = await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "pkg.tar.gz",
      upstream_url: "https://example.com/pkg.tar.gz",
    });
    expect(a.status).toBe("pending");

    const downloading = await updateArtifactStatus(pool, a.id, {
      status: "downloading",
      download_started_at: new Date(),
    });
    expect(downloading!.status).toBe("downloading");
    expect(downloading!.download_started_at).not.toBeNull();

    const available = await updateArtifactStatus(pool, a.id, {
      status: "available",
      gcs_path: "test-pkg/1.0.0/linux/x86-64/pkg.tar.gz",
      file_size: 12345,
      checksum: "deadbeef",
      checksum_type: "sha256",
      download_completed_at: new Date(),
    });
    expect(available!.status).toBe("available");
    expect(available!.gcs_path).toBe("test-pkg/1.0.0/linux/x86-64/pkg.tar.gz");
    expect(available!.file_size).toBe(12345);
    expect(available!.checksum).toBe("deadbeef");
  });

  it("status transition: pending → failed with error message", async () => {
    const a = await insertArtifact(pool, {
      version_id: versionId,
      os: "windows",
      arch: "x86-64",
      filename: "pkg.zip",
      upstream_url: "https://example.com/pkg.zip",
    });

    const failed = await updateArtifactStatus(pool, a.id, {
      status: "failed",
      error_message: "Connection timed out",
    });
    expect(failed!.status).toBe("failed");
    expect(failed!.error_message).toBe("Connection timed out");
  });

  it("listArtifactsByStatus filters correctly", async () => {
    await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "a.tar.gz",
      upstream_url: "https://example.com/a.tar.gz",
    });
    const b = await insertArtifact(pool, {
      version_id: versionId,
      os: "macos",
      arch: "arm64",
      filename: "b.tar.gz",
      upstream_url: "https://example.com/b.tar.gz",
    });
    await updateArtifactStatus(pool, b.id, { status: "available" });

    const pending = (await listArtifactsByStatus(pool, "pending")).filter(
      (a) => a.version_id === versionId,
    );
    const available = (await listArtifactsByStatus(pool, "available")).filter(
      (a) => a.version_id === versionId,
    );
    expect(pending).toHaveLength(1);
    expect(available).toHaveLength(1);
  });

  it("listArtifactsForVersion returns all platform artifacts", async () => {
    await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "a.tar.gz",
      upstream_url: "https://example.com/a.tar.gz",
    });
    await insertArtifact(pool, {
      version_id: versionId,
      os: "macos",
      arch: "arm64",
      filename: "b.tar.gz",
      upstream_url: "https://example.com/b.tar.gz",
    });

    const artifacts = await listArtifactsForVersion(pool, versionId);
    expect(artifacts).toHaveLength(2);
  });

  it("unique constraint prevents duplicate os/arch per version", async () => {
    await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "a.tar.gz",
      upstream_url: "https://example.com/a.tar.gz",
    });
    // The query uses ON CONFLICT DO NOTHING, so no error — but only one row
    await insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x86-64",
      filename: "different.tar.gz",
      upstream_url: "https://example.com/different.tar.gz",
    });
    const all = await listArtifactsForVersion(pool, versionId);
    expect(all).toHaveLength(1);
  });

  describe("provenance columns (WAL-58)", () => {
    it("an untransformed row reads correctly: transform and source fields NULL", async () => {
      const a = await insertArtifact(pool, {
        version_id: versionId,
        os: "linux",
        arch: "x86-64",
        filename: "tool-1.0.0-linux-x64.tar.gz",
        upstream_url: "https://example.com/tool-1.0.0-linux-x64.tar.gz",
      });
      const available = await updateArtifactStatus(pool, a.id, {
        status: "available",
        gcs_path: "p/1.0.0/linux/x86-64/tool-1.0.0-linux-x64.tar.gz",
        file_size: 100,
        checksum: "aaa111",
        checksum_type: "sha256",
      });
      // NULL is what "not a repackaging" looks like: the recorded checksum already IS the
      // upstream digest, and upstream_url is the source URL.
      expect(available!.transform).toBeNull();
      expect(available!.source_checksum).toBeNull();
      expect(available!.source_file_size).toBeNull();
    });

    it("round-trips the provenance fields of a transformed artifact", async () => {
      const a = await insertArtifact(pool, {
        version_id: versionId,
        os: "windows",
        arch: "x86-64",
        filename: "tool-1.0.0-windows-x86-64.zip",
        upstream_url: "https://example.com/tool-1.0.0-64-bit.tar.bz2",
      });
      const available = await updateArtifactStatus(pool, a.id, {
        status: "available",
        gcs_path: "p/1.0.0/windows/x86-64/tool-1.0.0-windows-x86-64.zip",
        // checksum / file_size describe the SERVED bytes — the zip — even though the
        // upstream URL still points at the tar.bz2 (WAL-58 AC3).
        file_size: 125_000_000,
        checksum: "zipdigest",
        checksum_type: "sha256",
        source_checksum: "tardigest",
        source_file_size: 117_000_000,
        transform: "tar-bz2-to-zip@1",
      });
      expect(available!.status).toBe("available");
      expect(available!.filename).toBe("tool-1.0.0-windows-x86-64.zip");
      expect(available!.checksum).toBe("zipdigest");
      expect(available!.file_size).toBe(125_000_000);
      expect(available!.upstream_url).toBe("https://example.com/tool-1.0.0-64-bit.tar.bz2");
      expect(available!.source_checksum).toBe("tardigest");
      expect(available!.source_file_size).toBe(117_000_000);
      expect(available!.transform).toBe("tar-bz2-to-zip@1");

      // ...and the fields survive a plain re-read, since SELECT * carries them.
      const refetched = await getArtifactById(pool, a.id);
      expect(refetched!.source_checksum).toBe("tardigest");
      expect(refetched!.transform).toBe("tar-bz2-to-zip@1");
    });

    it("a later failure clears the served digest but provenance keeps its last known value", async () => {
      const a = await insertArtifact(pool, {
        version_id: versionId,
        os: "windows",
        arch: "arm64",
        filename: "tool-1.0.0-windows-arm64.zip",
        upstream_url: "https://example.com/tool-1.0.0-arm64.tar.bz2",
      });
      await updateArtifactStatus(pool, a.id, {
        status: "available",
        gcs_path: "p/1.0.0/windows/arm64/tool.zip",
        file_size: 1,
        checksum: "oldzip",
        source_checksum: "oldtar",
        source_file_size: 2,
        transform: "tar-bz2-to-zip@1",
      });
      const failed = await updateArtifactStatus(pool, a.id, {
        status: "failed",
        error_message: "checksum mismatch",
      });
      expect(failed!.status).toBe("failed");
      // Provenance is historical record, not lifecycle state: it survives a redownload
      // failure and is overwritten by the next successful download.
      expect(failed!.source_checksum).toBe("oldtar");
    });
  });
});
