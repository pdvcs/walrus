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
});
