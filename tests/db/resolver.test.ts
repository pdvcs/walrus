import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../src/db/queries/package-aliases.js";
import { resolvePackage } from "../../src/vuln/resolver.js";
import { logUnresolvedQuery } from "../../src/db/queries/unresolved-queries.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const NAMES = ["res-openjdk", "res-azuljdk", "res-nodejs", "res-npp"];

async function seed(pool: Pool, name: string, display: string, aliases: string[]): Promise<void> {
  await upsertPackage(pool, {
    name,
    display_name: display,
    vendor: "Test",
    description: null,
    website: null,
    config_hash: "h",
    enabled: true,
  });
  await reconcilePackageVuln(pool, {
    packageName: name,
    aliases,
    cpes: [{ cpe_vendor: "v", cpe_product: name, is_primary: true }],
    osvEcosystem: null,
    osvName: null,
  });
}

describe("resolvePackage", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    await seed(pool, "res-openjdk", "Eclipse Temurin OpenJDK", [
      "temurin",
      "adoptium",
      "jdk",
      "java",
    ]);
    await seed(pool, "res-azuljdk", "Azul Zulu JDK", ["zulu", "azul", "jdk", "java"]);
    await seed(pool, "res-nodejs", "Node.js", ["node", "node.js", "node js", "nodejs"]);
    await seed(pool, "res-npp", "Notepad++", ["notepad++", "notepad plus plus", "npp"]);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM unresolved_queries WHERE query_text = ANY($1)`, [
      ["asdfghjkl", "   ", "jdk"],
    ]);
    await pool.end();
  });

  it("slug-exact: exact package name → confidence 1.0", async () => {
    const r = await resolvePackage(pool, "res-openjdk");
    expect(r).toMatchObject({
      resolved: true,
      slug: "res-openjdk",
      method: "slug-exact",
      confidence: 1.0,
    });
  });

  it("slug-exact via squashed form: 'res openjdk'", async () => {
    const r = await resolvePackage(pool, "res openjdk");
    expect(r.resolved).toBe(true);
    expect(r.slug).toBe("res-openjdk");
    expect(r.method).toBe("slug-exact");
  });

  it("alias-exact: 'npp' → res-npp, confidence 0.97", async () => {
    const r = await resolvePackage(pool, "npp");
    expect(r).toMatchObject({
      resolved: true,
      slug: "res-npp",
      method: "alias-exact",
      confidence: 0.97,
    });
  });

  it("alias-exact via normalization variants: 'Notepad++'", async () => {
    const r = await resolvePackage(pool, "Notepad++");
    expect(r.resolved).toBe(true);
    expect(r.slug).toBe("res-npp");
  });

  it("alias-exact squashed: 'node' → res-nodejs", async () => {
    const r = await resolvePackage(pool, "node");
    expect(r).toMatchObject({ resolved: true, slug: "res-nodejs" });
  });

  it("fuzzy: 'notpad plus' resolves to res-npp or ranks it first", async () => {
    const r = await resolvePackage(pool, "notpad plus");
    if (r.resolved) {
      expect(r.slug).toBe("res-npp");
      expect(r.method).toBe("fuzzy");
    } else {
      expect(r.candidates[0]?.slug).toBe("res-npp");
    }
  });

  it("ambiguous alias: 'jdk' returns both JDK packages as candidates", async () => {
    const r = await resolvePackage(pool, "jdk");
    expect(r.resolved).toBe(false);
    expect(r.candidates.map((c) => c.slug).sort()).toEqual(["res-azuljdk", "res-openjdk"]);
    expect(r.candidates[0]?.score).toBe(97);
  });

  it("garbage: unresolved with ≤5 candidates and null slug", async () => {
    const r = await resolvePackage(pool, "asdfghjkl");
    expect(r.resolved).toBe(false);
    expect(r.slug).toBeNull();
    expect(r.candidates.length).toBeLessThanOrEqual(5);
  });

  it("empty / whitespace is unresolved without throwing, empty candidates", async () => {
    const r = await resolvePackage(pool, "   ");
    expect(r.resolved).toBe(false);
    expect(r.candidates).toEqual([]);
  });

  it("does not throw on huge input", async () => {
    await expect(resolvePackage(pool, "x".repeat(5000))).resolves.toBeTruthy();
  });

  it("logs unresolved queries with normalized text and top candidate", async () => {
    const r = await resolvePackage(pool, "jdk");
    await logUnresolvedQuery(pool, "jdk", r.candidates[0]);
    const { rows } = await pool.query(
      `SELECT query_text, normalized, top_candidate_slug FROM unresolved_queries WHERE query_text = 'jdk' ORDER BY id DESC LIMIT 1`,
    );
    expect(rows[0].normalized).toBe("jdk");
    expect(["res-azuljdk", "res-openjdk"]).toContain(rows[0].top_candidate_slug);
  });
});
