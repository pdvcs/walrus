import { Router } from "express";
import { token_set_ratio } from "fuzzball";
import {
  ProductSearchResponseSchema,
  VulnProductResponseSchema,
  VulnsResponseSchema,
} from "./schemas.js";
import { Resolution } from "../vuln/resolver.js";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { AliasSearchRow } from "../db/queries/package-aliases.js";
import type { VulnProductMetadata } from "../db/queries/package-aliases.js";
import { normalizeName } from "../vuln/normalize.js";
import { queryVulns, DataFreshness } from "../services/vuln-query.js";

export type { DataFreshness };

export interface VulnsRouteDeps {
  resolvePackage: (query: string) => Promise<Resolution>;
  listAffectsForPackage: (packageName: string) => Promise<AffectsWithCveRow[]>;
  getDataFreshness: () => Promise<DataFreshness>;
  logUnresolved: (query: string, top?: { slug: string; score: number }) => Promise<void>;
  searchAliases: (normalizedQuery: string) => Promise<AliasSearchRow[]>;
  getProductMetadata: (name: string) => Promise<VulnProductMetadata | null>;
}

/**
 * GET /api/v1/vulns?product=&version=&include_unmatched= and
 * GET /api/v1/vulns/products/search?q= — the flagship query + autocomplete
 * (plan §4, WAL-11/WAL-12). The query core lives in services/vuln-query.ts so
 * the admin explorer renders from the same path.
 */
export function createVulnsRouter(deps: VulnsRouteDeps): Router {
  const router = Router();

  // GET /api/v1/vulns/products/search?q= — autocomplete over aliases.
  router.get("/products/search", async (req, res, next) => {
    try {
      const rawQ = optionalString(req.query.q);
      if (!rawQ) {
        res.status(400).json({ error: "query parameter 'q' is required" });
        return;
      }
      const q = normalizeName(rawQ);
      const rows = await deps.searchAliases(q);
      const best = new Map<string, { slug: string; display_name: string; score: number }>();
      for (const r of rows) {
        const aliasPrefix = r.alias.startsWith(q) ? 10 : 0;
        // A package whose own name prefixes the query outranks one that merely
        // carries a shared alias (e.g. "openj" → openjdk, not azuljdk, even though
        // both track the "openjdk" alias for upstream OpenJDK CVEs).
        const namePrefix = r.package_name.startsWith(q) ? 15 : 0;
        const score = Math.min(100, token_set_ratio(q, r.alias) + aliasPrefix + namePrefix);
        const cur = best.get(r.package_name);
        if (!cur || score > cur.score)
          best.set(r.package_name, { slug: r.package_name, display_name: r.display_name, score });
      }
      const results = [...best.values()].sort((a, b) => b.score - a.score).slice(0, 10);
      res.json(ProductSearchResponseSchema.parse({ query: rawQ, results }));
    } catch (err) {
      next(err);
    }
  });

  router.get("/products/:name", async (req, res, next) => {
    try {
      const product = await deps.getProductMetadata(req.params.name);
      if (!product) {
        res.status(404).json({ error: `Unknown package: ${req.params.name}` });
        return;
      }
      res.json(VulnProductResponseSchema.parse(product));
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const product = optionalString(req.query.product);
      if (!product) {
        res.status(400).json({ error: "query parameter 'product' is required" });
        return;
      }
      const version = optionalString(req.query.version);
      const includeUnmatched = parseBool(req.query.include_unmatched);

      const result = await queryVulns(deps, { product, version, includeUnmatched });
      res.json(VulnsResponseSchema.parse(result));
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function parseBool(value: unknown): boolean {
  return value === "true" || value === "1";
}
