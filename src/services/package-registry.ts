import fs from "fs";
import path from "path";
import TOML from "@iarna/toml";
import { PackageConfigSchema, PackageConfig } from "../types/package-config.js";
import { log } from "../common/log.js";

const PACKAGES_DIR = path.join(process.cwd(), "packages");

export interface LoadResult {
  config: PackageConfig;
  filePath: string;
}

export interface LoadError {
  filePath: string;
  error: string;
}

export interface RegistryLoadResult {
  configs: LoadResult[];
  errors: LoadError[];
}

export function loadPackageConfig(filePath: string): PackageConfig {
  const raw = fs.readFileSync(filePath, "utf-8");
  const parsed = TOML.parse(raw);
  const result = PackageConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid package config in ${filePath}:\n${issues}`);
  }
  return result.data;
}

export function loadAllPackages(packagesDir: string = PACKAGES_DIR): RegistryLoadResult {
  if (!fs.existsSync(packagesDir)) {
    return { configs: [], errors: [] };
  }

  const files = fs
    .readdirSync(packagesDir)
    .filter((f) => f.endsWith(".toml"))
    .map((f) => path.join(packagesDir, f));

  const configs: LoadResult[] = [];
  const errors: LoadError[] = [];

  for (const filePath of files) {
    try {
      const config = loadPackageConfig(filePath);
      configs.push({ config, filePath });
      log.debug({ package: config.name, file: filePath }, "Loaded package config");
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      errors.push({ filePath, error });
      log.warn({ filePath, error }, "Failed to load package config");
    }
  }

  return { configs, errors };
}
