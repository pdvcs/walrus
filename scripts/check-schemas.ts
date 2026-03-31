#!/usr/bin/env tsx
/**
 * check-schemas.ts — Fast schema-only validation for all packages/walrus-*.toml files.
 *
 * Parses each TOML file and runs it through the Zod schema. No network calls.
 * Suitable for pre-commit hooks and CI.
 *
 * Usage:
 *   npm run check-schemas
 */

import path from "path";
import { loadAllPackages } from "../src/services/package-registry.js";

const PACKAGES_DIR = path.join(process.cwd(), "packages");

const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;

const { configs, errors } = loadAllPackages(PACKAGES_DIR);
const total = configs.length + errors.length;

for (const { config, filePath } of configs) {
  const rel = path.relative(process.cwd(), filePath);
  console.log(`${green("✓")} ${rel} ${bold(`(${config.name})`)}`);
}

for (const { filePath, error } of errors) {
  const rel = path.relative(process.cwd(), filePath);
  console.log(`${red("✗")} ${rel}`);
  // Indent each line of the error message
  for (const line of error.split("\n")) {
    console.log(`  ${line}`);
  }
}

console.log("");
if (errors.length === 0) {
  console.log(green(`✓ All ${total} package schema(s) valid`));
  process.exit(0);
} else {
  console.log(red(`✗ ${errors.length} of ${total} package schema(s) failed`));
  process.exit(1);
}
