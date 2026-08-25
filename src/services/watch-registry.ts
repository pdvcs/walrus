import fs from "fs";
import path from "path";
import TOML from "@iarna/toml";
import { WatchConfigSchema, WatchConfig } from "../types/watch-config.js";
import { log } from "../common/log.js";

const WATCHLIST_DIR = path.join(process.cwd(), "watchlist");

export interface WatchLoadResult {
  config: WatchConfig;
  filePath: string;
}

export interface WatchLoadError {
  filePath: string;
  error: string;
}

export interface WatchRegistryLoadResult {
  configs: WatchLoadResult[];
  errors: WatchLoadError[];
}

export function loadWatchConfig(filePath: string): WatchConfig {
  const raw = fs.readFileSync(filePath, "utf-8");
  const parsed = TOML.parse(raw);
  const result = WatchConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid watch config in ${filePath}:\n${issues}`);
  }
  return result.data;
}

/** Load every `watchlist/*.toml`. A missing directory is not an error. */
export function loadAllWatchConfigs(watchlistDir: string = WATCHLIST_DIR): WatchRegistryLoadResult {
  if (!fs.existsSync(watchlistDir)) {
    return { configs: [], errors: [] };
  }

  const files = fs
    .readdirSync(watchlistDir)
    .filter((f) => f.endsWith(".toml"))
    .map((f) => path.join(watchlistDir, f));

  const configs: WatchLoadResult[] = [];
  const errors: WatchLoadError[] = [];

  for (const filePath of files) {
    try {
      const config = loadWatchConfig(filePath);
      configs.push({ config, filePath });
      log.debug({ package: config.name, file: filePath }, "Loaded watch config");
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      errors.push({ filePath, error });
      log.warn({ filePath, error }, "Failed to load watch config");
    }
  }

  return { configs, errors };
}
