import fs from "node:fs";
import TOML from "@iarna/toml";
import { z } from "zod";
import { log } from "./log.js";

/**
 * The traffic class an outbound request belongs to. Matches the classification each
 * `createEgressFetch()` call site declares (WAL-112): discovery, artifact bytes, checksum
 * sidecars, the NVD/OSV/KEV vuln feeds, and machine-auth JWKS verification.
 */
export type EgressPurpose = "discovery" | "artifact" | "checksum" | "vuln-feed" | "auth";

export type EgressMode = "direct" | "rules" | "strict";

export interface EgressRule {
  readonly match: string;
  readonly rewrite: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly purpose?: EgressPurpose;
}

export interface EgressMatch {
  readonly rewrittenUrl: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface EgressState {
  readonly mode: EgressMode;
  readonly rules: readonly EgressRule[];
}

const VAR_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

const EgressRuleSchema = z
  .object({
    match: z.string().min(1),
    rewrite: z.string().min(1),
    // Not z.record(): @iarna/toml tags every parsed table with hidden Symbol(type)/
    // Symbol(declared) own keys, and Zod v4's record validator walks Reflect.ownKeys — so it
    // trips on the symbol on every single rule with a headers table. Validated by hand below
    // with Object.entries, which only ever sees string keys.
    headers: z.unknown().optional(),
    purpose: z.enum(["discovery", "artifact", "checksum", "vuln-feed", "auth"]).optional(),
  })
  .strict();

const EgressRulesFileSchema = z
  .object({
    rule: z.array(EgressRuleSchema).default([]),
  })
  .strict();

/** `${VAR}` interpolation from the environment, at load time, so secrets never sit in the file. */
function interpolate(value: string, env: NodeJS.ProcessEnv): string {
  return value.replace(VAR_PATTERN, (_match, name: string) => {
    const resolved = env[name];
    if (resolved === undefined) {
      throw new Error(`Egress rule references undefined environment variable \${${name}}`);
    }
    return resolved;
  });
}

/** Validate and interpolate a rule's `headers` table by hand — see the note on `headers` above. */
function normalizeHeaders(
  raw: unknown,
  env: NodeJS.ProcessEnv,
): Record<string, string> | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("Egress rule 'headers' must be a table of string values");
  }
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value !== "string") {
      throw new Error(`Egress rule header '${key}' must be a string`);
    }
    result[key] = interpolate(value, env);
  }
  return result;
}

/** Parse and validate a `WALRUS_EGRESS_RULES` TOML document. Throws on any malformed input. */
export function parseEgressRules(
  source: string,
  env: NodeJS.ProcessEnv = process.env,
): EgressRule[] {
  let parsed: unknown;
  try {
    parsed = TOML.parse(source);
  } catch (err) {
    throw new Error(
      `Invalid egress rules TOML: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const result = EgressRulesFileSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(`Invalid egress rules: ${result.error.message}`);
  }
  return result.data.rule.map((rule) => ({
    ...rule,
    headers: normalizeHeaders(rule.headers, env),
  }));
}

/** Read and parse `filePath`. Throws on a missing file, bad TOML, or a failed schema check. */
export function loadEgressRulesFromFile(
  filePath: string,
  env: NodeJS.ProcessEnv = process.env,
): EgressRule[] {
  let source: string;
  try {
    source = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    throw new Error(
      `Unable to read egress rules '${filePath}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseEgressRules(source, env);
}

/**
 * The best rule for one request: the longest matching `match` prefix wins regardless of file
 * order — an adopter combining a catch-all with a more specific rule doesn't have to order them
 * carefully — restricted to rules carrying no `purpose` or one matching this request's.
 *
 * `purpose: undefined` skips that restriction entirely, matching against every rule regardless
 * of its own `purpose` — used only by the `GET /admin/v1/egress?url=` dry-run (WAL-115), which
 * reports "would this URL be rewritten at all" rather than for one specific traffic class.
 */
export function matchEgressRule(
  url: string,
  purpose: EgressPurpose | undefined,
  rules: readonly EgressRule[],
): EgressMatch | null {
  let best: EgressRule | null = null;
  for (const rule of rules) {
    if (purpose !== undefined && rule.purpose !== undefined && rule.purpose !== purpose) continue;
    if (!url.startsWith(rule.match)) continue;
    if (!best || rule.match.length > best.match.length) best = rule;
  }
  if (!best) return null;
  return {
    rewrittenUrl: best.rewrite + url.slice(best.match.length),
    headers: best.headers ?? {},
  };
}

let state: EgressState = { mode: "direct", rules: [] };

/** Replace the active egress configuration. Boot calls this once; tests call it per-case. */
export function configureEgress(next: EgressState): void {
  state = next;
}

/** The egress configuration every `createEgressFetch()`-created function consults per request. */
export function getEgressState(): EgressState {
  return state;
}

/**
 * Boot-time entry point: load `WALRUS_EGRESS_RULES` (if set) and apply `WALRUS_EGRESS_MODE`.
 * Throws — the same fail-fast contract as `loadConfig()` — on a malformed rules file, so a bad
 * config refuses to start the server rather than serving with the rules silently ignored.
 */
export function loadEgressConfig(options: {
  rulesFile?: string;
  mode: EgressMode;
  env?: NodeJS.ProcessEnv;
}): EgressState {
  const rules = options.rulesFile ? loadEgressRulesFromFile(options.rulesFile, options.env) : [];
  const next: EgressState = { mode: options.mode, rules };
  configureEgress(next);
  log.info({ mode: next.mode, ruleCount: next.rules.length }, "Egress configuration loaded");
  return next;
}
