/**
 * CPE 2.3 formatted-string helpers (ported from vulncheck `worker/cpe.ts`).
 * A formatted string looks like:
 *   cpe:2.3:a:notepad-plus-plus:notepad\+\+:*:*:*:*:*:*:*:*
 * Components are colon-separated; special characters inside a component are
 * backslash-escaped (so we must split on UNESCAPED colons only).
 */

export interface ParsedCpe {
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  sw_edition: string;
  target_sw: string;
  target_hw: string;
  other: string;
}

/**
 * The CPE 2.3 components a package's `cpe_exclude` may name. These are the ones NVD uses to file
 * a *different product* under the same vendor:product pair — Terraform Enterprise is
 * `hashicorp:terraform` with target_sw `enterprise`, the Ruby `git` gem is `git:git` with
 * target_sw `ruby`. Version, update and language never distinguish products, so they are not
 * excludable.
 */
export const CPE_QUALIFIER_FIELDS = [
  "edition",
  "sw_edition",
  "target_sw",
  "target_hw",
  "other",
] as const;

export type CpeQualifierField = (typeof CPE_QUALIFIER_FIELDS)[number];

/** One exclusion rule: a CPE is excluded when EVERY listed component equals the given value. */
export type CpeExclusion = Partial<Record<CpeQualifierField, string>>;

/**
 * True when the CPE matches any of the package's exclusion rules (rules are OR'd, the
 * components within one rule are AND'd). Comparison is case-insensitive on the unescaped
 * component; `*` (ANY) and `-` (NA) in the CPE never equal a configured value, so a rule only
 * ever removes CPEs that explicitly name the excluded qualifier.
 */
export function isCpeExcluded(cpe: ParsedCpe, exclusions: readonly CpeExclusion[]): boolean {
  return exclusions.some((rule) => {
    const entries = Object.entries(rule) as Array<[CpeQualifierField, string]>;
    return (
      entries.length > 0 &&
      entries.every(([field, value]) => cpe[field].toLowerCase() === value.toLowerCase())
    );
  });
}

/** Split on unescaped colons, then unescape each component. */
export function parseCpe(criteria: string): ParsedCpe | null {
  const comps: string[] = [];
  let cur = "";
  for (let i = 0; i < criteria.length; i++) {
    const ch = criteria[i];
    if (ch === "\\" && i + 1 < criteria.length) {
      cur += criteria[i + 1];
      i++;
    } else if (ch === ":") {
      comps.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  comps.push(cur);

  // cpe : 2.3 : part : vendor : product : version : update : edition : language : sw_edition :
  //   target_sw : target_hw : other
  if (comps.length < 6 || comps[0] !== "cpe" || comps[1] !== "2.3") return null;
  return {
    part: comps[2],
    vendor: comps[3],
    product: comps[4],
    version: comps[5] ?? "*",
    update: comps[6] ?? "*",
    edition: comps[7] ?? "*",
    language: comps[8] ?? "*",
    sw_edition: comps[9] ?? "*",
    target_sw: comps[10] ?? "*",
    target_hw: comps[11] ?? "*",
    other: comps[12] ?? "*",
  };
}

/** Escape a component value for use in a CPE formatted string / match string. */
export function escapeCpeComponent(value: string): string {
  // Alphanumerics plus '.', '_', '-' are legal unescaped; everything else gets a backslash.
  return value.replace(/[^a-zA-Z0-9._-]/g, (c) => `\\${c}`);
}

/** Build a virtualMatchString for an application vendor/product pair. */
export function buildMatchString(vendor: string, product: string): string {
  return `cpe:2.3:a:${escapeCpeComponent(vendor)}:${escapeCpeComponent(product)}`;
}
