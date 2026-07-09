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

  // cpe : 2.3 : part : vendor : product : version : update : ...
  if (comps.length < 6 || comps[0] !== "cpe" || comps[1] !== "2.3") return null;
  return {
    part: comps[2],
    vendor: comps[3],
    product: comps[4],
    version: comps[5] ?? "*",
    update: comps[6] ?? "*",
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
