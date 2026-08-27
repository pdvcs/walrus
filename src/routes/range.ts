/**
 * `Range` header parsing for artifact downloads (RFC 9110 §14.1).
 *
 * Resolved against the object's own size, so the route never has to reason about open-ended or
 * suffix forms — it gets absolute, inclusive, in-bounds byte offsets or a reason it cannot.
 */
export type RangeRequest =
  | { kind: "none" }
  | { kind: "single"; start: number; end: number }
  | { kind: "unsatisfiable" }
  /**
   * Syntactically valid but not something walrus serves as a `206` — today, only a multi-range
   * request. RFC 9110 permits answering with the full representation, which is what the route
   * does, so these are handled exactly like a request with no `Range` at all.
   */
  | { kind: "unsupported" };

const BYTE_RANGE = /^(\d*)-(\d*)$/;

export function parseRangeHeader(header: string | undefined, size: number): RangeRequest {
  if (header === undefined) return { kind: "none" };

  const [unit, sets] = splitOnce(header.trim(), "=");
  // An unrecognised range unit must be ignored, which means serving the whole representation.
  if (unit.toLowerCase() !== "bytes" || sets === undefined) return { kind: "none" };

  const specs = sets.split(",").map((s) => s.trim());
  if (specs.length === 0) return { kind: "none" };
  if (specs.length > 1) return { kind: "unsupported" };

  const match = BYTE_RANGE.exec(specs[0]);
  if (!match) return { kind: "none" };

  const [, firstRaw, lastRaw] = match;
  const hasFirst = firstRaw !== "";
  const hasLast = lastRaw !== "";
  if (!hasFirst && !hasLast) return { kind: "none" };

  // A zero-length object can satisfy no range at all, and `size - suffix` below would go
  // negative on it.
  if (size <= 0) return { kind: "unsatisfiable" };

  if (!hasFirst) {
    // Suffix form: the last N bytes. `bytes=-0` asks for nothing, which is unsatisfiable.
    const suffix = Number(lastRaw);
    if (suffix === 0) return { kind: "unsatisfiable" };
    return { kind: "single", start: Math.max(0, size - suffix), end: size - 1 };
  }

  const start = Number(firstRaw);
  if (start >= size) return { kind: "unsatisfiable" };

  // Open-ended, or a last-byte-pos clamped to the object: asking past the end is not an error
  // as long as the range starts inside it.
  const end = hasLast ? Math.min(Number(lastRaw), size - 1) : size - 1;
  if (end < start) return { kind: "unsatisfiable" };

  return { kind: "single", start, end };
}

function splitOnce(value: string, separator: string): [string, string | undefined] {
  const index = value.indexOf(separator);
  if (index === -1) return [value, undefined];
  return [value.slice(0, index), value.slice(index + separator.length)];
}
