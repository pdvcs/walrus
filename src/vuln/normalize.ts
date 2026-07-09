/**
 * Name normalization (ported from vulncheck `matching/normalize.ts`). Applied
 * identically to stored aliases and incoming queries so both sides land in the
 * same space. See plan §3.
 */

/** Canonical form: lowercase, trimmed, collapsed whitespace, unified separators. */
export function normalizeName(input: string): string {
  return input.toLowerCase().replace(/[_]/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Variants of a name used for exact-alias matching: the normalized form plus
 * `+`→` plus ` expansion and squashed (whitespace/punctuation-free) forms.
 * "Notepad++" → ["notepad++", "notepad plus plus", "notepadplusplus", ...]
 */
export function nameVariants(input: string): string[] {
  const base = normalizeName(input);
  const variants = new Set<string>([base]);

  if (base.includes("+")) {
    variants.add(normalizeName(base.replace(/\+/g, " plus ")));
  }
  if (base.includes(".")) {
    variants.add(base.replace(/\./g, ""));
    variants.add(base.replace(/\./g, " ").replace(/\s+/g, " ").trim());
  }

  for (const v of [...variants]) {
    const squashed = v.replace(/[\s\-_.]+/g, "");
    if (squashed) variants.add(squashed);
  }

  return [...variants];
}
