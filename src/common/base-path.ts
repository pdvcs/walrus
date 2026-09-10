/**
 * Prefixes a self-referential absolute path with the configured base path. Pure and
 * side-effect-free so every renderer/router factory takes `basePath` as an explicit parameter
 * rather than reading a module-level singleton — safe under parallel test execution, where two
 * `createApp()` instances in the same process may use different base paths.
 */
export function withBase(basePath: string, path: string): string {
  return `${basePath}${path}`;
}

// Priority is a single path segment (/foo); a multi-segment prefix (/corp/walrus) is accepted
// for free by the same pattern rather than being a design goal on its own. "" (root, today's
// behaviour) is validated separately by the caller — this pattern alone would reject it.
const BASE_PATH_PATTERN =
  /^\/[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?(?:\/[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?)*$/;

/** Empty string (root) or a /-separated path of letters/digits/-/_ segments, no trailing slash. */
export function isValidBasePath(value: string): boolean {
  return value === "" || BASE_PATH_PATTERN.test(value);
}
