import fs from "fs";
import path from "path";

/**
 * Nav-logo files (WALRUS_LOGO / WALRUS_ADMIN_LOGO). A logo is a path to an image file inside
 * the repository / deployed image, never a URL: the nav loads it on every page, so a remote
 * reference would make each page view a request to a third party and make the page's look
 * depend on someone else's uptime.
 *
 * SVG is deliberately not allowed. The file is served from walrus's own origin, and an SVG
 * opened directly (not via <img>) runs its scripts there.
 */
export const LOGO_CONTENT_TYPES: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
};

/** Large enough for any sensible nav logo; small enough that it is not a page-weight problem. */
export const LOGO_MAX_BYTES = 1024 * 1024;

const URL_SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

/**
 * Pure string check, safe to run at config-load time (it touches no filesystem, so importing
 * config in a test or build step cannot fail on a missing file). Returns a human reason when
 * the reference is unacceptable, or null when it is fine.
 */
export function logoRefProblem(ref: string): string | null {
  if (URL_SCHEME.test(ref) || ref.startsWith("//")) {
    return "must be a path to a file in the repository, not a URL (no http://, https://, file:, data: ...)";
  }
  if (path.isAbsolute(ref) || ref.startsWith("\\")) {
    return "must be relative to the application root, not an absolute path";
  }
  const normalized = path.normalize(ref);
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) {
    return "must stay inside the application root (no '..' escaping it)";
  }
  const ext = path.extname(normalized).toLowerCase();
  if (!(ext in LOGO_CONTENT_TYPES)) {
    return `must be an image file (${Object.keys(LOGO_CONTENT_TYPES).join(", ")}); got "${ext || "no extension"}"`;
  }
  return null;
}

export function isValidLogoRef(ref: string): boolean {
  return logoRefProblem(ref) === null;
}

/**
 * Resolve a logo reference to an absolute file and check it is really there. Run at boot, so a
 * typo refuses to start rather than shipping a nav with a broken image on every page.
 * Symlinks are resolved before the containment check: a link inside the repo that points
 * outside it is rejected, same as a `..` would be.
 */
export function resolveLogoFile(name: string, ref: string, root = process.cwd()): string {
  const problem = logoRefProblem(ref);
  if (problem) throw new Error(`${name} "${ref}" ${problem}`);

  const abs = path.resolve(root, ref);
  let real: string;
  let realRoot: string;
  try {
    real = fs.realpathSync(abs);
    realRoot = fs.realpathSync(root);
  } catch {
    throw new Error(`${name} "${ref}" does not exist (looked for ${abs})`);
  }
  const rel = path.relative(realRoot, real);
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(`${name} "${ref}" resolves outside the application root`);
  }
  const stat = fs.statSync(real);
  if (!stat.isFile()) throw new Error(`${name} "${ref}" is not a file`);
  if (stat.size > LOGO_MAX_BYTES) {
    throw new Error(
      `${name} "${ref}" is ${stat.size} bytes; the limit is ${LOGO_MAX_BYTES} (it loads on every page)`,
    );
  }
  return real;
}
