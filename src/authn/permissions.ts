import type { AdminRoster } from "./admins.js";

/**
 * Per-route authorization for the authenticated tier (`/auth`). The tier only proves who the
 * caller is; each route asks one of these questions about them.
 *
 * Today the only role is the admin roster (`config/admins.toml`). A planned `roles.toml` will
 * add roles such as `in_cooling_off_downloaders`; when it lands, only the bodies below change
 * (e.g. roster ∪ that role), not the routes that call them.
 */
export interface PermissionChecker {
  canDownloadDuringCoolingOff(subject: string): boolean;
}

export function createPermissionChecker(roster: AdminRoster): PermissionChecker {
  return {
    canDownloadDuringCoolingOff: (subject) => roster.has(subject),
  };
}
