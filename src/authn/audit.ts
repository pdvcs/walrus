import { insertAdminAction } from "../db/queries/admin-actions.js";
import type { Queryable } from "../db/queryable.js";
import type { MachineAuditEvent } from "./google-oidc.js";
import type { LoginAuditEvent, OperatorActionAuditEvent } from "./runtime.js";

export function createAuthAuditSinks(q: Queryable): {
  auditLogin: (event: LoginAuditEvent) => Promise<void>;
  auditAction: (event: OperatorActionAuditEvent) => Promise<void>;
  auditMachine: (event: MachineAuditEvent) => Promise<void>;
} {
  return {
    auditLogin: (event) =>
      insertAdminAction(q, {
        action_type: "operator-login",
        performed_by: event.subject ?? event.username,
        details: { ...event },
      }),
    auditAction: (event) =>
      insertAdminAction(q, {
        action_type: "operator-http",
        performed_by: event.subject,
        details: { ...event },
      }),
    auditMachine: (event) =>
      insertAdminAction(q, {
        action_type: "internal-http",
        performed_by: event.subject,
        details: { ...event },
      }),
  };
}
