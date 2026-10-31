import type { SessionKind, SessionPayload } from "./session.js";

declare global {
  namespace Express {
    interface Request {
      auth?: {
        subject: string;
        kind: SessionKind;
        payload: SessionPayload;
      };
      machinePrincipal?: string;
    }
  }
}

export {};
