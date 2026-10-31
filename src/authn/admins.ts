import fs from "node:fs";
import TOML from "@iarna/toml";
import { z } from "zod";

export type AdminMatchMode = "fold" | "exact";

const AdminsSchema = z
  .object({
    admins: z
      .array(z.string().trim().min(1))
      .min(1, "Admin roster must contain at least one subject"),
  })
  .strict();

export interface AdminRoster {
  readonly subjects: readonly string[];
  readonly matchMode: AdminMatchMode;
  has(subject: string): boolean;
}

export function loadAdminRoster(filePath: string, matchMode: AdminMatchMode = "fold"): AdminRoster {
  let source: string;
  try {
    source = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(
      `Unable to read admin roster '${filePath}': ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let parsedToml: unknown;
  try {
    parsedToml = TOML.parse(source);
  } catch (error) {
    throw new Error(
      `Invalid admin roster TOML in '${filePath}': ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const parsed = AdminsSchema.safeParse(parsedToml);
  if (!parsed.success) {
    throw new Error(`Invalid admin roster in '${filePath}': ${parsed.error.message}`);
  }

  return createAdminRoster(parsed.data.admins, matchMode);
}

export function createAdminRoster(
  subjects: readonly string[],
  matchMode: AdminMatchMode = "fold",
): AdminRoster {
  if (subjects.length === 0) throw new Error("Admin roster must contain at least one subject");
  const normalized = subjects.map((subject) => normalizeSubject(subject, matchMode));
  if (normalized.some((subject) => subject.length === 0)) {
    throw new Error("Admin roster subjects must not be blank");
  }
  const allowed = new Set(normalized);
  if (allowed.size !== normalized.length) {
    throw new Error("Admin roster contains duplicate subjects after normalization");
  }
  return {
    subjects: [...subjects],
    matchMode,
    has: (subject) => allowed.has(normalizeSubject(subject, matchMode)),
  };
}

export function normalizeSubject(subject: string, matchMode: AdminMatchMode): string {
  const trimmed = subject.trim();
  return matchMode === "exact" ? trimmed : trimmed.normalize("NFKC").toLowerCase();
}
