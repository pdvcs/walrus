import { Pool } from "pg";
import { insertAdminAction } from "../db/queries/admin-actions.js";
import { clearCoolingOffForVersion } from "../db/queries/artifacts.js";
import {
  CoolingOffWaiverRow,
  createCoolingOffWaiver,
  CreateCoolingOffWaiverInput,
  revokeCoolingOffWaiver,
} from "../db/queries/cooling-off-waivers.js";

/** The waiver cannot be created because of the state of the version, not the request's shape. */
export class CoolingOffWaiverRejectedError extends Error {
  constructor(
    readonly code: "version-not-found" | "not-embargoed",
    message: string,
  ) {
    super(message);
    this.name = "CoolingOffWaiverRejectedError";
  }
}

/**
 * Waive the release embargo on one version: record the waiver (so every later sync keeps the
 * version released), release its artifacts now, and write the audit row — atomically.
 *
 * Refuses when nothing is embargoed, so a typo'd version or an already-released one cannot leave
 * behind a waiver that looks meaningful in the audit trail but changed nothing.
 */
export async function createAuditedCoolingOffWaiver(
  pool: Pool,
  input: CreateCoolingOffWaiverInput,
): Promise<{ waiver: CoolingOffWaiverRow; artifacts_released: number }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows: versions } = await client.query<{ id: number; version: string }>(
      `SELECT id, version FROM versions WHERE package_name = $1 AND version = $2 FOR UPDATE`,
      [input.package_name, input.version.trim()],
    );
    if (versions.length === 0) {
      throw new CoolingOffWaiverRejectedError(
        "version-not-found",
        `Unknown version: ${input.package_name} ${input.version}`,
      );
    }
    const { rows: embargoed } = await client.query(
      `SELECT 1 FROM artifacts WHERE version_id = $1 AND cooling_off_until > now() LIMIT 1`,
      [versions[0].id],
    );
    if (embargoed.length === 0) {
      throw new CoolingOffWaiverRejectedError(
        "not-embargoed",
        `${input.package_name} ${input.version} is not in a cooling-off period`,
      );
    }

    const waiver = await createCoolingOffWaiver(client, input);
    const released = await clearCoolingOffForVersion(client, versions[0].id);
    await insertAdminAction(client, {
      action_type: "cooling-off-waived",
      package_name: input.package_name,
      version: waiver.version,
      performed_by: input.created_by,
      details: {
        waiver_id: waiver.id,
        reason: input.reason.trim(),
        artifacts_released: released,
      },
    });
    await client.query("COMMIT");
    return { waiver, artifacts_released: released };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Withdraw a waiver. Already-downloaded bytes stay stored; the next sync recomputes the embargo
 * from the upstream release date, so the version returns to 423 only if its period has not elapsed.
 */
export async function revokeAuditedCoolingOffWaiver(
  pool: Pool,
  input: { id: number; reason: string; revoked_by: string },
): Promise<CoolingOffWaiverRow | null> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const waiver = await revokeCoolingOffWaiver(client, input.id);
    if (!waiver) {
      await client.query("ROLLBACK");
      return null;
    }
    await insertAdminAction(client, {
      action_type: "cooling-off-waiver-revoked",
      package_name: waiver.package_name,
      version: waiver.version,
      performed_by: input.revoked_by,
      details: { waiver_id: waiver.id, reason: input.reason.trim() },
    });
    await client.query("COMMIT");
    return waiver;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
