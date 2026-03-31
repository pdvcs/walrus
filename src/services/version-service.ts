import { Pool } from "pg";
import {
  getLatestVersionInGroup,
  listVersionGroups,
  listVersions,
  ListVersionsOpts,
} from "../db/queries/versions.js";
import { VersionRow } from "../types/db.js";

export class VersionService {
  constructor(private readonly pool: Pool) {}

  listVersions(packageName: string, opts: ListVersionsOpts = {}): Promise<VersionRow[]> {
    return listVersions(this.pool, packageName, opts);
  }

  getLatestVersionInGroup(packageName: string, group: string): Promise<VersionRow | null> {
    return getLatestVersionInGroup(this.pool, packageName, group);
  }

  listVersionGroups(packageName: string): Promise<string[]> {
    return listVersionGroups(this.pool, packageName);
  }
}
