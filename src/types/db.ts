export interface PackageRow {
  name: string;
  display_name: string;
  vendor: string;
  description: string | null;
  website: string | null;
  config_hash: string;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface VersionRow {
  id: number;
  package_name: string;
  version: string;
  version_group: string;
  is_lts: boolean;
  discovered_at: Date;
  version_sort: string;
}

export type ArtifactStatus = "pending" | "downloading" | "available" | "failed" | "removed";

export interface ArtifactRow {
  id: number;
  version_id: number;
  os: string;
  arch: string;
  filename: string;
  gcs_path: string | null;
  file_size: number | null;
  checksum: string | null;
  checksum_type: string | null;
  upstream_url: string;
  status: ArtifactStatus;
  error_message: string | null;
  download_started_at: Date | null;
  download_completed_at: Date | null;
  removed_at: Date | null;
  created_at: Date;
  sync_job_id: number | null;
  cooling_off_until: Date | null;
}

export type SyncJobStatus = "running" | "completed" | "failed";
export type SyncJobTrigger = "scheduled" | "on-demand" | "admin";

export interface SyncJobRow {
  id: number;
  package_name: string;
  trigger_type: SyncJobTrigger;
  status: SyncJobStatus;
  versions_found: number;
  artifacts_queued: number;
  artifacts_downloaded: number;
  artifacts_failed: number;
  error_message: string | null;
  started_at: Date;
  completed_at: Date | null;
}

export type AdminActionType = "force-sync" | "redownload" | "remove" | "enable" | "disable";

export interface AdminActionRow {
  id: number;
  action_type: AdminActionType;
  package_name: string | null;
  version: string | null;
  artifact_id: number | null;
  performed_by: string | null;
  details: Record<string, unknown> | null;
  created_at: Date;
}
