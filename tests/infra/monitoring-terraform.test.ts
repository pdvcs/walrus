import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const monitoring = readFileSync(path.join(root, "infra/terraform/monitoring.tf"), "utf8");

/**
 * WAL-43. These assert the *shape* of the alerting, which is all Terraform can be asked about —
 * whether Google actually delivers a message is a manual step, and the email of 2026-08-31
 * recorded on the ticket is its evidence.
 *
 * What is worth pinning here is the reasoning that is easy to undo by accident: which resource
 * type each policy watches, that a transient failure cannot page, and that the informational
 * alert stays distinguishable from a service error.
 */
describe("monitoring deployment wiring", () => {
  it("routes every policy to the configured notification channel", () => {
    const policies = monitoring.match(/resource "google_monitoring_alert_policy"/g) ?? [];
    const routed = monitoring.match(/notification_channels\s*=/g) ?? [];
    expect(policies.length).toBeGreaterThanOrEqual(5);
    // A policy with no channel is worse than no policy: it looks like coverage in the console
    // and reaches nobody.
    expect(routed).toHaveLength(policies.length);
  });

  it("gives every policy a severity so informational alerts can be routed apart", () => {
    // The delivered email read "[ALERT - No severity]". AC5 asks for the blocked-version alert
    // to arrive at informational urgency, which is not expressible while every alert looks the
    // same in an inbox.
    const policies = monitoring.match(/resource "google_monitoring_alert_policy"/g) ?? [];
    const severities = monitoring.match(/^\s*severity\s*=/gm) ?? [];
    expect(severities).toHaveLength(policies.length);
  });

  it("watches Cloud Scheduler by resource type, not by an enumerated list of jobs (AC2)", () => {
    // scheduler.tf builds the vuln jobs with `for_each` and `name = "walrus-vuln-sync-${each.key}"`,
    // so no individual name exists in the source to compare against — deriving the list from there
    // would assert nothing, which is exactly how the first version of this test passed while a
    // single-job filter was in place. Assert the property directly instead: the scheduler policy
    // must select on the resource type alone and must not narrow to any one job.
    const policy = monitoring.slice(
      monitoring.indexOf('resource "google_monitoring_alert_policy" "scheduler_job_failure"'),
    );
    const filter = policy.slice(policy.indexOf("filter"), policy.indexOf("documentation"));

    expect(filter).toContain('resource.type="cloud_scheduler_job"');
    expect(filter).not.toMatch(/job_id|job_name/);
    expect(filter).not.toMatch(/walrus-(sync|vuln-sync|vuln-backfill-auto)/);
  });

  it("does not page on a single transient sync failure (AC3)", () => {
    // On 2026-08-31 the NVD sync failed once on a 30s upstream timeout and the next scheduled
    // tick recovered. Alerting on that trains an operator to ignore the channel.
    expect(monitoring).toContain('name   = "walrus/vuln_sync_failed"');
    expect(monitoring).toMatch(/threshold_value\s*=\s*1/);
    expect(monitoring).toMatch(/comparison\s*=\s*"COMPARISON_GT"/);
  });

  it("alerts on newly blocked versions from the transition log line (AC5)", () => {
    // Pinned against the emitting call site: src/services/availability-history.ts logs this
    // message with a numeric `blocked` field, and the filter is only meaningful if both match.
    expect(monitoring).toContain('jsonPayload.msg="Recorded version availability transitions"');
    expect(monitoring).toContain("jsonPayload.blocked>0");
  });

  it("tells an operator what to do, not just what happened (AC6)", () => {
    const policies = monitoring.match(/resource "google_monitoring_alert_policy"/g) ?? [];
    const documented = monitoring.match(/documentation\s*\{/g) ?? [];
    expect(documented).toHaveLength(policies.length);
  });
});
