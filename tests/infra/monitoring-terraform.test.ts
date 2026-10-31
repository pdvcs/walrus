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

  it("keeps notification_rate_limit off the metric-threshold policy", () => {
    // The API refuses it: "only log-based alert policies may specify a notification rate limit".
    // It is accepted by `terraform validate` and fails at apply, which is the worst place to find
    // out — it aborted a deploy mid-run and left the service and the Jobs on different images.
    const policy = monitoring.slice(
      monitoring.indexOf('resource "google_monitoring_alert_policy" "vuln_sync_degraded"'),
    );
    const body = policy.slice(0, policy.indexOf("\n}\n"));
    expect(body).toContain("condition_threshold");
    // The block form, not the bare word: the comment above the fix names it in prose, and
    // matching that would fail on the very explanation of why it is absent.
    expect(body).not.toMatch(/notification_rate_limit\s*\{/);
  });

  it("tells an operator what to do, not just what happened (AC6)", () => {
    const policies = monitoring.match(/resource "google_monitoring_alert_policy"/g) ?? [];
    const documented = monitoring.match(/documentation\s*\{/g) ?? [];
    expect(documented).toHaveLength(policies.length);
  });
});

/**
 * WAL-119 — tier 2, charted. These pin the reasoning that is cheap to undo by accident, not the
 * dashboard's appearance: which signals are on it, that each chart is fed by a metric type that
 * actually exists, and that the two log-based metrics are referenced through their resources
 * rather than by a copied string.
 *
 * The JSON's *syntax* is `terraform validate`'s job, not this file's — the dashboard is built by
 * `jsonencode()` from an HCL object, so there is no literal JSON here to parse.
 */
describe("operations dashboard", () => {
  const dashboard = monitoring.slice(
    monitoring.indexOf('resource "google_monitoring_dashboard" "walrus"'),
  );

  it("declares the dashboard in Terraform rather than leaving it a console artefact", () => {
    // A console-built dashboard is invisible to review, absent from a fresh project, and
    // divergent the moment someone drags a widget — the drift WAL-96 removed from the service.
    expect(monitoring).toContain('resource "google_monitoring_dashboard" "walrus"');
    expect(dashboard).toContain("dashboard_json");
  });

  it("charts all four signals the runbook promises", () => {
    for (const metricType of [
      "logging.googleapis.com/user/${google_logging_metric.vuln_sync_failed.name}",
      "logging.googleapis.com/user/${google_logging_metric.scheduler_job_failed.name}",
      "run.googleapis.com/request_count",
      "run.googleapis.com/job/completed_execution_count",
    ]) {
      expect(dashboard).toContain(metricType);
    }
  });

  it("references log-based metrics through their resources, so a rename cannot orphan a chart", () => {
    // The interpolation is the graph edge. A copied literal would keep planning cleanly while
    // charting a metric that no longer exists, which renders as an empty panel — indistinguishable
    // from "nothing has failed".
    expect(dashboard).not.toContain('user/walrus/vuln_sync_failed"');
    expect(dashboard).not.toContain('user/walrus/scheduler_job_failed"');
  });

  it("breaks the vuln-sync chart out by source instead of summing the sources together", () => {
    // The one distinction `label_extractors` exists to provide: "nvd is failing" and "everything
    // is failing" want different responses, and a single total cannot tell them apart.
    expect(dashboard).toMatch(/groupByFields\s*=\s*\["metric\.label\.source"\]/);
  });

  it("splits Job executions by result, not merely by job", () => {
    // A job that has silently stopped succeeding looks identical to one nobody triggered unless
    // the result is on the axis.
    expect(dashboard).toMatch(
      /groupByFields\s*=\s*\["resource\.label\.job_name",\s*"metric\.label\.result"\]/,
    );
  });

  it("feeds the scheduler chart from a log-based metric, because Cloud Scheduler publishes none", () => {
    // Verified against the deployed project: `cloudscheduler.googleapis.com/*` has no metric
    // descriptors at all, though the `cloud_scheduler_job` resource type is known. Anything
    // scheduler-shaped has to be counted from its log.
    expect(monitoring).toContain('resource "google_logging_metric" "scheduler_job_failed"');
    expect(dashboard).not.toContain("cloudscheduler.googleapis.com/");

    const metric = monitoring.slice(
      monitoring.indexOf('resource "google_logging_metric" "scheduler_job_failed"'),
    );
    const body = metric.slice(0, metric.indexOf("\n}\n"));
    expect(body).toContain('"job" = "EXTRACT(resource.labels.job_id)"');
    // Same breadth as the policy it mirrors: a seventh scheduler job counts the moment it exists.
    expect(body).toContain('resource.type="cloud_scheduler_job"');
    expect(body).not.toMatch(/job_id="walrus-/);
  });

  it("adds no notifying resource — tier 2 is looked at, not delivered", () => {
    // The whole point of the tier. A dashboard that pages is just another alert policy.
    expect(dashboard).not.toContain("notification_channels");
  });
});
