/**
 * SQL for "this artifact may be served to the public right now".
 *
 * `status = 'available'` only says the bytes exist in storage. An artifact fetched early
 * (`retention.prefetch_during_cooling_off`) is `available` while its `cooling_off_until` is still
 * in the future, and must not be served, offered as "latest", or counted as a cooling-off
 * watermark until that date passes. Use this fragment wherever "available" means "publicly
 * servable"; keep a bare `status = 'available'` only where the question is "do bytes exist".
 */
export function servableArtifactSql(alias = "a"): string {
  return `${alias}.status = 'available' AND (${alias}.cooling_off_until IS NULL OR ${alias}.cooling_off_until <= now())`;
}

/** The same rule for an artifact row already in memory. */
export function isServableArtifact(
  artifact: { status: string; cooling_off_until?: Date | null },
  now: Date = new Date(),
): boolean {
  return (
    artifact.status === "available" &&
    (!artifact.cooling_off_until || artifact.cooling_off_until <= now)
  );
}
