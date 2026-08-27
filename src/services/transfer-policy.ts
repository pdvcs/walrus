import { config } from "../config/index.js";

/**
 * How walrus transfers artifacts that are too large for one request.
 *
 * Cloud Run's 3600s request timeout is a hard ceiling, so past a certain size a single-request
 * download is not a slower path — it is one that cannot finish, and that leaves the client
 * nothing to resume from. Above the threshold walrus therefore refuses an unranged request
 * instead of serving it; below it, ranged transfer is a pure optimisation and a client that has
 * never heard of it keeps working exactly as before.
 *
 * Every decision about that policy resolves here. The expected end state is that oversized
 * artifacts are answered with a redirect to signed storage once walrus can validate an inbound
 * signature (WAL-66 notes); when that lands it becomes another variant of
 * `WholeObjectDecision`, not a second policy scattered through the download route.
 */
export interface TransferLimits {
  /** Artifacts larger than this may only be fetched with a `Range` request. */
  rangeRequiredBytes: number;
  /** Chunk size suggested to a client that has to chunk. A hint, never enforced. */
  suggestedChunkBytes: number;
}

export const defaultTransferLimits: TransferLimits = {
  rangeRequiredBytes: config.RANGE_REQUIRED_BYTES,
  suggestedChunkBytes: config.SUGGESTED_CHUNK_BYTES,
};

/**
 * Whether this artifact can only be fetched in ranges. Published in artifact metadata so a
 * client decides before it starts; a refused `GET` is the backstop for clients that did not
 * look, not the primary signal.
 *
 * An artifact of unknown size is not refused: without a size there is no ceiling to compare
 * against, and guessing would break the unaware-client guarantee for no gain.
 */
export function requiresRangedTransfer(
  fileSize: number | null | undefined,
  limits: TransferLimits = defaultTransferLimits,
): boolean {
  return typeof fileSize === "number" && fileSize > limits.rangeRequiredBytes;
}

export interface RangeRequiredError {
  error: string;
  code: "range_required";
  file_size: number;
  range_required_above_bytes: number;
  suggested_chunk_bytes: number;
}

export type WholeObjectDecision =
  | { kind: "serve" }
  | { kind: "refuse"; status: number; body: RangeRequiredError };

/**
 * The single decision point for "this request wants the whole object" — no `Range`, a range
 * walrus does not serve, or an object whose size is unknown.
 *
 * 400 is a deliberate choice among bad options: no status code means "you must use Range".
 * 416 is for a range that cannot be satisfied, and 428 is about lost updates. 400 with a
 * machine-readable body naming the requirement is the honest answer, and it is documented so
 * it can stay fixed.
 */
export function decideWholeObjectTransfer(
  fileSize: number | null | undefined,
  limits: TransferLimits = defaultTransferLimits,
): WholeObjectDecision {
  if (!requiresRangedTransfer(fileSize, limits)) return { kind: "serve" };

  return {
    kind: "refuse",
    status: 400,
    body: {
      error:
        "Artifact is too large to transfer in one request; retry with a Range header. " +
        "A single request cannot complete inside the 3600s server deadline at this size.",
      code: "range_required",
      file_size: fileSize as number,
      range_required_above_bytes: limits.rangeRequiredBytes,
      suggested_chunk_bytes: limits.suggestedChunkBytes,
    },
  };
}
