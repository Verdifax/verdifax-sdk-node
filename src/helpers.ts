/**
 * Request-body rules shared by every path to POST /execute.
 */

import { VerdifaxError } from "./errors.js";
import type { ExecuteRequest, JobLink, ReproducibilityContext } from "./types.js";
import { validateJobName } from "./validation.js";

/**
 * The payload the provider helpers attest: canonical JSON with sorted keys,
 * no extra whitespace and UTF-8 text, exactly
 * `{"prompt":...,"provider":...,"response":...}`. All four SDKs produce the
 * same bytes, and a shared test vector holds them to it.
 *
 * Text with an unpaired surrogate has no UTF-8 form and is refused.
 */
export function formatProviderPayload(
  provider: string,
  prompt: string,
  response: string,
): string {
  if ([provider, prompt, response].some((text) => /[\uD800-\uDFFF]/u.test(text))) {
    throw new VerdifaxError(
      "verdifax: provider payload text cannot be encoded as UTF-8",
    );
  }
  return JSON.stringify({ prompt, provider, response });
}

/** A field counts as provided unless it is null, undefined, empty text or false. */
function isProvided(value: unknown): boolean {
  return value !== null && value !== undefined && value !== "" && value !== false;
}

/** The block with `attested` derived from whether any other field is provided. */
export function withAttestedFlag(
  context: Record<string, unknown>,
): Record<string, unknown> {
  const provided = Object.entries(context).some(
    ([name, value]) => name !== "attested" && isProvided(value),
  );
  return { ...context, attested: provided };
}

/** The block with `declared` derived from whether any other field has a value. */
export function withDeclaredFlag(
  context: ReproducibilityContext,
): ReproducibilityContext {
  const declared = Object.entries(context).some(
    ([name, value]) =>
      name !== "declared" &&
      isProvided(value) &&
      !(Array.isArray(value) && value.length === 0),
  );
  return { ...context, declared };
}

/** The server computes these two fields and refuses a request that sets
 *  them, on POST /execute and in each row of a batch. */
export function refuseCallerOriginHashes(
  substance: Record<string, unknown> | undefined,
): void {
  const origin = substance?.origin as Record<string, unknown> | undefined;
  if (origin?.source_ip_hash || origin?.user_agent_hash) {
    throw new VerdifaxError(
      "verdifax: request_substance.origin.source_ip_hash and user_agent_hash are computed by the server and cannot be supplied",
    );
  }
}

// A Record, so the compiler fails here if JobLink gains a field.
const JOB_FIELDS: Record<keyof JobLink, true> = {
  job_id: true,
  step_id: true,
  previous_record_hashes: true,
  external_previous: true,
  final: true,
};

/** Throws on a key outside `known`, so a typo cannot silently drop a link.
 *  `Object.hasOwn` keeps names like `constructor` out of the known set. */
export function refuseUnknownFields(
  value: object,
  known: object,
  label: string,
): void {
  for (const name of Object.keys(value)) {
    if (!Object.hasOwn(known, name)) {
      throw new VerdifaxError(`verdifax: ${label} has an unknown field: ${name}`);
    }
  }
}

/** A hash list sorted ascending with repeats removed, as the server requires. */
function sortedUnique(hashes: readonly string[] | undefined, fieldName: string): string[] {
  if (hashes === undefined) return [];
  if (!Array.isArray(hashes) || hashes.some((hash) => typeof hash !== "string")) {
    throw new VerdifaxError(`verdifax: ${fieldName} must be a list of strings`);
  }
  return [...new Set(hashes as string[])].sort();
}

/** The job block in the one form the server accepts: unknown fields refused,
 *  names checked, lists sorted with no repeats, an empty list and a false
 *  `final` left out. */
export function normalizedJob(job: JobLink): JobLink {
  if (typeof job !== "object" || job === null || Array.isArray(job)) {
    throw new VerdifaxError("verdifax: job must be an object");
  }
  refuseUnknownFields(job, JOB_FIELDS, "job");
  validateJobName(job.job_id, "job_id");
  validateJobName(job.step_id, "step_id");
  if (job.final !== undefined && typeof job.final !== "boolean") {
    throw new VerdifaxError("verdifax: job.final must be true or false");
  }
  const out: JobLink = { job_id: job.job_id, step_id: job.step_id };
  const previous = sortedUnique(job.previous_record_hashes, "previous_record_hashes");
  if (previous.length > 0) out.previous_record_hashes = previous;
  const external = sortedUnique(job.external_previous, "external_previous");
  if (external.length > 0) out.external_previous = external;
  if (job.final) out.final = true;
  return out;
}

/** The request with its derived flags set and its job block normalized,
 *  on a copy. */
export function withExecuteFlags(req: ExecuteRequest): ExecuteRequest {
  const body = { ...req };
  if (req.job === undefined || req.job === null) {
    delete body.job;
  } else {
    body.job = normalizedJob(req.job);
  }
  if (req.attested_context) {
    body.attested_context = withAttestedFlag(req.attested_context);
  }
  if (req.reproducibility_context) {
    body.reproducibility_context = withDeclaredFlag(req.reproducibility_context);
  }
  return body;
}
