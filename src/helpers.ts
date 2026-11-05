/**
 * Request-body rules shared by every path to POST /execute.
 */

import { VerdifaxError } from "./errors.js";
import type { ExecuteRequest, ReproducibilityContext } from "./types.js";

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

/** The request with its derived flags set, on a copy. */
export function withExecuteFlags(req: ExecuteRequest): ExecuteRequest {
  const body = { ...req };
  if (req.attested_context) {
    body.attested_context = withAttestedFlag(req.attested_context);
  }
  if (req.reproducibility_context) {
    body.reproducibility_context = withDeclaredFlag(req.reproducibility_context);
  }
  return body;
}
