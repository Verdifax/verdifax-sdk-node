/**
 * Request-body rules shared by every path to POST /execute.
 */

import { createHmac } from "node:crypto";

import { VerdifaxError } from "./errors.js";
import type {
  DataUse,
  ExecuteRequest,
  JobLink,
  PolicyContext,
  DataQuality,
  DataCheck,
  DataCheckResult,
  ReproducibilityContext,
} from "./types.js";
import { validateHex64, validateJobName } from "./validation.js";

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

const POLICY_ACTOR_TYPES = ["agent", "user", "service", "system"];
const POLICY_OBJECT_TYPES = ["text", "transaction", "code", "data", "model", "file"];
const POLICY_CLASSIFICATIONS = [
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "RESTRICTED",
  "TOP_SECRET",
  "TS_SCI",
];
const MAX_POLICY_OBJECT_ID_BYTES = 256;

// A Record, so the compiler fails here if PolicyContext gains a field.
const POLICY_CONTEXT_FIELDS: Record<keyof PolicyContext, true> = {
  actor_type: true,
  mfa_satisfied: true,
  session_age_seconds: true,
  object_type: true,
  object_id: true,
  classification: true,
  data_quality: true,
  data_use: true,
};

const DATA_QUALITY_FIELDS: Record<keyof DataQuality, true> = {
  source: true,
  as_of: true,
  checks: true,
};
const DATA_CHECK_FIELDS: Record<keyof DataCheck, true> = { name: true, result: true };
const DATA_USE_FIELDS: Record<keyof DataUse, true> = {
  purpose: true,
  basis: true,
  categories: true,
  reference: true,
};
// A data-use code, matched against the whole text, as the server's
// psl.DataUseCode is (test/sdk-data-use-vector.json). No /m flag, so a
// trailing newline is refused.
const DATA_USE_CODE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
// The one form a data-use reference may take: a keyed digest the customer
// computed.
const DATA_USE_REFERENCE = /^hmac-sha256:[0-9a-f]{64}$/;
const MAX_DATA_USE_CATEGORIES = 20;
// The shortest key hmacSha256Reference takes, in bytes.
const MIN_REFERENCE_KEY_BYTES = 32;
const DATA_CHECK_RESULTS = ["pass", "fail", "warn"];
const MAX_DATA_SOURCE_BYTES = 200;
const MAX_DATA_CHECKS = 50;
const MAX_DATA_CHECK_NAME_BYTES = 100;

// The one form an as_of time may take, in ASCII digits, as the server
// checks it (test/sdk-data-quality-vector.json).
const AS_OF_SHAPE =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$/;

/** Whether `asOf` is a time the server accepts: the form above, a real
 *  calendar date and time, and an offset of at most 23:59. */
function validAsOf(asOf: string): boolean {
  const shape = AS_OF_SHAPE.exec(asOf);
  if (shape === null) return false;
  const part = (index: number): number => Number(shape[index]);
  const [year, month, day, hour, minute, second] = [part(1), part(2), part(3), part(4), part(5), part(6)];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > (monthDays[month - 1] ?? 0)) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  if (shape[9] !== undefined && (part(9) > 23 || part(10) > 59)) return false;
  return true;
}

// The characters Go's strings.TrimSpace removes, which the server uses to
// find a blank check name. U+FEFF is not one of them.
const GO_SPACE_ONLY = /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;

function plainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The data_quality block, checked the way the server checks it. Returns
 *  a copy with undefined keys left out. */
function checkedDataQuality(value: unknown): DataQuality {
  if (!plainObject(value)) {
    throw new VerdifaxError("verdifax: policy_context.data_quality must be an object");
  }
  refuseUnknownFields(value, DATA_QUALITY_FIELDS, "policy_context.data_quality");
  const out: DataQuality = {};
  const { source, as_of, checks } = value;
  if (source !== undefined) {
    if (typeof source !== "string") {
      throw new VerdifaxError("verdifax: policy_context.data_quality.source must be a string");
    }
    if (Buffer.byteLength(source, "utf8") > MAX_DATA_SOURCE_BYTES) {
      throw new VerdifaxError(
        `verdifax: policy_context.data_quality.source is longer than ${MAX_DATA_SOURCE_BYTES} bytes`,
      );
    }
    out.source = source;
  }
  if (as_of !== undefined) {
    if (typeof as_of !== "string" || (as_of !== "" && !validAsOf(as_of))) {
      throw new VerdifaxError(
        "verdifax: policy_context.data_quality.as_of must be a time of the form 2026-11-11T09:00:00Z or 2026-11-11T09:00:00+05:30",
      );
    }
    out.as_of = as_of;
  }
  if (checks !== undefined) {
    if (!Array.isArray(checks)) {
      throw new VerdifaxError("verdifax: policy_context.data_quality.checks must be a list");
    }
    if (checks.length > MAX_DATA_CHECKS) {
      throw new VerdifaxError(
        `verdifax: policy_context.data_quality names more than ${MAX_DATA_CHECKS} checks`,
      );
    }
    const seen = new Set<string>();
    out.checks = checks.map((check: unknown) => {
      if (!plainObject(check)) {
        throw new VerdifaxError("verdifax: each policy_context.data_quality check must be an object");
      }
      refuseUnknownFields(check, DATA_CHECK_FIELDS, "policy_context.data_quality check");
      const { name, result } = check;
      if (
        typeof name !== "string" ||
        GO_SPACE_ONLY.test(name) ||
        Buffer.byteLength(name, "utf8") > MAX_DATA_CHECK_NAME_BYTES ||
        seen.has(name)
      ) {
        throw new VerdifaxError(
          `verdifax: each policy_context.data_quality check needs a distinct name of at most ${MAX_DATA_CHECK_NAME_BYTES} bytes`,
        );
      }
      seen.add(name);
      if (typeof result !== "string" || !DATA_CHECK_RESULTS.includes(result)) {
        throw new VerdifaxError(
          `verdifax: policy_context.data_quality check ${JSON.stringify(name)} has a result that is not pass, fail or warn`,
        );
      }
      return { name, result: result as DataCheckResult };
    });
  }
  return out;
}

/** Checks a data-use declaration (`policy_context.data_use`, round 64) the
 *  way the server checks it, and returns a copy to send: `purpose` and
 *  `basis` are required codes, `categories` is a list of at most 20
 *  distinct codes, and `reference`, when given and not empty, is
 *  `hmac-sha256:` and 64 lowercase hex digits. A code is a lowercase letter
 *  or digit, then up to 63 lowercase letters, digits, dots, underscores,
 *  colons or hyphens, so no space or `@` can be written in one. No other
 *  field is accepted. An empty `categories` list or `reference` is a value
 *  left out, as the server reads it. Verdifax seals the declaration as
 *  made and does not check it. Throws {@link VerdifaxError} naming the
 *  first problem. */
export function validateDataUse(value: unknown): DataUse {
  if (!plainObject(value)) {
    throw new VerdifaxError("verdifax: policy_context.data_use must be an object");
  }
  refuseUnknownFields(value, DATA_USE_FIELDS, "policy_context.data_use");
  const { purpose, basis, categories, reference } = value;
  for (const [name, code] of [["purpose", purpose], ["basis", basis]] as const) {
    if (typeof code !== "string" || !DATA_USE_CODE.test(code)) {
      throw new VerdifaxError(
        `verdifax: policy_context.data_use.${name} is required and must be a code of the form ${DATA_USE_CODE.source}`,
      );
    }
  }
  const out: DataUse = { purpose: purpose as string, basis: basis as string };
  if (categories !== undefined) {
    if (!Array.isArray(categories)) {
      throw new VerdifaxError("verdifax: policy_context.data_use.categories must be a list");
    }
    if (categories.length > MAX_DATA_USE_CATEGORIES) {
      throw new VerdifaxError(
        `verdifax: policy_context.data_use names more than ${MAX_DATA_USE_CATEGORIES} categories`,
      );
    }
    const seen = new Set<string>();
    for (const category of categories as unknown[]) {
      if (typeof category !== "string" || !DATA_USE_CODE.test(category) || seen.has(category)) {
        throw new VerdifaxError(
          `verdifax: policy_context.data_use.categories must be distinct codes of the form ${DATA_USE_CODE.source}`,
        );
      }
      seen.add(category);
    }
    out.categories = [...seen];
  }
  if (reference !== undefined) {
    if (typeof reference !== "string" || (reference !== "" && !DATA_USE_REFERENCE.test(reference))) {
      throw new VerdifaxError(
        "verdifax: policy_context.data_use.reference must be hmac-sha256: and 64 lowercase hex digits, a keyed digest computed on your own machine (hmacSha256Reference)",
      );
    }
    out.reference = reference;
  }
  return out;
}

/** The keyed reference a data-use declaration may carry: `hmac-sha256:`
 *  and the lowercase hex HMAC-SHA256 of `id`'s UTF-8 bytes under `key`.
 *  It is computed here, on your machine, so the identifier itself (a
 *  consent or contract number, for example) never leaves it; only the
 *  digest is sent and sealed. `key` is a secret of at least 32 bytes that
 *  you keep; the same key and identifier always give the same reference.
 *  Verdifax seals the reference as declared and never checks it. Throws
 *  {@link VerdifaxError} for a shorter key or an empty identifier. */
export function hmacSha256Reference(key: Uint8Array, id: string): string {
  if (!(key instanceof Uint8Array) || key.length < MIN_REFERENCE_KEY_BYTES) {
    throw new VerdifaxError(
      `verdifax: hmacSha256Reference needs a key of at least ${MIN_REFERENCE_KEY_BYTES} bytes`,
    );
  }
  if (typeof id !== "string" || id === "") {
    throw new VerdifaxError("verdifax: hmacSha256Reference needs a non-empty identifier");
  }
  if (/[\uD800-\uDFFF]/u.test(id)) {
    throw new VerdifaxError("verdifax: hmacSha256Reference identifier has no UTF-8 form");
  }
  return "hmac-sha256:" + createHmac("sha256", key).update(Buffer.from(id, "utf8")).digest("hex");
}

function refuseOutsideList(
  value: unknown,
  allowed: readonly string[],
  fieldName: string,
): void {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new VerdifaxError(
      `verdifax: policy_context.${fieldName} must be one of ${allowed.join(", ")}`,
    );
  }
}

/** The policy_context block, checked the way the server checks it: an
 *  unknown key or a value no rule could read is refused, because a
 *  misspelt key would be dropped and a rule on it would read its zero
 *  value. A key set to undefined counts as left out. Returns a copy. */
export function checkedPolicyContext(context: PolicyContext): PolicyContext {
  if (typeof context !== "object" || context === null || Array.isArray(context)) {
    throw new VerdifaxError("verdifax: policy_context must be an object");
  }
  refuseUnknownFields(context, POLICY_CONTEXT_FIELDS, "policy_context");
  const out: PolicyContext = {};
  const {
    actor_type,
    mfa_satisfied,
    session_age_seconds,
    object_type,
    object_id,
    classification,
    data_quality,
    data_use,
  } = context;
  if (actor_type !== undefined) {
    refuseOutsideList(actor_type, POLICY_ACTOR_TYPES, "actor_type");
    out.actor_type = actor_type;
  }
  if (mfa_satisfied !== undefined) {
    if (typeof mfa_satisfied !== "boolean") {
      throw new VerdifaxError(
        "verdifax: policy_context.mfa_satisfied must be true or false",
      );
    }
    out.mfa_satisfied = mfa_satisfied;
  }
  if (session_age_seconds !== undefined) {
    if (!Number.isSafeInteger(session_age_seconds) || session_age_seconds < 0) {
      throw new VerdifaxError(
        "verdifax: policy_context.session_age_seconds must be a whole number of seconds, not negative",
      );
    }
    out.session_age_seconds = session_age_seconds;
  }
  if (object_type !== undefined) {
    refuseOutsideList(object_type, POLICY_OBJECT_TYPES, "object_type");
    out.object_type = object_type;
  }
  if (object_id !== undefined) {
    if (typeof object_id !== "string") {
      throw new VerdifaxError("verdifax: policy_context.object_id must be a string");
    }
    if (Buffer.byteLength(object_id, "utf8") > MAX_POLICY_OBJECT_ID_BYTES) {
      throw new VerdifaxError(
        `verdifax: policy_context.object_id is longer than ${MAX_POLICY_OBJECT_ID_BYTES} bytes`,
      );
    }
    out.object_id = object_id;
  }
  if (classification !== undefined) {
    refuseOutsideList(classification, POLICY_CLASSIFICATIONS, "classification");
    out.classification = classification;
  }
  if (data_quality !== undefined) {
    out.data_quality = checkedDataQuality(data_quality);
  }
  if (data_use !== undefined) {
    out.data_use = validateDataUse(data_use);
  }
  return out;
}

/** The server reads actor_type, mfa_satisfied and session_age_seconds only
 *  for an attested actor and refuses them without one, so this refuses
 *  them first: without an attested actor a rule on them would read their
 *  zero values. Like the server, a false mfa_satisfied and a zero
 *  session_age_seconds are not checked. `attested` is the block with the
 *  flag the client derived. */
function refuseActorFactsWithoutActor(
  context: PolicyContext,
  attested: Record<string, unknown> | undefined,
): void {
  const declaresActor =
    context.actor_type !== undefined ||
    context.mfa_satisfied === true ||
    (context.session_age_seconds ?? 0) !== 0;
  if (declaresActor && attested?.attested !== true) {
    throw new VerdifaxError(
      "verdifax: policy_context.actor_type, mfa_satisfied and session_age_seconds describe the attested actor; send attested_context with the actor, for example its actor_id",
    );
  }
}

// Every top-level key of a run request, the same list as execute_fields in
// scripts/sdk-parity.json, which a test holds it to, and the fields of the
// server's executeRequest. The server refuses a key it does not know with
// HTTP 400, and with lenient=1 drops it; the client refuses it first, so a
// misspelt one is never sent. A Record, so the compiler fails here if
// ExecuteRequest gains a field.
const EXECUTE_FIELD_SET: Record<keyof ExecuteRequest | "signed_request", true> = {
  payload: true,
  payload_text: true,
  program_id: true,
  route_id: true,
  registry_record_hash: true,
  ai_output_text: true,
  attested_context: true,
  reproducibility_context: true,
  request_substance: true,
  authorization_chain: true,
  regulatory_scaffolding: true,
  causal_graph: true,
  request_signature: true,
  signed_request: true,
  job: true,
  policy_context: true,
  expected_policy_hash: true,
};

/** Every top-level key a run request may hold. Any other key is refused
 *  before sending, so a misspelt field cannot be silently dropped. */
export const EXECUTE_FIELDS: readonly string[] = Object.freeze(
  Object.keys(EXECUTE_FIELD_SET),
);

// Every key the server reads in attested_context.
const ATTESTED_CONTEXT_FIELDS: Record<string, true> = {
  attested: true,
  actor_id: true,
  actor_role: true,
  authorization_policy: true,
  actor_signature: true,
  model_provider: true,
  model_name: true,
  model_version: true,
  model_temperature: true,
  prompt_hash: true,
  decision_kind: true,
  decision_result: true,
  decision_note: true,
  // Round 64: the AI assistant's own declared name and version, as an MCP
  // client gives them, sealed as declared, not verified.
  client_name: true,
  client_version: true,
};
const MAX_CLIENT_FIELD_BYTES = 128;

/** Refuses a declared client name or version the server would refuse: more
 *  than 128 bytes, anything but printable ASCII, or a leading or trailing
 *  space. An empty value is one left out. */
function checkClientFields(context: Record<string, unknown>): void {
  for (const name of ["client_name", "client_version"]) {
    const value = context[name];
    if (value === undefined || value === null) continue;
    if (
      typeof value !== "string" ||
      value.length > MAX_CLIENT_FIELD_BYTES ||
      !/^[\x20-\x7e]*$/.test(value) ||
      value.trim() !== value
    ) {
      throw new VerdifaxError(
        `verdifax: attested_context.${name} must be at most ${MAX_CLIENT_FIELD_BYTES} characters of printable ASCII with no leading or trailing space`,
      );
    }
  }
}

/** Throws on a top-level key outside {@link EXECUTE_FIELDS} or an
 *  attested_context key the server does not read. */
export function refuseUnknownRequestFields(req: object, label = "request"): void {
  if (typeof req !== "object" || req === null || Array.isArray(req)) {
    throw new VerdifaxError(`verdifax: ${label} must be an object`);
  }
  refuseUnknownFields(req, EXECUTE_FIELD_SET, label);
  const context = (req as ExecuteRequest).attested_context;
  if (typeof context === "object" && context !== null) {
    refuseUnknownFields(context, ATTESTED_CONTEXT_FIELDS, "attested_context");
    checkClientFields(context as Record<string, unknown>);
  }
}

/** The request with its derived flags set, its job block normalized and
 *  its policy fields checked, on a copy. A key outside
 *  {@link EXECUTE_FIELDS} or an unknown attested_context key is refused. A
 *  null or undefined job, policy_context or expected_policy_hash is left
 *  out. */
export function withExecuteFlags(req: ExecuteRequest): ExecuteRequest {
  refuseUnknownRequestFields(req);
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
  if (req.policy_context === undefined || req.policy_context === null) {
    delete body.policy_context;
  } else {
    body.policy_context = checkedPolicyContext(req.policy_context);
    refuseActorFactsWithoutActor(body.policy_context, body.attested_context);
  }
  if (req.expected_policy_hash === undefined || req.expected_policy_hash === null) {
    delete body.expected_policy_hash;
  } else {
    validateHex64(req.expected_policy_hash, "expected_policy_hash");
  }
  return body;
}
