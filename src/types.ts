/**
 * Type definitions for the Verdifax orchestrator REST API.
 *
 * Mirrors the canonical schemas from the OpenAPI spec at
 * `verdifax-orchestrator/openapi/verdifax.yaml`. When the spec
 * adds a new field, update this file alongside the OpenAPI to
 * keep the SDK's surface in sync.
 */

/** A 64-character lowercase hex string, the canonical §0
 *  SHA-256 encoding. Aliased rather than newtyped so callers
 *  pass plain strings without ceremony. */
export type Hex64 = string;

// ── Health + Version ────────────────────────────────────────────

export interface Health {
  ok: boolean;
  service: string;
  version: string;
  orchestrator_version?: string;
  orchestrator_git_sha?: string;
  time: string;
}

export interface FormulaEra {
  era: string;
  label: string;
}

export interface VerdifaxVersion {
  service: string;
  api_contract_version?: string;
  orchestrator_version?: string;
  orchestrator_git_sha?: string;
  formula_version?: string;
  formula_eras?: FormulaEra[];
  kernel_versions?: Record<string, string>;
  engine_versions?: Record<string, string>;
  aivp_t4_mode?: string;
  region?: string;
  instance?: string;
  time: string;
}

// ── Execute ─────────────────────────────────────────────────────

export interface ExecuteRequest {
  /** Base64-encoded payload bytes. Mutually exclusive with payload_text. */
  payload?: string;
  /** Plain-text payload. Mutually exclusive with payload. */
  payload_text?: string;
  program_id: Hex64;
  route_id: string;
  registry_record_hash: Hex64;
  /** When non-empty, opts the request into the AIVP governance pipeline. */
  ai_output_text?: string;
  /** Caller-attested actor + decision metadata; open schema. The client
   *  derives `attested` from whether any other field is provided. */
  attested_context?: Record<string, unknown>;
  /** Caller-declared runtime fingerprint, recorded in the audit bundle.
   *  Build it with {@link captureEnvironment}. */
  reproducibility_context?: ReproducibilityContext;
  /** Caller-supplied substance of the request: prompt, output, cost,
   *  latency and origin metadata. Recorded as supplied. Leave out
   *  `origin.source_ip_hash` and `origin.user_agent_hash`: the server
   *  computes those and refuses them. */
  request_substance?: Record<string, unknown>;
  /** Caller-supplied approval chain. Recorded as supplied, not verified
   *  by Verdifax. */
  authorization_chain?: Record<string, unknown>;
  /** Caller-supplied regulatory metadata. Recorded as supplied, not an
   *  assessment by Verdifax. */
  regulatory_scaffolding?: Record<string, unknown>;
  /** Caller-supplied record of what led to this run. Recorded as
   *  supplied. */
  causal_graph?: Record<string, unknown>;
  /** Places this run in a job map. Not accepted by a determinism check,
   *  which runs twice. */
  job?: JobLink;
  /** What this request declares for the rules of an active customer policy
   *  to read. Unknown keys and values outside the lists are refused before
   *  sending. */
  policy_context?: PolicyContext;
  /** The policy hash this request expects to run under. When another policy
   *  is active the server refuses the run with HTTP 409. */
  expected_policy_hash?: Hex64;
  /** A version 1 signature for an unsigned client to send. A client with
   *  the `signingKey` option sends version 2 and drops this field. */
  request_signature?: RequestSignature;
}

/** Who the attested actor is, for a policy rule to read. */
export type PolicyActorType = "agent" | "user" | "service" | "system";

/** What the request acts on, for a policy rule to read. */
export type PolicyObjectType =
  | "text"
  | "transaction"
  | "code"
  | "data"
  | "model"
  | "file";

/** A classification level, for a policy rule to read. */
export type PolicyClassification =
  | "PUBLIC"
  | "INTERNAL"
  | "CONFIDENTIAL"
  | "RESTRICTED"
  | "TOP_SECRET"
  | "TS_SCI";

/** The facts a request declares for the rules of a customer policy. These
 *  are the caller's own statements: a rule on them judges what was
 *  declared, and cannot show that it is true. Every key is optional, and
 *  the client refuses any other key before sending, because a misspelt key
 *  would be dropped and a rule on it would read its zero value.
 *
 *  `actor_type`, `mfa_satisfied` and `session_age_seconds` describe the
 *  attested actor, so a request that sets one of them must also carry an
 *  `attested_context` naming the actor, for example its `actor_id`. */
export interface PolicyContext {
  actor_type?: PolicyActorType;
  mfa_satisfied?: boolean;
  /** A non-negative whole number of seconds. */
  session_age_seconds?: number;
  object_type?: PolicyObjectType;
  /** At most 256 bytes of UTF-8. */
  object_id?: string;
  classification?: PolicyClassification;
}

// ── Policies ────────────────────────────────────────────────────

/** A stored policy document, as POST /policies and GET /policies return
 *  it. */
export interface Policy {
  policy_id: string;
  policy_version: string;
  policy_hash: Hex64;
  /** SHA-256 of the exact text that was uploaded. */
  document_hash: Hex64;
  created_at: string;
}

/** Returned by {@link VerdifaxClient.getPolicy}: the stored policy and its
 *  exact text. */
export interface PolicyWithDocument extends Policy {
  document: string;
}

/** Returned by {@link VerdifaxClient.listPolicies}. */
export interface PolicyList {
  ok: boolean;
  /** The chain of this key's policy changes, for example `api-key-7`. */
  chain_id?: string;
  /** The newest change, or 64 zeros when there is none yet. */
  newest_activation_hash: Hex64;
  /** The document in force, or empty under the built-in policy. */
  active_document_hash: string;
  policies: Policy[];
}

/** The argument of {@link VerdifaxClient.testPolicy}: sample inputs and
 *  exactly one of `document` or `documentHash`. */
export interface PolicyTestRequest {
  /** Sample inputs for the rules, passed through as given. */
  inputs: Record<string, unknown>;
  /** The exact text of a policy to test. */
  document?: string;
  /** The document hash of a policy already uploaded under this key. */
  documentHash?: Hex64;
  /** Whether the request being tried declares an AI output, as
   *  `ai_output_text` does on a run: a policy that requires an AI review
   *  refuses a step without one. Sent only when true. */
  aiOutputDeclared?: boolean;
}

/** Returned by {@link VerdifaxClient.testPolicy}. A test seals nothing. */
export interface PolicyTestResult {
  ok: boolean;
  /** Always false. */
  sealed: boolean;
  outcome: string;
  fired_rule_id: string;
  reason_code: string;
}

/** The signature of a policy activation: the request key's approval of
 *  the change. */
export interface PolicyActivationSignature {
  /** Base64 Ed25519 signature by the request key. */
  signature: string;
  /** RFC 3339 UTC with whole seconds. */
  signed_at: string;
  /** 16 random bytes as 32 lowercase hex characters, fresh per change. */
  nonce: string;
}

/** One policy change, as {@link VerdifaxClient.activatePolicy} and
 *  {@link VerdifaxClient.getPolicyHistory} return it. */
export interface PolicyActivation {
  format: string;
  chain_id: string;
  sequence: number;
  previous_activation_hash: Hex64;
  policy_id: string;
  policy_version: string;
  policy_hash: Hex64;
  document_hash: Hex64;
  activated_at: string;
  /** Present when the request key signed the change. */
  signature?: PolicyActivationSignature & { public_key: string };
  activation_hash: Hex64;
  /** Where the change was logged on the public log. */
  anchor?: Record<string, unknown>;
}

/** Places one run in a job. `job_id` and `step_id` are 1 to 128 letters,
 *  digits, dots, underscores, colons or dashes. The client sorts both
 *  lists, removes repeats and leaves out an empty list and a false
 *  `final`. */
export interface JobLink {
  job_id: string;
  step_id: string;
  /** Record hashes of the steps this one directly follows, in this job. */
  previous_record_hashes?: Hex64[];
  /** Record hashes from another account that this step follows. */
  external_previous?: Hex64[];
  /** True on the step that closes the job. */
  final?: boolean;
}

/** The runtime a caller declares for a run. Every field is optional.
 *  The server records these values as given and does not check them. */
export interface ReproducibilityContext {
  /** True when any other field has a value. The client derives this. */
  declared?: boolean;
  /** 64 hex characters, without the `sha256:` prefix. */
  container_image_hash?: string;
  runtime_name?: string;
  runtime_version?: string;
  /** `name==version` strings, sorted. */
  pinned_dependencies?: string[];
  git_commit_sha?: string;
  /** `library=seed` strings, sorted. */
  random_seeds?: string[];
  /** GOOS/GOARCH style, for example `linux/amd64`. */
  platform?: string;
}

/** The signature an API key with a registered request key must carry.
 *  The public key comes from the registration, never from the request. */
export interface RequestSignature {
  /** Base64 Ed25519 signature. */
  signature: string;
  /** RFC 3339 UTC with whole seconds, for example 2026-11-05T02:18:00Z. */
  signed_at: string;
  /** 16 random bytes as 32 lowercase hex characters, fresh per request. */
  nonce: string;
}

/** A version 2 request signature, which covers the exact `signed_request`
 *  text. */
export interface RequestSignatureV2 extends RequestSignature {
  version: "2";
}

/** The whole body of a signed call, and of each row of a signed batch.
 *  The server reads the request from `signed_request` alone. */
export interface SignedRequestBody {
  /** The request as JSON text, exactly as it was signed. */
  signed_request: string;
  request_signature: RequestSignatureV2;
}

/** The current key's approval of replacing or clearing itself. */
export interface RequestKeyChange {
  /** Base64 Ed25519 signature by the current key. */
  signature: string;
  /** RFC 3339 UTC with whole seconds. */
  signed_at: string;
  /** 16 random bytes as 32 lowercase hex characters, fresh per change. */
  nonce: string;
}

/** A key pair from {@link generateRequestKeyPair}, as raw bytes. */
export interface RequestKeyPair {
  /** The 32-byte Ed25519 public key. */
  publicKey: Buffer;
  /** The 32-byte Ed25519 private key. Keep it secret. */
  privateKey: Buffer;
}

/** Body of POST /keys/request-key. */
export interface RequestKeyRegistrationBody {
  /** Base64 of the raw 32-byte public key. */
  public_key: string;
  /** Base64 signature proving the caller holds the private key. */
  proof: string;
}

/** Returned by {@link VerdifaxClient.registerRequestKey} and
 *  {@link VerdifaxClient.rotateRequestKey}. */
export interface RequestKeyRegistration {
  ok: boolean;
  public_key: string;
}

export interface ExecuteResponse {
  ok: boolean;
  run_id: number;
  /** The record's hash: the manifest hash of a completed run. A refused or
   *  halted run throws an {@link APIError} carrying its `recordHash` and,
   *  when signed, its `signedRequest`. */
  record_hash?: Hex64;
  manifest_hash?: Hex64;
  manifest: ExecutionManifest;
  duration_ms: number;
  /** The exact text that was signed, when the call was signed. Keep it to
   *  pass to `verdifax-verify --request FILE`. */
  signed_request?: string;
  /** The text the AI review checked, when a review ran on the run's AI
   *  output. Verdifax returns it once and does not store it; its SHA-256 is
   *  sealed in `manifest.AivpReview`. Keep it for `verdifax-verify
   *  --aivp-trace`. */
  aivp_trace_text?: string;
}

/** One row of {@link ExecuteBatchResponse}. A successful row has
 *  `manifest`. A failed row has `error`, and `error_stage` and a typed
 *  receipt when the pipeline halted. A row refused before it ran has
 *  no `run_id`. */
export interface ExecuteBatchResult {
  index: number;
  ok: boolean;
  run_id?: number;
  /** The manifest hash of a completed row, or the receipt hash of a refused
   *  or halted one. */
  record_hash?: Hex64;
  manifest_hash?: Hex64;
  manifest?: ExecutionManifest;
  error?: string;
  error_stage?: string;
  duration_ms: number;
  /** The exact text that was signed for this row, when it was signed. */
  signed_request?: string;
  partial_manifest?: ExecutionManifest;
  deny_receipt?: Record<string, unknown>;
  ccv_halt_receipt?: Record<string, unknown>;
  macc_halt_receipt?: Record<string, unknown>;
  aivp_t4_halt_receipt?: Record<string, unknown>;
  attestation_gap_receipt?: Record<string, unknown>;
  /** The text the AI review checked on this row, returned once and not
   *  stored; its hash is sealed in the review. */
  aivp_trace_text?: string;
}

/** Body returned by POST /execute/batch. */
export interface ExecuteBatchResponse {
  ok: boolean;
  total: number;
  successful: number;
  failed: number;
  duration_ms: number;
  results: ExecuteBatchResult[];
}

/** One of the two runs of a determinism check. */
export interface DeterminismRun {
  run_id: number;
  manifest_hash: string;
  bundle_hash: string;
  duration_ms: number;
  /** `ok`, `stage_error`, or the refusal or halt kind, such as
   *  `pepg_deny`. */
  status: string;
  error?: string;
  /** The sealed receipt of a refused or halted run. The run's manifest
   *  hash covers its hash. */
  receipt?: Record<string, unknown>;
}

/** How the two runs of a determinism check compared. */
export interface DeterminismDiff {
  differs: boolean;
  manifest_hash_differs: boolean;
  bundle_hash_differs: boolean;
  differing_fields?: string[];
  /** Why there is no verdict, when neither run sealed a record. */
  reason?: string;
}

/** Body returned by POST /execute/verify-determinism. `deterministic`
 *  means both runs ended the same way, completed or refused, with equal
 *  manifest hashes. */
export interface VerifyDeterminismResponse {
  ok: boolean;
  deterministic: boolean;
  first: DeterminismRun;
  second: DeterminismRun;
  diff: DeterminismDiff;
  /** The exact text that was signed, when the call was signed. */
  signed_request?: string;
}

/**
 * Sealed manifest. Field names match the orchestrator's Go-default
 * JSON encoding (CapitalCamelCase).
 *
 * Subset of the canonical fields, see the orchestrator's
 * `internal/pipeline/types.go` for the full struct. The fields
 * listed here are the ones every Track-2 / Track-3 / Track-5
 * surface depends on.
 */
export interface ExecutionManifest {
  EnvelopeID: string;
  EnvelopeHash: Hex64;
  ManifestHash: Hex64;
  DseCommitmentHash?: Hex64;
  TokOrderingHash?: Hex64;
  DscFinalStateHash?: Hex64;
  NrepActorID?: string;
  NrepActorPublicKey?: string;
  NrepSignature?: string;
  AivpOutcome?: string;
  AivpPiaHash?: Hex64;
  AivpAdapterID?: string;
  AivpDecision?: string;
  /** The AI review's record of the answer it read, on runs sealed since the
   *  server's v1.10 manifest formula. */
  AivpReviewForm?: string;
  AivpReview?: AivpReview;
  /** Phase-17 (CRES) sealed-at-write erasure state. */
  EraseStatus?: "intact" | "shredded" | "tombstone" | "";
  ExecutionRegion?: string;
  FormalVerifierStatus?: string;
  HardwareAttestationHash?: Hex64;
  LedgerBackend?: string;
  LedgerLeafHash?: Hex64;
  LedgerProofHash?: Hex64;
  LogEntryID?: string;
}

// ── Runs ────────────────────────────────────────────────────────

/** Every status the server gives a run. */
export const RUN_STATUSES = [
  "ok",
  "probe",
  "pepg_deny",
  "ccv_halt",
  "macc_halt",
  "aivp_t4_halt",
  "attestation_gap",
  "stage_error",
] as const;

/** A run's status: one of {@link RUN_STATUSES}, or a value a newer server
 *  adds. Written with `string & {}` so editors still offer the known
 *  values and any string can be compared. */
export type RunStatus = (typeof RUN_STATUSES)[number] | (string & {});

export interface Run {
  ok: boolean;
  id: number;
  created_at: string;
  payload_hash: Hex64;
  program_id: Hex64;
  route_id: string;
  manifest_hash: Hex64;
  duration_ms: number;
  status: RunStatus;
  error_stage?: string;
  error_message?: string;
  manifest: ExecutionManifest;
}

export interface VerifyResponse {
  ok: boolean;
  verified: boolean;
  manifest_hash: Hex64;
  recomputed_hash: Hex64;
  formula_version: string;
  verification_at: string;
  verification_kind: string;
  dcae_engine_hint?: {
    available_at: string;
    engine_version: string;
  };
}

// ── Client config ──────────────────────────────────────────────

export interface ClientConfig {
  /** Orchestrator endpoint. Trailing slash optional. Defaults to https://api.verdifax.com. */
  baseURL?: string;
  /** X-Verdifax-Key value. Required for every endpoint except /health, /version, /dcae/verify. */
  apiKey?: string;
  /** Per-request timeout in ms. Defaults to 90000. */
  timeoutMs?: number;
  /** Override the default User-Agent. Useful for telemetry attribution. */
  userAgent?: string;
  /** Retry budget for idempotent GET/HEAD/OPTIONS that fail with a
   *  transient error (502/503/504/429 or network failure).
   *  Defaults to 3. Set to 0 to disable retries entirely. */
  maxRetries?: number;
  /** First inter-retry sleep in ms. The retry middleware doubles
   *  it on each subsequent retry (exponential backoff with full
   *  jitter). Defaults to 200ms. */
  retryBaseDelayMs?: number;
  /** The 32 raw bytes of an Ed25519 private key. When set, every path to
   *  POST /execute signs its request. The key is never sent to the
   *  server. Leave unset for unsigned requests. */
  signingKey?: Uint8Array;
}

// ── Higher-level helpers + extended endpoints ─────────────────

/** Friendly shape for {@link VerdifaxClient.attest}. Mirrors the
 *  Python SDK's `attest()` signature so polyglot teams have parity. */
export interface AttestRequest {
  /** Raw bytes, auto-base64-encoded before sending. Mutually
   *  exclusive with `payload_text`. */
  payload?: Buffer | Uint8Array;
  /** Plain-text payload, sent as-is. Mutually exclusive with
   *  `payload`. */
  payload_text?: string;
  program_id: Hex64;
  route_id: string;
  registry_record_hash: Hex64;
  ai_output_text?: string;
  attested_context?: Record<string, unknown>;
  reproducibility_context?: ReproducibilityContext;
  request_substance?: Record<string, unknown>;
  authorization_chain?: Record<string, unknown>;
  regulatory_scaffolding?: Record<string, unknown>;
  causal_graph?: Record<string, unknown>;
  /** Places this run in a job map. {@link VerdifaxJob.step} fills it in. */
  job?: JobLink;
  /** What this request declares for the rules of a customer policy. */
  policy_context?: PolicyContext;
  /** The policy hash this request expects to run under. */
  expected_policy_hash?: Hex64;
}

/** The second argument of {@link VerdifaxJob.step}: everything
 *  {@link VerdifaxClient.attest} takes except `job`, which the helper
 *  builds, plus the step's place in the job. */
export interface JobStepOptions extends Omit<AttestRequest, "job"> {
  /** Step ids in this job that this step directly follows. When omitted,
   *  the step follows the one run just before it through this helper. An
   *  empty list means it follows none. */
  after?: string[];
  /** Record hashes from another account that this step follows. */
  external_previous?: Hex64[];
  /** True on the step that closes the job. */
  final?: boolean;
}

/** Optional filters for {@link VerdifaxClient.listRuns}. */
export interface ListRunsParams {
  limit?: number;
  offset?: number;
}

/** Lightweight projection used in `/runs` and `/runs/search`
 *  responses. Excludes the heavy ManifestJSON; call `getRun(id)`
 *  for the full sealed manifest. */
export interface RunSummary {
  id: number;
  /** The key that requested the run. */
  api_key_id?: number;
  created_at: string;
  program_id: Hex64;
  route_id: string;
  manifest_hash: Hex64;
  status: RunStatus;
  outcome_kind?: string;
  duration_ms?: number;
  error_stage?: string;
  execution_region?: string;
}

/** Optional filters for {@link VerdifaxClient.searchRuns}. `from` and
 *  `to` are RFC 3339 times. */
export interface SearchRunsParams {
  /** Matches manifest hashes that start with this value. */
  manifest_hash?: string;
  program_id?: Hex64;
  route_id?: string;
  status?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

/** Period for {@link VerdifaxClient.exportRuns} and
 *  {@link VerdifaxClient.exportRunsCSV}, as RFC 3339 times. `from` is
 *  inclusive and `to` is exclusive. `to` defaults to the time of the
 *  request. */
export interface ExportRunsParams {
  from?: string;
  to?: string;
  /** Limits the export to the runs of one job. */
  job_id?: string;
}

/** One run in an evidence export: what the server stored, not a verdict. */
export interface ExportRow {
  run_id: number;
  /** The key that requested the run, so an account's export can be
   *  grouped by key. */
  api_key_id?: number;
  created_at: string;
  status: RunStatus;
  error_stage: string;
  route_id: string;
  manifest_hash: string;
  log_entry_id: string;
  leaf_hash: string;
  complete_record_entry_id: string;
  complete_record_leaf_hash: string;
  /** Where the row's public-log entry was read from: `bundle`, `receipt`
   *  or `none`. */
  anchor_source?: string;
  job_id?: string;
  step_id?: string;
}

/** Body returned by GET /runs/export in JSON form. */
export interface RunsExport {
  ok: boolean;
  /** The upper bound the server used for this export. */
  to: string;
  /** Runs held for the period. */
  total: number;
  /** Rows in this response. */
  returned: number;
  /** True when the period holds more rows than this response. */
  truncated: boolean;
  /** Rows returned, counted by status. */
  by_status: Record<string, number>;
  runs: ExportRow[];
  /** The key's policy documents, when it has loaded any. */
  policy_documents?: PolicyWithDocument[];
  /** The key's policy changes, oldest first, when it has loaded any. */
  policy_history?: PolicyActivation[];
  /** The key's account, as `account-N`. */
  account_id?: string;
  /** The account's policy documents, when it has loaded any. */
  account_policy_documents?: PolicyWithDocument[];
  /** The account's policy changes, oldest first, when it has loaded any. */
  account_policy_history?: PolicyActivation[];
}

/** Returned by {@link VerdifaxClient.exportAccountRuns}: the runs of every
 *  key in the account, with the account's policy documents and changes. */
export interface AccountRunsExport extends RunsExport {
  account_id: string;
  /** The account's whole chain of sign-offs, oldest first, as
   *  {@link VerdifaxClient.getSignOffHistory} returns it. Only the owner
   *  key's export carries it, and the SDK returns it as the server sent
   *  it, without checking it: check it with `verdifax-verify`. */
  signoffs?: SignOffRecord[];
}

/** Returned by {@link VerdifaxClient.exportRunsCSV}. */
export interface RunsExportCSV {
  /** The CSV text, unparsed. */
  csv: string;
  /** Runs held for the period. */
  total: number;
  /** True when the period holds more rows than `csv`. */
  truncated: boolean;
}

/** Optional paging for {@link VerdifaxClient.listAttestations}. */
export interface ListAttestationsParams {
  limit?: number;
  offset?: number;
}

/** Body returned by GET /attestations. Each row is a receipt as the
 *  server sends it, without its inclusion proof. */
export interface AttestationList {
  ok: boolean;
  count: number;
  limit: number;
  offset: number;
  attestations: Record<string, unknown>[];
}

/** Body returned by GET /stats. */
export interface RunStats {
  ok: boolean;
  total_runs: number;
  runs_today: number;
  runs_last_24h: number;
  pass_rate: number;
  avg_duration_ms: number;
  last_run_at: string;
  runs_by_program: Record<string, number>;
}

/** Audit-PDF format selector. */
export type PDFFormat = "brief" | "auditor" | "legal" | "comprehensive";

/** Options of an audit PDF request. `aiOutputText` is the AI's exact
 *  answer: the report prints it, marked as supplied by the caller, only
 *  when its SHA-256 is the hash the record seals. */
export interface AuditPDFOptions {
  aiOutputText?: string;
}

/** Body shape for {@link VerdifaxClient.adminErase}. */
export interface AdminEraseRequest {
  run_id: number;
  field_path: string;
  /** SHA-256 hex of the ciphertext that was sealed for this field
   *  at encryption time. Caller looks this up in their own records. */
  ciphertext_hash: Hex64;
  /** Optional opaque reference for the originating DSAR / RTBF /
   *  HIPAA-authorization. */
  dsar_reference?: string;
}

/** A sealed CRES DeletionReceipt. Mirrors the orchestrator's
 *  `cres.DeletionReceipt` shape with snake_case JSON keys. */
export interface DeletionReceipt {
  preimage_version: string;
  envelope_id: string;
  field_path: string;
  deletion_clock: string;
  actor_id: string;
  ciphertext_hash_at_shred: Hex64;
  dsar_reference?: string;
  engine_version: string;
  receipt_hash: Hex64;
  id?: number;
}

/** Input shape for {@link VerdifaxClient.dcaeVerify}. */
export interface DCAEProofBundle {
  preimage_version?: string;
  envelope_id: string;
  envelope_hash: Hex64;
  aer_hash: Hex64;
  zksp_binding_hash: Hex64;
  formal_verifier_status: string;
  manifest_hash: Hex64;
  canonical_manifest_preimage?: string;
}

/** Output shape for {@link VerdifaxClient.dcaeVerify}. */
export interface DCAEVerdict {
  verified: boolean;
  failure_reason?: string;
  verified_closure_hash?: Hex64;
  engine_version: string;
}

/** Body returned by `POST /admin/keys`. The `secret` field is
 *  shown ONCE, store it immediately. */
export interface AdminCreateKeyResponse {
  ok: boolean;
  id: number;
  name: string;
  secret: string;
  hint: string;
  /** The key's account, as `account-N`. */
  account_id?: string;
}

/** Options for {@link VerdifaxClient.adminCreateKey}. */
export interface AdminCreateKeyOptions {
  /** Puts the customer key in this existing account, by its number. Without
   *  it the key gets an account of its own. A key never changes account. */
  accountId?: number;
}

// ── Accounts ────────────────────────────────────────────────────

/** A key's tier. */
export type KeyTier = "trial" | "production";

/** An account, a company on Verdifax, as GET /admin/accounts lists it. The
 *  account number is a label Verdifax assigned, not a verified company
 *  identity. */
export interface Account {
  /** `account-N`, as records seal it. */
  account_id: string;
  id: number;
  name: string;
  tier: string;
  created_at: string;
  /** Member keys not revoked. */
  member_keys: number;
  /** Owner keys not revoked. */
  owner_keys: number;
  /** The chain of the account's policy changes, `account-N`. */
  chain_id: string;
  identity?: string;
  policy_scope?: string;
  /** The second zone the account's reports show beside UTC: an IANA zone,
   *  `"none"` for UTC alone, or empty for the zone of the server's region. */
  time_zone?: string;
}

/** Returned by {@link VerdifaxClient.setAccountTimeZone}. */
export interface AccountTimeZone {
  ok: boolean;
  account_id: string;
  time_zone: string;
}

/** Returned by {@link VerdifaxClient.getAccount}. */
export interface AccountInfo extends Account {
  ok: boolean;
}

/** One of an account's keys, without its secret. */
export interface AccountKey {
  id: number;
  name: string;
  account_id: string;
  /** True for an owner key, which manages the account and cannot run
   *  anything. */
  owner: boolean;
  tier: string;
  created_at: string;
  last_used_at: string;
  run_count: number;
  revoked: boolean;
  expires_at?: string;
}

/** Returned by {@link VerdifaxClient.listAccountKeys}. */
export interface AccountKeyList {
  ok: boolean;
  account_id: string;
  keys: AccountKey[];
}

/** A new key with its secret, which is shown this once. */
export interface CreatedAccountKey extends AccountKey {
  ok: boolean;
  secret: string;
  /** True when the key needs a request key before it can run. */
  request_key_required: boolean;
  hint: string;
}

/** Returned by {@link VerdifaxClient.revokeAccountKey}. */
export interface AccountKeyRevocation {
  ok: boolean;
  id: number;
  revoked: boolean;
}

/** Options for {@link VerdifaxClient.createAccountKey}. */
export interface CreateAccountKeyOptions {
  /** RFC 3339 or YYYY-MM-DD. */
  expiresAt?: string;
}

/** Options for {@link VerdifaxClient.adminCreateAccount}. */
export interface AdminCreateAccountOptions {
  /** `trial` when left out. */
  tier?: KeyTier;
  /** When the owner key expires: RFC 3339 or YYYY-MM-DD. */
  expiresAt?: string;
}

/** Returned by {@link VerdifaxClient.adminCreateAccount}: the account and
 *  its first owner key, with the secret. */
export interface AdminCreateAccountResponse {
  ok: boolean;
  account: Account;
  owner_key: CreatedAccountKey;
}

/** Projection returned by {@link VerdifaxClient.adminListKeys}.
 *  Secrets are NEVER surfaced, only metadata. */
export interface AdminAPIKey {
  id: number;
  name: string;
  created_at: string;
  last_used_at?: string;
  run_count: number;
  revoked: boolean;
}

// ── Sign-off ────────────────────────────────────────────────────

/** The kind of result a sign-off names: a completed run's record, a
 *  refused or halted run's receipt, or a whole job by its final step. */
export type SignOffTargetKind = "record" | "receipt" | "job";

/** An approver's decision on one result. */
export type SignOffDecision = "approve" | "reject";

/** The exact result a sign-off names, by what its public-log entry
 *  covers. */
export interface SignOffTarget {
  kind: SignOffTargetKind;
  /** The run: for a job, the run of its final step. */
  run_id: number;
  /** What the result's public-log entry covers. For a record, its
   *  `bundle_anchor.anchored_digest` in the bundle
   *  {@link VerdifaxClient.getRunArtifacts} returns. For a receipt, its
   *  hash. For a job, the final step's record digest, read the same way
   *  as a record's. 64 lowercase hex characters. */
  digest: Hex64;
  /** The job, for a job target only. */
  job_id?: string;
}

/** One record made public or withdrawn by the account's owner,
 *  verdifax.run-publication.v1: sealed with its place in the account's signal
 *  feed and anchored on the public log. `verdifax-verify --signals` reads it
 *  since v0.24.0. Save it as the server sent it. */
export interface RunPublication {
  format: string;
  /** `run.published` or `run.unpublished`. */
  action: "run.published" | "run.unpublished";
  /** Who decided: `owner`, or `verdifax_admin` when a Verdifax admin key
   *  withdrew the record. Absent on a v1 publication, which was the owner's. */
  decided_by?: "owner" | "verdifax_admin";
  run_id: number;
  /** The record's own hash, so the publication binds the exact record. */
  record_hash: Hex64;
  /** The record's job and step, when it has one. */
  job_id?: string;
  step_id?: string;
  changed_at: string;
  /** The record's place in the account's signal feed. */
  signal: { signal_account: string; signal_sequence: number; signal_previous_hash: Hex64 };
  publication_hash: Hex64;
  /** The public-log anchor; absent while the entry is still being anchored. */
  anchor?: unknown;
}

/** One successful run of an account, verdifax.run-sealed.v1: the entry of a
 *  `run.sealed` feed event, sealed with its place in the account's signal
 *  feed and anchored on the public log, so the feed lists every successful
 *  run. `verdifax-verify --signals` reads it since v0.28.0. Save it as the
 *  server sent it. */
export interface RunSealedRecord {
  format: string;
  run_id: number;
  /** The record's own hash, so the event binds the exact record. */
  record_hash: Hex64;
  /** The record's job and step, when it has one. */
  job_id?: string;
  step_id?: string;
  sealed_at: string;
  /** The event's place in the account's signal feed. */
  signal: { signal_account: string; signal_sequence: number; signal_previous_hash: Hex64 };
  run_sealed_hash: Hex64;
  /** The public-log anchor; absent while the entry is still being anchored. */
  anchor?: unknown;
}

/** A restore gap, verdifax.restore-gap.v1: after a restore from backup, one
 *  of the account's chains (`signals`, `signoffs`, `policy` or
 *  `account-policy`) skips places `lost_from` to `lost_to`, which may hold
 *  entries the restore lost, so no place on the public log is ever reused.
 *  It is the entry of a `chain.gap` feed event, sealed and anchored, and it
 *  sits in its place in a sign-off or policy history. `verdifax-verify`
 *  accepts a skip in a chain only through one, since v0.28.0. */
export interface RestoreGapRecord {
  format: "verdifax.restore-gap.v1";
  chain: "signals" | "signoffs" | "policy" | "account-policy";
  /** The key whose policy chain it is, for the `policy` chain only. */
  key_id?: number;
  lost_from: number;
  lost_to: number;
  recorded_at: string;
  signal: { signal_account: string; signal_sequence: number; signal_previous_hash: Hex64 };
  restore_gap_hash: Hex64;
  anchor?: unknown;
}

/** The answer to {@link VerdifaxClient.publishRun} and
 *  {@link VerdifaxClient.unpublishRun}: the run's public state, its links
 *  while public, and the publication the call sealed, null when the run was
 *  already in the asked state. */
export interface PublicationResult {
  ok: boolean;
  run_id: number;
  public: boolean;
  /** Where the record's audit bundle is served, while it is public and has one. */
  public_bundle_url?: string;
  /** Where a stopped run's sealed receipt is served, while it is public; a
   *  stopped run has no bundle address (R156). */
  public_receipt_url?: string;
  verify_url: string;
  publication: RunPublication | null;
}

/** One sign-off, verdifax.signoff.v1, as the server records it and
 *  `verdifax-verify --signoff` and `--signoff-history` read it. */
export interface SignOffRecord {
  format: string;
  /** The account's chain, `account-N`. */
  chain_id: string;
  sequence: number;
  /** The sign-off this one follows, or 64 zeros for the account's first. */
  previous_signoff_hash: Hex64;
  target: SignOffTarget;
  decision: SignOffDecision;
  /** SHA-256 of the approver's note, when there was one. The note's text
   *  never reaches Verdifax. */
  note_hash?: string;
  /** The base64 Ed25519 public key of the approver who signed. */
  approver_key: string;
  /** Base64 Ed25519 signature by the approver key. */
  signature: string;
  signed_at: string;
  nonce: string;
  recorded_at: string;
  signoff_hash: Hex64;
  /** Where the sign-off was logged on the public log. */
  anchor?: Record<string, unknown>;
}

/** What an approver signs against: the account's chain and its newest
 *  sign-off. Returned by {@link VerdifaxClient.getNewestSignOff}. */
export interface NewestSignOff {
  ok: boolean;
  /** The account's chain, `account-N`. */
  chain_id: string;
  /** The newest sign-off's hash, or 64 zeros when there is none yet. */
  newest_signoff_hash: Hex64;
  /** The newest sign-off's place in the chain, 0 when there is none. */
  sequence: number;
}

/** The approver key's part of a sign-off. */
export interface SignOffSignature {
  /** The base64 Ed25519 public key of the approver. */
  approver_key: string;
  /** Base64 Ed25519 signature by the approver key. */
  signature: string;
  /** RFC 3339 UTC with whole seconds. */
  signed_at: string;
  /** 16 random bytes as 32 lowercase hex characters, fresh per sign-off. */
  nonce: string;
}

/** Options for {@link VerdifaxClient.signOff}. */
export interface SignOffOptions {
  /** The approver's note. It is hashed on this machine and only its
   *  SHA-256 is sent and signed: the text never reaches Verdifax. Keep the
   *  text yourself to show it matches the hash. */
  note?: string;
  /** Use the owner key's routes, /account/signoffs/newest and
   *  /account/signoffs, instead of a member key's. */
  asOwner?: boolean;
}

/** For a method that serves both a member key's route and the owner
 *  key's /account route. */
export interface AsOwnerOptions {
  /** Use the owner key's /account route. */
  asOwner?: boolean;
}

/** An approver key's public key and the proof that its holder has the
 *  private key, from {@link approverKeyProof}. */
export interface ApproverKeyProof {
  /** Base64 of the raw 32-byte public key. */
  public_key: string;
  /** Base64 Ed25519 signature over verdifax.approver-key.v1, a zero byte
   *  and the base64 public key. */
  proof: string;
}

/** An approver key registered to an account. A key is not an identity:
 *  `name` is the label the owner gave it. */
export interface Approver {
  id: number;
  public_key: string;
  name: string;
  /** The account, `account-N`. */
  account_id: string;
  registered_at: string;
  revoked: boolean;
  revoked_at?: string;
}

/** Returned by {@link VerdifaxClient.registerApprover}. */
export interface ApproverRegistration extends Approver {
  ok: boolean;
}

/** Returned by {@link VerdifaxClient.listApprovers}: revoked keys
 *  included. */
export interface ApproverList {
  ok: boolean;
  account_id: string;
  approvers: Approver[];
}

/** Returned by {@link VerdifaxClient.revokeApprover}. */
export interface ApproverRevocation {
  ok: boolean;
  id: number;
  revoked: boolean;
}

// ── Signal feed ─────────────────────────────────────────────────

/** The kind of a control signal. Each is also a CloudEvents type,
 *  `com.verdifax.` and the kind. */
export type SignalKind =
  | "run.refused"
  | "run.halted"
  | "run.failed"
  | "policy.changed"
  | "signoff.recorded"
  | "approver.registered"
  | "approver.revoked"
  | "key.created"
  | "key.revoked"
  | "run.published"
  | "run.unpublished"
  /** A restore from backup made one of the account's chains skip places its
   *  entries may have held; the gap is sealed and on the public log. */
  | "chain.gap"
  /** A successful run, so the feed is a complete account ledger. */
  | "run.sealed";

/** The Verdifax event inside a {@link SignalEvent}, verdifax.signal.v1. */
export interface SignalEventData {
  /** `verdifax.signal.v1`. */
  form: string;
  kind: SignalKind | (string & {});
  /** The account, `account-N`. */
  account: string;
  /** The event's place in the account's feed, from 1. */
  sequence: number;
  /** The previous event's `event_hash`, or 64 zeros for the account's
   *  first event. */
  previous_signal_hash: Hex64;
  /** {@link signalEventHash} of the kind, the entry's hash and the place. */
  event_hash: Hex64;
  run_id?: number;
  api_key_id?: number;
  /** A short reason a reader can route on, for a refused, halted or
   *  failed run. */
  reason?: string;
  /** The sealed entry the event names, in the exact form
   *  `verdifax-verify` reads. */
  entry: Record<string, unknown>;
}

/** One control signal, as a CloudEvents 1.0 envelope. */
export interface SignalEvent {
  specversion: string;
  /** `account-N/SEQUENCE`. */
  id: string;
  source: string;
  /** `com.verdifax.` and the kind. */
  type: string;
  time: string;
  datacontenttype: string;
  data: SignalEventData;
}

/** One page of the feed. Returned by {@link VerdifaxClient.getSignals}. */
export interface SignalPage {
  /** The events after the place asked for, oldest first. */
  events: SignalEvent[];
  /** The place to read from next: the last event's sequence, or the
   *  place asked for when the page is empty. */
  next_after: number;
  /** The newest sequence in the account's feed, 0 when it is empty. */
  newest: number;
}

/** Options for {@link VerdifaxClient.getSignals}. */
export interface GetSignalsOptions {
  /** The last sequence already read. 0, the default, reads from the start. */
  after?: number;
  /** 1 to 500 events. The server's default is 100. */
  limit?: number;
  /** 0 to 25 seconds to hold the request open when there is no event yet.
   *  Defaults to 0. */
  wait?: number;
  /** Read GET /account/signals with the owner key instead of GET /signals
   *  with a feed key. */
  asOwner?: boolean;
}

/** Options for {@link VerdifaxClient.followSignals}. */
export interface FollowSignalsOptions {
  /** The last sequence already read. 0, the default, reads from the start. */
  after?: number;
  /** 0 to 25 seconds each read waits for the next event. Defaults to 25. */
  wait?: number;
  /** Read GET /account/signals with the owner key instead of GET /signals
   *  with a feed key. */
  asOwner?: boolean;
}

/** Options for {@link VerdifaxClient.createFeedKey}. */
export interface CreateFeedKeyOptions {
  /** RFC 3339 or YYYY-MM-DD. */
  expiresAt?: string;
}

/** A new feed key with its secret, which is shown this once. A feed key
 *  reads the account's signal feed and nothing else. Returned by
 *  {@link VerdifaxClient.createFeedKey}. */
export type CreatedFeedKey = CreatedAccountKey;

/** Returned by {@link VerdifaxClient.revokeFeedKey}. */
export interface FeedKeyRevocation {
  ok: boolean;
  id: number;
  revoked: boolean;
}

/** Options for {@link VerdifaxClient.createWebhook}. */
export interface CreateWebhookOptions {
  /** The kinds to deliver, each once. Empty or left out takes every kind. */
  types?: SignalKind[];
}

/** A webhook subscription, without its secret. */
export interface Webhook {
  id: number;
  url: string;
  /** The kinds it delivers. Empty means every kind. */
  types: SignalKind[];
  created_at: string;
}

/** A new webhook subscription with its secret, `whsec_` and base64,
 *  which is shown this once. Check each delivery with it using
 *  {@link verifyWebhook}. Returned by {@link VerdifaxClient.createWebhook}. */
export interface CreatedWebhook extends Webhook {
  ok: boolean;
  secret: string;
  hint: string;
}

/** Returned by {@link VerdifaxClient.listWebhooks}. */
export interface WebhookList {
  ok: boolean;
  webhooks: Webhook[];
}

/** Returned by {@link VerdifaxClient.deleteWebhook}. */
export interface WebhookDeletion {
  ok: boolean;
  id: number;
  deleted: boolean;
}

/** Options for {@link VerdifaxClient.listWebhookDeliveries}. */
export interface ListWebhookDeliveriesOptions {
  /** 1 to 500 deliveries. The server's default is 50. */
  limit?: number;
}

/** One delivery of one event to a webhook. A delivery is a copy: the pull
 *  feed and the public log are the record. */
export interface WebhookDelivery {
  /** The event's place in the account's feed. */
  sequence: number;
  /** `pending`, `delivered` or `failed`. */
  status: string;
  attempts: number;
  last_status_code: number;
  last_error: string;
  created_at: string;
  delivered_at?: string;
  next_attempt_at?: string;
}

/** Returned by {@link VerdifaxClient.listWebhookDeliveries}: the newest
 *  deliveries first. */
export interface WebhookDeliveryList {
  ok: boolean;
  webhook_id: number;
  deliveries: WebhookDelivery[];
}

/** The headers of a webhook delivery: a fetch `Headers`, or an object such
 *  as Node's `req.headers`. Names are read without regard to case. */
export type WebhookHeaders =
  | { get(name: string): string | null }
  | Record<string, string | string[] | undefined>;

/** Options for {@link verifyWebhook}. */
export interface VerifyWebhookOptions {
  /** How far, in seconds, `webhook-timestamp` may be from `now` in either
   *  direction. Defaults to 300. */
  toleranceSeconds?: number;
  /** The time to check the timestamp against. Defaults to the current
   *  time. */
  now?: Date;
}

/** An event's place in its account's feed, for {@link signalEventHash}. */
export interface SignalEventHashFields {
  /** The account, `account-N`. */
  account: string;
  /** The event's sequence, a whole number. */
  sequence: number;
  /** The previous event's hash, or 64 zeros for the account's first. */
  previousSignalHash: string;
}

/** The AI review's record of one answer it read: the review setup, the
 *  SHA-256 of the trace it checked, the checker, what the account policy
 *  chose a contradiction finding does, the outcome and the finding. */
export interface AivpReview {
  formula: string;
  prompt_id: string;
  model: string;
  trace_hash: Hex64;
  checker_id: string;
  contradiction_mode: "halt" | "record";
  contradiction_outcome: "clean" | "halted" | "recorded";
  finding?: AivpFinding;
}

/** The contradiction the review's checker found: two trace nodes, by id,
 *  and the opposing terms in them. */
export interface AivpFinding {
  node_a: string;
  node_b: string;
  term: string;
  opposite: string;
}
