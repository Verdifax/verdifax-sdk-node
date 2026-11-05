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
  /** Filled in by the client when the `signingKey` option is set. */
  request_signature?: RequestSignature;
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

/** Returned by {@link VerdifaxClient.registerRequestKey}. */
export interface RequestKeyRegistration {
  ok: boolean;
  public_key: string;
}

export interface ExecuteResponse {
  ok: boolean;
  run_id: number;
  manifest: ExecutionManifest;
  duration_ms: number;
}

/** One row of {@link ExecuteBatchResponse}. A successful row has
 *  `manifest`. A failed row has `error`, and `error_stage` and a typed
 *  receipt when the pipeline halted. A row refused before it ran has
 *  no `run_id`. */
export interface ExecuteBatchResult {
  index: number;
  ok: boolean;
  run_id?: number;
  manifest_hash?: Hex64;
  manifest?: ExecutionManifest;
  error?: string;
  error_stage?: string;
  duration_ms: number;
  partial_manifest?: ExecutionManifest;
  deny_receipt?: Record<string, unknown>;
  ccv_halt_receipt?: Record<string, unknown>;
  macc_halt_receipt?: Record<string, unknown>;
  aivp_t4_halt_receipt?: Record<string, unknown>;
  attestation_gap_receipt?: Record<string, unknown>;
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
  status: string;
  error?: string;
}

/** How the two runs of a determinism check compared. */
export interface DeterminismDiff {
  differs: boolean;
  manifest_hash_differs: boolean;
  bundle_hash_differs: boolean;
  differing_fields?: string[];
}

/** Body returned by POST /execute/verify-determinism. `deterministic`
 *  means both runs ended ok with equal manifest hashes. */
export interface VerifyDeterminismResponse {
  ok: boolean;
  deterministic: boolean;
  first: DeterminismRun;
  second: DeterminismRun;
  diff: DeterminismDiff;
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
}

/** One run in an evidence export: what the server stored, not a verdict. */
export interface ExportRow {
  run_id: number;
  created_at: string;
  status: RunStatus;
  error_stage: string;
  route_id: string;
  manifest_hash: string;
  log_entry_id: string;
  leaf_hash: string;
  complete_record_entry_id: string;
  complete_record_leaf_hash: string;
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
