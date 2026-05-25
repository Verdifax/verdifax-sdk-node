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
  /** When non-empty, opts the request into the AIVP-T4 governance pipeline. */
  ai_output_text?: string;
  /** Caller-attested actor + decision metadata; open schema. */
  attested_context?: Record<string, unknown>;
}

export interface ExecuteResponse {
  ok: boolean;
  run_id: number;
  manifest: ExecutionManifest;
  duration_ms: number;
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

export interface Run {
  ok: boolean;
  id: number;
  created_at: string;
  payload_hash: Hex64;
  program_id: Hex64;
  route_id: string;
  manifest_hash: Hex64;
  duration_ms: number;
  status: "ok" | "pepg_deny" | "ccv_halt" | "macc_halt" | "stage_error";
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
  /** Per-request timeout in ms. Defaults to 30000. */
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
  status: "ok" | "pepg_deny" | "ccv_halt" | "macc_halt" | "stage_error";
  outcome_kind?: string;
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
