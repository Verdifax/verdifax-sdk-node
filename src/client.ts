import {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  VerdifaxError,
} from "./errors.js";
import {
  loadSigningKey,
  policyActivationApproval,
  requestKeyChangeApproval,
  requestKeyRegistrationBody,
  signRequestV2,
} from "./signing.js";
import {
  EXECUTE_FIELDS,
  formatProviderPayload,
  refuseCallerOriginHashes,
  refuseUnknownFields,
  refuseUnknownRequestFields,
  withExecuteFlags,
} from "./helpers.js";
import { VerdifaxJob } from "./job.js";
import type {
  AdminAPIKey,
  AdminCreateKeyResponse,
  AdminEraseRequest,
  AttestationList,
  AttestRequest,
  ClientConfig,
  DCAEProofBundle,
  DCAEVerdict,
  DeletionReceipt,
  ExecuteBatchResponse,
  ExecuteRequest,
  ExecuteResponse,
  ExportRunsParams,
  Health,
  Hex64,
  JobLink,
  ListAttestationsParams,
  ListRunsParams,
  PDFFormat,
  Policy,
  PolicyActivation,
  PolicyActivationSignature,
  PolicyContext,
  PolicyList,
  PolicyTestRequest,
  PolicyTestResult,
  PolicyWithDocument,
  RequestKeyRegistration,
  Run,
  RunsExport,
  RunsExportCSV,
  RunStats,
  RunSummary,
  SearchRunsParams,
  SignedRequestBody,
  VerdifaxVersion,
  VerifyDeterminismResponse,
  VerifyResponse,
} from "./types.js";
import { validateHex64, validateRouteId } from "./validation.js";
import { SDK_VERSION } from "./version.js";
import type { KeyObject } from "node:crypto";

const DEFAULT_BASE_URL = "https://api.verdifax.com";
// A successful run makes two public-log entries and, when AI output is sent, an
// AI review; on a slow day that takes longer than 30 seconds, and a client
// that gave up then reported an error for a run the server went on to seal.
// 90 seconds keeps the SDK from being the limit.
const DEFAULT_TIMEOUT_MS = 90_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 200;
const SDK_USER_AGENT = `verdifax-sdk-node/${SDK_VERSION}`;
const HEADER_API_KEY = "X-Verdifax-Key";
const REQUEST_KEY_PATH = "/keys/request-key";
const POLICIES_PATH = "/policies";

const HEADER_EXPORT_TOTAL = "X-Verdifax-Total";
const HEADER_EXPORT_TRUNCATED = "X-Verdifax-Truncated";

const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);

/** The most rows POST /execute/batch accepts in one request. */
export const MAX_BATCH_ROWS = 1000;

// attest copies named fields only, so a key outside these would vanish.
// A Record, so the compiler fails here if AttestRequest gains a field.
const ATTEST_FIELDS: Record<keyof AttestRequest, true> = {
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
  job: true,
  policy_context: true,
  expected_policy_hash: true,
};

// The provider helpers copy named arguments only, so a key outside their own
// names and EXECUTE_FIELDS is refused. The execute fields stay accepted, so a
// run request spread into the arguments keeps working as it always has.
const PROVIDER_ARGS: Record<string, true> = Object.fromEntries(
  [
    "program_id",
    "route_id",
    "registry_record_hash",
    "prompt",
    "response",
    "govern",
    "job",
    "policy_context",
    "expected_policy_hash",
    ...EXECUTE_FIELDS,
  ].map((name) => [name, true]),
);

/** A response body kept as sent, with its headers. */
interface RawResponse {
  text: string;
  headers: Headers;
}

/**
 * The Verdifax SDK client.
 *
 * Carries Python-parity surface coverage:
 *
 * | Method | HTTP | Auth |
 * | --- | --- | --- |
 * | `health()` | GET /health | none |
 * | `version()` | GET /version | none |
 * | `getOpenAPI()` | GET /openapi.json | none |
 * | `getStats()` | GET /stats | required |
 * | `execute(req)` | POST /execute | required |
 * | `attest(req)` | POST /execute (helper) | required |
 * | `getRun(id)` | GET /runs/{id} | required |
 * | `verifyRun(id)` | GET /runs/{id}/verify | required |
 * | `listRuns(params)` | GET /runs | required |
 * | `searchRuns(params)` | GET /runs/search | required |
 * | `exportRuns(params)` | GET /runs/export | required |
 * | `exportRunsCSV(params)` | GET /runs/export?format=csv | required |
 * | `listAttestations(params)` | GET /attestations | required |
 * | `getAttestation(id)` | GET /attestations/{id} | required |
 * | `getRunArtifacts(id)` | GET /runs/{id}/artifacts | required |
 * | `getRunReport(id)` | GET /runs/{id}/report | required |
 * | `getPublicBundle(id)` | GET /runs/{id}/bundle.json | none |
 * | `getPublicBundleByToken(token)` | GET /public/runs/{token}/bundle.json | none |
 * | `executeBatch(runs)` | POST /execute/batch | required |
 * | `verifyDeterminism(req)` | POST /execute/verify-determinism | required |
 * | `downloadAuditPDF(id, format)` | GET /runs/{id}/report.pdf | required |
 * | `getAllowToken(id)` | GET /runs/{id}/allow-token | required |
 * | `getDenyReceipt(id)` | GET /runs/{id}/deny-receipt | required |
 * | `getCCVHaltReceipt(id)` | GET /runs/{id}/ccv-halt-receipt | required |
 * | `getMACCHaltReceipt(id)` | GET /runs/{id}/macc-halt-receipt | required |
 * | `getAivpT4HaltReceipt(id)` | GET /runs/{id}/aivp-t4-halt-receipt | required |
 * | `getAttestationGapReceipt(id)` | GET /runs/{id}/attestation-gap-receipt | required |
 * | `getCESAuditRecord(id)` | GET /runs/{id}/ces-audit-record | required |
 * | `listDeletionReceipts(id)` | GET /runs/{id}/deletion-receipts | required |
 * | `adminErase(req)` | POST /admin/erase | required |
 * | `dcaeVerify(bundle)` | POST /dcae/verify | none |
 * | `adminCreateKey(name)` | POST /admin/keys | required |
 * | `adminListKeys()` | GET /admin/keys | required |
 * | `adminRevokeKey(id)` | DELETE /admin/keys/{id} | required |
 * | `adminClearRequestKey(id)` | DELETE /admin/keys/{id}/request-key | required |
 * | `attestClaudeResponse(...)` | POST /execute (helper) | required |
 * | `attestOpenAIResponse(...)` | POST /execute (helper) | required |
 * | `registerRequestKey()` | POST /keys/request-key | required |
 * | `rotateRequestKey(newSigningKey)` | POST /keys/request-key | required |
 * | `clearRequestKey()` | DELETE /keys/request-key | required |
 * | `uploadPolicy(document)` | POST /policies | required |
 * | `listPolicies()` | GET /policies | required |
 * | `getPolicy(documentHash)` | GET /policies/{document_hash} | required |
 * | `testPolicy(req)` | POST /policies/test | required |
 * | `getPolicyHistory()` | GET /policies/history | required |
 * | `activatePolicy(documentHash)` | POST /policies/{document_hash}/activate | required |
 * | `job(jobId)` | none, returns a {@link VerdifaxJob} | none |
 *
 * With the `signingKey` option set, every path to POST /execute carries
 * a fresh request signature, each row of a batch carries its own, and a
 * determinism check carries one. Each sends `signed_request` and
 * `request_signature` and nothing else, and the result carries the signed
 * text as `signed_request`. Without it, requests are unsigned.
 *
 * Idempotent GETs that hit a transient failure (502/503/504/429)
 * are retried with exponential backoff + full jitter. Non-
 * idempotent methods (POST, PUT, DELETE) are NOT retried, replay
 * is the caller's responsibility.
 */
export class VerdifaxClient {
  private readonly baseURL: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly userAgent: string;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private signingKey: KeyObject | undefined;

  constructor(config: ClientConfig = {}) {
    this.baseURL = (config.baseURL ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.apiKey = config.apiKey ?? "";
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.userAgent = config.userAgent ?? SDK_USER_AGENT;
    this.maxRetries =
      config.maxRetries === undefined
        ? DEFAULT_MAX_RETRIES
        : Math.max(0, config.maxRetries);
    this.retryBaseDelayMs =
      config.retryBaseDelayMs ?? DEFAULT_RETRY_BASE_DELAY_MS;
    this.signingKey =
      config.signingKey === undefined
        ? undefined
        : loadSigningKey(config.signingKey);
  }

  // ── Health + Version (anonymous) ──────────────────────────────

  async health(): Promise<Health> {
    return this.request<Health>("GET", "/health");
  }

  async version(): Promise<VerdifaxVersion> {
    return this.request<VerdifaxVersion>("GET", "/version");
  }

  /** The server's own API description. */
  async getOpenAPI(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", "/openapi.json");
  }

  /** Run counts for this API key. */
  async getStats(): Promise<RunStats> {
    this.requireAPIKey();
    return this.request<RunStats>("GET", "/stats");
  }

  // ── Execute / Attest (auth) ───────────────────────────────────

  async execute(req: ExecuteRequest): Promise<ExecuteResponse> {
    refuseUnknownRequestFields(req);
    this.requireExecuteFields(req);
    const sent = this.prepared(req);
    const out = await this.request<ExecuteResponse>("POST", "/execute", sent);
    return withSignedText(out, sent);
  }

  /** Runs one payload twice on the server and compares the manifest
   *  hashes. One signature covers the request, and the server claims
   *  its nonce once. Both runs are recorded. A run that happens twice
   *  cannot be one job step, so a `job` is refused here. */
  async verifyDeterminism(
    req: ExecuteRequest,
  ): Promise<VerifyDeterminismResponse> {
    refuseUnknownRequestFields(req);
    this.requireExecuteFields(req);
    if (req.job !== undefined && req.job !== null) {
      throw new VerdifaxError(
        "verdifax: a determinism check runs twice, so it cannot be a job step",
      );
    }
    const sent = this.prepared(req);
    const out = await this.request<VerifyDeterminismResponse>(
      "POST",
      "/execute/verify-determinism",
      sent,
    );
    return withSignedText(out, sent);
  }

  /** Sends up to {@link MAX_BATCH_ROWS} runs in one request. With a
   *  signing key each row carries its own signature and nonce. A row
   *  that fails comes back in `results` with `ok: false`, so the call
   *  does not throw for it. The rows are not checked here, except a job
   *  block, a `policy_context` and an `expected_policy_hash`, which are
   *  refused before anything is sent: the server reports any other bad row
   *  in that row's result.
   *
   *  This is one POST and it is never retried. After a timeout the
   *  server may have run some or all of the rows. */
  async executeBatch(runs: ExecuteRequest[]): Promise<ExecuteBatchResponse> {
    this.requireAPIKey();
    if (!Array.isArray(runs) || runs.length === 0) {
      throw new VerdifaxError("verdifax: executeBatch needs at least one run");
    }
    if (runs.length > MAX_BATCH_ROWS) {
      throw new VerdifaxError(
        `verdifax: executeBatch accepts at most ${MAX_BATCH_ROWS} runs (got ${runs.length})`,
      );
    }
    runs.forEach((run, i) => refuseUnknownRequestFields(run, `runs[${i}]`));
    const sent = runs.map((run) => this.prepared(run));
    const out = await this.request<ExecuteBatchResponse>(
      "POST",
      "/execute/batch",
      { runs: sent },
    );
    if (!Array.isArray(out?.results)) return out;
    return {
      ...out,
      results: out.results.map((row, i) =>
        i < sent.length ? withSignedText(row, sent[i]!) : row,
      ),
    };
  }

  /** High-level convenience wrapper around `execute()`. Accepts
   *  either a Buffer (for binary payloads, auto-base64) or a
   *  string (for plain text). Validates the hex fields and
   *  routes the call through to the canonical /execute. */
  async attest(req: AttestRequest): Promise<ExecuteResponse> {
    this.requireAPIKey();
    refuseUnknownRequestFields(req, "attest request");
    refuseUnknownFields(req, ATTEST_FIELDS, "attest request");
    if (req.payload !== undefined && req.payload_text !== undefined) {
      throw new VerdifaxError(
        "verdifax: attest accepts payload OR payload_text, not both",
      );
    }
    if (req.payload === undefined && req.payload_text === undefined) {
      throw new VerdifaxError(
        "verdifax: attest needs payload or payload_text",
      );
    }
    validateHex64(req.program_id, "program_id");
    validateHex64(req.registry_record_hash, "registry_record_hash");
    validateRouteId(req.route_id);

    const body: ExecuteRequest = {
      program_id: req.program_id,
      route_id: req.route_id,
      registry_record_hash: req.registry_record_hash,
      ai_output_text: req.ai_output_text,
      attested_context: req.attested_context,
      reproducibility_context: req.reproducibility_context,
      request_substance: req.request_substance,
      authorization_chain: req.authorization_chain,
      regulatory_scaffolding: req.regulatory_scaffolding,
      causal_graph: req.causal_graph,
      job: req.job,
      policy_context: req.policy_context,
      expected_policy_hash: req.expected_policy_hash,
    };
    if (req.payload !== undefined) {
      body.payload = Buffer.isBuffer(req.payload)
        ? req.payload.toString("base64")
        : Buffer.from(req.payload).toString("base64");
    } else {
      body.payload_text = req.payload_text!;
    }
    return this.execute(body);
  }

  /** A helper that runs the steps of one job through {@link attest} and
   *  keeps each step's record hash, so a later step can name it. It makes
   *  no request until a step runs. */
  job(jobId: string): VerdifaxJob {
    return new VerdifaxJob(this, jobId);
  }

  // ── Request signing (auth) ───────────────────────────────────

  /** Registers this client's public key on its API key, with the proof
   *  that the client holds the private key. From then on the server
   *  refuses a run on this API key without a request signature. */
  async registerRequestKey(): Promise<RequestKeyRegistration> {
    this.requireAPIKey();
    if (!this.signingKey) {
      throw new VerdifaxError(
        "verdifax: registerRequestKey needs the signingKey client option",
      );
    }
    return this.request<RequestKeyRegistration>(
      "POST",
      REQUEST_KEY_PATH,
      requestKeyRegistrationBody(this.signingKey),
    );
  }

  /** Replaces the registered key with `newSigningKey`. The new key proves
   *  itself and this client's current key approves the change. After
   *  success this client signs with the new key. If the call fails it
   *  keeps the current key, including after a timeout, when the server may
   *  have made the change. */
  async rotateRequestKey(
    newSigningKey: Uint8Array | KeyObject,
  ): Promise<RequestKeyRegistration> {
    this.requireAPIKey();
    if (!this.signingKey) {
      throw new VerdifaxError(
        "verdifax: rotateRequestKey needs the current key in the signingKey client option",
      );
    }
    const next = loadSigningKey(newSigningKey);
    const registration = requestKeyRegistrationBody(next);
    const out = await this.request<RequestKeyRegistration>(
      "POST",
      REQUEST_KEY_PATH,
      {
        ...registration,
        change: requestKeyChangeApproval(
          this.signingKey,
          registration.public_key,
        ),
      },
    );
    this.signingKey = next;
    return out;
  }

  /** Clears the registered public key, so the server stops requiring
   *  request signatures on this API key. With a signing key the client
   *  sends that key's approval, which the server requires while a key is
   *  registered. After success the client drops its signing key and sends
   *  unsigned requests, because the server refuses a signed run on an API
   *  key with no registered key. If the call fails it keeps the key. */
  async clearRequestKey(): Promise<void> {
    this.requireAPIKey();
    await this.request<void>(
      "DELETE",
      REQUEST_KEY_PATH,
      this.signingKey
        ? { change: requestKeyChangeApproval(this.signingKey, "") }
        : undefined,
    );
    this.signingKey = undefined;
  }

  // ── Policies (auth) ──────────────────────────────────────────

  /** Stores a policy document. Nothing changes until it is activated with
   *  {@link activatePolicy}. The server hashes the exact text, so this
   *  sends the string it is given unchanged and refuses anything that is
   *  not a string: serializing an object here would change the hash.
   *  Verdifax does not write, review or approve a customer's policy. */
  async uploadPolicy(document: string): Promise<Policy> {
    this.requireAPIKey();
    if (typeof document !== "string") {
      throw new VerdifaxError(
        "verdifax: document must be the policy's exact text, as a string",
      );
    }
    return this.request<Policy>("POST", POLICIES_PATH, { document });
  }

  /** This key's stored documents, with the chain its changes belong to,
   *  the newest change in it (64 zeros when there is none yet) and the
   *  document in force (empty under the built-in policy). */
  async listPolicies(): Promise<PolicyList> {
    this.requireAPIKey();
    return this.request<PolicyList>("GET", POLICIES_PATH);
  }

  /** One stored document, with its exact text as `document`. */
  async getPolicy(documentHash: Hex64): Promise<PolicyWithDocument> {
    this.requireAPIKey();
    validateHex64(documentHash, "documentHash");
    return this.request<PolicyWithDocument>(
      "GET",
      `${POLICIES_PATH}/${documentHash}`,
    );
  }

  /** Shows which rule would fire on sample inputs, for a document given as
   *  text or one already stored, named by its hash: exactly one of the two.
   *  It seals nothing. */
  async testPolicy(req: PolicyTestRequest): Promise<PolicyTestResult> {
    this.requireAPIKey();
    const { inputs, document, documentHash } = req ?? ({} as PolicyTestRequest);
    if ((document === undefined) === (documentHash === undefined)) {
      throw new VerdifaxError(
        "verdifax: testPolicy needs exactly one of document or documentHash",
      );
    }
    if (typeof inputs !== "object" || inputs === null || Array.isArray(inputs)) {
      throw new VerdifaxError("verdifax: testPolicy needs inputs as an object");
    }
    const body: Record<string, unknown> = { inputs };
    if (document !== undefined) {
      if (typeof document !== "string") {
        throw new VerdifaxError(
          "verdifax: document must be the policy's exact text, as a string",
        );
      }
      body.document = document;
    } else {
      validateHex64(documentHash!, "documentHash");
      body.document_hash = documentHash;
    }
    return this.request<PolicyTestResult>(
      "POST",
      `${POLICIES_PATH}/test`,
      body,
    );
  }

  /** This key's policy changes, oldest first, as the list the server sends.
   *  Save it as JSON, for example with
   *  `writeFileSync("policy-history.json", JSON.stringify(history))`, and
   *  check it with `verdifax-verify --policy-history policy-history.json`. */
  async getPolicyHistory(): Promise<PolicyActivation[]> {
    this.requireAPIKey();
    return this.request<PolicyActivation[]>("GET", `${POLICIES_PATH}/history`);
  }

  /** Makes a stored document the policy in force and returns the change
   *  record. It first reads GET /policies for the chain and its newest
   *  change, then names that change as the one this follows. With the
   *  `signingKey` option the request key signs the change, which the server
   *  requires while a request key is registered.
   *
   *  Rolling back is activating an earlier document: it is one more change
   *  in the chain, so the change it undoes stays on the record.
   *
   *  An HTTP 409 means the chain moved because another change came first,
   *  or the document is not yet effective. It throws the usual
   *  {@link APIError} and is not retried: read the policies again and
   *  decide. */
  async activatePolicy(documentHash: Hex64): Promise<PolicyActivation> {
    this.requireAPIKey();
    validateHex64(documentHash, "documentHash");
    const chain = await this.listPolicies();
    const previous = chain?.newest_activation_hash;
    if (typeof previous !== "string") {
      throw new VerdifaxError(
        "verdifax: the server did not report newest_activation_hash, so the change cannot name the one it follows",
      );
    }
    const body: {
      previous_activation_hash: string;
      signature?: PolicyActivationSignature;
    } = { previous_activation_hash: previous };
    if (this.signingKey) {
      if (typeof chain.chain_id !== "string" || chain.chain_id === "") {
        throw new VerdifaxError(
          "verdifax: the server did not report chain_id, so the change cannot be signed",
        );
      }
      body.signature = policyActivationApproval(this.signingKey, {
        chain_id: chain.chain_id,
        document_hash: documentHash,
        previous_activation_hash: previous,
      });
    }
    const out = await this.request<{ ok: boolean; activation: PolicyActivation }>(
      "POST",
      `${POLICIES_PATH}/${documentHash}/activate`,
      body,
    );
    return out.activation;
  }

  // ── Runs ──────────────────────────────────────────────────────

  async getRun(runId: number): Promise<Run> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return this.request<Run>("GET", `/runs/${runId}`);
  }

  async verifyRun(runId: number): Promise<VerifyResponse> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return this.request<VerifyResponse>("GET", `/runs/${runId}/verify`);
  }

  async listRuns(params: ListRunsParams = {}): Promise<{
    runs: RunSummary[];
    total: number;
  }> {
    this.requireAPIKey();
    const q = new URLSearchParams();
    if (params.limit && params.limit > 0) {
      q.set("limit", String(params.limit));
    }
    if (params.offset && params.offset > 0) {
      q.set("offset", String(params.offset));
    }
    const qs = q.toString();
    const path = qs ? `/runs?${qs}` : "/runs";
    const out = await this.request<{
      ok: boolean;
      runs: RunSummary[];
      total: number;
    }>("GET", path);
    return { runs: out.runs ?? [], total: out.total ?? 0 };
  }

  /** Searches this key's runs. `manifest_hash` matches a prefix. The
   *  server ignores a `from` or `to` it cannot parse here, unlike
   *  {@link exportRuns}, which refuses one. */
  async searchRuns(params: SearchRunsParams = {}): Promise<{
    runs: RunSummary[];
    total: number;
  }> {
    this.requireAPIKey();
    const q = new URLSearchParams();
    for (const name of [
      "manifest_hash",
      "program_id",
      "route_id",
      "status",
      "from",
      "to",
    ] as const) {
      const value = params[name];
      if (value) q.set(name, value);
    }
    if (params.limit && params.limit > 0) {
      q.set("limit", String(params.limit));
    }
    if (params.offset && params.offset > 0) {
      q.set("offset", String(params.offset));
    }
    const qs = q.toString();
    const path = qs ? `/runs/search?${qs}` : "/runs/search";
    const out = await this.request<{
      ok: boolean;
      runs: RunSummary[];
      total: number;
    }>("GET", path);
    return { runs: out.runs ?? [], total: out.total ?? 0 };
  }

  /** Lists what the server holds for this key in a period, failures
   *  included, up to 10,000 rows. `truncated` is true when the period
   *  holds more. The list states what was stored, not a verdict, and a
   *  call that never reached Verdifax cannot appear in it. */
  async exportRuns(params: ExportRunsParams = {}): Promise<RunsExport> {
    this.requireAPIKey();
    return this.request<RunsExport>("GET", this.exportPath(params, "json"));
  }

  /** The same rows as {@link exportRuns}: the raw CSV text with `total`
   *  and `truncated` from the response headers. Check `truncated`: when
   *  true, the CSV is missing rows for the period. Throws when the server
   *  does not send those headers, so that a cut-off export cannot pass
   *  for a complete one. */
  async exportRunsCSV(params: ExportRunsParams = {}): Promise<RunsExportCSV> {
    this.requireAPIKey();
    const { text, headers } = await this.requestRaw(
      this.exportPath(params, "csv"),
    );
    const total = Number.parseInt(headers.get(HEADER_EXPORT_TOTAL) ?? "", 10);
    const truncated = headers.get(HEADER_EXPORT_TRUNCATED);
    if (
      !Number.isSafeInteger(total) ||
      (truncated !== "true" && truncated !== "false")
    ) {
      throw new VerdifaxError(
        `verdifax: the server did not report ${HEADER_EXPORT_TOTAL} and ${HEADER_EXPORT_TRUNCATED}, so this CSV may be cut off; use exportRuns instead`,
      );
    }
    return { csv: text, total, truncated: truncated === "true" };
  }

  private exportPath(params: ExportRunsParams, format: string): string {
    const q = new URLSearchParams();
    if (params.from) q.set("from", params.from);
    if (params.to) q.set("to", params.to);
    if (params.job_id) q.set("job_id", params.job_id);
    q.set("format", format);
    return `/runs/export?${q.toString()}`;
  }

  // ── Attestation receipts (auth) ──────────────────────────────

  async listAttestations(
    params: ListAttestationsParams = {},
  ): Promise<AttestationList> {
    this.requireAPIKey();
    const q = new URLSearchParams();
    if (params.limit && params.limit > 0) {
      q.set("limit", String(params.limit));
    }
    if (params.offset && params.offset > 0) {
      q.set("offset", String(params.offset));
    }
    const qs = q.toString();
    return this.request<AttestationList>(
      "GET",
      qs ? `/attestations?${qs}` : "/attestations",
    );
  }

  async getAttestation(attestationId: number): Promise<Record<string, unknown>> {
    this.requireAPIKey();
    if (attestationId <= 0) {
      throw new VerdifaxError("verdifax: attestationId must be > 0");
    }
    return this.request<Record<string, unknown>>(
      "GET",
      `/attestations/${attestationId}`,
    );
  }

  // ── Sealed-artifact retrieval (auth) ─────────────────────────

  async getAllowToken(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "allow-token");
  }

  async getDenyReceipt(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "deny-receipt");
  }

  async getCCVHaltReceipt(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "ccv-halt-receipt");
  }

  async getMACCHaltReceipt(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "macc-halt-receipt");
  }

  async getAivpT4HaltReceipt(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "aivp-t4-halt-receipt");
  }

  async getAttestationGapReceipt(
    runId: number,
  ): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "attestation-gap-receipt");
  }

  async getCESAuditRecord(runId: number): Promise<Record<string, unknown>> {
    return this.getRunArtifact(runId, "ces-audit-record");
  }

  /** The audit report for a run, as JSON. */
  async getRunReport(runId: number): Promise<Record<string, unknown>> {
    const out = await this.getRunArtifact(runId, "report");
    return out.report as Record<string, unknown>;
  }

  /** The run's sealed audit bundle as the exact JSON text the server
   *  sent, to save and check with `verdifax-verify`. It is not parsed:
   *  JSON.parse would round a number above 2^53 and the recomputed hash
   *  would stop matching. */
  async getRunArtifacts(runId: number): Promise<string> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return (await this.requestRaw(`/runs/${runId}/artifacts`)).text;
  }

  /** The public audit bundle of a record published by run id, as the
   *  exact JSON text the server sent. Needs no API key. */
  async getPublicBundle(runId: number): Promise<string> {
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return (await this.requestRaw(`/runs/${runId}/bundle.json`)).text;
  }

  /** The public audit bundle a share token points to, as the exact JSON
   *  text the server sent. Needs no API key. */
  async getPublicBundleByToken(token: string): Promise<string> {
    if (!token) throw new VerdifaxError("verdifax: token is required");
    const path = `/public/runs/${encodeURIComponent(token)}/bundle.json`;
    return (await this.requestRaw(path)).text;
  }

  private async getRunArtifact(
    runId: number,
    suffix: string,
  ): Promise<Record<string, unknown>> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return this.request<Record<string, unknown>>(
      "GET",
      `/runs/${runId}/${suffix}`,
    );
  }

  // ── Audit PDF (auth) ─────────────────────────────────────────

  /** Streams the audit PDF bytes as a Buffer. Format defaults to
   *  "comprehensive" when not specified. */
  async downloadAuditPDF(
    runId: number,
    format: PDFFormat = "comprehensive",
  ): Promise<Buffer> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    const path = `/runs/${runId}/report.pdf?format=${encodeURIComponent(format)}`;

    const headers: Record<string, string> = {
      "User-Agent": this.userAgent,
      [HEADER_API_KEY]: this.apiKey,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await fetch(this.baseURL + path, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      throw new APIError(resp.status, path, "audit PDF download failed");
    }
    const buf = await resp.arrayBuffer();
    return Buffer.from(buf);
  }

  // ── CRES, deletion receipts (auth) ──────────────────────────

  async listDeletionReceipts(runId: number): Promise<DeletionReceipt[]> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    const out = await this.request<{
      ok: boolean;
      run_id: number;
      count: number;
      receipts: DeletionReceipt[];
    }>("GET", `/runs/${runId}/deletion-receipts`);
    return out.receipts ?? [];
  }

  async adminErase(req: AdminEraseRequest): Promise<DeletionReceipt> {
    this.requireAPIKey();
    if (!req.run_id || req.run_id <= 0) {
      throw new VerdifaxError("verdifax: run_id must be > 0");
    }
    if (!req.field_path) {
      throw new VerdifaxError("verdifax: field_path is required");
    }
    validateHex64(req.ciphertext_hash, "ciphertext_hash");
    const out = await this.request<{
      ok: boolean;
      deletion_receipt: DeletionReceipt;
    }>("POST", "/admin/erase", req);
    return out.deletion_receipt;
  }

  // ── DCAE stateless verification (anonymous) ──────────────────

  async dcaeVerify(bundle: DCAEProofBundle): Promise<DCAEVerdict> {
    return this.request<DCAEVerdict>("POST", "/dcae/verify", bundle);
  }

  // ── Admin: API keys (auth) ───────────────────────────────────

  async adminCreateKey(name: string): Promise<AdminCreateKeyResponse> {
    this.requireAPIKey();
    if (!name) {
      throw new VerdifaxError("verdifax: name is required for adminCreateKey");
    }
    return this.request<AdminCreateKeyResponse>("POST", "/admin/keys", {
      name,
    });
  }

  async adminListKeys(): Promise<AdminAPIKey[]> {
    this.requireAPIKey();
    const out = await this.request<{ ok: boolean; keys: AdminAPIKey[] }>(
      "GET",
      "/admin/keys",
    );
    return out.keys ?? [];
  }

  async adminRevokeKey(keyId: number): Promise<void> {
    this.requireAPIKey();
    if (keyId <= 0) {
      throw new VerdifaxError("verdifax: keyId must be > 0");
    }
    await this.request<void>("DELETE", `/admin/keys/${keyId}`);
  }

  /** Clears the request key on an API key whose holder lost it, after a
   *  manual check. It is the one way to clear a key without that key. The
   *  id can be any API key, so this client keeps its own signing key. */
  async adminClearRequestKey(keyId: number): Promise<void> {
    this.requireAPIKey();
    if (keyId <= 0) {
      throw new VerdifaxError("verdifax: keyId must be > 0");
    }
    await this.request<void>("DELETE", `/admin/keys/${keyId}/request-key`);
  }

  // ── Provider helpers (Claude / OpenAI) ───────────────────────

  /** Convenience for attesting an Anthropic Claude API response. With
   *  `govern: true` the response text also goes to the AIVP review as
   *  `ai_output_text`; that is off by default, so the text leaves your
   *  machine for review only when you ask. */
  async attestClaudeResponse(args: {
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
    govern?: boolean;
    job?: JobLink;
    policy_context?: PolicyContext;
    expected_policy_hash?: Hex64;
  }): Promise<ExecuteResponse> {
    refuseUnknownFields(args, PROVIDER_ARGS, "attestClaudeResponse arguments");
    return this.attestProviderResponse({ ...args, provider: "anthropic" });
  }

  /** Convenience for attesting an OpenAI API response. `govern` works as
   *  in {@link attestClaudeResponse}. */
  async attestOpenAIResponse(args: {
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
    govern?: boolean;
    job?: JobLink;
    policy_context?: PolicyContext;
    expected_policy_hash?: Hex64;
  }): Promise<ExecuteResponse> {
    refuseUnknownFields(args, PROVIDER_ARGS, "attestOpenAIResponse arguments");
    return this.attestProviderResponse({ ...args, provider: "openai" });
  }

  private async attestProviderResponse(args: {
    provider: string;
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
    govern?: boolean;
    job?: JobLink;
    policy_context?: PolicyContext;
    expected_policy_hash?: Hex64;
  }): Promise<ExecuteResponse> {
    if (!args.response) {
      throw new VerdifaxError(
        "verdifax: response is required for attestation",
      );
    }
    return this.attest({
      payload_text: formatProviderPayload(
        args.provider,
        args.prompt,
        args.response,
      ),
      program_id: args.program_id,
      route_id: args.route_id,
      registry_record_hash: args.registry_record_hash,
      ai_output_text: args.govern ? args.response : undefined,
      attested_context: {
        actor_role: "ai_assistant",
        model_provider: args.provider,
      },
      job: args.job,
      policy_context: args.policy_context,
      expected_policy_hash: args.expected_policy_hash,
    });
  }

  // ── HTTP plumbing, retry-aware ──────────────────────────────

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    rawText = false,
  ): Promise<T> {
    const url = this.baseURL + path;
    const headers: Record<string, string> = {
      "User-Agent": this.userAgent,
    };
    if (this.apiKey) headers[HEADER_API_KEY] = this.apiKey;
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const isRetryable =
      method === "GET" || method === "HEAD" || method === "OPTIONS";
    const maxAttempts = isRetryable ? this.maxRetries + 1 : 1;

    let lastErr: unknown;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (attempt > 0) {
        // Exponential backoff with full jitter:
        //   sleep = rand(0, baseDelay * 2^(attempt-1))
        const max = this.retryBaseDelayMs * Math.pow(2, attempt - 1);
        const sleep = Math.floor(Math.random() * (max + 1));
        await new Promise((r) => setTimeout(r, sleep));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let resp: Response;
      try {
        resp = await fetch(url, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        lastErr = err;
        if (!isRetryable || attempt === maxAttempts - 1) {
          throw new VerdifaxError(
            `verdifax: HTTP transport: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
        continue;
      } finally {
        clearTimeout(timer);
      }

      const text = await resp.text();
      if (!resp.ok) {
        if (isRetryable && RETRYABLE_STATUSES.has(resp.status) && attempt < maxAttempts - 1) {
          continue;
        }
        let errMessage = text.trim();
        let recordHash: string | undefined;
        try {
          const env = JSON.parse(text) as {
            error?: string;
            record_hash?: unknown;
          };
          if (env.error) errMessage = env.error;
          if (typeof env.record_hash === "string" && env.record_hash) {
            recordHash = env.record_hash;
          }
        } catch {
          /* fall through to raw text */
        }
        switch (resp.status) {
          case 401:
            throw new AuthError(resp.status, errMessage);
          case 404:
            throw new NotFoundError(path, errMessage);
          default:
            throw new APIError(
              resp.status,
              path,
              errMessage,
              recordHash,
              (body as Partial<SignedRequestBody> | undefined)?.signed_request,
            );
        }
      }

      if (rawText) return { text, headers: resp.headers } as T;
      if (text.length === 0) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch (err) {
        throw new VerdifaxError(
          `verdifax: failed to decode response body at ${path}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }

    // Defense, should never reach here.
    throw new VerdifaxError(
      `verdifax: retry budget exhausted${
        lastErr ? `: ${String(lastErr)}` : ""
      }`,
    );
  }

  /** A GET whose body is kept as sent, retried like any other GET. */
  private requestRaw(path: string): Promise<RawResponse> {
    return this.request<RawResponse>("GET", path, undefined, true);
  }

  private requireAPIKey(): void {
    if (!this.apiKey) throw new APIKeyRequiredError();
  }

  private requireExecuteFields(req: ExecuteRequest): void {
    this.requireAPIKey();
    if (!req.payload && !req.payload_text) {
      throw new VerdifaxError(
        "verdifax: ExecuteRequest needs payload or payload_text",
      );
    }
    if (!req.program_id || !req.route_id || !req.registry_record_hash) {
      throw new VerdifaxError(
        "verdifax: program_id, route_id, and registry_record_hash are required",
      );
    }
    validateHex64(req.program_id, "program_id");
    validateHex64(req.registry_record_hash, "registry_record_hash");
    validateRouteId(req.route_id);
    refuseCallerOriginHashes(req.request_substance);
  }

  /** The body to send, on a copy: the request with its derived flags or,
   *  with a signing key, the signed text with a fresh signature and nonce. */
  private prepared(req: ExecuteRequest): ExecuteRequest | SignedRequestBody {
    return this.signingKey
      ? signRequestV2(this.signingKey, req)
      : withExecuteFlags(req);
  }
}

/** The result with the text that was signed, when the call was signed. */
function withSignedText<T>(
  result: T,
  sent: ExecuteRequest | SignedRequestBody,
): T {
  return "signed_request" in sent
    ? { ...result, signed_request: sent.signed_request }
    : result;
}
