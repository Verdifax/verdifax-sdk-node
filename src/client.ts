import {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  VerdifaxError,
} from "./errors.js";
import {
  approverKeyProof,
  approverKeyProofVerifies,
  loadSigningKey,
  policyActivationApproval,
  publicKeyOf,
  requestKeyChangeApproval,
  requestKeyRegistrationBody,
  sha256Hex,
  signOffSignature,
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
import {
  deliveriesPath,
  FEED_KEYS_PATH,
  feedKeyBody,
  followSignalFeed,
  followStart,
  signalsRead,
  webhookBody,
  WEBHOOKS_PATH,
} from "./signals.js";
import type {
  Account,
  AccountInfo,
  AccountKeyList,
  AccountKeyRevocation,
  AccountRunsExport,
  AdminAPIKey,
  AdminCreateAccountOptions,
  AdminCreateAccountResponse,
  AdminCreateKeyOptions,
  AdminCreateKeyResponse,
  AdminEraseRequest,
  ApproverKeyProof,
  ApproverList,
  ApproverRegistration,
  ApproverRevocation,
  AsOwnerOptions,
  AttestationList,
  AttestRequest,
  ClientConfig,
  CreateAccountKeyOptions,
  CreatedAccountKey,
  CreatedFeedKey,
  CreatedWebhook,
  CreateFeedKeyOptions,
  CreateWebhookOptions,
  DCAEProofBundle,
  DCAEVerdict,
  DeletionReceipt,
  ExecuteBatchResponse,
  ExecuteRequest,
  ExecuteResponse,
  ExportRunsParams,
  FeedKeyRevocation,
  FollowSignalsOptions,
  GetSignalsOptions,
  Health,
  Hex64,
  JobLink,
  ListAttestationsParams,
  ListRunsParams,
  ListWebhookDeliveriesOptions,
  NewestSignOff,
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
  SignalEvent,
  SignalPage,
  SignedRequestBody,
  SignOffDecision,
  SignOffOptions,
  SignOffRecord,
  PublicationResult,
  SignOffTarget,
  VerdifaxVersion,
  VerifyDeterminismResponse,
  VerifyResponse,
  WebhookDeletion,
  WebhookDeliveryList,
  WebhookList,
} from "./types.js";
import {
  asOwnerOf,
  requirePositiveId,
  validateHex64,
  validateJobName,
  validateRouteId,
} from "./validation.js";
import { SDK_VERSION } from "./version.js";
import { KeyObject } from "node:crypto";

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
const ACCOUNT_PATH = "/account";
const ACCOUNT_REQUEST_KEY_PATH = "/account/request-key";
const ACCOUNT_POLICIES_PATH = "/account/policies";
// The chain of an account's policy changes. An account change is signed
// over this id, so a chain of any other form is refused before signing.
const ACCOUNT_CHAIN_ID = /^account-[1-9][0-9]*$/;
const SIGNOFFS_PATH = "/signoffs";
const ACCOUNT_SIGNOFFS_PATH = "/account/signoffs";
const APPROVERS_PATH = "/account/approvers";
const SIGNOFF_TARGET_KINDS = new Set(["record", "receipt", "job"]);
const SIGNOFF_DECISIONS = new Set(["approve", "reject"]);
const MAX_APPROVER_NAME_BYTES = 200;

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
 * | `getPublicReceiptByToken(token)` | GET /public/runs/{token}/receipt.json | none |
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
 * | `adminCreateKey(name, options)` | POST /admin/keys | required |
 * | `adminListKeys()` | GET /admin/keys | required |
 * | `adminRevokeKey(id)` | DELETE /admin/keys/{id} | required |
 * | `adminClearRequestKey(id)` | DELETE /admin/keys/{id}/request-key | required |
 * | `adminCreateAccount(name, options)` | POST /admin/accounts | required |
 * | `adminListAccounts()` | GET /admin/accounts | required |
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
 * | `getAccount()` | GET /account | owner key |
 * | `createAccountKey(name, options)` | POST /account/keys | owner key |
 * | `listAccountKeys()` | GET /account/keys | owner key |
 * | `revokeAccountKey(id)` | DELETE /account/keys/{id} | owner key |
 * | `registerAccountRequestKey()` | POST /account/request-key | owner key |
 * | `clearAccountRequestKey()` | DELETE /account/request-key | owner key |
 * | `listAccountRuns(params)` | GET /account/runs | owner key |
 * | `exportAccountRuns(params)` | GET /account/runs/export | owner key |
 * | `exportAccountRunsCSV(params)` | GET /account/runs/export?format=csv | owner key |
 * | `uploadAccountPolicy(document)` | POST /account/policies | owner key |
 * | `listAccountPolicies()` | GET /account/policies | owner key |
 * | `getAccountPolicy(documentHash)` | GET /account/policies/{document_hash} | owner key |
 * | `testAccountPolicy(req)` | POST /account/policies/test | owner key |
 * | `getAccountPolicyHistory()` | GET /account/policies/history | owner key |
 * | `activateAccountPolicy(documentHash)` | POST /account/policies/{document_hash}/activate | owner key |
 * | `registerApprover(name, approver)` | POST /account/approvers | owner key |
 * | `listApprovers()` | GET /account/approvers | owner key |
 * | `revokeApprover(id)` | DELETE /account/approvers/{id} | owner key |
 * | `signOff(target, decision, approverKey, options)` | POST /signoffs, or POST /account/signoffs with asOwner | required |
 * | `getNewestSignOff(options)` | GET /signoffs/newest, or GET /account/signoffs/newest with asOwner | required |
 * | `getSignOffs(runId, options)` | GET /runs/{id}/signoffs, or GET /account/runs/{id}/signoffs with asOwner | required |
 * | `getSignOffHistory()` | GET /account/signoffs/history | owner key |
 * | `getSignals(options)` | GET /signals, or GET /account/signals with asOwner | feed key, or owner key |
 * | `followSignals(options)` | GET /signals page after page, or GET /account/signals with asOwner | feed key, or owner key |
 * | `createFeedKey(name, options)` | POST /account/feed-keys | owner key |
 * | `revokeFeedKey(id)` | DELETE /account/feed-keys/{id} | owner key |
 * | `createWebhook(url, options)` | POST /account/webhooks | owner key |
 * | `listWebhooks()` | GET /account/webhooks | owner key |
 * | `deleteWebhook(id)` | DELETE /account/webhooks/{id} | owner key |
 * | `listWebhookDeliveries(id, options)` | GET /account/webhooks/{id}/deliveries | owner key |
 * | `getFailureReceipt(id)` | GET /runs/{id}/failure-receipt | required |
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
    return this.registerRequestKeyAt(REQUEST_KEY_PATH, "registerRequestKey");
  }

  private async registerRequestKeyAt(
    path: string,
    method: string,
  ): Promise<RequestKeyRegistration> {
    this.requireAPIKey();
    if (!this.signingKey) {
      throw new VerdifaxError(
        `verdifax: ${method} needs the signingKey client option`,
      );
    }
    return this.request<RequestKeyRegistration>(
      "POST",
      path,
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
    await this.clearRequestKeyAt(REQUEST_KEY_PATH);
  }

  private async clearRequestKeyAt(path: string): Promise<void> {
    this.requireAPIKey();
    await this.request<void>(
      "DELETE",
      path,
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
    return this.uploadPolicyAt(POLICIES_PATH, document);
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
    return this.getPolicyAt(POLICIES_PATH, documentHash);
  }

  /** Shows which rule would fire on sample inputs, for a document given as
   *  text or one already stored, named by its hash: exactly one of the two.
   *  It seals nothing. */
  async testPolicy(req: PolicyTestRequest): Promise<PolicyTestResult> {
    return this.testPolicyAt(POLICIES_PATH, req, "testPolicy");
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
    return this.activatePolicyAt(
      POLICIES_PATH,
      documentHash,
      await this.listPolicies(),
    );
  }

  private async uploadPolicyAt(base: string, document: string): Promise<Policy> {
    this.requireAPIKey();
    if (typeof document !== "string") {
      throw new VerdifaxError(
        "verdifax: document must be the policy's exact text, as a string",
      );
    }
    return this.request<Policy>("POST", base, { document });
  }

  private async getPolicyAt(
    base: string,
    documentHash: Hex64,
  ): Promise<PolicyWithDocument> {
    this.requireAPIKey();
    validateHex64(documentHash, "documentHash");
    return this.request<PolicyWithDocument>("GET", `${base}/${documentHash}`);
  }

  private async testPolicyAt(
    base: string,
    req: PolicyTestRequest,
    method: string,
  ): Promise<PolicyTestResult> {
    this.requireAPIKey();
    const { inputs, document, documentHash } = req ?? ({} as PolicyTestRequest);
    if ((document === undefined) === (documentHash === undefined)) {
      throw new VerdifaxError(
        `verdifax: ${method} needs exactly one of document or documentHash`,
      );
    }
    if (typeof inputs !== "object" || inputs === null || Array.isArray(inputs)) {
      throw new VerdifaxError(`verdifax: ${method} needs inputs as an object`);
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
    return this.request<PolicyTestResult>("POST", `${base}/test`, body);
  }

  /** Posts the change that follows the newest one in `chain`, signed by
   *  the request key when the client has one. */
  private async activatePolicyAt(
    base: string,
    documentHash: Hex64,
    chain: PolicyList,
  ): Promise<PolicyActivation> {
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
      `${base}/${documentHash}/activate`,
      body,
    );
    return out.activation;
  }

  // ── Account, with its owner key (auth) ───────────────────────
  //
  // An account is a company on Verdifax. Every key belongs to one account
  // for life. These methods need the account's owner key, which manages the
  // account and cannot run anything: the server refuses it on every other
  // route. The account number is a label Verdifax assigned, not a verified
  // company identity.

  /** The owner's account: its number, name, tier, key counts and the
   *  chain of its policy changes. */
  async getAccount(): Promise<AccountInfo> {
    this.requireAPIKey();
    return this.request<AccountInfo>("GET", ACCOUNT_PATH);
  }

  /** Creates a member key in the account. It takes the account's tier and
   *  stays in the account for life. The secret is in the result this once.
   *  On a trial account the key needs a request key before it can run. */
  async createAccountKey(
    name: string,
    options: CreateAccountKeyOptions = {},
  ): Promise<CreatedAccountKey> {
    this.requireAPIKey();
    if (typeof name !== "string" || name.trim() === "") {
      throw new VerdifaxError(
        "verdifax: name is required for createAccountKey",
      );
    }
    const body: { name: string; expires_at?: string } = { name };
    if (options.expiresAt !== undefined) body.expires_at = options.expiresAt;
    return this.request<CreatedAccountKey>(
      "POST",
      `${ACCOUNT_PATH}/keys`,
      body,
    );
  }

  /** Every key in the account, owner keys included, without secrets. */
  async listAccountKeys(): Promise<AccountKeyList> {
    this.requireAPIKey();
    const out = await this.request<AccountKeyList>(
      "GET",
      `${ACCOUNT_PATH}/keys`,
    );
    return { ...out, keys: out?.keys ?? [] };
  }

  /** Revokes one of the account's member keys. A key in another account,
   *  or an owner key, throws {@link NotFoundError}. */
  async revokeAccountKey(keyId: number): Promise<AccountKeyRevocation> {
    this.requireAPIKey();
    requirePositiveId(keyId, "keyId");
    return this.request<AccountKeyRevocation>(
      "DELETE",
      `${ACCOUNT_PATH}/keys/${keyId}`,
    );
  }

  /** Registers this client's public key as the owner key's request key,
   *  which must sign every change to the account's policy. It works as
   *  {@link registerRequestKey} does. */
  async registerAccountRequestKey(): Promise<RequestKeyRegistration> {
    return this.registerRequestKeyAt(
      ACCOUNT_REQUEST_KEY_PATH,
      "registerAccountRequestKey",
    );
  }

  /** Clears the owner key's request key, as {@link clearRequestKey} does
   *  for a key's own. With none registered the account's policy cannot be
   *  changed. A trial owner key's request key cannot be cleared. */
  async clearAccountRequestKey(): Promise<void> {
    await this.clearRequestKeyAt(ACCOUNT_REQUEST_KEY_PATH);
  }

  /** The runs of every key in the account, paged as {@link listRuns}. */
  async listAccountRuns(params: ListRunsParams = {}): Promise<{
    runs: RunSummary[];
    total: number;
  }> {
    return this.listRunsAt(`${ACCOUNT_PATH}/runs`, params);
  }

  /** The runs of every key in the account in a period, as
   *  {@link exportRuns} lists a key's, with the account's number, its
   *  policy documents and its chain of changes. The account's view covers
   *  the runs its keys made through Verdifax, not runs made elsewhere. */
  async exportAccountRuns(
    params: ExportRunsParams = {},
  ): Promise<AccountRunsExport> {
    this.requireAPIKey();
    return this.request<AccountRunsExport>(
      "GET",
      this.exportPath(`${ACCOUNT_PATH}/runs/export`, params, "json"),
    );
  }

  /** The same rows as {@link exportAccountRuns} as raw CSV text, checked
   *  as {@link exportRunsCSV} checks a key's. */
  async exportAccountRunsCSV(
    params: ExportRunsParams = {},
  ): Promise<RunsExportCSV> {
    return this.exportCSVAt(`${ACCOUNT_PATH}/runs/export`, params);
  }

  /** Stores an account policy document, as {@link uploadPolicy} stores a
   *  key's. Every key in the account must pass the account's policy on top
   *  of its own. Verdifax does not write, review or approve it. */
  async uploadAccountPolicy(document: string): Promise<Policy> {
    return this.uploadPolicyAt(ACCOUNT_POLICIES_PATH, document);
  }

  /** The account's stored documents, its chain `account-N`, the newest
   *  change in it and the document in force. */
  async listAccountPolicies(): Promise<PolicyList> {
    this.requireAPIKey();
    return this.request<PolicyList>("GET", ACCOUNT_POLICIES_PATH);
  }

  /** One of the account's documents, with its exact text. */
  async getAccountPolicy(documentHash: Hex64): Promise<PolicyWithDocument> {
    return this.getPolicyAt(ACCOUNT_POLICIES_PATH, documentHash);
  }

  /** {@link testPolicy} for the account's documents. It seals nothing. */
  async testAccountPolicy(req: PolicyTestRequest): Promise<PolicyTestResult> {
    return this.testPolicyAt(ACCOUNT_POLICIES_PATH, req, "testAccountPolicy");
  }

  /** The account's policy changes, oldest first, in the form
   *  `verdifax-verify --policy-history FILE` reads. */
  async getAccountPolicyHistory(): Promise<PolicyActivation[]> {
    this.requireAPIKey();
    return this.request<PolicyActivation[]>(
      "GET",
      `${ACCOUNT_POLICIES_PATH}/history`,
    );
  }

  /** Makes a stored document the account's policy in force, as
   *  {@link activatePolicy} does for a key's. It reads
   *  {@link listAccountPolicies} for the chain and its newest change, and
   *  the owner key's request key signs the change over that chain,
   *  `account-N`. The server refuses an unsigned account change, so this
   *  needs the `signingKey` option and refuses to send without it. */
  async activateAccountPolicy(documentHash: Hex64): Promise<PolicyActivation> {
    this.requireAPIKey();
    validateHex64(documentHash, "documentHash");
    if (!this.signingKey) {
      throw new VerdifaxError(
        "verdifax: activateAccountPolicy needs the owner key's request key in the signingKey client option, because the server refuses an unsigned account policy change",
      );
    }
    const chain = await this.listAccountPolicies();
    if (typeof chain?.chain_id !== "string" || !ACCOUNT_CHAIN_ID.test(chain.chain_id)) {
      throw new VerdifaxError(
        "verdifax: the server did not report an account chain_id (account-N), so the change cannot be signed",
      );
    }
    return this.activatePolicyAt(ACCOUNT_POLICIES_PATH, documentHash, chain);
  }

  // ── Sign-off ─────────────────────────────────────────────────
  //
  // An account's owner registers approver keys. An approver signs a
  // decision, approve or reject, on one exact result on their own machine,
  // and any key in the account, or the owner key with asOwner, submits it.
  // A sign-off shows that the holder of a registered approver key signed
  // that decision on that exact result and that Verdifax logged it on the
  // public log. It does not show the review was careful, the result right,
  // or who the person is, and it gates nothing on its own.

  /** Registers an approver key to the owner's account. `approver` is the
   *  approver's signing key, from which the proof is made on this machine,
   *  or the `{ public_key, proof }` that {@link approverKeyProof} made on
   *  the approver's own machine, so the owner need not hold the private
   *  key. A proof that does not verify is refused before sending. The
   *  server refuses a key that is a request key in the same account.
   *  `name` is a label, not an identity. */
  async registerApprover(
    name: string,
    approver: Uint8Array | KeyObject | ApproverKeyProof,
  ): Promise<ApproverRegistration> {
    this.requireAPIKey();
    if (
      typeof name !== "string" ||
      name.trim() === "" ||
      Buffer.byteLength(name.trim(), "utf8") > MAX_APPROVER_NAME_BYTES
    ) {
      throw new VerdifaxError(
        "verdifax: registerApprover needs a name of at most 200 bytes",
      );
    }
    const body =
      approver instanceof Uint8Array || approver instanceof KeyObject
        ? approverKeyProof(approver)
        : { public_key: approver?.public_key, proof: approver?.proof };
    if (!approverKeyProofVerifies(body as ApproverKeyProof)) {
      throw new VerdifaxError(
        "verdifax: registerApprover needs the approver's signing key, or a public_key and proof from approverKeyProof that verify",
      );
    }
    if (this.signingKey && publicKeyOf(this.signingKey) === body.public_key) {
      throw new VerdifaxError(
        "verdifax: an approver key must not be a request key in the same account, and this is the client's signingKey",
      );
    }
    return this.request<ApproverRegistration>("POST", APPROVERS_PATH, {
      public_key: body.public_key,
      name,
      proof: body.proof,
    });
  }

  /** The account's approver keys, revoked ones included. */
  async listApprovers(): Promise<ApproverList> {
    this.requireAPIKey();
    const out = await this.request<ApproverList>("GET", APPROVERS_PATH);
    return { ...out, approvers: out?.approvers ?? [] };
  }

  /** Revokes one of the account's approver keys. Its earlier sign-offs
   *  stay on the record. A key that is not an active approver in the
   *  account throws {@link NotFoundError}. */
  async revokeApprover(approverId: number): Promise<ApproverRevocation> {
    this.requireAPIKey();
    requirePositiveId(approverId, "approverId");
    return this.request<ApproverRevocation>(
      "DELETE",
      `${APPROVERS_PATH}/${approverId}`,
    );
  }

  /** What an approver signs against: the account's chain `account-N` and
   *  its newest sign-off (64 zeros when there is none yet). With
   *  `asOwner` it reads the owner key's route. */
  async getNewestSignOff(
    options: AsOwnerOptions = {},
  ): Promise<NewestSignOff> {
    this.requireAPIKey();
    return this.request<NewestSignOff>(
      "GET",
      `${signOffsBase(options, "getNewestSignOff")}/newest`,
    );
  }

  /** Signs an approver's decision, approve or reject, on one exact result
   *  and submits it. It first reads {@link getNewestSignOff} for the
   *  account's chain and its newest sign-off, then signs over them with
   *  `approverKey` on this machine. The approver's private key is never
   *  sent.
   *
   *  `target.digest` is what the result's public-log entry covers: for a
   *  record, the `bundle_anchor.anchored_digest` of the bundle
   *  {@link getRunArtifacts} returns; for a receipt, its hash; for a job,
   *  the final step's record digest, read as a record's, with `job_id`.
   *
   *  `note` is hashed here and only its SHA-256 is sent and signed: the
   *  text never reaches Verdifax. With `asOwner` it uses the owner key's
   *  routes. Bad input is refused before anything is sent.
   *
   *  The record the server returns must carry the signature,
   *  approver_key, decision, previous_signoff_hash and target that were
   *  sent, or this throws {@link VerdifaxError}.
   *
   *  A later sign-off on the same result supersedes this one, and neither
   *  is deleted. An HTTP 409 means the chain moved or the target is not
   *  this account's result: it throws the usual {@link APIError} and is
   *  not retried. */
  async signOff(
    target: SignOffTarget,
    decision: SignOffDecision,
    approverKey: Uint8Array | KeyObject,
    options: SignOffOptions = {},
  ): Promise<SignOffRecord> {
    this.requireAPIKey();
    const base = signOffsBase(options, "signOff");
    const exact = signOffTargetOf(target);
    if (!SIGNOFF_DECISIONS.has(decision)) {
      throw new VerdifaxError(
        "verdifax: signOff decision must be approve or reject",
      );
    }
    const note = options?.note;
    if (note !== undefined && (typeof note !== "string" || note === "")) {
      throw new VerdifaxError(
        "verdifax: signOff note must be non-empty text when given",
      );
    }
    const key = loadSigningKey(approverKey);
    const note_hash = note === undefined ? "" : sha256Hex(note);
    const newest = await this.getNewestSignOff(options);
    if (
      typeof newest?.chain_id !== "string" ||
      !ACCOUNT_CHAIN_ID.test(newest.chain_id)
    ) {
      throw new VerdifaxError(
        "verdifax: the server did not report an account chain_id (account-N), so the sign-off cannot be signed",
      );
    }
    const previous = newest.newest_signoff_hash;
    if (typeof previous !== "string" || !/^[0-9a-f]{64}$/.test(previous)) {
      throw new VerdifaxError(
        "verdifax: the server did not report newest_signoff_hash, so the sign-off cannot name the one it follows",
      );
    }
    const signed = signOffSignature(key, {
      chain_id: newest.chain_id,
      previous_signoff_hash: previous,
      target: exact,
      decision,
      note_hash,
    });
    const body: Record<string, unknown> = {
      previous_signoff_hash: previous,
      target: exact,
      decision,
      ...(note_hash ? { note_hash } : {}),
      ...signed,
    };
    const out = await this.request<{ ok: boolean; signoff: SignOffRecord }>(
      "POST",
      base,
      body,
    );
    const record = out?.signoff;
    if (!recordMatchesSent(record, exact, decision, previous, signed)) {
      throw new VerdifaxError(
        "verdifax: the sign-off the server returned does not carry the signature, approver_key, decision, previous_signoff_hash and target that were sent",
      );
    }
    return record;
  }

  /** The sign-offs on one run, oldest first, in the form
   *  `verdifax-verify --signoff FILE` reads: for a member key, a run it
   *  made; with `asOwner`, any run of the account. The latest is the
   *  decision in force. */
  /** Make one of the account's records public on its random link with
   *  `POST /account/runs/{id}/publish`. Needs the account's owner key; the
   *  record may have been made by any key of the account. The decision is
   *  sealed as a run publication and placed in the signal feed as a
   *  `run.published` event. Idempotent: a record already public is answered
   *  as it is, with `publication: null`. The service's admin key cannot
   *  publish another key's record. */
  async publishRun(runId: number): Promise<PublicationResult> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    return this.request<PublicationResult>(
      "POST",
      `${ACCOUNT_PATH}/runs/${runId}/publish`,
    );
  }

  /** Withdraw one of the account's records from its public link with
   *  `POST /account/runs/{id}/unpublish`; the link is kept, so a later
   *  {@link publishRun} restores it. Sealed as a `run.unpublished` event.
   *  Needs the account's owner key. */
  async unpublishRun(runId: number): Promise<PublicationResult> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    return this.request<PublicationResult>(
      "POST",
      `${ACCOUNT_PATH}/runs/${runId}/unpublish`,
    );
  }

  async getSignOffs(
    runId: number,
    options: AsOwnerOptions = {},
  ): Promise<SignOffRecord[]> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    const base = asOwnerOf(options, "getSignOffs")
      ? `${ACCOUNT_PATH}/runs`
      : "/runs";
    return (
      (await this.request<SignOffRecord[]>(
        "GET",
        `${base}/${runId}/signoffs`,
      )) ?? []
    );
  }

  /** The account's whole chain of sign-offs, oldest first, in the form
   *  `verdifax-verify --signoff-history FILE` reads. Needs the owner key. */
  async getSignOffHistory(): Promise<SignOffRecord[]> {
    this.requireAPIKey();
    return (
      (await this.request<SignOffRecord[]>(
        "GET",
        `${ACCOUNT_SIGNOFFS_PATH}/history`,
      )) ?? []
    );
  }

  // ── Signal feed ──────────────────────────────────────────────
  //
  // Every control signal Verdifax recorded for the account, in order, each
  // with its sealed entry. The feed cannot show a signal Verdifax never
  // recorded. A feed key reads it on GET /signals and does nothing else;
  // the owner key reads it with asOwner and manages feed keys and webhooks.
  // The feed and webhook logic is in signals.ts.

  /** One page of the account's feed: the events after `after`, oldest
   *  first, with `next_after` to read from next. With `wait` the server
   *  holds the request open up to that many seconds for the next event, and
   *  this call's timeout is at least the wait plus 30 seconds. With
   *  `asOwner` it reads GET /account/signals with the owner key. Bad
   *  options are refused before sending. Save the events and check them
   *  with `verdifax-verify --signals`. */
  async getSignals(options: GetSignalsOptions = {}): Promise<SignalPage> {
    this.requireAPIKey();
    const read = signalsRead(options, "getSignals", this.timeoutMs);
    const out = await this.request<SignalPage>(
      "GET",
      read.path,
      undefined,
      false,
      read.timeoutMs,
    );
    return { ...out, events: out?.events ?? [] };
  }

  /** Follows the feed from `after`, yielding each event once, in order,
   *  until you stop with `break` or `return`. Each read starts at the page
   *  before's `next_after`, waits up to `wait` seconds (default 25) when
   *  there is no event, and is retried like any GET. A read that still
   *  fails throws {@link SignalFeedError}, whose `lastSequence` is the last
   *  sequence yielded: follow again from there and nothing is lost. Bad
   *  options are refused here, before anything is sent. */
  followSignals(
    options: FollowSignalsOptions = {},
  ): AsyncGenerator<SignalEvent, void, undefined> {
    this.requireAPIKey();
    const start = followStart(options);
    return followSignalFeed(
      (after) =>
        this.getSignals({ after, wait: start.wait, asOwner: start.asOwner }),
      start,
    );
  }

  /** Creates a feed key in the owner's account. A feed key reads the
   *  account's signal feed, with {@link getSignals} and
   *  {@link followSignals}, and nothing else. The secret is in the result
   *  this once. */
  async createFeedKey(
    name: string,
    options: CreateFeedKeyOptions = {},
  ): Promise<CreatedFeedKey> {
    this.requireAPIKey();
    return this.request<CreatedFeedKey>(
      "POST",
      FEED_KEYS_PATH,
      feedKeyBody(name, options?.expiresAt),
    );
  }

  /** Revokes one of the account's feed keys. An id that is not a feed key
   *  of the account throws {@link NotFoundError}. */
  async revokeFeedKey(id: number): Promise<FeedKeyRevocation> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    return this.request<FeedKeyRevocation>("DELETE", `${FEED_KEYS_PATH}/${id}`);
  }

  /** Subscribes an https address to the account's signals. `types` are the
   *  kinds to deliver, each once; empty or left out takes every kind. The
   *  secret, `whsec_` and base64, is in the result this once: check each
   *  delivery with {@link verifyWebhook}. A delivery is a copy: the pull
   *  feed and the public log are the record. The server checks the address
   *  too, and refuses an eleventh subscription with HTTP 409. */
  async createWebhook(
    url: string,
    options: CreateWebhookOptions = {},
  ): Promise<CreatedWebhook> {
    this.requireAPIKey();
    return this.request<CreatedWebhook>(
      "POST",
      WEBHOOKS_PATH,
      webhookBody(url, options),
    );
  }

  /** The account's webhook subscriptions, without their secrets. */
  async listWebhooks(): Promise<WebhookList> {
    this.requireAPIKey();
    const out = await this.request<WebhookList>("GET", WEBHOOKS_PATH);
    return { ...out, webhooks: out?.webhooks ?? [] };
  }

  /** Ends a webhook subscription. Its events stay in the pull feed. */
  async deleteWebhook(id: number): Promise<WebhookDeletion> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    return this.request<WebhookDeletion>("DELETE", `${WEBHOOKS_PATH}/${id}`);
  }

  /** A webhook's newest deliveries first, up to `limit` (1 to 500; the
   *  server's default is 50). */
  async listWebhookDeliveries(
    id: number,
    options: ListWebhookDeliveriesOptions = {},
  ): Promise<WebhookDeliveryList> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    const out = await this.request<WebhookDeliveryList>(
      "GET",
      deliveriesPath(id, options),
    );
    return { ...out, deliveries: out?.deliveries ?? [] };
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
    return this.listRunsAt("/runs", params);
  }

  private async listRunsAt(base: string, params: ListRunsParams): Promise<{
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
    const path = qs ? `${base}?${qs}` : base;
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
    return this.request<RunsExport>(
      "GET",
      this.exportPath("/runs/export", params, "json"),
    );
  }

  /** The same rows as {@link exportRuns}: the raw CSV text with `total`
   *  and `truncated` from the response headers. Check `truncated`: when
   *  true, the CSV is missing rows for the period. Throws when the server
   *  does not send those headers, so that a cut-off export cannot pass
   *  for a complete one. */
  async exportRunsCSV(params: ExportRunsParams = {}): Promise<RunsExportCSV> {
    return this.exportCSVAt("/runs/export", params);
  }

  private async exportCSVAt(
    base: string,
    params: ExportRunsParams,
  ): Promise<RunsExportCSV> {
    this.requireAPIKey();
    const { text, headers } = await this.requestRaw(
      this.exportPath(base, params, "csv"),
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

  private exportPath(
    base: string,
    params: ExportRunsParams,
    format: string,
  ): string {
    const q = new URLSearchParams();
    if (params.from) q.set("from", params.from);
    if (params.to) q.set("to", params.to);
    if (params.job_id) q.set("job_id", params.job_id);
    q.set("format", format);
    return `${base}?${q.toString()}`;
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

  /** A failed run's sealed failure receipt, in the form `verdifax-verify`
   *  reads. A run that failed before failure receipts were sealed has none
   *  and throws {@link NotFoundError}. */
  async getFailureReceipt(runId: number): Promise<Record<string, unknown>> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    return this.getRunArtifact(runId, "failure-receipt");
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

  /** The sealed receipt of a published stopped run (a refusal, a halt or
   *  a failure) a share token points to, as the exact JSON text the server
   *  sent: the same document the key holder reads from the run's receipt
   *  route. Needs no API key. */
  async getPublicReceiptByToken(token: string): Promise<string> {
    if (!token) throw new VerdifaxError("verdifax: token is required");
    const path = `/public/runs/${encodeURIComponent(token)}/receipt.json`;
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

  /** Creates a customer key. With `accountId` the key joins that existing
   *  account; without it the key gets an account of its own. A key never
   *  changes account. */
  async adminCreateKey(
    name: string,
    options: AdminCreateKeyOptions = {},
  ): Promise<AdminCreateKeyResponse> {
    this.requireAPIKey();
    if (!name) {
      throw new VerdifaxError("verdifax: name is required for adminCreateKey");
    }
    const body: { name: string; account_id?: number } = { name };
    if (options.accountId !== undefined) {
      requirePositiveId(options.accountId, "accountId");
      body.account_id = options.accountId;
    }
    return this.request<AdminCreateKeyResponse>("POST", "/admin/keys", body);
  }

  /** Creates an account and its first owner key, whose secret is in the
   *  result this once. The owner key creates the member keys. The account
   *  number is a label Verdifax assigned, not a verified company identity. */
  async adminCreateAccount(
    name: string,
    options: AdminCreateAccountOptions = {},
  ): Promise<AdminCreateAccountResponse> {
    this.requireAPIKey();
    if (typeof name !== "string" || name.trim() === "") {
      throw new VerdifaxError(
        "verdifax: name is required for adminCreateAccount",
      );
    }
    const body: { name: string; tier?: string; expires_at?: string } = { name };
    if (options.tier !== undefined) body.tier = options.tier;
    if (options.expiresAt !== undefined) body.expires_at = options.expiresAt;
    return this.request<AdminCreateAccountResponse>(
      "POST",
      "/admin/accounts",
      body,
    );
  }

  /** Every account, with its key counts. */
  async adminListAccounts(): Promise<Account[]> {
    this.requireAPIKey();
    const out = await this.request<{ ok: boolean; accounts: Account[] }>(
      "GET",
      "/admin/accounts",
    );
    return out?.accounts ?? [];
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
    timeoutMs = this.timeoutMs,
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
      const timer = setTimeout(() => controller.abort(), timeoutMs);
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

/** The sign-off routes' base: the owner key's with `asOwner`, otherwise a
 *  member key's. Anything but true, false or nothing is refused. */
function signOffsBase(options: AsOwnerOptions, method: string): string {
  return asOwnerOf(options, method) ? ACCOUNT_SIGNOFFS_PATH : SIGNOFFS_PATH;
}

/** The target as the server reads it, with only its own fields, or a
 *  refusal naming what is wrong. */
function signOffTargetOf(target: SignOffTarget): SignOffTarget {
  if (typeof target !== "object" || target === null || Array.isArray(target)) {
    throw new VerdifaxError("verdifax: signOff needs a target object");
  }
  for (const name of Object.keys(target)) {
    if (!["kind", "run_id", "digest", "job_id"].includes(name)) {
      throw new VerdifaxError(`verdifax: signOff target has an unknown field: ${name}`);
    }
  }
  if (!SIGNOFF_TARGET_KINDS.has(target.kind)) {
    throw new VerdifaxError(
      "verdifax: signOff target kind must be record, receipt or job",
    );
  }
  requirePositiveId(target.run_id, "target.run_id");
  validateHex64(target.digest, "target.digest");
  if (target.kind === "job") {
    validateJobName(target.job_id as string, "target.job_id");
    return {
      kind: target.kind,
      run_id: target.run_id,
      digest: target.digest,
      job_id: target.job_id,
    };
  }
  if (target.job_id !== undefined) {
    throw new VerdifaxError(
      "verdifax: signOff target job_id is for a job target only",
    );
  }
  return { kind: target.kind, run_id: target.run_id, digest: target.digest };
}

/** True when the record the server returned carries the signature,
 *  approver key, decision, previous sign-off and target that were sent. */
function recordMatchesSent(
  record: SignOffRecord | undefined,
  target: SignOffTarget,
  decision: SignOffDecision,
  previous: string,
  signed: { approver_key: string; signature: string },
): record is SignOffRecord {
  const got = record?.target;
  return (
    typeof record === "object" &&
    record !== null &&
    record.signature === signed.signature &&
    record.approver_key === signed.approver_key &&
    record.decision === decision &&
    record.previous_signoff_hash === previous &&
    typeof got === "object" &&
    got !== null &&
    got.kind === target.kind &&
    got.run_id === target.run_id &&
    got.digest === target.digest &&
    (got.job_id ?? "") === (target.job_id ?? "")
  );
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
