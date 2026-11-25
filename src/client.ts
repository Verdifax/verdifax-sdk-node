import {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  SignOffRefusedError,
  VerdifaxError,
} from "./errors.js";
import {
  ACCOUNT_RESUMED_CHANGE,
  ACCOUNT_STOPPED_CHANGE,
  accountStopSubject,
  allowedToolsFromHeader,
  checkedAllowedTools,
  stopReasonHash,
  stopScopeOf,
} from "./account-stop.js";
import {
  approverKeyProof,
  approverKeyProofVerifies,
  loadSigningKey,
  ownerChangeSignature,
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
import { parseSealed, type Sealed, type SealedList } from "./sealed.js";
import {
  deliveriesPath,
  FEED_KEYS_PATH,
  feedKeyBody,
  followSignalFeed,
  followStart,
  signalsRead,
  webhookBody,
  webhookValue,
  WEBHOOK_DELETED,
  WEBHOOK_SUBSCRIBED,
  WEBHOOKS_PATH,
} from "./signals.js";
import type {
  FeedHead,
  PeriodSummary,
  ResponseTimesOptions,
  ResponseTimesReport,
  SummaryAnswer,
  SummaryList,
  AccountChange,
  AccountStopRecord,
  AccountStopResult,
  AccountStopState,
  AdminResumeAccountOptions,
  AdminStopAccountOptions,
  ResumeAccountOptions,
  SignOffRefusalRecord,
  StopAccountOptions,
  StopScope,
  Account,
  AccountInfo,
  AccountSetting,
  AccountSettingResult,
  AccountSettingValue,
  OwnerChangeOptions,
  OwnerChangeSignature,
  OwnerKeyReplacement,
  OwnerSignature,
  RunDeletionResult,
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
  AuditPDFOptions,
  PublicSignOffAnswer,
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
  SignalFollower,
  SignalPage,
  SignedRequestBody,
  SignOffDecision,
  SignOffOptions,
  SignOffRecord,
  AccountTimeZone,
  RestoreGapRecord,
  ChainInterruptedRecord,
  SignOffHeadRecord,
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
// The owner's blocks, by route name, and the change name the owner signs.
const ACCOUNT_SETTING_CHANGES: Record<AccountSetting, string> = {
  "owner-replacement": "setting.owner_replacement",
  "verdifax-deletion": "setting.verdifax_deletion",
  // Round 64: the owner's setting that allows or blocks Verdifax's stop.
  "verdifax-stop": "setting.verdifax_stop",
  // Whether the owner key reads the account's records.
  "owner-reads": "setting.owner_reads",
};
const ACCOUNT_SETTING_VALUES = new Set(["allowed", "blocked"]);
const RUN_DELETED_CHANGE = "run.deleted";
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
 * | `getPublicSignOff(id)` | GET /runs/{id}/signoff.json | none |
 * | `getPublicSignOffByToken(token)` | GET /public/runs/{token}/signoff.json | none |
 * | `executeBatch(runs)` | POST /execute/batch | required |
 * | `verifyDeterminism(req)` | POST /execute/verify-determinism | required |
 * | `downloadAuditPDF(id, format, { aiOutputText })` | GET or POST /runs/{id}/report.pdf | required |
 * | `downloadPublicAuditPDF(token, format, { aiOutputText })` | GET or POST /public/runs/{token}/report.pdf | none |
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
 * | `adminReplaceOwnerKey(accountId)` | POST /admin/accounts/{id}/owner-key/replace | required |
 * | `adminDeleteRun(runId)` | POST /admin/runs/{id}/delete | required |
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
 * | `rotateAccountRequestKey(newSigningKey)` | POST /account/request-key | owner key |
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
 * | `setAccountSetting(setting, value, options)` | PUT /account/settings/{setting} | owner key |
 * | `deleteRun(runId, recordHash, options)` | POST /account/runs/{id}/delete | owner key |
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
 * | `createWebhook(url, options)` | POST /account/webhooks | owner key, signed by its request key |
 * | `listWebhooks()` | GET /account/webhooks | owner key |
 * | `deleteWebhook(id, options)` | DELETE /account/webhooks/{id} | owner key, signed by its request key |
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

  /** The tool allowlist this key's owner granted it (round 64), from the
   *  X-Verdifax-Allowed-Tools header of GET /stats: the names, or null when
   *  the key has no allowlist and is admitted by its scope alone. */
  async getAllowedTools(): Promise<string[] | null> {
    this.requireAPIKey();
    const raw = await this.requestRaw("/stats");
    return allowedToolsFromHeader(raw.headers.get("X-Verdifax-Allowed-Tools"));
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
    // Each parsed row takes its signed text in place, so the answer, its
    // list and its rows keep their sealedJson.
    out.results.forEach((row, i) => {
      if (i < sent.length) withSignedText(row, sent[i]!);
    });
    return out;
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
   *  refuses a run on this API key without a request signature. For a key
   *  in a customer's account the server seals the registration in the
   *  account's feed as a `request_key.registered` account change. An
   *  {@link APIError} with status 409 and the server's message means
   *  another change replaced the request key first. */
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
   *  have made the change. For a key in a customer's account the server
   *  seals the change in the account's feed as a `request_key.rotated`
   *  account change carrying the approval. An {@link APIError} with status
   *  409 and the server's message means the request key changed since the
   *  approval was signed: read the key again and sign with the one in force. */
  async rotateRequestKey(
    newSigningKey: Uint8Array | KeyObject,
  ): Promise<RequestKeyRegistration> {
    return this.rotateRequestKeyAt(
      REQUEST_KEY_PATH,
      "rotateRequestKey",
      newSigningKey,
    );
  }

  /** Sends the new key, its proof and the current key's approval to
   *  `path`, then signs with the new key. The client switches keys only
   *  after the server's 2xx answer, so a refusal, a 409 or a timeout keeps
   *  the current key. */
  private async rotateRequestKeyAt(
    path: string,
    method: string,
    newSigningKey: Uint8Array | KeyObject,
  ): Promise<RequestKeyRegistration> {
    this.requireAPIKey();
    if (!this.signingKey) {
      throw new VerdifaxError(
        `verdifax: ${method} needs the current key in the signingKey client option`,
      );
    }
    const next = loadSigningKey(newSigningKey);
    const registration = requestKeyRegistrationBody(next);
    const out = await this.request<RequestKeyRegistration>(
      "POST",
      path,
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
   *  key with no registered key. If the call fails it keeps the key. For a
   *  key in a customer's account the server seals the clear in the
   *  account's feed as a `request_key.cleared` account change decided by
   *  `owner`, with the approval. An {@link APIError} with status 409 means
   *  the request key changed since the approval was signed. */
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
   *  `writeFileSync("policy-history.json", history.sealedJson)`, the exact
   *  text the server sent, and
   *  check it with `verdifax-verify --policy-history policy-history.json`.
   *  A place a restore skipped holds a restore gap, and a place whose change
   *  the public log never confirmed holds an interrupted record. */
  async getPolicyHistory(): Promise<SealedList<PolicyActivation | RestoreGapRecord | ChainInterruptedRecord>> {
    this.requireAPIKey();
    return this.request<SealedList<PolicyActivation | RestoreGapRecord | ChainInterruptedRecord>>("GET", `${POLICIES_PATH}/history`);
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
    const { inputs, document, documentHash, aiOutputDeclared } = req ?? ({} as PolicyTestRequest);
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
    if (aiOutputDeclared !== undefined && typeof aiOutputDeclared !== "boolean") {
      throw new VerdifaxError("verdifax: aiOutputDeclared must be a boolean");
    }
    if (aiOutputDeclared) {
      body.ai_output_declared = true;
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

  /** Chooses the second time zone the account's audit reports show beside
   *  UTC: an IANA zone such as `Europe/London`, `"none"` for UTC alone, or
   *  `""` for the zone of the server's region, which an account that never
   *  chose sees. Needs the owner key. It changes how times are displayed,
   *  never a sealed value. */
  async setAccountTimeZone(timeZone: string): Promise<AccountTimeZone> {
    this.requireAPIKey();
    if (typeof timeZone !== "string" || timeZone.length > 64) {
      throw new VerdifaxError("verdifax: timeZone must be a string of at most 64 characters");
    }
    return this.request<AccountTimeZone>("PUT", `${ACCOUNT_PATH}/time-zone`, { time_zone: timeZone });
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
    const body: { name: string; expires_at?: string; allowed_tools?: string[] } = { name };
    if (options.expiresAt !== undefined) body.expires_at = options.expiresAt;
    if (options.allowedTools !== undefined) {
      body.allowed_tools = checkedAllowedTools(options.allowedTools);
    }
    const out = await this.request<CreatedAccountKey>(
      "POST",
      `${ACCOUNT_PATH}/keys`,
      body,
    );
    if (body.allowed_tools !== undefined) {
      const want = [...body.allowed_tools].sort();
      const got = out?.allowed_tools;
      if (!Array.isArray(got) || got.length !== want.length || got.some((name, i) => name !== want[i])) {
        throw new VerdifaxError(
          "verdifax: the key the server made does not carry the tool allowlist that was sent",
        );
      }
    }
    return out;
  }

  /** Every key in the account, owner keys included, without secrets. */
  async listAccountKeys(): Promise<AccountKeyList> {
    this.requireAPIKey();
    const out = await this.request<AccountKeyList>(
      "GET",
      `${ACCOUNT_PATH}/keys`,
    );
    return withList(out, "keys");
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

  /** Replaces the owner key's request key with `newSigningKey`, as
   *  {@link rotateRequestKey} does for a key's own, at POST
   *  /account/request-key: the new key proves itself and the current key,
   *  this client's `signingKey`, approves the change. After success this
   *  client signs with the new key; if the call fails, including with an
   *  {@link APIError} 409 because another change replaced the request key
   *  first, it keeps the current key. The server seals the change in the
   *  account's feed as a `request_key.rotated` account change carrying the
   *  approval. */
  async rotateAccountRequestKey(
    newSigningKey: Uint8Array | KeyObject,
  ): Promise<RequestKeyRegistration> {
    return this.rotateRequestKeyAt(
      ACCOUNT_REQUEST_KEY_PATH,
      "rotateAccountRequestKey",
      newSigningKey,
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
  ): Promise<Sealed<AccountRunsExport>> {
    this.requireAPIKey();
    return this.request<Sealed<AccountRunsExport>>(
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
   *  `verdifax-verify --policy-history FILE` reads, with restore gaps and
   *  interrupted records in the places they close. */
  async getAccountPolicyHistory(): Promise<SealedList<PolicyActivation | RestoreGapRecord | ChainInterruptedRecord>> {
    this.requireAPIKey();
    return this.request<SealedList<PolicyActivation | RestoreGapRecord | ChainInterruptedRecord>>(
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

  /** Sets one of the owner's settings: `owner-replacement`, which
   *  while `blocked` stops Verdifax replacing, revoking or starting a
   *  replacement of the owner key; `verdifax-deletion`, which while
   *  `blocked` stops Verdifax deleting one of the account's records;
   *  `verdifax-stop`, which while `blocked` stops Verdifax placing its own
   *  stop; or `owner-reads`, which while `allowed` lets the owner key read
   *  the record, receipts and reports of every run of the account, and is `blocked` until
   *  the owner allows it. `value` is `allowed` or `blocked`.
   *
   *  The owner key's request key signs the change, such as
   *  `setting.owner_replacement` or `setting.owner_reads`, over the account's label and the value,
   *  and the record seals the signature, so Verdifax cannot make the change
   *  itself. The server refuses an unsigned owner change, so this needs the
   *  `signingKey` option and refuses to send without it. The label,
   *  `account-N`, is read from {@link getAccount} unless `accountId` is
   *  given. Bad input is refused before anything is sent.
   *
   *  Asking for the value already set changes nothing and seals nothing:
   *  `account_change` is then null. Otherwise the change the server returns
   *  must seal the action and value that were sent, `decided_by` owner and
   *  the signature sent under the client's request key, or this throws
   *  {@link VerdifaxError}. */
  async setAccountSetting(
    setting: AccountSetting,
    value: AccountSettingValue,
    options: OwnerChangeOptions = {},
  ): Promise<AccountSettingResult> {
    this.requireAPIKey();
    if (!Object.hasOwn(ACCOUNT_SETTING_CHANGES, setting)) {
      throw new VerdifaxError(
        "verdifax: setAccountSetting setting must be owner-replacement, verdifax-deletion, verdifax-stop or owner-reads",
      );
    }
    if (!ACCOUNT_SETTING_VALUES.has(value)) {
      throw new VerdifaxError(
        "verdifax: setAccountSetting value must be allowed or blocked",
      );
    }
    const action = ACCOUNT_SETTING_CHANGES[setting];
    const signed = await this.ownerSigned("setAccountSetting", action, value, options);
    const out = await this.request<AccountSettingResult>(
      "PUT",
      `${ACCOUNT_PATH}/settings/${setting}`,
      { value, owner_signature: signed.owner_signature },
    );
    const change = out?.account_change;
    if (
      change !== null &&
      (typeof change !== "object" ||
        change.action !== action ||
        change.value !== value ||
        change.decided_by !== "owner" ||
        !ownerSignatureMatchesSent(change.owner_signature, signed))
    ) {
      throw new VerdifaxError(
        "verdifax: the account change the server returned does not seal the action, value, decided_by owner and owner_signature that were sent",
      );
    }
    return out;
  }

  /** Deletes one of the account's records, with the owner key. Its
   *  tombstone, which names the exact record, stays in the account's
   *  signal feed as a `run.deleted` event. `recordHash` is the record's
   *  hash: a completed run's `record_hash`, or a stopped run's receipt
   *  hash. The server refuses a hash that is not this run's with an HTTP
   *  409, and a public record the same way: withdraw it first with
   *  {@link unpublishRun}.
   *
   *  The owner key's request key signs `run.deleted` over the account's
   *  label and `RUN_ID:RECORD_HASH`. The server refuses an unsigned owner
   *  change, so this needs the `signingKey` option and refuses to send
   *  without it. The label, `account-N`, is read from {@link getAccount}
   *  unless `accountId` is given. Bad input is refused before anything is
   *  sent. The owner's own deletions are never blocked. The tombstone the
   *  server returns must seal the run, the record hash, `decided_by` owner
   *  and the signature sent under the client's request key, or this throws
   *  {@link VerdifaxError}. */
  async deleteRun(
    runId: number,
    recordHash: Hex64,
    options: OwnerChangeOptions = {},
  ): Promise<RunDeletionResult> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    validateHex64(recordHash, "recordHash");
    const signed = await this.ownerSigned(
      "deleteRun",
      RUN_DELETED_CHANGE,
      `${runId}:${recordHash}`,
      options,
    );
    const out = await this.request<RunDeletionResult>(
      "POST",
      `${ACCOUNT_PATH}/runs/${runId}/delete`,
      { record_hash: recordHash, owner_signature: signed.owner_signature },
    );
    const deletion = out?.run_deletion;
    if (
      typeof deletion !== "object" ||
      deletion === null ||
      deletion.run_id !== runId ||
      deletion.record_hash !== recordHash ||
      deletion.decided_by !== "owner" ||
      !ownerSignatureMatchesSent(deletion.owner_signature, signed)
    ) {
      throw new VerdifaxError(
        "verdifax: the run deletion the server returned does not seal the run_id, record_hash, decided_by owner and owner_signature that were sent",
      );
    }
    return out;
  }

  /** The owner key's request-key signature over one change, naming the
   *  account's label: `options.accountId`, or `account_id` from GET
   *  /account, with the public key it verifies under. Refuses before any
   *  request without a signing key or with a label that is not
   *  `account-N`. */
  /** The owner key's request key, or a refusal before anything is sent. */
  private requireOwnerSigningKey(method: string): KeyObject {
    if (!this.signingKey) {
      throw new VerdifaxError(
        `verdifax: ${method} needs the owner key's request key in the signingKey client option, because the server refuses an unsigned owner change`,
      );
    }
    return this.signingKey;
  }

  private async ownerSigned(
    method: string,
    change: string,
    subject: string,
    options: OwnerChangeOptions,
  ): Promise<SentOwnerSignature> {
    const signingKey = this.requireOwnerSigningKey(method);
    const given = options?.accountId;
    if (given !== undefined && (typeof given !== "string" || !ACCOUNT_CHAIN_ID.test(given))) {
      throw new VerdifaxError(
        `verdifax: ${method} accountId must be the account's label, account-N`,
      );
    }
    const account = given ?? (await this.getAccount())?.account_id;
    if (typeof account !== "string" || !ACCOUNT_CHAIN_ID.test(account)) {
      throw new VerdifaxError(
        "verdifax: the server did not report an account_id (account-N), so the change cannot be signed",
      );
    }
    return {
      owner_signature: ownerChangeSignature(signingKey, { account, change, subject }),
      public_key: publicKeyOf(signingKey),
    };
  }

  // ── Account stop (round 64) ──────────────────────────────────
  //
  // The owner and Verdifax each hold a stop of their own on the account
  // and lift only their own; the account runs only while neither stands.
  // While a stop stands every new run is refused with a sealed deny
  // receipt, runs already in progress finish, and no key is revoked or
  // changed. Each stop and lift is sealed in the account's feed.

  /** Places the owner's stop with POST /account/stop. By default the owner
   *  key's request key, this client's `signingKey`, signs it, naming the
   *  owner key's id (`keyId`, or the one owner key not revoked in GET
   *  /account/keys) and the account's label (`accountId`, or GET
   *  /account's). With `unsigned: true` no signature is sent and nothing is
   *  read first; the record then seals the server's word that this key
   *  asked. A member key its owner granted `account_stop` stops only that
   *  way. The record the server returns must seal the action, scope,
   *  reason hash and, for a signed stop, the key and signature sent, or
   *  this throws {@link VerdifaxError}. Bad input is refused before
   *  anything is sent. */
  async stopAccount(options: StopAccountOptions = {}): Promise<AccountStopResult> {
    this.requireAPIKey();
    const scope = stopScopeOf(options.signoffs, options.webhooks);
    const reasonHash = stopReasonHash(options.reason);
    if (options.unsigned !== undefined && typeof options.unsigned !== "boolean") {
      throw new VerdifaxError("verdifax: stopAccount unsigned must be true or false");
    }
    const body: Record<string, unknown> = { signoffs: scope.signoffs, webhooks: scope.webhooks };
    if (reasonHash) body.reason = options.reason;
    if (options.unsigned === true) {
      const out = await this.request<AccountStopResult>("POST", `${ACCOUNT_PATH}/stop`, body);
      const record = checkedStopRecord(out, "stop", "owner", scope, reasonHash);
      if (record.owner_signature !== undefined || typeof record.unsigned !== "string" || record.unsigned === "") {
        throw new VerdifaxError(
          "verdifax: the unsigned stop the server returned does not seal the unsigned statement",
        );
      }
      return out;
    }
    this.requireOwnerSigningKey("stopAccount (or pass unsigned: true for an unsigned stop)");
    const keyId = await this.ownerKeyId(options.keyId, "stopAccount");
    const subject = accountStopSubject({
      action: "stop",
      keyId,
      signoffs: scope.signoffs,
      webhooks: scope.webhooks,
      reason: options.reason,
    });
    const signed = await this.ownerSigned("stopAccount", ACCOUNT_STOPPED_CHANGE, subject, options);
    body.owner_signature = signed.owner_signature;
    const out = await this.request<AccountStopResult>("POST", `${ACCOUNT_PATH}/stop`, body);
    const record = checkedStopRecord(out, "stop", "owner", scope, reasonHash);
    if (record.key_id !== keyId || !ownerSignatureMatchesSent(record.owner_signature, signed)) {
      throw new VerdifaxError(
        "verdifax: the stop the server returned does not seal the key_id and owner_signature that were sent",
      );
    }
    return out;
  }

  /** Lifts the owner's stop with POST /account/resume, always signed by
   *  the owner key's request key. `liftsSequence` names the stop by its
   *  feed place; left out, it is read from GET /account/stop. It never
   *  lifts Verdifax's stop. The record returned must seal what was sent,
   *  or this throws {@link VerdifaxError}. */
  async resumeAccount(options: ResumeAccountOptions = {}): Promise<AccountStopResult> {
    this.requireAPIKey();
    this.requireOwnerSigningKey("resumeAccount");
    const reasonHash = stopReasonHash(options.reason);
    let lifts = options.liftsSequence;
    if (lifts !== undefined) requirePositiveId(lifts, "liftsSequence");
    const keyId = await this.ownerKeyId(options.keyId, "resumeAccount");
    if (lifts === undefined) {
      const state = await this.getAccountStop();
      const hold = (Array.isArray(state?.holds) ? state.holds : []).find((h) => h?.holder === "owner");
      if (hold === undefined || !Number.isSafeInteger(hold.stop_sequence) || hold.stop_sequence <= 0) {
        throw new VerdifaxError("verdifax: no owner stop stands on this account, so there is none to lift");
      }
      lifts = hold.stop_sequence;
    }
    const subject = accountStopSubject({ action: "resume", keyId, liftsSequence: lifts, reason: options.reason });
    const signed = await this.ownerSigned("resumeAccount", ACCOUNT_RESUMED_CHANGE, subject, options);
    const body: Record<string, unknown> = { lifts_sequence: lifts };
    if (reasonHash) body.reason = options.reason;
    body.owner_signature = signed.owner_signature;
    const out = await this.request<AccountStopResult>("POST", `${ACCOUNT_PATH}/resume`, body);
    const record = checkedStopRecord(out, "resume", "owner", undefined, reasonHash);
    if (
      record.lifts_sequence !== lifts ||
      record.key_id !== keyId ||
      !ownerSignatureMatchesSent(record.owner_signature, signed)
    ) {
      throw new VerdifaxError(
        "verdifax: the resume the server returned does not seal the lifts_sequence, key_id and owner_signature that were sent",
      );
    }
    return out;
  }

  /** The account's stops, from GET /account/stop with the owner key: each
   *  stop standing, the owner's verdifax-stop setting and the runs in
   *  progress. Reading changes nothing. */
  async getAccountStop(): Promise<AccountStopState> {
    this.requireAPIKey();
    const out = await this.request<AccountStopState>("GET", `${ACCOUNT_PATH}/stop`);
    return withList(out, "holds");
  }

  // ── Board summary and response times (round 64) ──────────────
  //
  // The SDK fetches these documents and returns them as the server sent
  // them. It never recounts a figure: verdifax-verify recounts each one
  // from the account's feed.

  /** Seals a period summary for a board with POST /account/summaries
   *  (owner key): the figures the counting rules give over the account's
   *  feed from `from` to `to` (RFC 3339 times), up to a feed head on the
   *  public log, stated by Verdifax and anchored as its own public-log
   *  entry. The answer is `{id, reused, summary}`: `reused` is true (HTTP
   *  200) when that period was already sealed over the same feed, and false
   *  (HTTP 201) when it was sealed now. The summary keeps its exact text in
   *  `sealedJson`; save it and check it with `verdifax-verify`, which
   *  recounts every figure. It counts what the feed shows and judges none
   *  of it. Throws {@link VerdifaxError} for an answer that is not a sealed
   *  summary. */
  async createSummary(from: string, to: string): Promise<SummaryAnswer> {
    this.requireAPIKey();
    requireText(from, "from");
    requireText(to, "to");
    const out = await this.request<SummaryAnswer>("POST", `${ACCOUNT_PATH}/summaries`, { from, to });
    if (!Number.isSafeInteger(out?.id) || out.id <= 0 || typeof out.reused !== "boolean") {
      throw new VerdifaxError("verdifax: the server's summary answer has no id or no reused flag");
    }
    checkSummary(out.summary);
    if (out.head !== undefined && out.head !== null) checkSummaryHead(out.head, out.summary, "POST /account/summaries");
    return out;
  }

  /** The account's period summaries, newest first, from GET
   *  /account/summaries (owner key). `limit` is a whole number of 1 or more;
   *  the server lists at most 200. */
  async listSummaries(limit?: number): Promise<SummaryList> {
    this.requireAPIKey();
    let path = `${ACCOUNT_PATH}/summaries`;
    if (limit !== undefined) {
      requirePositiveId(limit, "limit");
      path += `?limit=${limit}`;
    }
    const out = await this.request<SummaryList>("GET", path);
    if (!Array.isArray(out?.summaries)) {
      throw new VerdifaxError("verdifax: the server's summary list has no summaries list");
    }
    return out;
  }

  /** One period summary exactly as sealed, from GET /account/summaries/{id}
   *  (owner key), with its exact text in `sealedJson`. */
  async getSummary(id: number): Promise<Sealed<PeriodSummary>> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    const out = await this.request<Sealed<PeriodSummary>>("GET", `${ACCOUNT_PATH}/summaries/${id}`);
    checkSummary(out);
    return out;
  }

  /** The feed-head statement a summary counted up to, from GET
   *  /account/summaries/{id}/head (owner key), exactly as Verdifax put it on
   *  the public log, with its exact text in `sealedJson`. It is served also
   *  after later events reach the feed: save it beside the summary and give
   *  it to `verdifax-verify --summary-head` when the feed page you check
   *  does not end with it. */
  async getSummaryHead(id: number): Promise<Sealed<FeedHead>> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    const out = await this.request<Sealed<FeedHead>>("GET", `${ACCOUNT_PATH}/summaries/${id}/head`);
    checkSummaryHead(out, undefined, "GET /account/summaries/{id}/head");
    return out;
  }

  /** One period summary as a PDF for a board, from GET
   *  /account/summaries/{id}/report.pdf (owner key): the sealed figures
   *  printed as stated. Throws {@link VerdifaxError} when the answer is not
   *  a PDF. */
  async downloadSummaryReport(id: number): Promise<Buffer> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    const path = `${ACCOUNT_PATH}/summaries/${id}/report.pdf`;
    const headers: Record<string, string> = { "User-Agent": this.userAgent };
    if (this.apiKey) headers[HEADER_API_KEY] = this.apiKey;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await fetch(this.baseURL + path, { method: "GET", headers, signal: controller.signal });
    } catch (err) {
      throw new VerdifaxError(`verdifax: HTTP transport: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      let message = "summary report download failed";
      try {
        const parsed = (await resp.json()) as { error?: unknown };
        if (typeof parsed.error === "string" && parsed.error) message = parsed.error;
      } catch {
        // Not JSON: keep the generic message.
      }
      if (resp.status === 404) throw new NotFoundError(path, message);
      if (resp.status === 401) throw new AuthError(resp.status, message);
      throw new APIError(resp.status, path, message);
    }
    const pdf = Buffer.from(await resp.arrayBuffer());
    if (pdf.subarray(0, 5).toString("latin1") !== "%PDF-") {
      throw new VerdifaxError("verdifax: the summary report the server sent is not a PDF");
    }
    return pdf;
  }

  /** The response-time report, verdifax.response-times.v1, from GET
   *  /account/signoffs/response-times (owner key): for each result sealed
   *  from `from` to `to`, the waits to its first sign-off, its first
   *  approval and the decision in force, public-log times first with the
   *  sealed record times beside, and the customer's own target where one
   *  applies. A sign-off shows that a registered approver key signed, not
   *  who reviewed. `target` (1 to 31622400 seconds) applies to each result
   *  that seals none; `pack` adds the feed it was counted from, so
   *  `verdifax-verify` can recount it offline. The SDK returns the report as
   *  sent and recounts nothing. */
  async getResponseTimes(from: string, to: string, options: ResponseTimesOptions = {}): Promise<ResponseTimesReport> {
    this.requireAPIKey();
    requireText(from, "from");
    requireText(to, "to");
    refuseUnknownFields(options, { target: true, pack: true }, "getResponseTimes options");
    const query = new URLSearchParams({ from, to });
    if (options.target !== undefined) {
      if (!Number.isSafeInteger(options.target) || options.target < 1 || options.target > MAX_TARGET_SECONDS) {
        throw new VerdifaxError(`verdifax: target must be a whole number of seconds from 1 to ${MAX_TARGET_SECONDS}`);
      }
      query.set("target", String(options.target));
    }
    if (options.pack !== undefined && typeof options.pack !== "boolean") {
      throw new VerdifaxError("verdifax: pack must be true or false");
    }
    if (options.pack) query.set("pack", "1");
    const out = await this.request<ResponseTimesReport>("GET", `${ACCOUNT_PATH}/signoffs/response-times?${query.toString()}`);
    if (out?.form !== RESPONSE_TIMES_FORM) {
      throw new VerdifaxError(`verdifax: the server's report is not ${RESPONSE_TIMES_FORM}`);
    }
    return out;
  }

  /** The owner key's id: the one given, or the one owner key not revoked. */
  private async ownerKeyId(given: number | undefined, method: string): Promise<number> {
    if (given !== undefined) {
      requirePositiveId(given, "keyId");
      return given;
    }
    const owners = (await this.listAccountKeys()).keys.filter((k) => k?.owner === true && k?.revoked !== true);
    if (owners.length !== 1 || !Number.isSafeInteger(owners[0]?.id) || (owners[0]?.id ?? 0) <= 0) {
      throw new VerdifaxError(
        `verdifax: ${method} found ${owners.length} owner keys not revoked; pass keyId, this owner key's id`,
      );
    }
    return owners[0]!.id;
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
    return withList(out, "approvers");
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
    let out: { ok: boolean; signoff: SignOffRecord };
    try {
      out = await this.request<{ ok: boolean; signoff: SignOffRecord }>("POST", base, body);
    } catch (err) {
      if (err instanceof SignOffRefusedError && !refusalNamesSent(err.signoffRefusal, signed)) {
        throw new VerdifaxError(
          "verdifax: the sign-off refusal the server returned does not name the signature and nonce that were sent",
        );
      }
      throw err;
    }
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
  ): Promise<SealedList<SignOffRecord>> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    const base = asOwnerOf(options, "getSignOffs")
      ? `${ACCOUNT_PATH}/runs`
      : "/runs";
    return (
      (await this.request<SealedList<SignOffRecord>>(
        "GET",
        `${base}/${runId}/signoffs`,
      )) ?? parseSealed("[]")
    );
  }

  /** The account's whole chain of sign-offs, oldest first, in the form
   *  `verdifax-verify --signoff-history FILE` reads, with restore gaps and
   *  interrupted records in the places they close. It ends with the
   *  chain's head statement, anchored on the public log, whenever the chain
   *  holds a place; if the head could not be anchored it is left out, and
   *  `verdifax-verify` then cannot call the history complete. Needs the
   *  owner key. */
  async getSignOffHistory(): Promise<SealedList<SignOffRecord | RestoreGapRecord | ChainInterruptedRecord | SignOffHeadRecord>> {
    this.requireAPIKey();
    return (
      (await this.request<SealedList<SignOffRecord | RestoreGapRecord | ChainInterruptedRecord | SignOffHeadRecord>>(
        "GET",
        `${ACCOUNT_SIGNOFFS_PATH}/history`,
      )) ?? parseSealed("[]")
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
   *  options are refused before sending. A page that reaches the feed's end
   *  carries the feed's head statement in `head`, anchored on the public
   *  log; it is not an event. Save the page and check it with
   *  `verdifax-verify --signals`. */
  async getSignals(options: GetSignalsOptions = {}): Promise<Sealed<SignalPage>> {
    this.requireAPIKey();
    const read = signalsRead(options, "getSignals", this.timeoutMs);
    const out = await this.request<Sealed<SignalPage>>(
      "GET",
      read.path,
      undefined,
      false,
      read.timeoutMs,
    );
    // The page keeps its exact text; an absent list reads as empty, and
    // anything else is left for the follower to refuse.
    if (out && (out.events === undefined || out.events === null)) {
      out.events = parseSealed<SealedList<SignalEvent>>("[]");
    }
    return out;
  }

  /** Follows the feed from `after`, yielding each event once, in order,
   *  until you stop with `break` or `return`. Each read starts at the page
   *  before's `next_after`, waits up to `wait` seconds (default 25) when
   *  there is no event, and is retried like any GET. A read that still
   *  fails throws {@link SignalFeedError}, whose `lastSequence` is the last
   *  sequence yielded and whose `afterEventHash` is that event's hash: follow
   *  again from there with both and nothing is lost. Bad
   *  options are refused here, before anything is sent. A page's feed head
   *  is never yielded as an event. The returned follower's `head` is the
   *  newest head kept: one whose `sequence` is its page's `next_after` and
   *  whose `head_hash` is the `event_hash` of the last event you finished,
   *  kept once you have moved past every event on that page, so it never
   *  states the feed beyond the events you handled. Each newer head kept
   *  is also passed to `onHead`. */
  followSignals(
    options: FollowSignalsOptions = {},
  ): SignalFollower {
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

  /** Subscribes an https address to the account's signals, with the owner
   *  key. `types` are the kinds to deliver, each once; empty or left out
   *  takes every kind. The secret, `whsec_` and base64, is in the result
   *  this once: check each delivery with {@link verifyWebhook}. A delivery
   *  is a copy: the pull feed and the public log are the record. The server
   *  checks the address too, and refuses an eleventh subscription with HTTP
   *  409.
   *
   *  From verifier v0.35.0's server release on, the subscription is added
   *  only with its record in the account's feed, an `account.changed`
   *  event `webhook.subscribed` signed by the owner key's request key over
   *  {@link webhookValue}: the SHA-256 of the address, never the address,
   *  and the kinds. So this needs the `signingKey` option and refuses to
   *  send without it. Send the address exactly as the server stores it: the
   *  server refuses another form with HTTP 400 naming the stored one. The
   *  label, `account-N`, is read from {@link getAccount} unless `accountId`
   *  is given. The record returned must seal the change, the value,
   *  `decided_by` owner and the signature sent, or this throws
   *  {@link VerdifaxError}. The new subscription receives its own record's
   *  event first. */
  async createWebhook(
    url: string,
    options: CreateWebhookOptions = {},
  ): Promise<CreatedWebhook> {
    this.requireAPIKey();
    const body = webhookBody(url, options);
    const value = webhookValue(body.url, body.types ?? []);
    const signed = await this.ownerSigned("createWebhook", WEBHOOK_SUBSCRIBED, value, options);
    // The same body, in the same order, as every SDK sends: the address, the
    // kinds when named, then the owner's signature.
    const sent: { url: string; types?: string[]; owner_signature?: OwnerChangeSignature } = { url: body.url };
    if (body.types !== undefined) sent.types = body.types;
    sent.owner_signature = signed.owner_signature;
    const out = await this.request<CreatedWebhook>("POST", WEBHOOKS_PATH, sent);
    return checkWebhookChange(out, WEBHOOK_SUBSCRIBED, value, signed);
  }

  /** The account's webhook subscriptions, without their secrets. */
  async listWebhooks(): Promise<WebhookList> {
    this.requireAPIKey();
    const out = await this.request<WebhookList>("GET", WEBHOOKS_PATH);
    return withList(out, "webhooks");
  }

  /** Ends a webhook subscription, with the owner key. Its events stay in
   *  the pull feed. The client reads the subscription from
   *  {@link listWebhooks} and signs `webhook.deleted` over its
   *  {@link webhookValue} with the owner key's request key; the removal is
   *  sealed in the account's feed, and the removed subscription is not sent
   *  that event. Needs the `signingKey` option, and refuses to send without
   *  it. Throws {@link VerdifaxError} when the account holds no live
   *  subscription with this id, or the record returned does not seal what
   *  was sent. */
  async deleteWebhook(id: number, options: OwnerChangeOptions = {}): Promise<WebhookDeletion> {
    this.requireAPIKey();
    requirePositiveId(id, "id");
    this.requireOwnerSigningKey("deleteWebhook");
    const hook = (await this.listWebhooks()).webhooks.find((w) => w.id === id);
    if (!hook) throw new VerdifaxError(`verdifax: the account holds no webhook ${id}`);
    const value = webhookValue(hook.url, hook.types ?? []);
    const signed = await this.ownerSigned("deleteWebhook", WEBHOOK_DELETED, value, options);
    const out = await this.request<WebhookDeletion>("DELETE", `${WEBHOOKS_PATH}/${id}`, {
      owner_signature: signed.owner_signature,
    });
    return checkWebhookChange(out, WEBHOOK_DELETED, value, signed);
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
    return withList(out, "deliveries");
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
    if (params.lenient) q.set("lenient", "1");
    const qs = q.toString();
    const path = qs ? `${base}?${qs}` : base;
    const out = await this.request<{
      ok: boolean;
      runs: RunSummary[];
      total: number;
    }>("GET", path);
    return { runs: out.runs ?? parseSealed("[]"), total: out.total ?? 0 };
  }

  /** Searches this key's runs. `manifest_hash` matches a prefix. A
   *  `from` or `to` the server cannot read throws an APIError (400) unless
   *  `lenient` is set, which asks the server to leave it out instead. */
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
    if (params.lenient) q.set("lenient", "1");
    const qs = q.toString();
    const path = qs ? `/runs/search?${qs}` : "/runs/search";
    const out = await this.request<{
      ok: boolean;
      runs: RunSummary[];
      total: number;
    }>("GET", path);
    return { runs: out.runs ?? parseSealed("[]"), total: out.total ?? 0 };
  }

  /** Lists what the server holds for this key in a period, failures
   *  included, up to 10,000 rows. `truncated` is true when the period
   *  holds more. The list states what was stored, not a verdict, and a
   *  call that never reached Verdifax cannot appear in it. */
  async exportRuns(params: ExportRunsParams = {}): Promise<Sealed<RunsExport>> {
    this.requireAPIKey();
    return this.request<Sealed<RunsExport>>(
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
    if (params.lenient) q.set("lenient", "1");
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

  /** The sign-off a published run's audit report prints: the decision in
   *  force, and for a step of a job the job's decision on its final step.
   *  Needs no API key. */
  async getPublicSignOffByToken(token: string): Promise<PublicSignOffAnswer> {
    if (!token) throw new VerdifaxError("verdifax: token is required");
    return this.request<PublicSignOffAnswer>(
      "GET",
      `/public/runs/${encodeURIComponent(token)}/signoff.json`,
    );
  }

  /** {@link getPublicSignOffByToken} for a run made public before share
   *  tokens, by its number. Needs no API key. */
  async getPublicSignOff(runId: number): Promise<PublicSignOffAnswer> {
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return this.request<PublicSignOffAnswer>("GET", `/runs/${runId}/signoff.json`);
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
   *  "comprehensive" when not specified; a format the server does not know
   *  throws an APIError (400) unless `fallback: "comprehensive"` is set. With `aiOutputText`, the AI's
   *  exact answer, the report prints it on its first page, marked as
   *  supplied by the caller, only when its SHA-256 is the hash the record
   *  seals; other text throws an APIError (422). Verdifax stores only the
   *  hash. */
  async downloadAuditPDF(
    runId: number,
    format: PDFFormat = "comprehensive",
    options: AuditPDFOptions = {},
  ): Promise<Buffer> {
    this.requireAPIKey();
    if (runId <= 0) throw new VerdifaxError("verdifax: runId must be > 0");
    return this.fetchAuditPDF(`/runs/${runId}/report.pdf`, format, options);
  }

  /** The audit PDF of a published record a share token points to, with
   *  the answer printed as `downloadAuditPDF` prints it. Needs no API key. */
  async downloadPublicAuditPDF(
    token: string,
    format: PDFFormat = "comprehensive",
    options: AuditPDFOptions = {},
  ): Promise<Buffer> {
    if (!token) throw new VerdifaxError("verdifax: token is required");
    return this.fetchAuditPDF(
      `/public/runs/${encodeURIComponent(token)}/report.pdf`,
      format,
      options,
    );
  }

  private async fetchAuditPDF(
    base: string,
    format: PDFFormat,
    options: AuditPDFOptions,
  ): Promise<Buffer> {
    const answer = options.aiOutputText;
    if (answer !== undefined && (typeof answer !== "string" || answer === "")) {
      throw new VerdifaxError(
        "verdifax: aiOutputText must be the AI's exact answer, a non-empty string",
      );
    }
    const headers: Record<string, string> = { "User-Agent": this.userAgent };
    if (this.apiKey) headers[HEADER_API_KEY] = this.apiKey;
    let path = base;
    let body: string | undefined;
    const fallback = options.fallback;
    if (answer === undefined) {
      const query = new URLSearchParams({ format });
      if (fallback !== undefined) query.set("fallback", fallback);
      path += `?${query.toString()}`;
    } else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(
        fallback === undefined
          ? { format, ai_output_text: answer }
          : { format, fallback, ai_output_text: answer },
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await fetch(this.baseURL + path, {
        method: answer === undefined ? "GET" : "POST",
        headers,
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      let message = "audit PDF download failed";
      try {
        const parsed = (await resp.json()) as { error?: unknown };
        if (typeof parsed.error === "string" && parsed.error) message = parsed.error;
      } catch {
        // Not JSON: keep the generic message.
      }
      throw new APIError(resp.status, path, message);
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
    return out.receipts ?? parseSealed("[]");
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
    return out?.accounts ?? parseSealed("[]");
  }

  /** Starts the replacement of a lost owner key, on the owner's written
   *  request. `accountId` is the account's number, as
   *  {@link adminListAccounts} lists it in `id`. The request is sealed in the
   *  account's feed as Verdifax's decision, and a one-time link, good for
   *  72 hours, is emailed to the address of the access request that made
   *  the account. The result never holds the link or a key: the new key is
   *  made when the owner opens the link, so Verdifax never sees it. The
   *  server refuses it with an HTTP 409 while the owner blocks owner-key
   *  replacement, or when no address is on file. */
  async adminReplaceOwnerKey(accountId: number): Promise<OwnerKeyReplacement> {
    this.requireAPIKey();
    requirePositiveId(accountId, "accountId");
    return this.request<OwnerKeyReplacement>(
      "POST",
      `/admin/accounts/${accountId}/owner-key/replace`,
    );
  }

  /** Places Verdifax's own stop on an account with POST
   *  /admin/accounts/{id}/stop, sealed in the account's feed as Verdifax's
   *  decision. The server refuses it with an HTTP 409 while the owner
   *  blocks Verdifax stops. The record returned must seal the action, scope
   *  and reason hash sent, decided by verdifax_admin, or this throws
   *  {@link VerdifaxError}. */
  async adminStopAccount(accountId: number, options: AdminStopAccountOptions = {}): Promise<AccountStopResult> {
    this.requireAPIKey();
    requirePositiveId(accountId, "accountId");
    const scope = stopScopeOf(options.signoffs, options.webhooks);
    const reasonHash = stopReasonHash(options.reason);
    const body: Record<string, unknown> = { signoffs: scope.signoffs, webhooks: scope.webhooks };
    if (reasonHash) body.reason = options.reason;
    const out = await this.request<AccountStopResult>("POST", `/admin/accounts/${accountId}/stop`, body);
    const record = checkedStopRecord(out, "stop", "verdifax_admin", scope, reasonHash);
    if (record.owner_signature !== undefined) {
      throw new VerdifaxError("verdifax: Verdifax's stop the server returned carries an owner_signature");
    }
    return out;
  }

  /** Lifts Verdifax's own stop with POST /admin/accounts/{id}/resume. It
   *  never lifts the owner's. `liftsSequence`, when given, must name the
   *  stop that stands. */
  async adminResumeAccount(accountId: number, options: AdminResumeAccountOptions = {}): Promise<AccountStopResult> {
    this.requireAPIKey();
    requirePositiveId(accountId, "accountId");
    const reasonHash = stopReasonHash(options.reason);
    const body: Record<string, unknown> = {};
    if (options.liftsSequence !== undefined) {
      requirePositiveId(options.liftsSequence, "liftsSequence");
      body.lifts_sequence = options.liftsSequence;
    }
    if (reasonHash) body.reason = options.reason;
    const out = await this.request<AccountStopResult>("POST", `/admin/accounts/${accountId}/resume`, body);
    const record = checkedStopRecord(out, "resume", "verdifax_admin", undefined, reasonHash);
    if (options.liftsSequence !== undefined && record.lifts_sequence !== options.liftsSequence) {
      throw new VerdifaxError("verdifax: the resume the server returned lifts another stop than the one named");
    }
    return out;
  }

  /** Deletes one record as Verdifax's decision, sealed as a tombstone in
   *  the feed of the record's account. The server refuses it with an HTTP
   *  409 while the account's owner blocks Verdifax deletion, and for a
   *  public record until it is withdrawn. */
  async adminDeleteRun(runId: number): Promise<RunDeletionResult> {
    this.requireAPIKey();
    requirePositiveId(runId, "runId");
    return this.request<RunDeletionResult>(
      "POST",
      `/admin/runs/${runId}/delete`,
    );
  }

  async adminListKeys(): Promise<AdminAPIKey[]> {
    this.requireAPIKey();
    const out = await this.request<{ ok: boolean; keys: AdminAPIKey[] }>(
      "GET",
      "/admin/keys",
    );
    return out.keys ?? parseSealed("[]");
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
        let aivpTraceText: string | undefined;
        try {
          const env = JSON.parse(text) as {
            error?: string;
            record_hash?: unknown;
            aivp_trace_text?: unknown;
          };
          if (env.error) errMessage = env.error;
          if (typeof env.record_hash === "string" && env.record_hash) {
            recordHash = env.record_hash;
          }
          if (typeof env.aivp_trace_text === "string" && env.aivp_trace_text) {
            aivpTraceText = env.aivp_trace_text;
          }
        } catch {
          /* fall through to raw text */
        }
        const refusal = signOffRefusalOf(resp.status, path, text);
        if (refusal !== undefined) {
          throw new SignOffRefusedError(resp.status, path, errMessage, refusal, recordHash);
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
              aivpTraceText,
            );
        }
      }

      if (rawText) return { text, headers: resp.headers } as T;
      if (text.length === 0) return undefined as T;
      try {
        // Every object and list keeps the exact text the server sent, in
        // sealedJson, so no sealed record is rounded or loses a field
        // (round 57, N5).
        return parseSealed<T>(text);
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

const PERIOD_SUMMARY_FORM = "verdifax.period-summary.v1";
const RESPONSE_TIMES_FORM = "verdifax.response-times.v1";
const MAX_TARGET_SECONDS = 366 * 24 * 3600;

/** A non-empty string argument, or a refusal before sending. */
function requireText(value: unknown, name: string): void {
  if (typeof value !== "string" || value === "") {
    throw new VerdifaxError(`verdifax: ${name} must be a non-empty string, an RFC 3339 time`);
  }
}

/** A period summary as sealed: its format and its hash, or a refusal. */
function checkSummary(summary: unknown): void {
  const s = summary as { format?: unknown; summary_hash?: unknown } | undefined;
  if (s?.format !== PERIOD_SUMMARY_FORM || typeof s.summary_hash !== "string" || !/^[0-9a-f]{64}$/.test(s.summary_hash)) {
    throw new VerdifaxError(`verdifax: the server's summary is not a sealed ${PERIOD_SUMMARY_FORM}`);
  }
}

/** Checks the shape of a summary's feed-head statement, and, when the
 *  summary is given, that it is the head the summary names. */
function checkSummaryHead(head: unknown, summary: PeriodSummary | undefined, source: string): void {
  const h = head as Partial<FeedHead> | undefined;
  const hex = (v: unknown): boolean => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  if (
    typeof h !== "object" || h === null || Array.isArray(h) || h.format !== "verdifax.feed-head.v1" ||
    typeof h.account !== "string" || !/^account-[0-9]+$/.test(h.account) ||
    !Number.isSafeInteger(h.sequence) || (h.sequence as number) <= 0 ||
    !hex(h.head_hash) || !hex(h.head_statement_hash) || typeof h.stated_at !== "string" || h.stated_at === "" ||
    (h.anchor !== undefined && h.anchor !== null && (typeof h.anchor !== "object" || Array.isArray(h.anchor)))
  ) {
    throw new VerdifaxError(`verdifax: ${source} returned a head that is not a verdifax.feed-head.v1 statement`);
  }
  if (
    summary !== undefined &&
    (h.head_statement_hash !== summary.head_statement_hash || h.sequence !== summary.head_sequence || h.head_hash !== summary.head_hash)
  ) {
    throw new VerdifaxError(`verdifax: ${source} returned a head that is not the one its summary names`);
  }
}

/** The sealed refusal on the 409 a sign-off route answers while a stop
 *  refusing sign-offs stands, or undefined for every other answer. It keeps
 *  the server's exact text in sealedJson. */
function signOffRefusalOf(status: number, path: string, text: string): SignOffRefusalRecord | undefined {
  if (status !== 409 || (path !== SIGNOFFS_PATH && path !== ACCOUNT_SIGNOFFS_PATH)) return undefined;
  let env: { error_code?: unknown; signoff_refusal?: unknown };
  try {
    env = parseSealed<{ error_code?: unknown; signoff_refusal?: unknown }>(text);
  } catch {
    return undefined;
  }
  const refusal = env?.signoff_refusal;
  if (env?.error_code !== "ACCOUNT_STOPPED" || typeof refusal !== "object" || refusal === null || Array.isArray(refusal)) {
    return undefined;
  }
  return refusal as SignOffRefusalRecord;
}

/** True when a sealed sign-off refusal names the sign-off that was sent. */
function refusalNamesSent(refusal: SignOffRefusalRecord, sent: { signature: string; nonce: string }): boolean {
  return (
    refusal.format === "verdifax.signoff-refusal.v1" &&
    refusal.signature === sent.signature &&
    refusal.nonce === sent.nonce
  );
}

/** A stop or resume answer's record, checked against what was sent: the
 *  action, who decided, the scope (a resume carries none) and the reason's
 *  hash. Throws {@link VerdifaxError} on any difference. */
function checkedStopRecord(
  out: AccountStopResult,
  action: "stop" | "resume",
  decidedBy: "owner" | "verdifax_admin",
  scope: StopScope | undefined,
  reasonHash: string,
): AccountStopRecord {
  const record = out?.account_stop;
  const sealedScope = record?.scope;
  const scopeMatches =
    scope === undefined
      ? sealedScope === undefined || sealedScope === null
      : typeof sealedScope === "object" &&
        sealedScope !== null &&
        sealedScope.signoffs === scope.signoffs &&
        sealedScope.webhooks === scope.webhooks;
  if (
    typeof record !== "object" ||
    record === null ||
    record.format !== "verdifax.account-stop.v1" ||
    record.action !== action ||
    record.decided_by !== decidedBy ||
    !scopeMatches ||
    (record.reason_sha256 ?? "") !== reasonHash
  ) {
    throw new VerdifaxError(
      `verdifax: the ${action} the server returned does not seal the action, decided_by, scope and reason that were sent`,
    );
  }
  return record;
}

/** An owner signature as sent, with the public key of the key that made it. */
interface SentOwnerSignature {
  owner_signature: OwnerChangeSignature;
  public_key: string;
}

/** True when a sealed owner signature is the one that was sent, under the
 *  client's own request key. */
/** A webhook change's answer, checked: its record must seal the change, the
 *  value, `decided_by` owner and the signature sent. */
function checkWebhookChange<T extends { account_change?: AccountChange }>(
  out: T,
  action: string,
  value: string,
  signed: SentOwnerSignature,
): T {
  const change = out?.account_change;
  if (
    typeof change !== "object" ||
    change === null ||
    change.action !== action ||
    change.value !== value ||
    change.decided_by !== "owner" ||
    !ownerSignatureMatchesSent(change.owner_signature, signed)
  ) {
    throw new VerdifaxError(
      "verdifax: the webhook change the server returned does not seal the action, value, decided_by owner and owner_signature that were sent",
    );
  }
  return out;
}

function ownerSignatureMatchesSent(
  sealed: OwnerSignature | undefined,
  sent: SentOwnerSignature,
): boolean {
  return (
    typeof sealed === "object" &&
    sealed !== null &&
    sealed.public_key === sent.public_key &&
    sealed.signature === sent.owner_signature.signature &&
    sealed.signed_at === sent.owner_signature.signed_at &&
    sealed.nonce === sent.owner_signature.nonce
  );
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
  if (!("signed_request" in sent)) return result;
  // The parsed result keeps its sealedJson: the text is added to it, not
  // copied into a new object.
  if (result !== null && typeof result === "object") {
    (result as Record<string, unknown>).signed_request = sent.signed_request;
    return result;
  }
  // No answer body: the text alone, as before.
  return { signed_request: sent.signed_request } as T;
}

/** The parsed answer with an absent list read as empty. The answer itself
 *  is returned, so it keeps the server's exact text in sealedJson. */
function withList<T extends object, K extends keyof T>(out: T, field: K): T {
  if (out === undefined || out === null) {
    return { [field]: parseSealed("[]") } as unknown as T;
  }
  if (out[field] === undefined || out[field] === null) {
    (out as Record<K, unknown>)[field] = parseSealed("[]");
  }
  return out;
}
