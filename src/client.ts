import {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  VerdifaxError,
} from "./errors.js";
import type {
  AdminAPIKey,
  AdminCreateKeyResponse,
  AdminEraseRequest,
  AttestRequest,
  ClientConfig,
  DCAEProofBundle,
  DCAEVerdict,
  DeletionReceipt,
  ExecuteRequest,
  ExecuteResponse,
  Health,
  Hex64,
  ListRunsParams,
  PDFFormat,
  Run,
  RunSummary,
  VerdifaxVersion,
  VerifyResponse,
} from "./types.js";
import { validateHex64, validateRouteId } from "./validation.js";

const DEFAULT_BASE_URL = "https://api.verdifax.com";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 200;
const SDK_USER_AGENT = "verdifax-sdk-node/0.2.0";
const HEADER_API_KEY = "X-Verdifax-Key";

const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);

/**
 * The Verdifax SDK client.
 *
 * Carries Python-parity surface coverage:
 *
 * | Method | HTTP | Auth |
 * | --- | --- | --- |
 * | `health()` | GET /health | none |
 * | `version()` | GET /version | none |
 * | `execute(req)` | POST /execute | required |
 * | `attest(req)` | POST /execute (helper) | required |
 * | `getRun(id)` | GET /runs/{id} | required |
 * | `verifyRun(id)` | GET /runs/{id}/verify | required |
 * | `listRuns(params)` | GET /runs | required |
 * | `downloadAuditPDF(id, format)` | GET /runs/{id}/report.pdf | required |
 * | `getAllowToken(id)` | GET /runs/{id}/allow-token | required |
 * | `getDenyReceipt(id)` | GET /runs/{id}/deny-receipt | required |
 * | `getCCVHaltReceipt(id)` | GET /runs/{id}/ccv-halt-receipt | required |
 * | `getMACCHaltReceipt(id)` | GET /runs/{id}/macc-halt-receipt | required |
 * | `getAivpT4HaltReceipt(id)` | GET /runs/{id}/aivp-t4-halt-receipt | required |
 * | `listDeletionReceipts(id)` | GET /runs/{id}/deletion-receipts | required |
 * | `adminErase(req)` | POST /admin/erase | required |
 * | `dcaeVerify(bundle)` | POST /dcae/verify | none |
 * | `adminCreateKey(name)` | POST /admin/keys | required |
 * | `adminListKeys()` | GET /admin/keys | required |
 * | `adminRevokeKey(id)` | DELETE /admin/keys/{id} | required |
 * | `attestClaudeResponse(...)` | POST /execute (helper) | required |
 * | `attestOpenAIResponse(...)` | POST /execute (helper) | required |
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
  }

  // ── Health + Version (anonymous) ──────────────────────────────

  async health(): Promise<Health> {
    return this.request<Health>("GET", "/health");
  }

  async version(): Promise<VerdifaxVersion> {
    return this.request<VerdifaxVersion>("GET", "/version");
  }

  // ── Execute / Attest (auth) ───────────────────────────────────

  async execute(req: ExecuteRequest): Promise<ExecuteResponse> {
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
    return this.request<ExecuteResponse>("POST", "/execute", req);
  }

  /** High-level convenience wrapper around `execute()`. Accepts
   *  either a Buffer (for binary payloads, auto-base64) or a
   *  string (for plain text). Validates the hex fields and
   *  routes the call through to the canonical /execute. */
  async attest(req: AttestRequest): Promise<ExecuteResponse> {
    this.requireAPIKey();
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

  // ── Provider helpers (Claude / OpenAI) ───────────────────────

  /** Convenience for attesting an Anthropic Claude API response.
   *  Wires the response text into the AIVP-T4 governance pipeline
   *  by setting `ai_output_text`. */
  async attestClaudeResponse(args: {
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
  }): Promise<ExecuteResponse> {
    return this.attestProviderResponse({ ...args, provider: "anthropic" });
  }

  /** Convenience for attesting an OpenAI API response. */
  async attestOpenAIResponse(args: {
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
  }): Promise<ExecuteResponse> {
    return this.attestProviderResponse({ ...args, provider: "openai" });
  }

  private async attestProviderResponse(args: {
    provider: string;
    program_id: Hex64;
    route_id: string;
    registry_record_hash: Hex64;
    prompt: string;
    response: string;
  }): Promise<ExecuteResponse> {
    if (!args.response) {
      throw new VerdifaxError(
        "verdifax: response is required for attestation",
      );
    }
    const payloadText = JSON.stringify({
      provider: args.provider,
      prompt: args.prompt,
      response: args.response,
    });
    return this.attest({
      payload_text: payloadText,
      program_id: args.program_id,
      route_id: args.route_id,
      registry_record_hash: args.registry_record_hash,
      ai_output_text: args.response,
      attested_context: {
        actor_role: "ai_assistant",
        model_provider: args.provider,
      },
    });
  }

  // ── HTTP plumbing, retry-aware ──────────────────────────────

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
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
        try {
          const env = JSON.parse(text) as { error?: string };
          if (env.error) errMessage = env.error;
        } catch {
          /* fall through to raw text */
        }
        switch (resp.status) {
          case 401:
            throw new AuthError(resp.status, errMessage);
          case 404:
            throw new NotFoundError(path, errMessage);
          default:
            throw new APIError(resp.status, path, errMessage);
        }
      }

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

  private requireAPIKey(): void {
    if (!this.apiKey) throw new APIKeyRequiredError();
  }
}
