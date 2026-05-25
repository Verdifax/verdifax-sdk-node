/**
 * Environment-variable constructor, mirrors the Python SDK's
 * `from_env()` and the Go SDK's `FromEnv()` for polyglot parity.
 *
 * Variables consumed (identical names across SDKs):
 *
 *   VERDIFAX_BASE_URL    base URL (defaults to https://api.verdifax.com)
 *   VERDIFAX_API_KEY     X-Verdifax-Key value
 *   VERDIFAX_TIMEOUT_MS  per-request timeout in ms (defaults to 30000)
 *   VERDIFAX_USER_AGENT  override the default User-Agent
 *   VERDIFAX_MAX_RETRIES retry budget for idempotent GETs (defaults to 3)
 */

import { VerdifaxClient } from "./client.js";
import { VerdifaxError } from "./errors.js";
import type { ClientConfig } from "./types.js";

export function fromEnv(): VerdifaxClient {
  const cfg: ClientConfig = {
    baseURL: process.env.VERDIFAX_BASE_URL ?? undefined,
    apiKey: process.env.VERDIFAX_API_KEY ?? undefined,
    userAgent: process.env.VERDIFAX_USER_AGENT ?? undefined,
  };

  const timeoutRaw = process.env.VERDIFAX_TIMEOUT_MS;
  if (timeoutRaw !== undefined && timeoutRaw !== "") {
    const ms = Number.parseInt(timeoutRaw, 10);
    if (!Number.isFinite(ms)) {
      throw new VerdifaxError(
        `verdifax: VERDIFAX_TIMEOUT_MS=${timeoutRaw!} is not an integer`,
      );
    }
    cfg.timeoutMs = ms;
  }

  const retriesRaw = process.env.VERDIFAX_MAX_RETRIES;
  if (retriesRaw !== undefined && retriesRaw !== "") {
    const n = Number.parseInt(retriesRaw, 10);
    if (!Number.isFinite(n)) {
      throw new VerdifaxError(
        `verdifax: VERDIFAX_MAX_RETRIES=${retriesRaw!} is not an integer`,
      );
    }
    cfg.maxRetries = n;
  }

  return new VerdifaxClient(cfg);
}
