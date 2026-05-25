/**
 * Input-validation helpers, mirrors the Python SDK's
 * `_validation.py` and the Go SDK's `validation.go` for
 * cross-language parity.
 *
 * Every helper throws (rather than returning a boolean) so the
 * SDK's type system surfaces the failure as a typed error.
 */

import { VerdifaxError } from "./errors.js";

/** Throws unless `value` is exactly 64 lowercase hex characters , 
 *  the §0-canonical SHA-256 encoding the orchestrator expects for
 *  program_id, registry_record_hash, manifest_hash, and
 *  ciphertext_hash. */
export function validateHex64(value: string, fieldName: string): void {
  if (typeof value !== "string" || value.length !== 64) {
    throw new VerdifaxError(
      `verdifax: ${fieldName} must be 64 hex characters (got ${
        typeof value === "string" ? value.length : typeof value
      })`,
    );
  }
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new VerdifaxError(
      `verdifax: ${fieldName} must contain only lowercase hex (0-9, a-f)`,
    );
  }
}

/** Throws unless `value` is a non-empty, printable-ASCII route
 *  identifier of bounded length (≤ 256). The orchestrator accepts
 *  a wider character set, but the SDK enforces the conservative
 *  subset by default to catch typos early. */
export function validateRouteId(value: string): void {
  if (!value || typeof value !== "string") {
    throw new VerdifaxError("verdifax: route_id is required");
  }
  if (value.length > 256) {
    throw new VerdifaxError(
      `verdifax: route_id is too long (${value.length} > 256)`,
    );
  }
  if (!/^[\x20-\x7E]+$/.test(value)) {
    throw new VerdifaxError(
      "verdifax: route_id contains non-printable-ASCII character",
    );
  }
}
