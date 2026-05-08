/**
 * Public API surface for the Verdifax Node.js / TypeScript SDK.
 *
 * Re-exports the client class, error classes, and every type
 * definition. Callers import from "verdifax" directly:
 *
 * ```typescript
 * import { VerdifaxClient, type ExecuteRequest, NotFoundError } from "verdifax";
 * ```
 */

export { VerdifaxClient } from "./client.js";
export { fromEnv } from "./config.js";
export { validateHex64, validateRouteId } from "./validation.js";

export {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  VerdifaxError,
} from "./errors.js";

export type {
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
  ExecutionManifest,
  FormulaEra,
  Health,
  Hex64,
  ListRunsParams,
  PDFFormat,
  Run,
  RunSummary,
  VerdifaxVersion,
  VerifyResponse,
} from "./types.js";
