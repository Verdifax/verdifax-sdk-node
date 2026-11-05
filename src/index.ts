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

export { MAX_BATCH_ROWS, VerdifaxClient } from "./client.js";
export { fromEnv } from "./config.js";
export { captureEnvironment } from "./environment.js";
export { formatProviderPayload } from "./helpers.js";
export { RUN_STATUSES } from "./types.js";
export {
  CRES_ENGINE_VERSION,
  CRES_PREIMAGE_VERSION,
  cresReceiptHash,
  DCAE_PREIMAGE_VERSION,
  dcaeClosureHash,
  DSE_FORMULA_VERSION,
  dseDispatchHash,
} from "./section0.js";
export {
  generateRequestKeyPair,
  requestKeyRegistrationBody,
  requestSignaturePreimage,
  signRequest,
} from "./signing.js";
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
  AttestationList,
  AttestRequest,
  ClientConfig,
  DCAEProofBundle,
  DCAEVerdict,
  DeletionReceipt,
  DeterminismDiff,
  DeterminismRun,
  ExecuteBatchResponse,
  ExecuteBatchResult,
  ExecuteRequest,
  ExecuteResponse,
  ExecutionManifest,
  ExportRow,
  ExportRunsParams,
  FormulaEra,
  Health,
  Hex64,
  ListAttestationsParams,
  ListRunsParams,
  PDFFormat,
  RequestKeyPair,
  RequestKeyRegistration,
  RequestKeyRegistrationBody,
  RequestSignature,
  ReproducibilityContext,
  Run,
  RunsExport,
  RunsExportCSV,
  RunStats,
  RunStatus,
  RunSummary,
  SearchRunsParams,
  VerdifaxVersion,
  VerifyDeterminismResponse,
  VerifyResponse,
} from "./types.js";
