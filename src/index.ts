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
export { VerdifaxJob } from "./job.js";
export { fromEnv } from "./config.js";
export { captureEnvironment } from "./environment.js";
export { EXECUTE_FIELDS, formatProviderPayload } from "./helpers.js";
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
  policyActivationApproval,
  policyActivationPreimage,
  requestKeyChangeApproval,
  requestKeyChangePreimage,
  requestKeyRegistrationBody,
  requestSignaturePreimage,
  requestSignaturePreimageV2,
  signRequest,
  signRequestV2,
} from "./signing.js";
export {
  validateHex64,
  validateJobName,
  validateRouteId,
} from "./validation.js";

export {
  APIError,
  APIKeyRequiredError,
  AuthError,
  NotFoundError,
  VerdifaxError,
} from "./errors.js";

export type {
  Account,
  AccountInfo,
  AccountKey,
  AccountKeyList,
  AccountKeyRevocation,
  AccountRunsExport,
  AdminAPIKey,
  AdminCreateAccountOptions,
  AdminCreateAccountResponse,
  AdminCreateKeyOptions,
  AdminCreateKeyResponse,
  AdminEraseRequest,
  AttestationList,
  AttestRequest,
  ClientConfig,
  CreateAccountKeyOptions,
  CreatedAccountKey,
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
  JobLink,
  JobStepOptions,
  KeyTier,
  ListAttestationsParams,
  ListRunsParams,
  PDFFormat,
  Policy,
  PolicyActivation,
  PolicyActivationSignature,
  PolicyActorType,
  PolicyClassification,
  PolicyContext,
  PolicyList,
  PolicyObjectType,
  PolicyTestRequest,
  PolicyTestResult,
  PolicyWithDocument,
  RequestKeyChange,
  RequestKeyPair,
  RequestKeyRegistration,
  RequestKeyRegistrationBody,
  RequestSignature,
  RequestSignatureV2,
  ReproducibilityContext,
  Run,
  RunsExport,
  RunsExportCSV,
  RunStats,
  RunStatus,
  RunSummary,
  SearchRunsParams,
  SignedRequestBody,
  VerdifaxVersion,
  VerifyDeterminismResponse,
  VerifyResponse,
} from "./types.js";
