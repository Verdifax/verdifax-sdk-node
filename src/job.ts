/**
 * The job helper: runs the steps of one job and keeps the map of step ids
 * to record hashes, so a later step can name the steps it follows.
 */

import { APIError, VerdifaxError } from "./errors.js";
import { refuseUnknownFields } from "./helpers.js";
import type {
  AttestRequest,
  ExecuteResponse,
  Hex64,
  JobStepOptions,
} from "./types.js";
import { validateJobName } from "./validation.js";

// `attest` copies named fields only, so a mistyped option would vanish before
// the job block is checked and `afer` would silently use the default link. A
// Record, so the compiler fails here if JobStepOptions gains a field.
const STEP_OPTIONS: Record<keyof JobStepOptions, true> = {
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
  policy_context: true,
  expected_policy_hash: true,
  after: true,
  external_previous: true,
  final: true,
};

/** Returned by {@link VerdifaxClient.job}.
 *
 *  Every step goes through `attest`, so it signs when the client signs. A
 *  refused or halted step stays in the map and a later step can name it.
 *  A step that sealed nothing, for example a timeout or a 409, is not in the
 *  map and does not move the default `after`, so it can run again under the
 *  same id. An empty `after` starts another root step.
 *
 *  `signedRequests` holds the payloads of signed steps, so it is a private
 *  field: logging a job prints the hashes and not that text.
 *
 *  To run branches at the same time, give each its `after`: the default
 *  reads the last step that finished. */
export class VerdifaxJob {
  readonly jobId: string;
  private readonly client: { attest(req: AttestRequest): Promise<ExecuteResponse> };
  private readonly hashes = new Map<string, Hex64>();
  readonly #signedRequests = new Map<string, string>();
  private lastStepId: string | undefined;

  constructor(
    client: { attest(req: AttestRequest): Promise<ExecuteResponse> },
    jobId: string,
  ) {
    validateJobName(jobId, "job_id");
    this.client = client;
    this.jobId = jobId;
  }

  /** Step id to record hash for every step that left a record, on a copy. */
  get recordHashes(): Record<string, Hex64> {
    return Object.fromEntries(this.hashes);
  }

  /** Step id to the exact text that was signed, for every signed step that
   *  left a record, refused and halted steps included, on a copy. Each text
   *  can be passed to `verdifax-verify --request FILE`. */
  get signedRequests(): Record<string, string> {
    return Object.fromEntries(this.#signedRequests);
  }

  /** Runs one step and records its hash and signed text. A refused or halted
   *  step records both from the error, then throws the same error `attest`
   *  throws. */
  async step(
    stepId: string,
    options: JobStepOptions,
  ): Promise<ExecuteResponse> {
    validateJobName(stepId, "step_id");
    refuseUnknownFields(options, STEP_OPTIONS, "step options");
    const { after, external_previous, final, ...attest } = options;
    const job = {
      job_id: this.jobId,
      step_id: stepId,
      previous_record_hashes: this.previousHashes(after),
      external_previous,
      final,
    };
    let result: ExecuteResponse;
    try {
      result = await this.client.attest({ ...attest, job });
    } catch (err) {
      if (err instanceof APIError && err.recordHash) {
        this.record(stepId, err.recordHash, err.signedRequest);
      }
      throw err;
    }
    // A completed run's record hash is its manifest hash. /execute nests that
    // in `manifest`, and only batch rows have it at the top level.
    const hash =
      result?.record_hash ||
      result?.manifest_hash ||
      result?.manifest?.ManifestHash;
    if (!hash) {
      throw new VerdifaxError(
        `verdifax: the server returned no record_hash or manifest_hash for step ${stepId}, so the job map cannot continue from it`,
      );
    }
    this.record(stepId, hash, result.signed_request);
    return result;
  }

  private previousHashes(after: string[] | undefined | null): Hex64[] {
    if (after === undefined || after === null) {
      return this.lastStepId === undefined
        ? []
        : [this.hashes.get(this.lastStepId)!];
    }
    if (!Array.isArray(after)) {
      throw new VerdifaxError("verdifax: after must be a list of step ids");
    }
    return after.map((stepId) => {
      const hash = this.hashes.get(stepId);
      if (hash === undefined) {
        throw new VerdifaxError(
          `verdifax: after names ${String(stepId)}, which is not a step in job ${this.jobId}`,
        );
      }
      return hash;
    });
  }

  private record(stepId: string, hash: Hex64, signedRequest?: string): void {
    this.hashes.set(stepId, hash);
    if (signedRequest !== undefined) {
      this.#signedRequests.set(stepId, signedRequest);
    }
    this.lastStepId = stepId;
  }
}
