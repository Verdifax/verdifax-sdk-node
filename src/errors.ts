/**
 * Typed errors returned by the Verdifax SDK.
 *
 * Callers can use `instanceof` to discriminate:
 *
 * ```typescript
 * try {
 *   await client.getRun(142);
 * } catch (err) {
 *   if (err instanceof NotFoundError) {
 *     // run doesn't exist (or belongs to a different key)
 *   } else if (err instanceof AuthError) {
 *     // missing or invalid API key
 *   } else if (err instanceof APIError) {
 *     // every other non-2xx
 *   }
 * }
 * ```
 */

// Base class types `name` as `string` (not a literal) so subclasses
// can narrow with their own literal types via `override`. Without
// this the dts compiler (tsup) refuses to emit declarations
// because each subclass's narrower literal isn't assignment-
// compatible with the parent's literal.
export class VerdifaxError extends Error {
  override readonly name: string = "VerdifaxError";
}

/** HTTP 401, missing or invalid API key. */
export class AuthError extends VerdifaxError {
  override readonly name: string = "VerdifaxAuthError";
  constructor(
    public readonly status: number,
    public override readonly message: string,
  ) {
    super(`verdifax: auth error (HTTP ${status}): ${message}`);
  }
}

/** HTTP 404, resource not found. Carries the path that 404'd
 *  for easier diagnosis. */
export class NotFoundError extends VerdifaxError {
  override readonly name: string = "VerdifaxNotFoundError";
  constructor(
    public readonly path: string,
    public override readonly message: string,
  ) {
    super(`verdifax: not found at ${path}: ${message}`);
  }
}

/** Every other non-2xx response. Carries the HTTP status and
 *  the path so callers can switch on either dimension. `recordHash` is
 *  the receipt hash of a refused or halted run, when the server sealed
 *  one; it is undefined when no record exists.
 *
 *  `signedRequest` is the exact text that was signed, when the call was a
 *  signed run. Keep it to pass to `verdifax-verify --request FILE`. It holds
 *  the payload, so it stays out of the message and is not enumerable: read
 *  it by name, and logging the error does not print it. */
export class APIError extends VerdifaxError {
  override readonly name: string = "VerdifaxAPIError";
  declare readonly signedRequest?: string;
  constructor(
    public readonly status: number,
    public readonly path: string,
    public override readonly message: string,
    public readonly recordHash?: string,
    signedRequest?: string,
    /** The text the AI review checked, on a run its review halted:
     *  returned once, and the halt receipt seals its hash. */
    public readonly aivpTraceText?: string,
  ) {
    super(`verdifax: API error at ${path} (HTTP ${status}): ${message}`);
    if (signedRequest !== undefined) {
      Object.defineProperty(this, "signedRequest", {
        value: signedRequest,
        enumerable: false,
      });
    }
  }
}

/** Returned when an authenticated method is called on a client
 *  constructed without an apiKey. */
export class APIKeyRequiredError extends VerdifaxError {
  override readonly name: string = "VerdifaxAPIKeyRequiredError";
  constructor() {
    super("verdifax: apiKey is required for this endpoint");
  }
}

/** Thrown by {@link VerdifaxClient.followSignals} when a read fails or a
 *  page does not follow on from the last one. `lastSequence` is the last
 *  sequence the generator handed out, so the feed is never lost: follow
 *  again with `after: lastSequence`. The error the read threw, after the
 *  client's normal retries, is `cause`. */
export class SignalFeedError extends VerdifaxError {
  override readonly name: string = "VerdifaxSignalFeedError";
  constructor(
    public readonly lastSequence: number,
    reason: string,
    options?: { cause?: unknown },
  ) {
    super(
      `verdifax: the signal feed stopped after sequence ${lastSequence}: ${reason}; follow again with after: ${lastSequence}`,
      options,
    );
  }
}
