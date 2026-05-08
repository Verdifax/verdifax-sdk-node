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

/** HTTP 401 — missing or invalid API key. */
export class AuthError extends VerdifaxError {
  override readonly name: string = "VerdifaxAuthError";
  constructor(
    public readonly status: number,
    public override readonly message: string,
  ) {
    super(`verdifax: auth error (HTTP ${status}): ${message}`);
  }
}

/** HTTP 404 — resource not found. Carries the path that 404'd
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
 *  the path so callers can switch on either dimension. */
export class APIError extends VerdifaxError {
  override readonly name: string = "VerdifaxAPIError";
  constructor(
    public readonly status: number,
    public readonly path: string,
    public override readonly message: string,
  ) {
    super(`verdifax: API error at ${path} (HTTP ${status}): ${message}`);
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
