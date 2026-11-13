/**
 * The signal feed: every control signal Verdifax recorded for an account,
 * in order, each with its sealed entry. The feed cannot show a signal
 * Verdifax never recorded.
 *
 * A feed key reads the feed and nothing else. The owner key reads the same
 * feed on its /account route and manages feed keys and webhooks. A webhook
 * delivery is a copy: the pull feed and the public log are the record.
 *
 * The request building, the checks made before sending, the follow loop,
 * webhook verification and the event hash live here; the client's methods
 * are thin wrappers over them.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { SignalFeedError, VerdifaxError } from "./errors.js";
import { parseSealed } from "./sealed.js";
import type {
  CreateWebhookOptions,
  FeedHead,
  FollowSignalsOptions,
  GetSignalsOptions,
  ListWebhookDeliveriesOptions,
  SignalEvent,
  SignalEventHashFields,
  SignalFollower,
  SignalKind,
  SignalPage,
  VerifyWebhookOptions,
  WebhookHeaders,
} from "./types.js";
import { asOwnerOf, validateHex64 } from "./validation.js";

const SIGNAL_FORM = "verdifax.signal.v1";
export const SIGNALS_PATH = "/signals";
export const ACCOUNT_SIGNALS_PATH = "/account/signals";
export const FEED_KEYS_PATH = "/account/feed-keys";
export const WEBHOOKS_PATH = "/account/webhooks";

const MAX_SIGNAL_LIMIT = 500;
const MAX_SIGNAL_WAIT_SECONDS = 25;
const DEFAULT_FOLLOW_WAIT_SECONDS = 25;
// A signals call may be held open for its whole wait, so its timeout is at
// least the wait plus this margin, whatever the client's default.
const SIGNAL_TIMEOUT_MARGIN_MS = 30_000;
// followSignals pauses this long after an empty page read with wait 0, so
// it does not send one read after another without a pause.
const EMPTY_PAGE_PAUSE_MS = 1_000;
const MAX_DELIVERY_LIMIT = 500;
const MAX_FEED_KEY_NAME_BYTES = 200;

const WEBHOOK_SECRET_PREFIX = "whsec_";
const WEBHOOK_SIGNATURE_VERSION = "v1";
const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;
const HMAC_SHA256_BYTES = 32;

/** Every signal kind, in the server's order. */
const SIGNAL_KINDS: readonly SignalKind[] = Object.freeze([
  "run.refused",
  "run.halted",
  "run.failed",
  "policy.changed",
  "signoff.recorded",
  "approver.registered",
  "approver.revoked",
  "key.created",
  "key.revoked",
  "run.published",
  "run.unpublished",
  "chain.gap",
  "run.sealed",
  "chain.interrupted",
  "account.changed",
  "run.deleted",
]);

/** A read of the feed: the path with its query and the timeout to use. */
export interface SignalsRead {
  path: string;
  timeoutMs: number;
}

/** Checks the options of a feed read and builds its path and timeout. `after`
 *  and `wait` are always sent; `limit` only when given. */
export function signalsRead(
  options: GetSignalsOptions | undefined,
  method: string,
  clientTimeoutMs: number,
): SignalsRead {
  const asOwner = asOwnerOf(options, method);
  const after = given(options?.after, 0);
  const limit = options?.limit;
  const wait = given(options?.wait, 0);
  requireAfter(after, method);
  if (limit !== undefined) requireLimit(limit, method, MAX_SIGNAL_LIMIT);
  requireWait(wait, method);
  const q = new URLSearchParams();
  q.set("after", String(after));
  if (limit !== undefined) q.set("limit", String(limit));
  q.set("wait", String(wait));
  return {
    path: `${asOwner ? ACCOUNT_SIGNALS_PATH : SIGNALS_PATH}?${q.toString()}`,
    timeoutMs: Math.max(clientTimeoutMs, wait * 1000 + SIGNAL_TIMEOUT_MARGIN_MS),
  };
}

/** The checked options of {@link followSignalFeed}. */
export interface FollowStart {
  after: number;
  wait: number;
  asOwner: boolean;
  onHead?: (head: FeedHead) => void;
  afterEventHash?: string;
}

/** Checks the options of followSignals before anything is sent. */
export function followStart(options: FollowSignalsOptions | undefined): FollowStart {
  const method = "followSignals";
  const asOwner = asOwnerOf(options, method);
  const after = given(options?.after, 0);
  const wait = given(options?.wait, DEFAULT_FOLLOW_WAIT_SECONDS);
  const onHead = options?.onHead;
  requireAfter(after, method);
  requireWait(wait, method);
  if (onHead !== undefined && typeof onHead !== "function") {
    throw new VerdifaxError(`verdifax: ${method} onHead must be a function`);
  }
  // An empty afterEventHash is the same as none, as in the Go SDK.
  const savedHash = options?.afterEventHash;
  const afterEventHash = savedHash === "" ? undefined : savedHash;
  if (afterEventHash !== undefined) {
    validateHex64(afterEventHash, `${method} afterEventHash`);
  }
  const out: FollowStart = { after, wait, asOwner };
  if (onHead !== undefined) out.onHead = onHead;
  if (afterEventHash !== undefined) out.afterEventHash = afterEventHash;
  return out;
}

/** Reads page after page from `after`, handing out each event once, in
 *  order. Each read starts at the page before's `next_after`, so nothing is
 *  skipped; a page that would skip, or go back, is refused. An empty page
 *  is read again: the read itself waits up to `wait` seconds on the server,
 *  and with `wait` 0 the loop pauses a second first. A read that still
 *  fails after the client's retries ends the loop with a
 *  {@link SignalFeedError} carrying the last sequence handed out. It runs
 *  until the caller stops it, with `break` or `return`.
 *
 *  A page's feed head is not an event and is never handed out (round 61,
 *  N23). The follower keeps the newest head that states the feed through
 *  the last event the caller handled: a head is kept only when its
 *  `sequence` is the page's `next_after` and its `head_hash` is the
 *  `event_hash` of the last event the caller finished, and only once the
 *  caller has moved past every event on that page, so a head is never kept
 *  for an event the caller has not handled. Before the caller finishes an
 *  event in this follow, the last event's hash is `afterEventHash`, the
 *  saved `event_hash` of event `after`, so a follower resuming at the
 *  feed's end keeps the head it is served; without it, no head is kept
 *  until the caller finishes an event. A head already kept, read again
 *  on an idle poll, is not kept again. Each newer head kept is the
 *  follower's `head` and is passed to `onHead`. */
export function followSignalFeed(
  read: (after: number) => Promise<SignalPage>,
  start: FollowStart,
): SignalFollower {
  const kept: { head: FeedHead | undefined } = { head: undefined };
  const follower = followPages(read, start, kept);
  Object.defineProperty(follower, "head", {
    get: () => kept.head,
    enumerable: true,
  });
  return follower as SignalFollower;
}

/** Whether `next`, a page's head, is one to keep over `kept`, matching the
 *  Go SDK's newerFeedHead: it is an object that states the feed through
 *  `handled`, the page's `next_after`, names `handledHash`, the
 *  `event_hash` of the last event the caller finished, as its `head_hash`,
 *  and is another statement than `kept`, at kept's event or later. */
function newerFeedHead(
  kept: FeedHead | undefined,
  next: unknown,
  handled: number,
  handledHash: string | undefined,
): next is FeedHead {
  if (typeof next !== "object" || next === null || Array.isArray(next)) {
    return false;
  }
  const head = next as FeedHead;
  if (head.sequence !== handled) return false;
  if (handledHash === undefined || head.head_hash !== handledHash) return false;
  return (
    kept === undefined ||
    (head.sequence >= kept.sequence &&
      head.head_statement_hash !== kept.head_statement_hash)
  );
}

async function* followPages(
  read: (after: number) => Promise<SignalPage>,
  start: FollowStart,
  kept: { head: FeedHead | undefined },
): AsyncGenerator<SignalEvent, void, undefined> {
  let last = start.after;
  // The event_hash of the last event the caller finished in this follow,
  // or the caller's afterEventHash before the first.
  let lastHash: string | undefined = start.afterEventHash;
  for (;;) {
    let page: SignalPage;
    try {
      page = await read(last);
    } catch (err) {
      throw new SignalFeedError(
        last,
        err instanceof Error ? err.message : String(err),
        { cause: err, afterEventHash: lastHash },
      );
    }
    const events = pageEvents(page, last, lastHash);
    for (const event of events) {
      yield event;
      last = event.data.sequence;
      lastHash = event.data.event_hash;
    }
    // Reached only when the caller asked for the event after the page's
    // last one: every event on the page is handled. A caller that stops
    // inside the page never gets here, so its head is not kept.
    if (newerFeedHead(kept.head, page.head, page.next_after, lastHash)) {
      kept.head = page.head;
      start.onHead?.(page.head);
    }
    if (events.length === 0 && start.wait === 0) {
      await new Promise((r) => setTimeout(r, EMPTY_PAGE_PAUSE_MS));
    }
  }
}

/** The page's events, after checking each follows the one before and that
 *  `next_after` is the last event's sequence, or `after` for an empty page.
 *  A refusal carries `after` and `afterHash`, the event_hash of event
 *  `after` when known, so the caller can follow again from there. */
function pageEvents(
  page: SignalPage,
  after: number,
  afterHash: string | undefined,
): SignalEvent[] {
  const where = { afterEventHash: afterHash };
  const events = page?.events ?? [];
  if (!Array.isArray(events)) {
    throw new SignalFeedError(after, "the server's page has no events list", where);
  }
  let previous = after;
  for (const event of events) {
    const sequence = event?.data?.sequence;
    if (!Number.isSafeInteger(sequence) || sequence <= previous) {
      throw new SignalFeedError(
        after,
        `the server's page holds an event out of order (sequence ${String(sequence)} after ${previous})`,
        where,
      );
    }
    previous = sequence;
  }
  if (page?.next_after !== previous) {
    throw new SignalFeedError(
      after,
      `the server's next_after ${String(page?.next_after)} is not the last sequence on its page (${previous})`,
      where,
    );
  }
  return events;
}

/** Checks a feed key's name and expiry and builds the request body. */
export function feedKeyBody(
  name: string,
  expiresAt: string | undefined,
): { name: string; expires_at?: string } {
  if (
    typeof name !== "string" ||
    name.trim() === "" ||
    Buffer.byteLength(name.trim(), "utf8") > MAX_FEED_KEY_NAME_BYTES
  ) {
    throw new VerdifaxError(
      "verdifax: createFeedKey needs a name of at most 200 bytes",
    );
  }
  if (expiresAt !== undefined && typeof expiresAt !== "string") {
    throw new VerdifaxError(
      "verdifax: createFeedKey expiresAt must be an RFC 3339 time or a YYYY-MM-DD date, as a string",
    );
  }
  return expiresAt === undefined ? { name } : { name, expires_at: expiresAt };
}

/** Checks a webhook's address and kinds and builds the request body. The
 *  server checks the address too: this is only the first check. */
export function webhookBody(
  url: string,
  options: CreateWebhookOptions | undefined,
): { url: string; types?: SignalKind[] } {
  if (typeof url !== "string" || !url.startsWith("https://") || url.length <= 8) {
    throw new VerdifaxError(
      "verdifax: createWebhook needs a url that starts with https://",
    );
  }
  const types = options?.types;
  if (types === undefined) return { url };
  if (!Array.isArray(types)) {
    throw new VerdifaxError(
      "verdifax: createWebhook types must be a list of signal kinds",
    );
  }
  const seen = new Set<string>();
  for (const kind of types) {
    if (!SIGNAL_KINDS.includes(kind) || seen.has(kind)) {
      throw new VerdifaxError(
        `verdifax: createWebhook types must be distinct signal kinds (${SIGNAL_KINDS.join(", ")}); an empty list takes every kind`,
      );
    }
    seen.add(kind);
  }
  return { url, types: [...types] };
}

/** The path of a webhook's delivery log, with `limit` when given. */
export function deliveriesPath(
  id: number,
  options: ListWebhookDeliveriesOptions | undefined,
): string {
  const limit = options?.limit;
  if (limit === undefined) return `${WEBHOOKS_PATH}/${id}/deliveries`;
  requireLimit(limit, "listWebhookDeliveries", MAX_DELIVERY_LIMIT);
  return `${WEBHOOKS_PATH}/${id}/deliveries?limit=${limit}`;
}

/**
 * Checks one webhook delivery under the Standard Webhooks scheme and
 * returns its CloudEvent. Pass the headers as received, the body as the
 * exact bytes received (a Buffer, a Uint8Array or a string, never parsed
 * JSON) and the subscription's `whsec_` secret.
 *
 * The signed content is `webhook-id`, a dot, `webhook-timestamp`, a dot and
 * the body. `webhook-signature` is a space-separated list of `v1,<base64>`
 * entries, and any one may match; each is compared in constant time. A
 * timestamp more than `toleranceSeconds` (default 300) from `now` in either
 * direction is refused. Header names are read without regard to case. The
 * body must be a JSON object whose top-level `id` is a string equal to
 * `webhook-id`.
 *
 * Throws {@link VerdifaxError} naming the check that failed. The secret is
 * never placed in an error message. A delivery is a copy: the pull feed and
 * the public log are the record.
 */
export function verifyWebhook(
  headers: WebhookHeaders,
  body: Uint8Array | string,
  secret: string,
  options: VerifyWebhookOptions = {},
): SignalEvent {
  const key = webhookSecretBytes(secret);
  const tolerance = options?.toleranceSeconds ?? DEFAULT_WEBHOOK_TOLERANCE_SECONDS;
  if (typeof tolerance !== "number" || !Number.isFinite(tolerance) || tolerance < 0) {
    throw new VerdifaxError(
      "verdifax: verifyWebhook toleranceSeconds must be a number of seconds of 0 or more",
    );
  }
  const now = options?.now ?? new Date();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new VerdifaxError("verdifax: verifyWebhook now must be a valid Date");
  }
  let raw: Buffer;
  if (typeof body === "string") {
    raw = Buffer.from(body, "utf8");
  } else if (body instanceof Uint8Array) {
    raw = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  } else {
    throw new VerdifaxError(
      "verdifax: verifyWebhook needs the body as the raw bytes received (a Buffer, Uint8Array or string), not parsed JSON",
    );
  }

  const id = singleHeader(headers, "webhook-id");
  const timestamp = singleHeader(headers, "webhook-timestamp");
  const signatures = headerValues(headers, "webhook-signature").join(" ");
  if (!signatures) {
    throw new VerdifaxError("verdifax: webhook check failed: the webhook-signature header is missing");
  }
  if (!/^[0-9]{1,15}$/.test(timestamp)) {
    throw new VerdifaxError(
      "verdifax: webhook check failed: webhook-timestamp is not a whole number of seconds",
    );
  }
  const age = Math.abs(now.getTime() / 1000 - Number(timestamp));
  if (age > tolerance) {
    throw new VerdifaxError(
      `verdifax: webhook check failed: webhook-timestamp is more than ${tolerance} seconds from now`,
    );
  }

  const expected = createHmac("sha256", key)
    .update(`${id}.${timestamp}.`, "utf8")
    .update(raw)
    .digest();
  let v1Seen = false;
  let matched = false;
  for (const entry of signatures.split(" ")) {
    const comma = entry.indexOf(",");
    if (comma < 0 || entry.slice(0, comma) !== WEBHOOK_SIGNATURE_VERSION) continue;
    v1Seen = true;
    const given = Buffer.from(entry.slice(comma + 1), "base64");
    // Every v1 entry is compared, so the time taken does not show which.
    if (given.length === HMAC_SHA256_BYTES && timingSafeEqual(given, expected)) {
      matched = true;
    }
  }
  if (!v1Seen) {
    throw new VerdifaxError(
      "verdifax: webhook check failed: webhook-signature holds no v1 signature",
    );
  }
  if (!matched) {
    throw new VerdifaxError(
      "verdifax: webhook check failed: no v1 signature in webhook-signature matches the id, timestamp and body under this secret",
    );
  }

  let event: unknown;
  try {
    // The event keeps the exact text it was signed as, in sealedJson.
    event = parseSealed(raw.toString("utf8"));
  } catch {
    throw new VerdifaxError(
      "verdifax: webhook check failed: the signature matches but the body is not JSON",
    );
  }
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    throw new VerdifaxError(
      "verdifax: webhook check failed: the signature matches but the body is not a CloudEvent object",
    );
  }
  // The signature covers webhook-id and the body separately, so a body
  // whose own id differs from the header is refused here.
  if ((event as { id?: unknown }).id !== id) {
    throw new VerdifaxError(
      "verdifax: webhook check failed: the event id in the body does not match webhook-id",
    );
  }
  return event as SignalEvent;
}

/**
 * The hash the next event in an account's feed names, matching the
 * orchestrator's SignalEventHash: hex SHA-256 of `verdifax.signal.v1`, the
 * kind, the hash of the event's entry, the account, the decimal sequence
 * and the previous event's hash, joined by single zero bytes. It makes no
 * request.
 */
export function signalEventHash(
  kind: string,
  entryHash: string,
  fields: SignalEventHashFields,
): string {
  const { account, sequence, previousSignalHash } =
    fields ?? ({} as SignalEventHashFields);
  for (const [name, value] of [
    ["kind", kind],
    ["entryHash", entryHash],
    ["account", account],
    ["previousSignalHash", previousSignalHash],
  ] as const) {
    if (typeof value !== "string" || value.includes("\0")) {
      throw new VerdifaxError(
        `verdifax: signalEventHash ${name} must be text without a zero byte`,
      );
    }
  }
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new VerdifaxError(
      "verdifax: signalEventHash sequence must be a whole number of 0 or more",
    );
  }
  return createHash("sha256")
    .update(
      [SIGNAL_FORM, kind, entryHash, account, String(sequence), previousSignalHash].join("\0"),
      "utf8",
    )
    .digest("hex");
}

// ── Checks ─────────────────────────────────────────────────────

/** An option's value, or its default when it is left out. A null is kept,
 *  so it is refused rather than read as left out. */
function given<T>(value: T | undefined, fallback: T): T {
  return value === undefined ? fallback : value;
}

function requireAfter(after: unknown, method: string): void {
  if (!Number.isSafeInteger(after) || (after as number) < 0) {
    throw new VerdifaxError(
      `verdifax: ${method} after must be a whole number of 0 or more, the last sequence read`,
    );
  }
}

function requireLimit(limit: unknown, method: string, max: number): void {
  if (!Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > max) {
    throw new VerdifaxError(
      `verdifax: ${method} limit must be a whole number from 1 to ${max}`,
    );
  }
}

function requireWait(wait: unknown, method: string): void {
  if (
    !Number.isSafeInteger(wait) ||
    (wait as number) < 0 ||
    (wait as number) > MAX_SIGNAL_WAIT_SECONDS
  ) {
    throw new VerdifaxError(
      `verdifax: ${method} wait must be a whole number of seconds from 0 to ${MAX_SIGNAL_WAIT_SECONDS}`,
    );
  }
}

/** The key bytes of a `whsec_` secret. The secret itself is never placed
 *  in an error message. */
function webhookSecretBytes(secret: string): Buffer {
  if (typeof secret !== "string" || !secret.startsWith(WEBHOOK_SECRET_PREFIX)) {
    throw new VerdifaxError(
      "verdifax: verifyWebhook needs the subscription's secret, which starts with whsec_",
    );
  }
  const encoded = secret.slice(WEBHOOK_SECRET_PREFIX.length);
  const key = Buffer.from(encoded, "base64");
  if (
    !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) ||
    key.length === 0 ||
    key.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")
  ) {
    throw new VerdifaxError(
      "verdifax: verifyWebhook needs the subscription's secret: whsec_ and then base64",
    );
  }
  return key;
}

/** Every value of a header, by name without regard to case. */
function headerValues(headers: WebhookHeaders, name: string): string[] {
  if (typeof headers !== "object" || headers === null) {
    throw new VerdifaxError("verdifax: verifyWebhook needs the delivery's headers");
  }
  if (typeof (headers as { get?: unknown }).get === "function") {
    const value = (headers as { get(name: string): string | null }).get(name);
    return value === null || value === undefined ? [] : [String(value)];
  }
  const out: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    if (Array.isArray(value)) out.push(...value.map(String));
    else if (value !== undefined) out.push(String(value));
  }
  return out;
}

/** The one value of a header that must appear once. */
function singleHeader(headers: WebhookHeaders, name: string): string {
  const values = headerValues(headers, name);
  if (values.length === 0 || values[0] === "") {
    throw new VerdifaxError(`verdifax: webhook check failed: the ${name} header is missing`);
  }
  if (values.length > 1) {
    throw new VerdifaxError(`verdifax: webhook check failed: the ${name} header appears more than once`);
  }
  return values[0]!;
}

/**
 * The runs among `events` whose allowing policy rule requires a person's
 * sign-off (their `run.sealed` entry says `signoff_required`) and on whose
 * record no approval is in force. The decision in force is read as
 * verdifax-verify reads it: the last job sign-off on the run governs when
 * there is one, and otherwise the last record sign-off; a receipt sign-off
 * does not name a record (round 59, N15 and N19). Pass the account's feed
 * from its start, or a page that includes each run's sign-offs, so a
 * sign-off recorded later is seen (round 58, B7). A run whose deletion is
 * among `events`, a `run.deleted` event naming its run, is left out
 * wherever that event stands in the list: its record is gone, so no
 * sign-off can be given on it. A `run.sealed` or `run.deleted` event that
 * names no run (a null entry, or a run id that is not a whole number above
 * zero) is refused with {@link VerdifaxError}: the server serves every
 * `run.sealed` event with its own entry, even after the run is deleted.
 * Returned in feed order.
 */
export function pendingSignOffs(events: readonly SignalEvent[]): number[] {
  const order: number[] = [];
  const required = new Set<number>();
  const latestJob = new Map<number, unknown>();
  const latestRecord = new Map<number, unknown>();
  const deleted = new Set<number>();
  for (const e of events) {
    const entry = (e.data?.entry ?? {}) as Record<string, unknown>;
    if (e.data?.kind === "run.sealed") {
      // The server serves every run.sealed event with its own entry, even
      // after the run is deleted, so one that names no run, a null entry or
      // run 0 included, is refused, never skipped.
      const run = entry.run_id;
      if (!isRunId(run)) {
        throw new VerdifaxError(`verdifax: the run.sealed entry of event ${e.id} names no run`);
      }
      if (entry.signoff_required === true && !required.has(run)) {
        required.add(run);
        order.push(run);
      }
    } else if (e.data?.kind === "run.deleted") {
      const run = entry.run_id;
      if (!isRunId(run)) {
        throw new VerdifaxError(`verdifax: the run.deleted entry of event ${e.id} names no run`);
      }
      deleted.add(run);
    } else if (e.data?.kind === "signoff.recorded") {
      const target = (entry.target ?? {}) as Record<string, unknown>;
      if (typeof target.run_id === "number") {
        if (target.kind === "job") {
          latestJob.set(target.run_id, entry.decision);
        } else if (target.kind === "record") {
          latestRecord.set(target.run_id, entry.decision);
        }
      }
    }
  }
  const inForce = (run: number) => (latestJob.has(run) ? latestJob.get(run) : latestRecord.get(run));
  return order.filter((run) => !deleted.has(run) && inForce(run) !== "approve");
}

/** A run id as the server gives one: a whole number above zero. */
function isRunId(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}
