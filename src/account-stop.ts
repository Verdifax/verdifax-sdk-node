/**
 * The account stop and the member-key tool allowlist (round 64): the
 * subject the owner's request key signs, and the checks made before a stop,
 * a resume or an allowlist is sent.
 */

import { createHash } from "node:crypto";

import { VerdifaxError } from "./errors.js";
import type { AccountStopSubjectFields, AllowedTool } from "./types.js";
import { requirePositiveId } from "./validation.js";

/** The change an owner's stop and resume sign, the feed kinds of their
 *  records. */
export const ACCOUNT_STOPPED_CHANGE = "account.stopped";
export const ACCOUNT_RESUMED_CHANGE = "account.resumed";

const STOP_SIGNOFFS = new Set(["accept", "refuse"]);
const STOP_WEBHOOKS = new Set(["continue", "pause"]);
const MAX_STOP_REASON_BYTES = 1000;

/** The names a member key's allowlist may hold: the verdifax-mcp tools and
 *  the stop permission, as the server lists them. */
export const ALLOWED_TOOLS: readonly AllowedTool[] = Object.freeze([
  "verify_record",
  "verify_feed",
  "get_record",
  "list_records",
  "read_feed",
  "list_pending_signoffs",
  "get_signoffs",
  "test_policy",
  "seal_decision",
  "prepare_signoff",
  "account_stop",
]);

// Powers the server never grants, with why.
const NEVER_GRANTED: Record<string, string> = {
  account_resume: "lifting a stop is the owner's alone",
  resume: "lifting a stop is the owner's alone",
  owner: "owner powers are never granted to a member key",
  manage_keys: "owner powers are never granted to a member key",
  manage_policy: "owner powers are never granted to a member key",
  approver: "an approver key is never granted; sign-offs are signed by a person's own approver key",
  sign_off: "an approver key is never granted; sign-offs are signed by a person's own approver key",
  signoff: "an approver key is never granted; sign-offs are signed by a person's own approver key",
};

/** The scope of a stop, checked, with the defaults accept and continue. */
export function stopScopeOf(
  signoffs: unknown,
  webhooks: unknown,
): { signoffs: "accept" | "refuse"; webhooks: "continue" | "pause" } {
  const s = signoffs ?? "accept";
  const w = webhooks ?? "continue";
  if (typeof s !== "string" || !STOP_SIGNOFFS.has(s)) {
    throw new VerdifaxError("verdifax: a stop's signoffs must be accept or refuse");
  }
  if (typeof w !== "string" || !STOP_WEBHOOKS.has(w)) {
    throw new VerdifaxError("verdifax: a stop's webhooks must be continue or pause");
  }
  return { signoffs: s as "accept" | "refuse", webhooks: w as "continue" | "pause" };
}

/** The reason's sealed SHA-256, or "" for none. A reason is text of at most
 *  1000 UTF-8 bytes; only its hash is sealed. */
export function stopReasonHash(reason: unknown): string {
  if (reason === undefined || reason === null || reason === "") return "";
  if (typeof reason !== "string" || /[\uD800-\uDFFF]/u.test(reason)) {
    throw new VerdifaxError("verdifax: a stop's reason must be text");
  }
  if (Buffer.byteLength(reason, "utf8") > MAX_STOP_REASON_BYTES) {
    throw new VerdifaxError(
      `verdifax: a stop's reason must be at most ${MAX_STOP_REASON_BYTES} bytes; only its SHA-256 is sealed`,
    );
  }
  return createHash("sha256").update(Buffer.from(reason, "utf8")).digest("hex");
}

/** The subject the owner key's request key signs for a stop or a resume,
 *  as the server builds it: the action, `key=` and the owner key's id, for
 *  a stop `signoffs=` and `webhooks=` (defaults accept and continue), for a
 *  resume `lifts=` and the feed place of the stop it lifts, and
 *  `reason_sha256=` and the reason's SHA-256 (nothing when there is no
 *  reason), joined by single spaces. It is signed over
 *  {@link ownerChangePreimage} with the change `account.stopped` or
 *  `account.resumed`. Bad input throws {@link VerdifaxError}. */
export function accountStopSubject(fields: AccountStopSubjectFields): string {
  if (typeof fields !== "object" || fields === null) {
    throw new VerdifaxError("verdifax: accountStopSubject needs its fields");
  }
  const { action, keyId, signoffs, webhooks, liftsSequence, reason } = fields;
  requirePositiveId(keyId, "keyId");
  const reasonHash = stopReasonHash(reason);
  if (action === "stop") {
    if (liftsSequence !== undefined && liftsSequence !== null) {
      throw new VerdifaxError("verdifax: a stop names no liftsSequence; a resume lifts a stop");
    }
    const scope = stopScopeOf(signoffs, webhooks);
    return `stop key=${keyId} signoffs=${scope.signoffs} webhooks=${scope.webhooks} reason_sha256=${reasonHash}`;
  }
  if (action === "resume") {
    if ((signoffs !== undefined && signoffs !== null) || (webhooks !== undefined && webhooks !== null)) {
      throw new VerdifaxError("verdifax: a resume names no scope");
    }
    requirePositiveId(liftsSequence as number, "liftsSequence");
    return `resume key=${keyId} lifts=${liftsSequence} reason_sha256=${reasonHash}`;
  }
  throw new VerdifaxError("verdifax: accountStopSubject action must be stop or resume");
}

/** An allowlist checked as the server checks it: one or more distinct
 *  grantable names, never an owner power or an approver key. Returns the
 *  list as given; the server seals it sorted. */
export function checkedAllowedTools(tools: unknown): AllowedTool[] {
  if (!Array.isArray(tools) || tools.length === 0) {
    throw new VerdifaxError("verdifax: allowedTools must name one or more tools, or be left out");
  }
  const seen = new Set<string>();
  for (const tool of tools as unknown[]) {
    if (typeof tool === "string" && Object.hasOwn(NEVER_GRANTED, tool)) {
      throw new VerdifaxError(`verdifax: allowedTools: ${tool} can never be granted: ${NEVER_GRANTED[tool]}`);
    }
    if (typeof tool !== "string" || !(ALLOWED_TOOLS as readonly string[]).includes(tool)) {
      throw new VerdifaxError(
        `verdifax: allowedTools: ${JSON.stringify(tool)} is not a tool; the names are ${ALLOWED_TOOLS.join(", ")}`,
      );
    }
    if (seen.has(tool)) {
      throw new VerdifaxError(`verdifax: allowedTools names ${tool} twice`);
    }
    seen.add(tool);
  }
  return [...(tools as AllowedTool[])];
}

/** The allowlist in the X-Verdifax-Allowed-Tools header, or null when the
 *  header is absent (the key has none). */
export function allowedToolsFromHeader(header: string | null): string[] | null {
  if (header === null) return null;
  return header
    .split(",")
    .map((name) => name.trim())
    .filter((name) => name !== "");
}
