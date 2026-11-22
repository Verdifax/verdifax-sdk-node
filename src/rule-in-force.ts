/**
 * The rule in force (round 64, design 02): the policy change each decision
 * in a record or receipt was made under. Every decision Verdifax seals names
 * the change (`activation_hash`) of the policy in force; a refusal for
 * missing fields sealed before round 64 names none on the receipt itself,
 * and its receipt context or the policy history gives it. This reads the
 * documents as the server sent them and makes no request. `verdifax-verify`
 * stays the check of the history and the records.
 */

import { VerdifaxError } from "./errors.js";
import type { RuleInForceDecision } from "./types.js";

const ACTIVATION_FORM = "verdifax.policy.activation.v1";
const GAP_KEY = "attestation_gap_receipt";
const TIME =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:(Z)|([+-])([0-9]{2}):([0-9]{2}))$/;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function text(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/** An RFC 3339 time as nanoseconds since 1970, or undefined. BigInt, so no
 *  nanosecond is rounded away as Date would. */
export function instantOf(value: unknown): bigint | undefined {
  if (typeof value !== "string") return undefined;
  const m = TIME.exec(value);
  if (m === null) return undefined;
  const n = (i: number): number => Number(m[i]);
  const year = n(1);
  const month = n(2);
  const day = n(3);
  const hour = n(4);
  const minute = n(5);
  const second = n(6);
  if (!(month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 60)) {
    return undefined;
  }
  // Days from the civil date (proleptic Gregorian).
  const y = year - (month <= 2 ? 1 : 0);
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const days = era * 146097 + doe - 719468;
  let seconds = BigInt(days) * 86400n + BigInt(hour * 3600 + minute * 60 + second);
  if (m[8] === undefined) {
    const offset = BigInt(Number(m[10]) * 3600 + Number(m[11]) * 60);
    seconds -= m[9] === "+" ? offset : -offset;
  }
  const nanos = BigInt((m[7] ?? "").padEnd(9, "0"));
  return seconds * 1_000_000_000n + nanos;
}

function decision(policy: RuleInForceDecision["policy"], b: Obj, foundBy: RuleInForceDecision["found_by"]): RuleInForceDecision {
  return {
    policy,
    activation_hash: text(b.activation_hash),
    policy_hash: text(b.policy_hash),
    fired_rule_id: text(b.fired_rule_id),
    outcome: text(b.outcome),
    found_by: foundBy,
    sequence: null,
    chain_id: null,
    activated_at: null,
  };
}

function bindings(holder: Obj, accountKey: string, keyKey: string): Array<["account" | "key", unknown]> {
  return [
    ["account", holder[accountKey]],
    ["key", holder[keyKey]],
  ];
}

function parse(value: unknown, what: string): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    throw new VerdifaxError(`verdifax: ${what} is not JSON`);
  }
}

function changesOf(history: unknown): Obj[] {
  if (history === undefined || history === null) return [];
  const list = parse(history, "policyHistory");
  if (!Array.isArray(list)) {
    throw new VerdifaxError("verdifax: policyHistory must be a list, as getPolicyHistory returns it");
  }
  return list.filter((item): item is Obj => isObj(item) && item.format === ACTIVATION_FORM);
}

function policyOfChain(chain: unknown): "account" | "key" | "" {
  if (typeof chain === "string" && chain.startsWith("account-")) return "account";
  if (typeof chain === "string" && chain.startsWith("api-key-")) return "key";
  return "";
}

function inForce(changes: Obj[], clock: unknown): Obj {
  const at = instantOf(clock);
  if (at === undefined) {
    throw new VerdifaxError(`verdifax: the refusal's gap_clock ${JSON.stringify(clock)} is not an RFC 3339 time`);
  }
  let found: Obj | undefined;
  for (const change of changes) {
    const activated = instantOf(change.activated_at);
    if (activated !== undefined && activated <= at) found = change;
  }
  if (found === undefined) {
    throw new VerdifaxError(`verdifax: no change in this history was in force at the refusal's clock, ${String(clock)}`);
  }
  return found;
}

function gapDecision(gap: Obj, context: Obj, changes: Obj[], given: boolean): RuleInForceDecision {
  const policyHash = text(gap.policy_hash);
  const sealed = text(gap.activation_hash);
  const matched = bindings(context, "account_policy", "policy").filter(
    (pair): pair is ["account" | "key", Obj] =>
      isObj(pair[1]) && pair[1].policy_hash === policyHash && Boolean(pair[1].activation_hash),
  );
  const base = { policy_hash: policyHash, fired_rule_id: "", outcome: "attestation_gap" };
  let out: RuleInForceDecision;
  if (sealed) {
    if (matched.length > 0 && matched.every(([, b]) => b.activation_hash !== sealed)) {
      throw new VerdifaxError(
        "verdifax: the attestation-gap receipt seals another policy change than its receipt context names for the same policy",
      );
    }
    const policy = matched.find(([, b]) => b.activation_hash === sealed)?.[0] ?? "";
    out = decision(policy, { ...base, activation_hash: sealed }, "receipt");
  } else if (matched.length > 0) {
    const [policy, b] = matched[0]!;
    out = decision(policy, { ...base, activation_hash: b.activation_hash }, "receipt_context");
  } else {
    if (!given) {
      throw new VerdifaxError(
        "verdifax: this refusal for missing fields names no policy change; pass policyHistory, the history of the policy it names, to find the change in force at its clock",
      );
    }
    const change = inForce(changes, gap.gap_clock);
    if (change.policy_hash !== policyHash) {
      throw new VerdifaxError(
        `verdifax: change ${String(change.sequence)}, in force at the refusal's clock, put another policy in force than the refusal names`,
      );
    }
    out = decision(policyOfChain(change.chain_id), { ...base, activation_hash: text(change.activation_hash) }, "policy_history");
  }
  if (out.activation_hash && changes.some((c) => c.activation_hash === out.activation_hash)) {
    const change = inForce(changes, gap.gap_clock);
    if (change.activation_hash !== out.activation_hash) {
      throw new VerdifaxError(
        `verdifax: the refusal was made under another change than change ${String(change.sequence)}, the one in force at its clock`,
      );
    }
  }
  return out;
}

/**
 * The policy change each decision in a record or receipt was made under.
 *
 * `document` is a record bundle, as {@link VerdifaxClient.getRunArtifacts}
 * returns it (an object or its JSON text), whose `epa` section seals the
 * key's `policy_gate` and the account's `account_policy_gate`; or a receipt
 * answer, such as {@link VerdifaxClient.getDenyReceipt} returns, whose
 * `receipt_context` seals each decision. A refusal for missing fields
 * (`attestation_gap_receipt`) gives one decision: the change it seals, or
 * the one its receipt context names for the same policy, or, for a receipt
 * that names none, the change in force at its `gap_clock` in
 * `policyHistory`, which is then required. Times are compared to the
 * nanosecond, as instants.
 *
 * `policyHistory` is otherwise optional: the list
 * {@link VerdifaxClient.getPolicyHistory} or the account's history returns.
 * When it holds a decision's change, the answer adds that change's
 * `sequence`, `chain_id` and `activated_at`. A decision under the built-in
 * policy names no change and is left out. `verdifax-verify` stays the
 * check of the history and the records; this helper only reads them.
 *
 * Throws {@link VerdifaxError} for a document of neither shape, a refusal
 * whose change cannot be told without a history, a receipt context that
 * names another change for the same policy, or a history that shows
 * another change in force at the refusal's clock.
 */
export function ruleInForce(document: unknown, policyHistory?: unknown): RuleInForceDecision[] {
  const doc = parse(document, "document");
  if (!isObj(doc)) {
    throw new VerdifaxError("verdifax: document must be a record bundle or a receipt answer");
  }
  const given = policyHistory !== undefined && policyHistory !== null;
  const changes = changesOf(policyHistory);
  const out: RuleInForceDecision[] = [];
  if (isObj(doc.epa)) {
    for (const [policy, gate] of bindings(doc.epa, "account_policy_gate", "policy_gate")) {
      if (isObj(gate) && gate.activation_hash) out.push(decision(policy, gate, "record"));
    }
  } else if (isObj(doc.receipt_context)) {
    const context = doc.receipt_context;
    const gap = doc[GAP_KEY];
    if (isObj(gap)) {
      out.push(gapDecision(gap, context, changes, given));
    } else {
      for (const [policy, b] of bindings(context, "account_policy", "policy")) {
        if (isObj(b) && b.activation_hash) out.push(decision(policy, b, "receipt_context"));
      }
    }
  } else {
    throw new VerdifaxError(
      "verdifax: document must be a record bundle (with an epa section) or a receipt answer (with a receipt_context)",
    );
  }
  for (const d of out) {
    for (const change of changes) {
      if (change.activation_hash === d.activation_hash) {
        d.sequence = Number.isSafeInteger(change.sequence) ? (change.sequence as number) : null;
        d.chain_id = text(change.chain_id) || null;
        d.activated_at = text(change.activated_at) || null;
        if (!d.policy) d.policy = policyOfChain(change.chain_id);
      }
    }
  }
  return out;
}
