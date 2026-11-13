// SDK 1.15.0: the feed head on a page that reaches the feed's end, the
// request-key changes sealed as account changes, and the server's 409 when
// the request key changed since a change was signed. The mock server
// listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  SignalFeedError,
  VerdifaxClient,
  VerdifaxError,
  pendingSignOffs,
  requestKeyChangeApproval,
} from "../dist/index.mjs";
import { publicKeyObject } from "./signed-body.mjs";

const PKCS8_ED25519_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");
const ZEROS = "0".repeat(64);

/** The base64 public key of a 32-byte seed, written out independently of
 *  the SDK. */
function publicKeyOf(seed) {
  const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_HEADER, seed]), format: "der", type: "pkcs8" });
  return crypto.createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
}

const SEED_A = Buffer.alloc(32, 0x41);
const SEED_B = Buffer.alloc(32, 0x42);
const KEY_A = publicKeyOf(SEED_A).toString("base64");
const KEY_B = publicKeyOf(SEED_B).toString("base64");

/** Answers each request from `answer(request, body, index)`, which returns
 *  `{ status, json, text }`; `text`, when given, is sent exactly. */
async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, raw, body });
      const reply = answer?.(req, body, seen.length - 1) ?? {};
      const { status = 200, json = { ok: true } } = reply;
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(reply.text ?? JSON.stringify(json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({
      baseURL: `http://127.0.0.1:${server.address().port}`,
      apiKey: "owner",
      retryBaseDelayMs: 1,
      ...config,
    });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const requests = (seen) => seen.map((r) => `${r.method} ${r.url}`);

/** The event_hash of the event at `sequence`, as the shared vector derives
 *  it: the SHA-256 of "e" and the sequence. */
const eventHashOf = (sequence) => crypto.createHash("sha256").update(`e${sequence}`, "utf8").digest("hex");

/** A CloudEvent at `sequence` carrying `entry`, in the server's form. */
function event(sequence, kind, entry, eventHash = eventHashOf(sequence)) {
  return {
    specversion: "1.0",
    id: `account-7/${sequence}`,
    source: "https://api.verdifax.com/accounts/account-7",
    type: `com.verdifax.${kind}`,
    time: "2026-11-12T20:00:00Z",
    datacontenttype: "application/json",
    data: {
      form: "verdifax.signal.v1",
      kind,
      account: "account-7",
      sequence,
      previous_signal_hash: sequence === 1 ? ZEROS : "e".repeat(64),
      event_hash: eventHash,
      entry,
    },
  };
}

/** The feed head the server states for `sequence`. Its anchor carries a
 *  number above 2^53, whose exact digits only the sealed text keeps. */
function head(sequence, statedAt = "2026-11-12T21:58:20.123456789Z") {
  return {
    format: "verdifax.feed-head.v1",
    account: "account-7",
    sequence,
    head_hash: eventHashOf(sequence),
    stated_at: statedAt,
    head_statement_hash: "c".repeat(64),
    anchor: { receipt_kind: "feed_head", log_index: 9007199254740993, integrated_time: 1794520700 },
  };
}

/** The JSON text of a page, with the head's log index as its exact digits. */
function pageText(events, nextAfter, newest, pageHead) {
  const page = { events, next_after: nextAfter, newest };
  if (pageHead !== undefined) page.head = pageHead;
  return JSON.stringify(page).replace(/9007199254740992/g, "9007199254740993");
}

// ── The feed head on a page ─────────────────────────────────────

test("getSignals keeps the page's feed head, with its exact text, apart from the events", async () => {
  const events = [event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })];
  const text = pageText(events, 2, 2, head(2));
  const { seen, result } = await withServer(() => ({ text }), (c) => c.getSignals({ asOwner: true }));
  assert.deepEqual(requests(seen), ["GET /account/signals?after=0&wait=0"]);
  assert.equal(result.sealedJson, text);
  assert.equal(result.events.length, 2);
  assert.ok(result.events.every((e) => e.data.form === "verdifax.signal.v1"));
  const expected = head(2);
  assert.deepEqual(Object.keys(result.head).sort(), Object.keys(expected).sort());
  for (const field of ["format", "account", "sequence", "head_hash", "stated_at", "head_statement_hash"]) {
    assert.equal(result.head[field], expected[field], field);
  }
  assert.equal(result.head.anchor.receipt_kind, "feed_head");
  // The sealed text keeps the anchor's exact digits, which JSON.parse rounds.
  const headText = /"head":(\{.*\})\}$/.exec(text)[1];
  assert.equal(result.head.sealedJson, headText);
  assert.match(result.head.sealedJson, /"log_index":9007199254740993/);
  assert.equal(JSON.parse(result.head.sealedJson).stated_at, "2026-11-12T21:58:20.123456789Z");
});

test("getSignals reads a page without a head as before", async () => {
  const text = pageText([event(1, "run.sealed", { run_id: 10 })], 1, 3);
  const { result } = await withServer(() => ({ text }), (c) => c.getSignals());
  assert.equal(result.head, undefined);
  assert.equal(result.events.length, 1);
});

// ── The follow loop and the head ────────────────────────────────

const STATEMENT = { A: "a".repeat(64), B: "b".repeat(64), C: "c".repeat(64) };

/** A head at `sequence` stated as statement `name`. */
const headAs = (sequence, name) => ({ ...head(sequence, `2026-11-12T21:0${"ABC".indexOf(name)}:00Z`), head_statement_hash: STATEMENT[name] });

test("followSignals keeps a head only once the caller passes its page and only when it matches next_after, and reports each newer head once", async () => {
  const pages = [
    pageText([event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })], 2, 3),
    pageText([event(3, "account.changed", { action: "request_key.registered" })], 3, 3, headAs(3, "A")),
    // The same statement on an idle poll is not reported again.
    pageText([], 3, 3, headAs(3, "A")),
    // A newer statement of the same end is.
    pageText([], 3, 3, headAs(3, "B")),
    // A head that does not match next_after is never kept.
    pageText([], 3, 3, headAs(9, "C")),
    pageText([event(4, "run.sealed", { run_id: 12 })], 4, 4, headAs(3, "C")),
    pageText([event(5, "run.sealed", { run_id: 13 })], 5, 5),
  ];
  const { seen, result } = await withServer(
    (req, body, i) => ({ text: pages[i] ?? pageText([], 5, 5) }),
    async (c) => {
      const log = [];
      const follower = c.followSignals({ wait: 1, onHead: (h) => log.push(`head ${h.head_statement_hash[0]} ${follower.head === h}`) });
      const heads = [follower.head];
      const got = [];
      for await (const e of follower) {
        got.push(e);
        log.push(String(e.data.sequence));
        heads.push(follower.head?.head_statement_hash[0]);
        if (e.data.sequence === 5) break;
      }
      return { got, heads, log, last: follower.head };
    },
  );
  assert.deepEqual(result.got.map((e) => e.data.sequence), [1, 2, 3, 4, 5]);
  for (const e of result.got) {
    assert.equal(e.specversion, "1.0");
    assert.notEqual(e.format, "verdifax.feed-head.v1");
    assert.equal(e.data.form, "verdifax.signal.v1");
  }
  // The head of event 3's page is kept only after the caller handled event 3.
  assert.deepEqual(result.log, ["1", "2", "3", "head a true", "head b true", "4", "5"]);
  assert.deepEqual(result.heads, [undefined, undefined, undefined, undefined, "b", "b"]);
  assert.equal(result.last.sequence, 3);
  assert.equal(result.last.head_statement_hash, STATEMENT.B);
  assert.equal(result.last.format, "verdifax.feed-head.v1");
  assert.match(result.last.sealedJson, /"log_index":9007199254740993/);
  assert.deepEqual(requests(seen), [
    "GET /signals?after=0&wait=1",
    "GET /signals?after=2&wait=1",
    "GET /signals?after=3&wait=1",
    "GET /signals?after=3&wait=1",
    "GET /signals?after=3&wait=1",
    "GET /signals?after=3&wait=1",
    "GET /signals?after=4&wait=1",
  ]);
});

// The shared vector, copied unchanged from scripts/sdk-feed-head-vector.json:
// every SDK's follower keeps and reports the feed head by the same rule.
const FEED_HEAD_VECTOR = JSON.parse(readFileSync(new URL("./sdk-feed-head-vector.json", import.meta.url), "utf8"));

test("vector: followSignals keeps and reports the feed head as every SDK does", async () => {
  assert.ok(FEED_HEAD_VECTOR.cases.length >= 13);
  assert.ok(FEED_HEAD_VECTOR.cases.some((c) => c.start?.after_hash_of != null));
  assert.ok(FEED_HEAD_VECTOR.cases.some((c) => c.pages.some((p) => p.head?.head_hash_of !== undefined)));
  // A statement label stands for its head_statement_hash, its SHA-256, so
  // equal labels are the same statement.
  const hashOf = (label) => crypto.createHash("sha256").update(label, "utf8").digest("hex");
  const labels = new Map();
  const served = (h) => {
    labels.set(hashOf(h.statement), h.statement);
    return {
      ...head(h.sequence, `2026-11-12T21:00:00Z ${h.statement}`),
      head_hash: eventHashOf(h.head_hash_of ?? h.sequence),
      head_statement_hash: hashOf(h.statement),
    };
  };
  const asCase = (h) => ({ sequence: h.sequence, statement: labels.get(h.head_statement_hash) ?? `unknown ${h.head_statement_hash}` });
  for (const c of FEED_HEAD_VECTOR.cases) {
    const pages = c.pages.map((p) =>
      pageText(p.events.map((n) => event(n, "run.sealed", { run_id: 100 + n })), p.next_after, p.next_after, p.head === null ? undefined : served(p.head)),
    );
    const { seen, result } = await withServer(
      // After the case's pages the server refuses, which ends the follow.
      (req, body, i) => (i < pages.length ? { text: pages[i] } : { status: 400, json: { ok: false, error: "end of the case" } }),
      async (client) => {
        const reported = [];
        const handled = [];
        const options = { wait: 1, onHead: (h) => reported.push(asCase(h)) };
        if (c.start != null) {
          options.after = c.start.after;
          if (c.start.after_hash_of != null) options.afterEventHash = eventHashOf(c.start.after_hash_of);
        }
        const follower = client.followSignals(options);
        let stoppedBy;
        try {
          for await (const e of follower) {
            handled.push(e.data.sequence);
            if (e.data.sequence === c.handle_until) break;
          }
        } catch (err) {
          stoppedBy = err;
        }
        return { reported, handled, kept: follower.head === undefined ? null : asCase(follower.head), stoppedBy };
      },
    );
    assert.deepEqual(result.kept, c.expected_kept, c.name);
    assert.deepEqual(result.reported, c.expected_reported, c.name);
    const all = c.pages.flatMap((p) => p.events);
    assert.deepEqual(result.handled, c.handle_until === null ? all : all.slice(0, all.indexOf(c.handle_until) + 1), c.name);
    if (c.handle_until === null) {
      assert.ok(result.stoppedBy instanceof SignalFeedError, c.name);
      assert.equal(seen.length, pages.length + 1, c.name);
    } else {
      assert.equal(result.stoppedBy, undefined, c.name);
    }
  }
});

test("a head that does not match its page's next_after or the last event's hash is not kept", async () => {
  for (const [label, pageHead] of [
    ["below next_after", headAs(1, "A")],
    ["above next_after", headAs(3, "A")],
    ["above next_after, naming the last event's hash", { ...headAs(3, "A"), head_hash: eventHashOf(2) }],
    ["below next_after, naming the last event's hash", { ...headAs(1, "A"), head_hash: eventHashOf(2) }],
    ["not an object", "head"],
    ["naming another event's hash", { ...headAs(2, "A"), head_hash: eventHashOf(1) }],
    ["with no head_hash", { ...headAs(2, "A"), head_hash: undefined }],
  ]) {
    const pages = [pageText([event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })], 2, 2, pageHead), pageText([event(3, "run.sealed", { run_id: 12 })], 3, 3)];
    // A head that does match is kept by the same run.
    if (label === "below next_after") {
      const { result: ok } = await withServer(
        (req, body, i) => ({ text: [pageText([event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })], 2, 2, headAs(2, "A")), pages[1]][i] }),
        async (c) => {
          const follower = c.followSignals({ wait: 0 });
          for await (const e of follower) if (e.data.sequence === 3) break;
          return follower.head;
        },
      );
      assert.equal(ok.sequence, 2);
    }
    const { result } = await withServer(
      (req, body, i) => ({ text: pages[i] }),
      async (c) => {
        const reported = [];
        const follower = c.followSignals({ wait: 0, onHead: (h) => reported.push(h) });
        for await (const e of follower) if (e.data.sequence === 3) break;
        return { head: follower.head, reported };
      },
    );
    assert.equal(result.head, undefined, label);
    assert.deepEqual(result.reported, [], label);
  }
});

test("a follow that starts after a stored place keeps a head for it only with afterEventHash", async () => {
  const pages = [pageText([], 3, 3, headAs(3, "A")), pageText([event(4, "run.sealed", { run_id: 12 })], 4, 4, headAs(4, "B")), pageText([event(5, "run.sealed", { run_id: 13 })], 5, 5)];
  for (const [afterEventHash, expected] of [
    [undefined, [4]],
    [eventHashOf(3), [3, 4]],
    // A saved hash that is not event 3's keeps nothing for event 3.
    [eventHashOf(2), [4]],
  ]) {
    const { seen, result } = await withServer(
      (req, body, i) => ({ text: pages[i] }),
      async (c) => {
        const reported = [];
        const options = { after: 3, wait: 1, onHead: (h) => reported.push(h.sequence) };
        if (afterEventHash !== undefined) options.afterEventHash = afterEventHash;
        const follower = c.followSignals(options);
        for await (const e of follower) if (e.data.sequence === 5) break;
        return reported;
      },
    );
    assert.deepEqual(result, expected, String(afterEventHash));
    assert.deepEqual(requests(seen), ["GET /signals?after=3&wait=1", "GET /signals?after=3&wait=1", "GET /signals?after=4&wait=1"].slice(0, seen.length));
  }
});

test("followSignals refuses a non-empty afterEventHash that is not 64 lowercase hex before sending, and reads an empty one as none", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const bad of ["ab", eventHashOf(3).slice(1), "A".repeat(64), eventHashOf(3).toUpperCase(), "g".repeat(64), 5, null]) {
      assert.throws(() => c.followSignals({ after: 3, afterEventHash: bad }), (err) => err instanceof VerdifaxError && /followSignals afterEventHash must (be 64 hex characters|contain only lowercase hex)/.test(err.message), String(bad));
    }
  });
  assert.equal(seen.length, 0);
  // An empty afterEventHash is no hash: a resumed follower keeps no head for event `after`.
  const { result } = await withServer(
    (req, body, i) => ({ text: [pageText([], 3, 3, headAs(3, "A")), pageText([event(4, "run.sealed", { run_id: 12 })], 4, 4)][i] }),
    async (c) => {
      const follower = c.followSignals({ after: 3, wait: 1, afterEventHash: "" });
      for await (const e of follower) if (e.data.sequence === 4) break;
      return follower.head;
    },
  );
  assert.equal(result, undefined);
});

test("a head on a page the caller stopped inside is not kept", async () => {
  for (const stopAt of [1, 2]) {
    const { seen, result } = await withServer(
      () => ({ text: pageText([event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })], 2, 2, headAs(2, "A")) }),
      async (c) => {
        const reported = [];
        const follower = c.followSignals({ wait: 0, onHead: (h) => reported.push(h) });
        for await (const e of follower) if (e.data.sequence === stopAt) break;
        return { head: follower.head, reported };
      },
    );
    assert.equal(result.head, undefined, `stopped at ${stopAt}`);
    assert.deepEqual(result.reported, [], `stopped at ${stopAt}`);
    assert.equal(seen.length, 1);
  }
});

test("the follower's head is read-only and shown when the follower is listed", async () => {
  const pages = [pageText([event(1, "run.sealed", { run_id: 10 })], 1, 1, headAs(1, "A")), pageText([event(2, "run.sealed", { run_id: 11 })], 2, 2)];
  const { result } = await withServer(
    (req, body, i) => ({ text: pages[i] }),
    async (c) => {
      const follower = c.followSignals({ wait: 0 });
      // A module is strict, so writing a getter-only property throws.
      assert.throws(() => {
        follower.head = undefined;
      }, TypeError);
      for await (const e of follower) if (e.data.sequence === 2) break;
      return { head: follower.head, keys: Object.keys(follower) };
    },
  );
  assert.equal(result.head.sequence, 1);
  assert.ok(result.keys.includes("head"));
});

test("followSignals refuses an onHead that is not a function before sending, and passes on what onHead throws", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const onHead of ["log", 5, null, {}]) {
      assert.throws(() => c.followSignals({ onHead }), (err) => err instanceof VerdifaxError && /followSignals onHead must be a function/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
  const failed = new Error("the caller's store is down");
  const { result } = await withServer(
    () => ({ text: pageText([event(1, "run.sealed", { run_id: 10 })], 1, 1, headAs(1, "A")) }),
    async (c) => {
      const follower = c.followSignals({ wait: 0, onHead: () => { throw failed; } });
      try {
        for await (const e of follower) continue;
      } catch (err) {
        return { err, head: follower.head };
      }
    },
  );
  assert.equal(result.err, failed);
  assert.equal(result.head.sequence, 1);
});

// ── Request-key changes sealed as account changes ───────────────

const SIGNAL = (sequence) => ({ signal_account: "account-7", signal_sequence: sequence, signal_previous_hash: "e".repeat(64) });

/** The approval the server seals, as the client sent it: the key in force
 *  signs the change to `newKey`. */
function approval(seed, currentKey, newKey, signedAt, nonce) {
  return { public_key: currentKey, ...requestKeyChangeApproval(seed, newKey, { signedAt, nonce }) };
}

const REGISTERED = {
  format: "verdifax.account-change.v1",
  action: "request_key.registered",
  decided_by: "owner",
  key_id: 31,
  value: KEY_A,
  changed_at: "2026-11-12T20:00:00.000000001Z",
  signal: SIGNAL(1),
  account_change_hash: "1".repeat(64),
  anchor: { receipt_kind: "account_change", log_index: 41 },
};
const ROTATED = {
  format: "verdifax.account-change.v1",
  action: "request_key.rotated",
  decided_by: "owner",
  key_id: 31,
  value: KEY_B,
  changed_at: "2026-11-12T20:01:00.000000002Z",
  request_key_approval: approval(SEED_A, KEY_A, KEY_B, "2026-11-12T20:01:00Z", "0b".repeat(16)),
  signal: SIGNAL(2),
  account_change_hash: "2".repeat(64),
  anchor: { receipt_kind: "account_change", log_index: 42 },
};
const CLEARED_BY_OWNER = {
  format: "verdifax.account-change.v1",
  action: "request_key.cleared",
  decided_by: "owner",
  key_id: 31,
  value: "",
  changed_at: "2026-11-12T20:02:00.000000003Z",
  request_key_approval: approval(SEED_B, KEY_B, "", "2026-11-12T20:02:00Z", "0c".repeat(16)),
  signal: SIGNAL(3),
  account_change_hash: "3".repeat(64),
  anchor: { receipt_kind: "account_change", log_index: 43 },
};
const CLEARED_BY_VERDIFAX = {
  format: "verdifax.account-change.v1",
  action: "request_key.cleared",
  decided_by: "verdifax_admin",
  key_id: 32,
  value: "",
  changed_at: "2026-11-12T20:03:00.000000004Z",
  signal: SIGNAL(4),
  account_change_hash: "4".repeat(64),
};
const SHAPES = [REGISTERED, ROTATED, CLEARED_BY_OWNER, CLEARED_BY_VERDIFAX];

/** Verifies an approval over the request-key change preimage, written out
 *  independently of the SDK, under the key it names. */
function approvalVerifies(a, newKey) {
  const signed = `verdifax.request-key-change.v1\0${newKey}\0${a.signed_at}\0${a.nonce}`;
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(Buffer.from(a.public_key, "base64")), Buffer.from(a.signature, "base64"));
}

test("the fixtures' approvals are the request-key change approvals the server checks", () => {
  assert.ok(approvalVerifies(ROTATED.request_key_approval, KEY_B));
  assert.ok(approvalVerifies(CLEARED_BY_OWNER.request_key_approval, ""));
  assert.equal(approvalVerifies(ROTATED.request_key_approval, KEY_A), false);
  assert.equal(approvalVerifies(CLEARED_BY_OWNER.request_key_approval, KEY_B), false);
});

test("each new account-change shape is read from the feed with every field, as sent", async () => {
  const events = SHAPES.map((entry, i) => event(i + 1, "account.changed", entry));
  const text = pageText(events, 4, 4, head(4));
  const { result } = await withServer(() => ({ text }), (c) => c.getSignals({ asOwner: true }));
  assert.equal(result.events.length, SHAPES.length);
  for (const [i, sent] of SHAPES.entries()) {
    const entry = result.events[i].data.entry;
    assert.equal(result.events[i].data.kind, "account.changed");
    assert.deepEqual(Object.keys(entry), Object.keys(sent), sent.action);
    assert.deepEqual(entry, sent, sent.action);
    assert.equal(entry.sealedJson, JSON.stringify(sent), sent.action);
    assert.equal(entry.owner_signature, undefined, sent.action);
  }
  const [registered, rotated, ownerClear, verdifaxClear] = result.events.map((e) => e.data.entry);
  assert.equal(registered.request_key_approval, undefined);
  assert.equal(registered.value, KEY_A);
  assert.deepEqual(Object.keys(rotated.request_key_approval), ["public_key", "signature", "signed_at", "nonce"]);
  assert.equal(rotated.request_key_approval.public_key, KEY_A);
  assert.equal(rotated.request_key_approval.sealedJson, JSON.stringify(ROTATED.request_key_approval));
  assert.ok(approvalVerifies(rotated.request_key_approval, rotated.value));
  assert.equal(ownerClear.decided_by, "owner");
  assert.equal(ownerClear.value, "");
  assert.ok(approvalVerifies(ownerClear.request_key_approval, ""));
  assert.equal(verdifaxClear.decided_by, "verdifax_admin");
  assert.equal(verdifaxClear.request_key_approval, undefined);
});

test("followSignals and pendingSignOffs read the new account changes like any other event", async () => {
  const entries = [
    ["run.sealed", { run_id: 10, signoff_required: true }],
    ...SHAPES.map((entry) => ["account.changed", entry]),
    ["run.sealed", { run_id: 11, signoff_required: true }],
    ["signoff.recorded", { decision: "approve", target: { kind: "record", run_id: 11 } }],
  ];
  const events = entries.map(([kind, entry], i) => event(i + 1, kind, entry));
  const n = events.length;
  const pages = [pageText(events, n, n, head(n)), pageText([event(n + 1, "run.sealed", { run_id: 12 })], n + 1, n + 1)];
  const { result } = await withServer(
    (req, body, i) => ({ text: pages[i] }),
    async (c) => {
      const follower = c.followSignals({ wait: 0 });
      const got = [];
      for await (const e of follower) {
        got.push(e);
        if (e.data.sequence === n + 1) break;
      }
      return { got, head: follower.head };
    },
  );
  assert.deepEqual(result.got.map((e) => e.data.kind), [...entries.map(([kind]) => kind), "run.sealed"]);
  assert.deepEqual(result.got.slice(1, 5).map((e) => e.data.entry.action), SHAPES.map((s) => s.action));
  assert.equal(result.head.sequence, n);
  assert.deepEqual(pendingSignOffs(result.got), [10]);
  assert.deepEqual(pendingSignOffs(events), [10]);
});

// ── A deleted record's event and its tombstone (round 60) ──────────

const TOMBSTONE = {
  format: "verdifax.run-deletion.v1",
  decided_by: "owner",
  run_id: 21,
  record_hash: "ab".repeat(32),
  log_entries: ["1201", "1202", "18446744073709551615"],
  changed_at: "2026-11-12T20:30:00.000000005Z",
  owner_signature: { public_key: KEY_A, signature: "c2ln", signed_at: "2026-11-12T20:30:00Z", nonce: "0d".repeat(16) },
  signal: SIGNAL(3),
  deletion_hash: "5".repeat(64),
  anchor: { receipt_kind: "run_deletion", log_index: 9007199254740993 },
};

/** A deleted job step's tombstone, with its own job links, as the server
 *  writes it from this release on. */
const JOB_TOMBSTONE = {
  format: "verdifax.run-deletion.v1",
  decided_by: "verdifax_admin",
  run_id: 23,
  record_hash: "cd".repeat(32),
  job_id: "job-1",
  step_id: "step-2",
  job_links: { previous_record_hashes: ["0a".repeat(32), "0b".repeat(32)], external_previous: ["0c".repeat(32)], final: true },
  log_entries: ["1301"],
  changed_at: "2026-11-12T20:31:00.000000006Z",
  signal: SIGNAL(5),
  deletion_hash: "6".repeat(64),
};

/** A deleted job step that followed nothing and did not close its job: its
 *  links are present and empty. */
const EMPTY_LINKS_TOMBSTONE = { ...JOB_TOMBSTONE, run_id: 24, step_id: "step-1", job_links: {}, signal: SIGNAL(6), deletion_hash: "7".repeat(64) };

/** The receipt event of a refused run whose record was deleted: its entry
 *  is that record, so it is served with entry null and the tombstone in
 *  `deleted`. */
function deletedReceiptEvent(sequence) {
  const e = event(sequence, "run.refused", null);
  e.data.run_id = 21;
  e.data.reason = "the record was deleted by owner; its tombstone stands in its place";
  e.data.deleted = TOMBSTONE;
  return e;
}

test("a deleted record's receipt event keeps its null entry and its tombstone, log_entries included, as sent", async () => {
  const events = [deletedReceiptEvent(1), event(2, "run.sealed", { run_id: 22, signoff_required: true }), event(3, "run.deleted", TOMBSTONE)];
  const text = pageText(events, 3, 3);
  const { result } = await withServer(() => ({ text }), (c) => c.getSignals({ asOwner: true }));
  const [gone, sealed, tombstoneEvent] = result.events;
  assert.equal(gone.data.kind, "run.refused");
  assert.equal(gone.data.entry, null);
  const expected = JSON.parse(JSON.stringify(TOMBSTONE));
  assert.deepEqual(gone.data.deleted, expected);
  assert.equal(gone.data.deleted.job_links, undefined);
  assert.deepEqual(gone.data.deleted.log_entries, ["1201", "1202", "18446744073709551615"]);
  assert.equal(gone.data.deleted.log_entries.sealedJson, '["1201","1202","18446744073709551615"]');
  // The exact text keeps the anchor's digits, which JSON.parse rounds.
  const tombstoneText = JSON.stringify(TOMBSTONE).replace(/9007199254740992/g, "9007199254740993");
  assert.equal(gone.data.deleted.sealedJson, tombstoneText);
  assert.equal(tombstoneEvent.data.entry.sealedJson, tombstoneText);
  assert.deepEqual(tombstoneEvent.data.entry.log_entries, TOMBSTONE.log_entries);
  assert.ok(result.sealedJson.includes(`"entry":null,`));
  assert.ok(result.sealedJson.includes(`"deleted":${tombstoneText}}`));
  // An event that is its own sealed record keeps its entry.
  assert.deepEqual(sealed.data.entry, { run_id: 22, signoff_required: true });
  assert.equal(sealed.data.deleted, undefined);
});

test("a job step's tombstone keeps its job_links, full or empty, as sent, and an older one has none", async () => {
  const events = [
    event(4, "run.sealed", { run_id: 23, signoff_required: true }),
    event(5, "run.deleted", JOB_TOMBSTONE),
    event(6, "run.deleted", EMPTY_LINKS_TOMBSTONE),
    event(7, "run.deleted", TOMBSTONE),
  ];
  const text = pageText(events, 7, 7);
  const { result } = await withServer(() => ({ text }), (c) => c.getSignals({ after: 3, asOwner: true }));
  const [, full, empty, older] = result.events.map((e) => e.data.entry);
  assert.deepEqual(full, JOB_TOMBSTONE);
  assert.deepEqual(full.job_links, { previous_record_hashes: ["0a".repeat(32), "0b".repeat(32)], external_previous: ["0c".repeat(32)], final: true });
  assert.equal(full.job_links.sealedJson, JSON.stringify(JOB_TOMBSTONE.job_links));
  assert.equal(full.job_links.previous_record_hashes.sealedJson, JSON.stringify(JOB_TOMBSTONE.job_links.previous_record_hashes));
  assert.equal(full.sealedJson, JSON.stringify(JOB_TOMBSTONE));
  assert.deepEqual(empty.job_links, {});
  assert.equal(empty.job_links.sealedJson, "{}");
  assert.equal(empty.sealedJson, JSON.stringify(EMPTY_LINKS_TOMBSTONE));
  assert.equal("job_links" in older, false);
});

test("pendingSignOffs and followSignals read a feed with a deleted record's receipt event and a deleted job step", async () => {
  const sealedRequired = (sequence, run) => event(sequence, "run.sealed", { run_id: run, signoff_required: true });
  const events = [deletedReceiptEvent(1), sealedRequired(2, 22), sealedRequired(3, 23), event(4, "run.deleted", JOB_TOMBSTONE)];
  assert.deepEqual(pendingSignOffs(events), [22]);
  // The deleted step's own run.sealed event keeps its entry: without its
  // run.deleted event, it is still listed.
  assert.deepEqual(pendingSignOffs(events.slice(0, 3)), [22, 23]);
  // A run.sealed event with no run is still refused.
  assert.throws(() => pendingSignOffs([event(1, "run.sealed", null)]), (err) => err instanceof VerdifaxError && /names no run/.test(err.message));
  const { result } = await withServer(
    () => ({ text: pageText(events, 4, 4) }),
    async (c) => {
      const got = [];
      for await (const e of c.followSignals({ wait: 0 })) {
        got.push(e);
        if (e.data.sequence === 4) break;
      }
      return got;
    },
  );
  assert.deepEqual(result.map((e) => e.data.sequence), [1, 2, 3, 4]);
  assert.deepEqual(pendingSignOffs(result), [22]);
});

// The shared vector, copied unchanged from scripts/sdk-pending-signoffs-vector.json:
// every SDK's pendingSignOffs answers the same for the same feed (R257).
const PENDING_VECTOR = JSON.parse(readFileSync(new URL("./sdk-pending-signoffs-vector.json", import.meta.url), "utf8"));

/** A tombstone served in place of an entry, for the vector's `deleted`. */
const tombstoneFor = (deleted, sequence) => ({ ...TOMBSTONE, run_id: deleted.run_id, signal: SIGNAL(sequence) });

test("vector: pendingSignOffs answers every shared case as every SDK does", async () => {
  assert.ok(PENDING_VECTOR.cases.length >= 8);
  for (const c of PENDING_VECTOR.cases) {
    const events = c.events.map((abstract, i) => {
      const e = event(i + 1, abstract.kind, abstract.entry);
      if (abstract.deleted !== null) {
        e.data.reason = "the record was deleted by owner; its tombstone stands in its place";
        e.data.deleted = tombstoneFor(abstract.deleted, i + 1);
      }
      return e;
    });
    // Served and read as the client reads any page.
    const { result: page } = await withServer(() => ({ text: pageText(events, events.length, events.length) }), (client) => client.getSignals({ asOwner: true }));
    assert.equal(page.events.length, c.events.length, c.name);
    for (const [i, abstract] of c.events.entries()) {
      assert.deepEqual(page.events[i].data.entry, abstract.entry, c.name);
      assert.equal(page.events[i].data.deleted?.run_id, abstract.deleted?.run_id, c.name);
    }
    if (c.expected_error) {
      assert.throws(() => pendingSignOffs(page.events), (err) => err instanceof VerdifaxError && /names no run/.test(err.message), c.name);
    } else {
      assert.deepEqual(pendingSignOffs(page.events), c.expected_pending, c.name);
    }
  }
});

test("pendingSignOffs refuses a run.sealed or run.deleted event whose run id is not a whole number above zero", () => {
  for (const [kind, entry] of [
    ["run.sealed", { run_id: 0, signoff_required: true }],
    ["run.sealed", { run_id: -1, signoff_required: true }],
    ["run.sealed", { run_id: 1.5, signoff_required: true }],
    ["run.sealed", { run_id: "10", signoff_required: true }],
    ["run.sealed", null],
    ["run.deleted", { run_id: 0 }],
    ["run.deleted", null],
  ]) {
    assert.throws(() => pendingSignOffs([event(1, kind, entry)]), (err) => err instanceof VerdifaxError && new RegExp(`the ${kind.replace(".", "\\.")} entry of event account-7/1 names no run`).test(err.message), JSON.stringify([kind, entry]));
  }
});

// ── The server's 409: the request key changed since the change was signed ──

const MOVED = "the request key changed since this change was signed; read the key again and sign the change with it";

test("each request-key method passes on the server's 409 as an APIError with its message, without a retry", async () => {
  const next = Buffer.alloc(32, 0x43);
  for (const [name, call, method, path] of [
    ["registerRequestKey", (c) => c.registerRequestKey(), "POST", "/keys/request-key"],
    ["rotateRequestKey", (c) => c.rotateRequestKey(next), "POST", "/keys/request-key"],
    ["clearRequestKey", (c) => c.clearRequestKey(), "DELETE", "/keys/request-key"],
    ["registerAccountRequestKey", (c) => c.registerAccountRequestKey(), "POST", "/account/request-key"],
    ["rotateAccountRequestKey", (c) => c.rotateAccountRequestKey(next), "POST", "/account/request-key"],
    ["clearAccountRequestKey", (c) => c.clearAccountRequestKey(), "DELETE", "/account/request-key"],
  ]) {
    const { seen } = await withServer(
      () => ({ status: 409, json: { ok: false, error: MOVED } }),
      async (c) => {
        await assert.rejects(call(c), (err) => {
          assert.ok(err instanceof APIError, name);
          assert.ok(err instanceof VerdifaxError, name);
          assert.equal(err.status, 409, name);
          assert.equal(err.path, path, name);
          assert.equal(err.message, MOVED, name);
          return true;
        });
      },
      { signingKey: SEED_A, maxRetries: 3 },
    );
    assert.deepEqual(requests(seen), [`${method} ${path}`], name);
  }
});

test("after a 409, rotateRequestKey and clearRequestKey keep the client's current key", async () => {
  const next = Buffer.alloc(32, 0x43);
  const nextKey = publicKeyOf(next).toString("base64");
  const { seen } = await withServer(
    (req, body, i) => (i % 2 === 0 ? { status: 409, json: { ok: false, error: MOVED } } : { json: { ok: true } }),
    async (c) => {
      await assert.rejects(c.rotateRequestKey(next), (err) => err instanceof APIError && err.status === 409);
      await c.rotateRequestKey(next);
      await assert.rejects(c.clearRequestKey(), (err) => err instanceof APIError && err.status === 409);
      await c.clearRequestKey();
    },
    { signingKey: SEED_A },
  );
  assert.deepEqual(requests(seen), ["POST /keys/request-key", "POST /keys/request-key", "DELETE /keys/request-key", "DELETE /keys/request-key"]);
  // The retried rotation is still approved by the key in force before it.
  for (const i of [0, 1]) {
    assert.ok(approvalVerifies({ public_key: KEY_A, ...seen[i].body.change }, nextKey), `rotation ${i}`);
  }
  // The rotation succeeded, so both clears are approved by the new key.
  for (const i of [2, 3]) {
    assert.ok(approvalVerifies({ public_key: nextKey, ...seen[i].body.change }, ""), `clear ${i}`);
  }
});

// ── rotateAccountRequestKey: the owner key's request-key rotation ──────

const OWNER_KEY_PATH = "/account/request-key";

test("rotateAccountRequestKey sends the new key, its proof and the current key's approval, then signs with the new key", async () => {
  const next = Buffer.alloc(32, 0x44);
  const nextKey = publicKeyOf(next).toString("base64");
  const { seen, result } = await withServer(
    (req) => (req.method === "POST" ? { json: { ok: true, public_key: nextKey } } : { json: { ok: true } }),
    async (c) => {
      const out = await c.rotateAccountRequestKey(next);
      await c.clearAccountRequestKey();
      return out;
    },
    { signingKey: SEED_A },
  );
  assert.deepEqual(result, { ok: true, public_key: nextKey });
  assert.deepEqual(requests(seen), [`POST ${OWNER_KEY_PATH}`, `DELETE ${OWNER_KEY_PATH}`]);
  const { public_key, proof, change } = seen[0].body;
  assert.deepEqual(Object.keys(seen[0].body).sort(), ["change", "proof", "public_key"]);
  assert.deepEqual(Object.keys(change).sort(), ["nonce", "signature", "signed_at"]);
  assert.equal(public_key, nextKey);
  const proofText = Buffer.from(`verdifax.request-key.v1\0${nextKey}`, "utf8");
  assert.ok(crypto.verify(null, proofText, publicKeyObject(publicKeyOf(next)), Buffer.from(proof, "base64")), "the proof is by the new key");
  assert.ok(approvalVerifies({ public_key: KEY_A, ...change }, nextKey), "the change is approved by the current key");
  assert.match(change.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(change.nonce, /^[0-9a-f]{32}$/);
  // After the 2xx the client signs with the new key.
  assert.ok(approvalVerifies({ public_key: nextKey, ...seen[1].body.change }, ""), "the next change is approved by the new key");
  assert.equal(approvalVerifies({ public_key: KEY_A, ...seen[1].body.change }, ""), false);
});

test("a refused rotateAccountRequestKey keeps the current key, and is not retried", async () => {
  const next = Buffer.alloc(32, 0x44);
  for (const [status, error] of [[403, "the current request key must approve this change"], [409, MOVED], [503, "unavailable"]]) {
    const { seen } = await withServer(
      (req) => (req.method === "POST" ? { status, json: { ok: false, error } } : { json: { ok: true } }),
      async (c) => {
        await assert.rejects(c.rotateAccountRequestKey(next), (err) => err instanceof APIError && err.status === status && err.message === error && err.path === OWNER_KEY_PATH);
        await c.clearAccountRequestKey();
      },
      { signingKey: SEED_A, maxRetries: 3 },
    );
    assert.deepEqual(requests(seen), [`POST ${OWNER_KEY_PATH}`, `DELETE ${OWNER_KEY_PATH}`], String(status));
    assert.ok(approvalVerifies({ public_key: KEY_A, ...seen[1].body.change }, ""), `${status}: the client still signs with the current key`);
  }
});

test("rotateAccountRequestKey needs a current key, a good new key and an API key, without a request", async () => {
  const next = Buffer.alloc(32, 0x44);
  const { seen } = await withServer(null, async (c) => {
    await assert.rejects(c.rotateAccountRequestKey(next), (err) => err instanceof VerdifaxError && /rotateAccountRequestKey needs the current key in the signingKey client option/.test(err.message));
  });
  assert.equal(seen.length, 0);
  const signed = await withServer(null, async (c) => {
    await assert.rejects(c.rotateAccountRequestKey(Buffer.alloc(5)), VerdifaxError);
  }, { signingKey: SEED_A });
  assert.equal(signed.seen.length, 0);
  const noKey = await withServer(null, async (c) => {
    await assert.rejects(c.rotateAccountRequestKey(next), APIKeyRequiredError);
  }, { apiKey: "", signingKey: SEED_A });
  assert.equal(noKey.seen.length, 0);
});

test("sdk-parity.json names rotateAccountRequestKey, onHead and afterEventHash for Node, and the client has the method", () => {
  const parity = JSON.parse(readFileSync(new URL("./sdk-parity.json", import.meta.url), "utf8"));
  const names = JSON.stringify(parity);
  for (const name of ['"node":"rotateAccountRequestKey"', '"node":"onHead"', '"node":"afterEventHash"']) {
    assert.ok(names.replace(/\s+/g, "").includes(name), name);
  }
  assert.equal(typeof VerdifaxClient.prototype.rotateAccountRequestKey, "function");
});

// ── The error that stops following carries afterEventHash ─────────

test("SignalFeedError carries the event_hash of event lastSequence, so a caller resumes with both values", async () => {
  // Two events finished, then the read fails: the hash of event 2.
  const failing = await withServer(
    (req, body, i) => (i === 0 ? { text: pageText([event(1, "run.sealed", { run_id: 10 }), event(2, "run.sealed", { run_id: 11 })], 2, 2) } : { status: 403, json: { ok: false, error: "this key is revoked" } }),
    async (c) => {
      try {
        for await (const e of c.followSignals({ wait: 1 })) continue;
      } catch (err) {
        return err;
      }
    },
  );
  const err = failing.result;
  assert.ok(err instanceof SignalFeedError);
  assert.equal(err.lastSequence, 2);
  assert.equal(err.afterEventHash, eventHashOf(2));
  assert.ok(err.cause instanceof APIError);
  assert.match(err.message, /follow again with after: 2$/);

  // Resumed with both values, a follower at the feed's end keeps its head.
  const resumed = await withServer(
    (req, body, i) => ({ text: [pageText([], 2, 2, headAs(2, "A")), pageText([event(3, "run.sealed", { run_id: 12 })], 3, 3)][i] }),
    async (c) => {
      const follower = c.followSignals({ after: err.lastSequence, afterEventHash: err.afterEventHash, wait: 1 });
      for await (const e of follower) if (e.data.sequence === 3) break;
      return follower.head;
    },
  );
  assert.deepEqual(requests(resumed.seen), ["GET /signals?after=2&wait=1", "GET /signals?after=2&wait=1"]);
  assert.equal(resumed.result.sequence, 2);
});

test("SignalFeedError.afterEventHash is the given hash before any event is finished, absent with none, and set on a refused page", async () => {
  const stop = { status: 403, json: { ok: false, error: "stop" } };
  const followUntilError = (options, answer) =>
    withServer(answer, async (c) => {
      try {
        for await (const e of c.followSignals({ wait: 1, ...options })) continue;
      } catch (err) {
        return err;
      }
    });
  const none = (await followUntilError({}, () => stop)).result;
  assert.equal(none.lastSequence, 0);
  assert.equal(none.afterEventHash, undefined);
  assert.equal("afterEventHash" in none, false);
  const empty = (await followUntilError({ after: 3, afterEventHash: "" }, () => stop)).result;
  assert.equal(empty.afterEventHash, undefined);
  const given = (await followUntilError({ after: 3, afterEventHash: eventHashOf(3) }, () => stop)).result;
  assert.equal(given.lastSequence, 3);
  assert.equal(given.afterEventHash, eventHashOf(3));
  // A page that goes back is refused with the place and hash of the last event finished.
  const refused = (
    await followUntilError({}, (req, body, i) => ({ text: pageText([event(1, "run.sealed", { run_id: 10 })], 1, 3) }))
  ).result;
  assert.ok(refused instanceof SignalFeedError);
  assert.equal(refused.lastSequence, 1);
  assert.equal(refused.afterEventHash, eventHashOf(1));
  assert.match(refused.message, /out of order/);
});

// ── Types, exports and docs ─────────────────────────────────────

test("the typed models carry the two new actions, request_key_approval, the page's head, onHead, log_entries and deleted", () => {
  for (const file of ["../dist/index.d.ts", "../dist/index.d.mts"]) {
    const dts = readFileSync(new URL(file, import.meta.url), "utf8").replace(/\/\*\*[\s\S]*?\*\//g, "").replace(/\s+/g, " ");
    const actions = /type AccountChangeAction = ([^;]+);/.exec(dts)?.[1] ?? "";
    assert.deepEqual(
      [...actions.matchAll(/"([^"]+)"/g)].map((m) => m[1]),
      [
        "account.created",
        "request_key.cleared",
        "key.tier_set",
        "key.submitter_class_set",
        "key.billing_set",
        "owner_key.replacement_requested",
        "setting.owner_replacement",
        "setting.verdifax_deletion",
        "request_key.registered",
        "request_key.rotated",
      ],
      file,
    );
    const body = (name) => new RegExp(`interface ${name}(?: extends [^{]+)? \\{([^}]*)\\}`).exec(dts)?.[1] ?? "";
    assert.match(body("AccountChange"), /action: AccountChangeAction \| \(string & \{/, file);
    assert.match(dts, /request_key_approval\?: RequestKeyApproval;/, file);
    assert.equal(body("RequestKeyApproval").trim(), "public_key: string; signature: string; signed_at: string; nonce: string;", file);
    assert.match(body("SignalPage"), /head\?: FeedHead;/, file);
    for (const field of ['format: "verdifax.feed-head.v1";', "account: string;", "sequence: number;", "head_hash: Hex64;", "stated_at: string;", "head_statement_hash: Hex64;", "anchor?: unknown;"]) {
      assert.ok(body("FeedHead").includes(field), `${file} FeedHead ${field}`);
    }
    assert.match(dts, /interface SignalFollower extends AsyncGenerator<SignalEvent, void, undefined> \{ readonly head: FeedHead \| undefined; \}/, file);
    assert.match(dts, /followSignals\(options\?: FollowSignalsOptions\): SignalFollower;/, file);
    assert.match(body("FollowSignalsOptions"), /onHead\?: \(head: FeedHead\) => void;/, file);
    assert.match(body("FollowSignalsOptions"), /afterEventHash\?: string;/, file);
    assert.match(dts, /class SignalFeedError extends VerdifaxError \{[^}]*readonly afterEventHash\?: string;/, file);
    assert.match(dts, /rotateAccountRequestKey\(newSigningKey: Uint8Array \| KeyObject\): Promise<RequestKeyRegistration>;/, file);
    assert.match(body("RunDeletion"), /log_entries\?: string\[\];/, file);
    assert.match(body("RunDeletion"), /job_links\?: DeletedJobLinks;/, file);
    assert.equal(body("DeletedJobLinks").trim(), "previous_record_hashes?: string[]; external_previous?: string[]; final?: boolean;", file);
    assert.match(dts, /interface SignalEventData \{[^]*?entry: Record<string, unknown> \| null; deleted\?: RunDeletion; \}/, file);
    const exported = /export \{([^}]+)\}/.exec(readFileSync(new URL(file, import.meta.url), "utf8"))[1];
    const names = exported.split(",").map((name) => name.trim().replace(/^type /, "").split(" as ").pop());
    for (const name of ["AccountChangeAction", "DeletedJobLinks", "FeedHead", "RequestKeyApproval", "SignalFollower"]) {
      assert.ok(names.includes(name), `${file} does not export ${name}`);
    }
  }
});

test("the README describes the feed head and the sealed request-key changes", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8").replace(/\s+/g, " ");
  for (const sentence of [
    "A page that reaches the feed's end carries the feed's head statement in `head` (`verdifax.feed-head.v1`)",
    "`followSignals` never hands out the head as an event. The follower it returns keeps the newest head in `head`, undefined until one is kept, and passes each newer one to the `onHead` option.",
    "A head is kept only when its `sequence` is its page's `next_after` and its `head_hash` is the `event_hash` of the last event you finished, and only once you have moved past every event on that page",
    "An event whose entry is a record that was deleted, the receipt event of a refused, halted or failed run, carries `entry: null` and the record's tombstone, a `RunDeletion`, in `data.deleted`. An event that is its own sealed record, such as `run.sealed`, keeps its entry.",
    "carries the step's own `job_links` (`previous_record_hashes`, `external_previous` and `final`), present even when empty",
    "A `run.sealed` or `run.deleted` entry that does not name a whole number above zero (a null entry, 0, a negative or fractional number, or a string) is refused with `VerdifaxError`; earlier releases accepted run 0",
    "`rotateAccountRequestKey(newSigningKey)` replaces the owner key's request key as `rotateRequestKey` does for a key's own",
    "whose `afterEventHash` is that event's `event_hash`",
    "afterEventHash = err.afterEventHash;",
    "(`request_key.registered`), replaces it (`request_key.rotated`) or clears it (`request_key.cleared`, decided by `owner`)",
    "a rotation and a holder's clear carry `request_key_approval`",
    "the server refuses the registration, rotation or clear with an `APIError` (409)",
  ]) {
    assert.ok(readme.includes(sentence), sentence);
  }
});

test("the 1.15.0 changelog entry comes first", () => {
  const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
  assert.match(changelog, /^# Changelog\n\n## 1\.15\.0\n/);
  assert.ok(changelog.includes("The user agent is `verdifax-sdk-node/1.15.0`."));
  assert.ok(changelog.includes("`pendingSignOffs` now refuses, with `VerdifaxError`, a `run.sealed` or `run.deleted` entry that does not name a whole number above zero: a null entry, 0, a negative or fractional number, or a string. Earlier releases accepted run 0. The shared pending sign-offs vector holds all four SDKs to this."));
});

test("no dash longer than a hyphen in the 1.15.0 sources, README, CHANGELOG or this test", () => {
  for (const file of ["../src/signals.ts", "../src/client.ts", "../src/types.ts", "../src/index.ts", "../README.md", "../CHANGELOG.md", "./round-61.test.mjs"]) {
    const text = readFileSync(new URL(file, import.meta.url), "utf8");
    assert.ok(!/[\u2013\u2014]/.test(text), `${file} has an en or em dash`);
  }
});
