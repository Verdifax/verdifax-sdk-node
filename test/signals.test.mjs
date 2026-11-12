// SDK 1.5.0: the signal feed, feed keys, webhooks, failure receipts,
// verifyWebhook and signalEventHash. The mock server listens on localhost
// only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  NotFoundError,
  SignalFeedError,
  VerdifaxClient,
  VerdifaxError,
  signalEventHash,
  verifyWebhook,
} from "../dist/index.mjs";

// The byte authority, copied unchanged from scripts/sdk-signature-vector.json.
const VECTOR = JSON.parse(readFileSync(new URL("./sdk-signature-vector.json", import.meta.url), "utf8"));
const ZEROS = "0".repeat(64);
const KINDS = [
  "run.refused",
  "run.halted",
  "run.failed",
  "policy.changed",
  "signoff.recorded",
  "approver.registered",
  "approver.revoked",
  "key.created",
  "key.revoked",
];

/** Answers each request from `answer(request, body, index)`, which returns
 *  `{ status, json, text, delayMs }`. */
async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, raw, headers: req.headers, body });
      const reply = answer?.(req, body, seen.length - 1) ?? {};
      const { status = 200, json = { ok: true }, delayMs = 0 } = reply;
      setTimeout(() => {
        res.statusCode = status;
        res.setHeader("Content-Type", "application/json");
        res.end(reply.text ?? JSON.stringify(json));
      }, delayMs);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({
      baseURL: `http://127.0.0.1:${server.address().port}`,
      apiKey: "feed",
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

/** A CloudEvent at `sequence`, in the server's form. */
function event(sequence, kind = "run.refused") {
  return {
    specversion: "1.0",
    id: `account-7/${sequence}`,
    source: "https://api.verdifax.com/accounts/account-7",
    type: `com.verdifax.${kind}`,
    time: "2026-11-07T12:00:00Z",
    datacontenttype: "application/json",
    data: {
      form: "verdifax.signal.v1",
      kind,
      account: "account-7",
      sequence,
      previous_signal_hash: sequence === 1 ? ZEROS : "e".repeat(64),
      event_hash: "f".repeat(64),
      run_id: 42,
      entry: { ok: true },
    },
  };
}

const page = (events, nextAfter, newest = 4) => ({ json: { events, next_after: nextAfter, newest } });

// ── The vector ──────────────────────────────────────────────────

const HEADERS = {
  "webhook-id": VECTOR.webhook_id,
  "webhook-timestamp": VECTOR.webhook_timestamp,
  "webhook-signature": VECTOR.webhook_signature,
};
const AT = new Date(Number(VECTOR.webhook_timestamp) * 1000);
const at = (seconds) => new Date((Number(VECTOR.webhook_timestamp) + seconds) * 1000);

/** One byte of `text` changed, at `index`. */
function changed(text, index = text.length - 2) {
  const c = text[index] === "a" ? "b" : "a";
  return text.slice(0, index) + c + text.slice(index + 1);
}

test("vector: signalEventHash", () => {
  const hash = signalEventHash(VECTOR.signal_kind, VECTOR.signal_entry_hash, {
    account: VECTOR.signal_account,
    sequence: VECTOR.signal_sequence,
    previousSignalHash: VECTOR.signal_previous_hash,
  });
  assert.equal(hash, VECTOR.signal_event_hash);
  // Written out independently of the SDK.
  const joined = ["verdifax.signal.v1", VECTOR.signal_kind, VECTOR.signal_entry_hash, VECTOR.signal_account, String(VECTOR.signal_sequence), VECTOR.signal_previous_hash].join("\0");
  assert.equal(crypto.createHash("sha256").update(joined, "utf8").digest("hex"), VECTOR.signal_event_hash);
});

test("signalEventHash is bound to every field", () => {
  const fields = { account: VECTOR.signal_account, sequence: VECTOR.signal_sequence, previousSignalHash: VECTOR.signal_previous_hash };
  for (const [kind, entry, f] of [
    ["run.halted", VECTOR.signal_entry_hash, fields],
    [VECTOR.signal_kind, "c".repeat(64), fields],
    [VECTOR.signal_kind, VECTOR.signal_entry_hash, { ...fields, account: "account-8" }],
    [VECTOR.signal_kind, VECTOR.signal_entry_hash, { ...fields, sequence: 13 }],
    [VECTOR.signal_kind, VECTOR.signal_entry_hash, { ...fields, previousSignalHash: ZEROS }],
  ]) {
    assert.notEqual(signalEventHash(kind, entry, f), VECTOR.signal_event_hash);
  }
});

test("signalEventHash refuses a field it cannot hash unambiguously", () => {
  const fields = { account: "account-7", sequence: 1, previousSignalHash: ZEROS };
  for (const [kind, entry, f, message] of [
    [5, "d", fields, /kind/],
    ["run.refused", undefined, fields, /entryHash/],
    ["run.refused", "d", { ...fields, account: "a\0b" }, /account/],
    ["run.refused", "d", { ...fields, previousSignalHash: undefined }, /previousSignalHash/],
    ["run.refused", "d", { ...fields, sequence: 1.5 }, /sequence/],
    ["run.refused", "d", { ...fields, sequence: -1 }, /sequence/],
    ["run.refused", "d", { ...fields, sequence: "12" }, /sequence/],
    ["run.refused", "d", undefined, /account/],
  ]) {
    assert.throws(() => signalEventHash(kind, entry, f), (err) => err instanceof VerdifaxError && message.test(err.message));
  }
});

test("vector: verifyWebhook accepts the delivery and returns its CloudEvent", () => {
  const out = verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT });
  assert.deepEqual(out, JSON.parse(VECTOR.webhook_body));
  // The same delivery as bytes, as a Uint8Array view and with a fetch Headers.
  assert.deepEqual(verifyWebhook(HEADERS, Buffer.from(VECTOR.webhook_body), VECTOR.webhook_secret, { now: AT }), out);
  const bytes = new TextEncoder().encode(VECTOR.webhook_body);
  assert.deepEqual(verifyWebhook(HEADERS, bytes, VECTOR.webhook_secret, { now: AT }), out);
  const padded = new Uint8Array(bytes.length + 4);
  padded.set(bytes, 2);
  assert.deepEqual(verifyWebhook(HEADERS, padded.subarray(2, 2 + bytes.length), VECTOR.webhook_secret, { now: AT }), out);
  assert.deepEqual(verifyWebhook(new Headers(HEADERS), VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), out);
});

test("verifyWebhook reads header names without regard to case", () => {
  const upper = {
    "Webhook-Id": VECTOR.webhook_id,
    "WEBHOOK-TIMESTAMP": VECTOR.webhook_timestamp,
    "Webhook-Signature": [VECTOR.webhook_signature],
  };
  assert.ok(verifyWebhook(upper, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }));
});

test("verifyWebhook refuses one changed byte of the body, the id, the timestamp or the signature", () => {
  const signature = VECTOR.webhook_signature;
  const cases = [
    [HEADERS, changed(VECTOR.webhook_body, 5), /no v1 signature in webhook-signature matches/],
    [{ ...HEADERS, "webhook-id": changed(VECTOR.webhook_id) }, VECTOR.webhook_body, /no v1 signature in webhook-signature matches/],
    [{ ...HEADERS, "webhook-timestamp": String(Number(VECTOR.webhook_timestamp) + 1) }, VECTOR.webhook_body, /no v1 signature in webhook-signature matches/],
    [{ ...HEADERS, "webhook-signature": changed(signature, 10) }, VECTOR.webhook_body, /no v1 signature in webhook-signature matches/],
  ];
  for (const [headers, body, message] of cases) {
    assert.throws(() => verifyWebhook(headers, body, VECTOR.webhook_secret, { now: AT }), (err) => err instanceof VerdifaxError && message.test(err.message));
  }
  const bytes = Buffer.from(VECTOR.webhook_body);
  bytes[0] ^= 1;
  assert.throws(() => verifyWebhook(HEADERS, bytes, VECTOR.webhook_secret, { now: AT }), /no v1 signature/);
});

test("verifyWebhook refuses a timestamp more than the tolerance away, in either direction", () => {
  for (const seconds of [301, -301, 100000]) {
    assert.throws(
      () => verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: at(seconds) }),
      (err) => err instanceof VerdifaxError && /webhook-timestamp is more than 300 seconds from now/.test(err.message),
    );
  }
  for (const seconds of [300, -300, 0]) {
    assert.ok(verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: at(seconds) }));
  }
  assert.ok(verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: at(500), toleranceSeconds: 600 }));
  assert.throws(() => verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: at(11), toleranceSeconds: 10 }), /more than 10 seconds/);
  // The current time, by default: the vector's timestamp is far from it.
  assert.throws(() => verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret), /more than 300 seconds/);
});

test("verifyWebhook accepts the right v1 entry beside a wrong one, and ignores other versions", () => {
  const wrong = `v1,${Buffer.alloc(32, 7).toString("base64")}`;
  for (const list of [
    `${wrong} ${VECTOR.webhook_signature}`,
    `${VECTOR.webhook_signature} ${wrong}`,
    `v1a,abc ${VECTOR.webhook_signature}`,
    `v1,short ${VECTOR.webhook_signature}`,
  ]) {
    assert.ok(verifyWebhook({ ...HEADERS, "webhook-signature": list }, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), list);
  }
  assert.throws(
    () => verifyWebhook({ ...HEADERS, "webhook-signature": wrong }, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }),
    /no v1 signature in webhook-signature matches/,
  );
  const v2 = `v2,${VECTOR.webhook_signature.slice(3)}`;
  assert.throws(() => verifyWebhook({ ...HEADERS, "webhook-signature": v2 }, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), /holds no v1 signature/);
});

test("verifyWebhook refuses a wrong secret prefix, a bad secret or another secret, never naming it", () => {
  const encoded = VECTOR.webhook_secret.slice("whsec_".length);
  const other = `whsec_${Buffer.alloc(32, 5).toString("base64")}`;
  for (const [secret, message] of [
    [encoded, /starts with whsec_/],
    [`whsek_${encoded}`, /starts with whsec_/],
    [`WHSEC_${encoded}`, /starts with whsec_/],
    [undefined, /starts with whsec_/],
    ["whsec_", /whsec_ and then base64/],
    ["whsec_not base64!", /whsec_ and then base64/],
    [other, /no v1 signature in webhook-signature matches/],
  ]) {
    assert.throws(
      () => verifyWebhook(HEADERS, VECTOR.webhook_body, secret, { now: AT }),
      (err) => err instanceof VerdifaxError && message.test(err.message) && (typeof secret !== "string" || secret.length < 7 || !err.message.includes(secret.slice(6))),
      String(secret),
    );
  }
  // An unpadded copy of the right secret is the same key.
  assert.ok(verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret.replace(/=+$/, ""), { now: AT }));
});

test("verifyWebhook says which check failed for a missing header, a bad timestamp, parsed JSON or a body that is not JSON", () => {
  const without = (name) => Object.fromEntries(Object.entries(HEADERS).filter(([k]) => k !== name));
  for (const name of ["webhook-id", "webhook-timestamp", "webhook-signature"]) {
    assert.throws(() => verifyWebhook(without(name), VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), new RegExp(`the ${name} header is missing`));
  }
  assert.throws(
    () => verifyWebhook({ ...HEADERS, "webhook-id": [VECTOR.webhook_id, "account-7/13"] }, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }),
    /webhook-id header appears more than once/,
  );
  for (const ts of ["17940960.5", "-1794096000", "soon", "1794096000 "]) {
    assert.throws(() => verifyWebhook({ ...HEADERS, "webhook-timestamp": ts }, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), /not a whole number of seconds/);
  }
  assert.throws(() => verifyWebhook(HEADERS, JSON.parse(VECTOR.webhook_body), VECTOR.webhook_secret, { now: AT }), /raw bytes received/);
  assert.throws(() => verifyWebhook(undefined, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT }), /needs the delivery's headers/);
  assert.throws(() => verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: AT, toleranceSeconds: -1 }), /toleranceSeconds/);
  assert.throws(() => verifyWebhook(HEADERS, VECTOR.webhook_body, VECTOR.webhook_secret, { now: Number(VECTOR.webhook_timestamp) }), /now must be a valid Date/);

  // A body that is signed but not a JSON object.
  const key = Buffer.from(VECTOR.webhook_secret.slice(6), "base64");
  const sign = (body) => `v1,${crypto.createHmac("sha256", key).update(`${VECTOR.webhook_id}.${VECTOR.webhook_timestamp}.${body}`).digest("base64")}`;
  for (const [body, message] of [["not json", /body is not JSON/], ["[1]", /not a CloudEvent object/]]) {
    assert.throws(() => verifyWebhook({ ...HEADERS, "webhook-signature": sign(body) }, body, VECTOR.webhook_secret, { now: AT }), message);
  }
});

test("verifyWebhook refuses a correctly signed body whose id differs from webhook-id", () => {
  const key = Buffer.from(VECTOR.webhook_secret.slice(6), "base64");
  const sign = (body) => `v1,${crypto.createHmac("sha256", key).update(`${VECTOR.webhook_id}.${VECTOR.webhook_timestamp}.${body}`).digest("base64")}`;
  const event = JSON.parse(VECTOR.webhook_body);
  for (const id of ["account-7/13", "", 12, null, undefined]) {
    const body = JSON.stringify({ ...event, id });
    assert.throws(
      () => verifyWebhook({ ...HEADERS, "webhook-signature": sign(body) }, body, VECTOR.webhook_secret, { now: AT }),
      (err) => err instanceof VerdifaxError
        && /the event id in the body does not match webhook-id/.test(err.message)
        && !err.message.includes(VECTOR.webhook_secret.slice(6, 20)),
      JSON.stringify(id),
    );
  }
});

// ── Reading the feed ────────────────────────────────────────────

test("getSignals sends after and wait, and limit when given, with the feed key", async () => {
  const body = { events: [event(1), event(2)], next_after: 2, newest: 4 };
  const { seen, result } = await withServer(
    () => ({ json: body }),
    async (c) => [
      await c.getSignals(),
      await c.getSignals({ after: 2, limit: 500, wait: 25 }),
      await c.getSignals({ after: 3, limit: 1, wait: 0 }),
    ],
  );
  assert.deepEqual(requests(seen), [
    "GET /signals?after=0&wait=0",
    "GET /signals?after=2&limit=500&wait=25",
    "GET /signals?after=3&limit=1&wait=0",
  ]);
  for (const r of seen) {
    assert.equal(r.headers["x-verdifax-key"], "feed");
    assert.equal(r.body, undefined);
  }
  assert.deepEqual(result[0], body);
});

test("getSignals with asOwner reads GET /account/signals", async () => {
  const { seen, result } = await withServer(
    () => ({ json: { next_after: 9, newest: 9 } }),
    async (c) => [await c.getSignals({ after: 9, asOwner: true }), await c.getSignals({ asOwner: false })],
    { apiKey: "owner" },
  );
  assert.deepEqual(requests(seen), ["GET /account/signals?after=9&wait=0", "GET /signals?after=0&wait=0"]);
  assert.equal(seen[0].headers["x-verdifax-key"], "owner");
  assert.deepEqual(result[0], { events: [], next_after: 9, newest: 9 });
});

test("getSignals refuses a bad after, limit, wait or asOwner before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const [options, message] of [
      [{ after: -1 }, /getSignals after must be a whole number of 0 or more/],
      [{ after: 1.5 }, /after must be/],
      [{ after: "1" }, /after must be/],
      [{ after: NaN }, /after must be/],
      [{ after: null }, /after must be/],
      [{ after: 2 ** 53 }, /after must be/],
      [{ limit: 0 }, /getSignals limit must be a whole number from 1 to 500/],
      [{ limit: 501 }, /limit must be/],
      [{ limit: 2.5 }, /limit must be/],
      [{ limit: "10" }, /limit must be/],
      [{ limit: null }, /limit must be/],
      [{ wait: -1 }, /getSignals wait must be a whole number of seconds from 0 to 25/],
      [{ wait: 26 }, /wait must be/],
      [{ wait: 0.5 }, /wait must be/],
      [{ wait: "5" }, /wait must be/],
      [{ wait: null }, /wait must be/],
      [{ asOwner: "yes" }, /getSignals asOwner must be true or false/],
      [{ asOwner: 1 }, /asOwner must be true or false/],
    ]) {
      await assert.rejects(c.getSignals(options), (err) => err instanceof VerdifaxError && message.test(err.message), JSON.stringify(options));
    }
  });
  assert.equal(seen.length, 0);
});

test("a signals call's timeout is at least the wait plus 30 seconds, whatever the client's default", async () => {
  // The client's own timeout is 100 ms and the server answers after 400 ms.
  const slow = () => ({ delayMs: 400, json: { events: [], next_after: 0, newest: 0 } });
  const { result } = await withServer(
    slow,
    async (c) => [await c.getSignals({ wait: 1 }), await c.getSignals(), await c.listWebhooks().catch((err) => err)],
    { timeoutMs: 100, maxRetries: 0 },
  );
  assert.deepEqual(result[0], { events: [], next_after: 0, newest: 0 });
  assert.deepEqual(result[1], { events: [], next_after: 0, newest: 0 });
  // Any other call keeps the client's timeout.
  assert.ok(result[2] instanceof VerdifaxError);
  assert.match(result[2].message, /HTTP transport/);
});

test("getSignals is retried as a GET", async () => {
  let calls = 0;
  const { result } = await withServer(
    () => (++calls === 1 ? { status: 503, json: {} } : page([event(1)], 1)),
    (c) => c.getSignals(),
  );
  assert.equal(calls, 2);
  assert.equal(result.events.length, 1);
});

// ── Following the feed ──────────────────────────────────────────

test("followSignals follows next_after through two pages and an empty page, and stops when the caller stops", async () => {
  const pages = [page([event(1), event(2)], 2), page([event(3, "policy.changed")], 3), page([], 3), page([event(4, "key.created")], 4)];
  const { seen, result } = await withServer(
    (req, body, i) => pages[i] ?? page([], 4),
    async (c) => {
      const got = [];
      for await (const e of c.followSignals()) {
        got.push(e.data.sequence);
        if (e.data.sequence === 4) break;
      }
      // Nothing more is read once the caller stops.
      await new Promise((r) => setTimeout(r, 50));
      return got;
    },
  );
  assert.deepEqual(result, [1, 2, 3, 4]);
  assert.deepEqual(requests(seen), [
    "GET /signals?after=0&wait=25",
    "GET /signals?after=2&wait=25",
    "GET /signals?after=3&wait=25",
    "GET /signals?after=3&wait=25",
  ]);
});

test("followSignals starts after a place, with its own wait, on the owner route with asOwner", async () => {
  const { seen, result } = await withServer(
    () => page([event(8)], 8),
    async (c) => {
      for await (const e of c.followSignals({ after: 7, wait: 3, asOwner: true })) return e;
    },
    { apiKey: "owner" },
  );
  assert.deepEqual(requests(seen), ["GET /account/signals?after=7&wait=3"]);
  assert.equal(result.id, "account-7/8");
});

test("followSignals retries a failed page with the client's retry policy", async () => {
  let calls = 0;
  const { result } = await withServer(
    () => (++calls === 2 ? { status: 503, json: {} } : calls === 1 ? page([event(1)], 1) : page([event(2)], 2)),
    async (c) => {
      const got = [];
      for await (const e of c.followSignals()) {
        got.push(e.data.sequence);
        if (got.length === 2) break;
      }
      return got;
    },
  );
  assert.deepEqual(result, [1, 2]);
  assert.equal(calls, 3);
});

test("followSignals raises a failed read with the last sequence read, and never loses its place", async () => {
  const { seen, result } = await withServer(
    (req, body, i) => (i === 0 ? page([event(1), event(2)], 2) : { status: 403, json: { ok: false, error: "this key is revoked" } }),
    async (c) => {
      const got = [];
      try {
        for await (const e of c.followSignals()) got.push(e.data.sequence);
      } catch (err) {
        return { got, err };
      }
    },
    { maxRetries: 3 },
  );
  assert.deepEqual(result.got, [1, 2]);
  assert.ok(result.err instanceof SignalFeedError);
  assert.ok(result.err instanceof VerdifaxError);
  assert.equal(result.err.lastSequence, 2);
  assert.ok(result.err.cause instanceof APIError);
  assert.equal(result.err.cause.status, 403);
  assert.match(result.err.message, /stopped after sequence 2: .*this key is revoked; follow again with after: 2$/);
  assert.equal(seen.length, 2);
});

test("followSignals refuses a page that would skip or go back, before handing out any of it", async () => {
  for (const bad of [
    page([event(1), event(3)], 4),
    page([event(2), event(1)], 2),
    { json: { events: [event(1)] } },
    page([], 5),
    { json: { events: [{ data: { sequence: "1" } }], next_after: 1 } },
    { json: { events: "none", next_after: 0 } },
  ]) {
    const { result } = await withServer(
      () => bad,
      async (c) => {
        const got = [];
        try {
          for await (const e of c.followSignals({ after: 0 })) got.push(e);
        } catch (err) {
          return { got, err };
        }
      },
    );
    assert.deepEqual(result.got, [], JSON.stringify(bad));
    assert.ok(result.err instanceof SignalFeedError, JSON.stringify(bad));
    assert.equal(result.err.lastSequence, 0);
  }
});

test("followSignals refuses a bad after, wait or asOwner at once, before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const [options, message] of [
      [{ after: -1 }, /followSignals after must be/],
      [{ after: 0.5 }, /followSignals after must be/],
      [{ wait: 26 }, /followSignals wait must be a whole number of seconds from 0 to 25/],
      [{ wait: -1 }, /followSignals wait must be/],
      [{ wait: null }, /followSignals wait must be/],
      [{ after: null }, /followSignals after must be/],
      [{ asOwner: "true" }, /followSignals asOwner must be true or false/],
    ]) {
      assert.throws(() => c.followSignals(options), (err) => err instanceof VerdifaxError && message.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

// ── Feed keys ───────────────────────────────────────────────────

test("createFeedKey posts the name and expiry to /account/feed-keys", async () => {
  const reply = { ok: true, id: 12, name: "customer:grc reader", account_id: "account-7", owner: false, tier: "production", secret: "s", hint: "h", request_key_required: false };
  const { seen, result } = await withServer(
    () => ({ status: 201, json: reply }),
    async (c) => [await c.createFeedKey("grc reader"), await c.createFeedKey("grc reader", { expiresAt: "2027-01-01" })],
    { apiKey: "owner" },
  );
  assert.deepEqual(requests(seen), ["POST /account/feed-keys", "POST /account/feed-keys"]);
  assert.deepEqual(seen[0].body, { name: "grc reader" });
  assert.deepEqual(seen[1].body, { name: "grc reader", expires_at: "2027-01-01" });
  assert.equal(seen[0].headers["x-verdifax-key"], "owner");
  assert.deepEqual(result[0], reply);
});

test("revokeFeedKey sends DELETE /account/feed-keys/{id} and maps another key to NotFoundError", async () => {
  const body = { ok: true, id: 12, revoked: true };
  const { seen, result } = await withServer(() => ({ json: body }), (c) => c.revokeFeedKey(12));
  assert.deepEqual(requests(seen), ["DELETE /account/feed-keys/12"]);
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, body);
  const missing = await withServer(
    () => ({ status: 404, json: { ok: false, error: "no such feed key in this account" } }),
    (c) => c.revokeFeedKey(3).catch((err) => err),
    { maxRetries: 3 },
  );
  assert.ok(missing.result instanceof NotFoundError);
  assert.equal(missing.seen.length, 1);
});

test("the feed key methods refuse a bad name, expiry or id before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const name of ["", "   ", undefined, null, 5, "x".repeat(201)]) {
      await assert.rejects(c.createFeedKey(name), /createFeedKey needs a name of at most 200 bytes/);
    }
    await assert.rejects(c.createFeedKey("reader", { expiresAt: 5 }), /createFeedKey expiresAt/);
    for (const id of [0, -1, 1.5, NaN, "5", "../keys", undefined, null]) {
      await assert.rejects(c.revokeFeedKey(id), (err) => err instanceof VerdifaxError && /id must be a whole number > 0/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

// ── Webhooks ────────────────────────────────────────────────────

test("createWebhook posts the address and kinds to /account/webhooks", async () => {
  const reply = { ok: true, id: 3, url: "https://hooks.example.com/v", types: ["run.refused"], created_at: "2026-11-07T12:00:00Z", secret: VECTOR.webhook_secret, hint: "h" };
  const { seen, result } = await withServer(
    () => ({ status: 201, json: reply }),
    async (c) => [
      await c.createWebhook("https://hooks.example.com/v", { types: ["run.refused", "run.halted"] }),
      await c.createWebhook("https://hooks.example.com/v"),
      await c.createWebhook("https://hooks.example.com/v", { types: [] }),
      await c.createWebhook("https://hooks.example.com/v", { types: KINDS }),
    ],
    { apiKey: "owner" },
  );
  assert.deepEqual(requests(seen), Array(4).fill("POST /account/webhooks"));
  assert.deepEqual(seen[0].body, { url: "https://hooks.example.com/v", types: ["run.refused", "run.halted"] });
  assert.deepEqual(seen[1].body, { url: "https://hooks.example.com/v" });
  assert.deepEqual(seen[2].body, { url: "https://hooks.example.com/v", types: [] });
  assert.deepEqual(seen[3].body.types, KINDS);
  assert.deepEqual(result[0], reply);
});

test("createWebhook refuses an address that is not https or a bad kind before sending", async () => {
  const url = "https://hooks.example.com/v";
  const { seen } = await withServer(undefined, async (c) => {
    for (const bad of ["http://hooks.example.com/v", "HTTPS://hooks.example.com", "hooks.example.com", "https://", "", undefined, 5]) {
      await assert.rejects(c.createWebhook(bad), /createWebhook needs a url that starts with https:\/\//);
    }
    for (const types of [["run.refused", "run.refused"], ["run.denied"], ["com.verdifax.run.refused"], [""], [5], "run.refused", {}, null]) {
      await assert.rejects(c.createWebhook(url, { types }), (err) => err instanceof VerdifaxError && /createWebhook types must/.test(err.message), JSON.stringify(types));
    }
  });
  assert.equal(seen.length, 0);
});

test("createWebhook passes on the server's refusals and is not retried", async () => {
  for (const [status, error] of [
    [400, "the address resolves to a private network"],
    [409, "an account may hold 10 webhook subscriptions"],
    [503, "webhooks need the deployment's KMS key, which is not configured here; read GET /signals instead"],
  ]) {
    const { seen, result } = await withServer(
      () => ({ status, json: { ok: false, error } }),
      (c) => c.createWebhook("https://hooks.example.com/v").catch((err) => err),
      { maxRetries: 3 },
    );
    assert.ok(result instanceof APIError);
    assert.equal(result.status, status);
    assert.equal(result.message, error);
    assert.equal(seen.length, 1);
  }
});

test("listWebhooks, deleteWebhook and listWebhookDeliveries send their routes", async () => {
  const hook = { id: 3, url: "https://hooks.example.com/v", types: [], created_at: "2026-11-07T12:00:00Z" };
  const delivery = { sequence: 4, status: "delivered", attempts: 1, last_status_code: 200, last_error: "", created_at: "2026-11-07T12:00:00Z", delivered_at: "2026-11-07T12:00:01Z" };
  const replies = [
    { json: { ok: true, webhooks: [hook] } },
    { json: { ok: true, id: 3, deleted: true } },
    { json: { ok: true, webhook_id: 3, deliveries: [delivery] } },
    { json: { ok: true, webhook_id: 3, deliveries: [] } },
    { json: { ok: true } },
    { json: { ok: true, webhook_id: 3 } },
  ];
  const { seen, result } = await withServer(
    (req, body, i) => replies[i],
    async (c) => [
      await c.listWebhooks(),
      await c.deleteWebhook(3),
      await c.listWebhookDeliveries(3),
      await c.listWebhookDeliveries(3, { limit: 500 }),
      await c.listWebhooks(),
      await c.listWebhookDeliveries(3, { limit: 1 }),
    ],
    { apiKey: "owner" },
  );
  assert.deepEqual(requests(seen), [
    "GET /account/webhooks",
    "DELETE /account/webhooks/3",
    "GET /account/webhooks/3/deliveries",
    "GET /account/webhooks/3/deliveries?limit=500",
    "GET /account/webhooks",
    "GET /account/webhooks/3/deliveries?limit=1",
  ]);
  for (const r of seen) assert.equal(r.body, undefined);
  assert.deepEqual(result[0], { ok: true, webhooks: [hook] });
  assert.deepEqual(result[1], { ok: true, id: 3, deleted: true });
  assert.deepEqual(result[2].deliveries, [delivery]);
  assert.deepEqual(result[4], { ok: true, webhooks: [] });
  assert.deepEqual(result[5], { ok: true, webhook_id: 3, deliveries: [] });
});

test("the webhook methods refuse a bad id or limit before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const id of [0, -1, 1.5, NaN, "3", "../keys", undefined, null]) {
      await assert.rejects(c.deleteWebhook(id), /id must be a whole number > 0/);
      await assert.rejects(c.listWebhookDeliveries(id), /id must be a whole number > 0/);
    }
    for (const limit of [0, 501, 1.5, "10", null]) {
      await assert.rejects(c.listWebhookDeliveries(3, { limit }), /listWebhookDeliveries limit must be a whole number from 1 to 500/);
    }
  });
  assert.equal(seen.length, 0);
});

// ── Failure receipts ────────────────────────────────────────────

test("getFailureReceipt reads GET /runs/{id}/failure-receipt and refuses a bad run id", async () => {
  const receipt = { ok: true, run_id: 42, failure_receipt: { hash: "a".repeat(64) }, receipt_anchor: { log_index: 3 } };
  const { seen, result } = await withServer(() => ({ json: receipt }), (c) => c.getFailureReceipt(42));
  assert.deepEqual(requests(seen), ["GET /runs/42/failure-receipt"]);
  assert.equal(seen[0].headers["x-verdifax-key"], "feed");
  assert.deepEqual(result, receipt);
  const old = await withServer(
    () => ({ status: 404, json: { ok: false, error: "run 41 failed before failure receipts were sealed, so it has none" } }),
    (c) => c.getFailureReceipt(41).catch((err) => err),
  );
  assert.ok(old.result instanceof NotFoundError);
  assert.match(old.result.message, /before failure receipts were sealed/);
  const none = await withServer(undefined, async (c) => {
    for (const id of [0, -1, 1.5, "42", undefined]) {
      await assert.rejects(c.getFailureReceipt(id), /runId must be a whole number > 0/);
    }
  });
  assert.equal(none.seen.length, 0);
});

// ── Everything else ─────────────────────────────────────────────

test("every signal feed method needs an API key", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  for (const call of [
    () => c.getSignals(),
    () => c.getSignals({ asOwner: true }),
    () => c.createFeedKey("reader"),
    () => c.revokeFeedKey(1),
    () => c.createWebhook("https://hooks.example.com/v"),
    () => c.listWebhooks(),
    () => c.deleteWebhook(1),
    () => c.listWebhookDeliveries(1),
    () => c.getFailureReceipt(1),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
  assert.throws(() => c.followSignals(), APIKeyRequiredError);
});

test("the README describes the signal feed and its limits", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8").replace(/\s+/g, " ");
  for (const sentence of [
    "## Signal feed",
    "client.followSignals(",
    "verifyWebhook(",
    "A feed key reads the feed and nothing else.",
    "A webhook delivery is a copy: the pull feed and the public log are the record.",
    "The feed cannot show a signal Verdifax never recorded.",
    "verdifax-verify --signals",
  ]) {
    assert.ok(readme.includes(sentence), sentence);
  }
});

test("no dash longer than a hyphen in the 1.5.0 sources, README or CHANGELOG", () => {
  for (const file of ["../src/signals.ts", "../src/client.ts", "../src/types.ts", "../src/errors.ts", "../README.md", "../CHANGELOG.md", "./signals.test.mjs"]) {
    const text = readFileSync(new URL(file, import.meta.url), "utf8");
    assert.ok(!/[\u2013\u2014]/.test(text), `${file} has an en or em dash`);
  }
});

test("the signal feed types and functions are exported", () => {
  for (const file of ["../dist/index.d.ts", "../dist/index.d.mts"]) {
    const exported = /export \{([^}]+)\}/.exec(readFileSync(new URL(file, import.meta.url), "utf8"))[1];
    const names = exported.split(",").map((name) => name.trim().replace(/^type /, "").split(" as ").pop());
    for (const name of [
      "CreatedFeedKey",
      "CreatedWebhook",
      "CreateFeedKeyOptions",
      "CreateWebhookOptions",
      "FeedKeyRevocation",
      "FollowSignalsOptions",
      "GetSignalsOptions",
      "ListWebhookDeliveriesOptions",
      "SignalEvent",
      "SignalEventData",
      "SignalEventHashFields",
      "SignalFeedError",
      "SignalKind",
      "SignalPage",
      "VerifyWebhookOptions",
      "Webhook",
      "WebhookDeletion",
      "WebhookDelivery",
      "WebhookDeliveryList",
      "WebhookHeaders",
      "WebhookList",
      "signalEventHash",
      "verifyWebhook",
    ]) {
      assert.ok(names.includes(name), `${file} does not export ${name}`);
    }
  }
});

// Round 58, B7: a run whose rule requires a sign-off is pending until the
// last sign-off on its record is an approval.
test("pendingSignOffs lists required runs without an approval in force", async () => {
  const { pendingSignOffs } = await import("../dist/index.js");
  const ev = (seq, kind, entry) => ({ id: `account-7/${seq}`, data: { kind, sequence: seq, entry } });
  const signOff = (run, decision, kind) => ({ decision, target: { kind, run_id: run } });
  const events = [
    ev(1, "run.sealed", { run_id: 10, signoff_required: true }),
    ev(2, "run.sealed", { run_id: 11 }),
    ev(3, "run.sealed", { run_id: 12, signoff_required: true }),
    ev(4, "run.sealed", { run_id: 13, signoff_required: true }),
    ev(5, "signoff.recorded", signOff(10, "approve", "record")),
    ev(6, "signoff.recorded", signOff(12, "approve", "record")),
    ev(7, "signoff.recorded", signOff(12, "reject", "record")),
    ev(8, "signoff.recorded", signOff(13, "approve", "receipt")),
  ];
  assert.deepEqual(pendingSignOffs(events), [12, 13]);
  assert.throws(() => pendingSignOffs([ev(1, "run.sealed", {})]));
});

// Round 59, N15 and N19: a job sign-off on a run's record counts, and the
// job's decision governs the record's own, as the verifier reads it.
test("pendingSignOffs reads a job sign-off as the verifier does", async () => {
  const { pendingSignOffs } = await import("../dist/index.js");
  const ev = (seq, kind, entry) => ({ id: `account-7/${seq}`, data: { kind, sequence: seq, entry } });
  const signOff = (run, decision, kind) => ({ decision, target: { kind, run_id: run } });
  const events = [
    ev(1, "run.sealed", { run_id: 20, signoff_required: true }),
    ev(2, "run.sealed", { run_id: 21, signoff_required: true }),
    ev(3, "run.sealed", { run_id: 22, signoff_required: true }),
    ev(4, "signoff.recorded", signOff(20, "approve", "job")),
    ev(5, "signoff.recorded", signOff(21, "reject", "job")),
    ev(6, "signoff.recorded", signOff(21, "approve", "record")),
    ev(7, "signoff.recorded", signOff(22, "reject", "record")),
    ev(8, "signoff.recorded", signOff(22, "approve", "job")),
  ];
  // 20: approved by its job. 21: the job's rejection governs its own
  // approval. 22: the job's approval governs its own rejection.
  assert.deepEqual(pendingSignOffs(events), [21]);
});
