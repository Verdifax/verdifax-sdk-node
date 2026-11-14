// SDK 1.14.0: the owner's blocks on Verdifax and run deletion, each signed by
// the owner key's request key, and the two admin routes that the blocks
// govern. The mock server listens on localhost only; nothing leaves this
// machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  VerdifaxClient,
  VerdifaxError,
  ownerChangePreimage,
} from "../dist/index.mjs";
import { publicKeyObject, signedFields } from "./signed-body.mjs";
import { webhookSealer } from "./webhook-server.mjs";

// The round 60 vector (business-records/sdk-spec-round60.md), computed with
// Go crypto/ed25519. Ed25519 is deterministic, so every SDK makes exactly
// this signature.
const OWNER_VECTOR = {
  seed: Buffer.alloc(32, 0x6f),
  account: "account-7",
  change: "setting.verdifax_deletion",
  subject: "blocked",
  signed_at: "2026-11-12T18:00:00Z",
  nonce: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
  public_key: "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68=",
  signature: "LuDMETlzleMt3lXhdED4f3qAy5tdgEsGW4uJmvJlv9Ld0mNlY0v8aIDLXxq1npkW3v5/gdPjIBent1yt5P/9Bw==",
};

const PKCS8_ED25519_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");

/** Signs an owner change from its preimage, as a caller holding the key
 *  would; the SDK keeps its own signer internal. */
function signOwner(seed, fields, { signedAt, nonce } = {}) {
  const signed_at = signedAt ?? new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const fresh = nonce ?? crypto.randomBytes(16).toString("hex");
  const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_HEADER, seed]), format: "der", type: "pkcs8" });
  const signature = crypto.sign(null, ownerChangePreimage({ ...fields, signed_at, nonce: fresh }), key).toString("base64");
  return { signature, signed_at, nonce: fresh };
}

const SEED = Buffer.alloc(32, 9);
const PUBLIC_KEY = crypto
  .createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SEED]), format: "der", type: "pkcs8" }))
  .export({ format: "der", type: "spki" })
  .subarray(-32);
const RECORD_HASH = "ab".repeat(32);
const ACCOUNT = { ok: true, account_id: "account-7", id: 7, name: "Acme", owner_replacement: "allowed", verdifax_deletion: "allowed" };
const SIGNAL = { signal_account: "account-7", signal_sequence: 5, signal_previous_hash: "e".repeat(64) };

/** Answers each request from `answer(request, body, index)`, which returns
 *  `{ status, json }`. */
async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, raw, headers: req.headers, body });
      const { status = 200, json = { ok: true } } = answer?.(req, body, seen.length - 1) ?? {};
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(json));
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

/** Rebuilds the owner-change preimage independently of the SDK and verifies
 *  the signature over it. */
function ownerVerifies(signature, account, change, subject, publicKey = PUBLIC_KEY) {
  const signed = ["verdifax.owner-change-signature.v1", account, change, subject, signature.signed_at, signature.nonce].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(publicKey), Buffer.from(signature.signature, "base64"));
}

function checkSignatureShape(signature) {
  assert.deepEqual(Object.keys(signature).sort(), ["nonce", "signature", "signed_at"]);
  assert.match(signature.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(signature.nonce, /^[0-9a-f]{32}$/);
  assert.ok(Math.abs(Date.parse(signature.signed_at) - Date.now()) < 60_000);
}

/** The record a server that seals what it was sent returns: the setting's
 *  account change or the run's tombstone, with the owner's signature under
 *  the client's key. `change` edits it, to make a mismatch. */
function sealedAnswer(req, body, change = (record) => record) {
  const owner_signature = { public_key: PUBLIC_KEY.toString("base64"), ...body.owner_signature };
  const setting = /^\/account\/settings\/(.+)$/.exec(req.url);
  if (setting) {
    const action = { "owner-replacement": "setting.owner_replacement", "verdifax-deletion": "setting.verdifax_deletion" }[setting[1]];
    const record = { format: "verdifax.account-change.v1", action, decided_by: "owner", key_id: 0, value: body.value, owner_signature, signal: SIGNAL };
    return { json: { ok: true, setting: setting[1], value: body.value, account_change: change(record) } };
  }
  const run_id = Number(/^\/account\/runs\/(\d+)\/delete$/.exec(req.url)[1]);
  const record = { format: "verdifax.run-deletion.v1", decided_by: "owner", run_id, record_hash: body.record_hash, owner_signature, signal: SIGNAL };
  return { json: { ok: true, run_id, deleted: true, run_deletion: change(record) } };
}

/** GET /account answers ACCOUNT; a change is answered by sealedAnswer. */
function sealingServer(change) {
  return (req, body) => (req.method === "GET" && req.url === "/account" ? { json: ACCOUNT } : sealedAnswer(req, body, change));
}

/** GET /account answers `account`; anything else answers `reply`. */
function ownerServer(reply, account = ACCOUNT) {
  return (req) => (req.method === "GET" && req.url === "/account" ? { json: account } : reply);
}

// ── The vector, byte for byte ───────────────────────────────────

test("vector: ownerChangePreimage joins the form and fields with zero bytes", () => {
  const preimage = ownerChangePreimage(OWNER_VECTOR);
  const expected = ["verdifax.owner-change-signature.v1", "account-7", "setting.verdifax_deletion", "blocked", "2026-11-12T18:00:00Z", "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"];
  assert.equal(preimage.toString("hex"), Buffer.from(expected.join("\u0000"), "utf8").toString("hex"));
  assert.equal(preimage.filter((byte) => byte === 0).length, 5);
});

test("vector: the preimage signed with the round 60 seed gives the round 60 signature", () => {
  const signature = signOwner(
    OWNER_VECTOR.seed,
    { account: OWNER_VECTOR.account, change: OWNER_VECTOR.change, subject: OWNER_VECTOR.subject },
    { signedAt: OWNER_VECTOR.signed_at, nonce: OWNER_VECTOR.nonce },
  );
  assert.deepEqual(signature, { signature: OWNER_VECTOR.signature, signed_at: OWNER_VECTOR.signed_at, nonce: OWNER_VECTOR.nonce });
  const publicKey = Buffer.from(OWNER_VECTOR.public_key, "base64");
  const derived = crypto
    .createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), OWNER_VECTOR.seed]), format: "der", type: "pkcs8" }))
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  assert.equal(derived.toString("base64"), OWNER_VECTOR.public_key);
  assert.ok(ownerVerifies(signature, OWNER_VECTOR.account, OWNER_VECTOR.change, OWNER_VECTOR.subject, publicKey));
  assert.ok(!ownerVerifies(signature, OWNER_VECTOR.account, "setting.owner_replacement", OWNER_VECTOR.subject, publicKey));
});

test("ownerChangeSignature is not exported: only the preimage helper is", async () => {
  const sdk = await import("../dist/index.mjs");
  const cjs = await import("../dist/index.js");
  assert.equal(typeof sdk.ownerChangePreimage, "function");
  assert.equal(sdk.ownerChangeSignature, undefined);
  assert.equal(cjs.ownerChangeSignature, undefined);
});

test("each owner change carries the current time and a fresh nonce", async () => {
  const { seen } = await withServer(
    (req, body) => sealedAnswer(req, body),
    async (c) => {
      await c.deleteRun(1, RECORD_HASH, { accountId: "account-7" });
      await c.deleteRun(1, RECORD_HASH, { accountId: "account-7" });
    },
    { signingKey: SEED },
  );
  const [first, second] = seen.map((r) => r.body.owner_signature);
  checkSignatureShape(first);
  checkSignatureShape(second);
  assert.notEqual(first.nonce, second.nonce);
  assert.ok(ownerVerifies(first, "account-7", "run.deleted", `1:${RECORD_HASH}`));
});

// ── setAccountSetting ───────────────────────────────────────────

test("setAccountSetting reads the account label, then signs the setting's change over the value", async () => {
  const { seen, result } = await withServer(sealingServer(), (c) => c.setAccountSetting("verdifax-deletion", "blocked"), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account", "PUT /account/settings/verdifax-deletion"]);
  const body = seen[1].body;
  assert.deepEqual(Object.keys(body).sort(), ["owner_signature", "value"]);
  assert.equal(body.value, "blocked");
  checkSignatureShape(body.owner_signature);
  assert.ok(ownerVerifies(body.owner_signature, "account-7", "setting.verdifax_deletion", "blocked"));
  // Bound to the account, the change and the value.
  assert.ok(!ownerVerifies(body.owner_signature, "account-8", "setting.verdifax_deletion", "blocked"));
  assert.ok(!ownerVerifies(body.owner_signature, "account-7", "setting.owner_replacement", "blocked"));
  assert.ok(!ownerVerifies(body.owner_signature, "account-7", "setting.verdifax_deletion", "allowed"));
  assert.equal(result.account_change.action, "setting.verdifax_deletion");
  assert.equal(result.account_change.value, "blocked");
  assert.equal(result.account_change.owner_signature.signature, body.owner_signature.signature);
});

test("setAccountSetting signs setting.owner_replacement for owner-replacement", async () => {
  const answer = { ok: true, setting: "owner-replacement", value: "allowed", account_change: null };
  const { seen, result } = await withServer(ownerServer({ json: answer }), (c) => c.setAccountSetting("owner-replacement", "allowed"), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account", "PUT /account/settings/owner-replacement"]);
  assert.ok(ownerVerifies(seen[1].body.owner_signature, "account-7", "setting.owner_replacement", "allowed"));
  // A value already set changes nothing: account_change is null.
  assert.equal(result.account_change, null);
});

test("setAccountSetting with accountId signs over it and does not read GET /account", async () => {
  const { seen } = await withServer(
    (req, body) => sealedAnswer(req, body),
    (c) => c.setAccountSetting("owner-replacement", "blocked", { accountId: "account-12" }),
    { signingKey: SEED },
  );
  assert.deepEqual(requests(seen), ["PUT /account/settings/owner-replacement"]);
  assert.ok(ownerVerifies(seen[0].body.owner_signature, "account-12", "setting.owner_replacement", "blocked"));
});

test("setAccountSetting refuses a setting or value outside the server's before sending", async () => {
  const { seen } = await withServer(ownerServer({}), async (c) => {
    for (const setting of ["owner_replacement", "verdifax_deletion", "Owner-Replacement", "", undefined, "constructor", "toString"]) {
      await assert.rejects(c.setAccountSetting(setting, "blocked"), (err) => err instanceof VerdifaxError && /setting must be owner-replacement or verdifax-deletion/.test(err.message));
    }
    for (const value of ["Blocked", "block", "", true, undefined, null]) {
      await assert.rejects(c.setAccountSetting("verdifax-deletion", value), (err) => err instanceof VerdifaxError && /value must be allowed or blocked/.test(err.message));
    }
  }, { signingKey: SEED });
  assert.equal(seen.length, 0);
});

test("setAccountSetting without a signing key refuses before any request", async () => {
  const { seen, result } = await withServer(ownerServer({}), (c) => c.setAccountSetting("verdifax-deletion", "blocked").catch((err) => err));
  assert.ok(result instanceof VerdifaxError);
  assert.match(result.message, /setAccountSetting needs the owner key's request key in the signingKey client option/);
  assert.equal(seen.length, 0);
});

test("an accountId that is not account-N is refused before any request", async () => {
  const { seen } = await withServer(ownerServer({}), async (c) => {
    for (const accountId of ["7", "account-0", "account-", "api-key-7", " account-7", 7, null]) {
      await assert.rejects(c.setAccountSetting("owner-replacement", "blocked", { accountId }), (err) => err instanceof VerdifaxError && /accountId/.test(err.message));
      await assert.rejects(c.deleteRun(1, RECORD_HASH, { accountId }), (err) => err instanceof VerdifaxError && /accountId/.test(err.message));
    }
  }, { signingKey: SEED });
  assert.equal(seen.length, 0);
});

test("an account_id from GET /account that is not account-N is refused before the change is sent", async () => {
  for (const account_id of [undefined, "", "account-0", "api-key-7", 7]) {
    const { seen, result } = await withServer(
      ownerServer({}, { ...ACCOUNT, account_id }),
      (c) => c.setAccountSetting("verdifax-deletion", "blocked").catch((err) => err),
      { signingKey: SEED },
    );
    assert.ok(result instanceof VerdifaxError, String(account_id));
    assert.match(result.message, /account_id \(account-N\)/);
    assert.deepEqual(requests(seen), ["GET /account"]);
  }
});

test("a refused owner change throws APIError with the server's message and is not retried", async () => {
  for (const status of [400, 409, 503]) {
    const { seen, result } = await withServer(
      ownerServer({ status, json: { ok: false, error: "refused" } }),
      (c) => c.setAccountSetting("verdifax-deletion", "blocked").catch((err) => err),
      { signingKey: SEED, maxRetries: 3 },
    );
    assert.ok(result instanceof APIError);
    assert.equal(result.status, status);
    assert.equal(result.message, "refused");
    assert.equal(seen.length, 2);
  }
});

// ── deleteRun ───────────────────────────────────────────────────

test("deleteRun signs run.deleted over RUN_ID:RECORD_HASH and sends the record hash", async () => {
  const { seen, result } = await withServer(sealingServer(), (c) => c.deleteRun(42, RECORD_HASH), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account", "POST /account/runs/42/delete"]);
  const body = seen[1].body;
  assert.deepEqual(Object.keys(body).sort(), ["owner_signature", "record_hash"]);
  assert.equal(body.record_hash, RECORD_HASH);
  checkSignatureShape(body.owner_signature);
  assert.ok(ownerVerifies(body.owner_signature, "account-7", "run.deleted", `42:${RECORD_HASH}`));
  assert.ok(!ownerVerifies(body.owner_signature, "account-7", "run.deleted", `43:${RECORD_HASH}`));
  assert.ok(!ownerVerifies(body.owner_signature, "account-7", "run.deleted", `42:${"cd".repeat(32)}`));
  assert.ok(!ownerVerifies(body.owner_signature, "account-8", "run.deleted", `42:${RECORD_HASH}`));
  assert.equal(result.run_deletion.run_id, 42);
  assert.equal(result.run_deletion.record_hash, RECORD_HASH);
  assert.equal(result.run_deletion.owner_signature.nonce, body.owner_signature.nonce);
});

test("deleteRun with accountId does not read GET /account", async () => {
  const { seen } = await withServer((req, body) => sealedAnswer(req, body), (c) => c.deleteRun(3, RECORD_HASH, { accountId: "account-7" }), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["POST /account/runs/3/delete"]);
  assert.ok(ownerVerifies(seen[0].body.owner_signature, "account-7", "run.deleted", `3:${RECORD_HASH}`));
});

test("deleteRun refuses a bad run id or record hash, or no signing key, before any request", async () => {
  const { seen } = await withServer(ownerServer({}), async (c) => {
    for (const runId of [0, -1, 1.5, "42", NaN, null]) {
      await assert.rejects(c.deleteRun(runId, RECORD_HASH), (err) => err instanceof VerdifaxError && /runId/.test(err.message));
    }
    for (const hash of ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33), "g".repeat(64), "", undefined]) {
      await assert.rejects(c.deleteRun(42, hash), (err) => err instanceof VerdifaxError && /recordHash/.test(err.message));
    }
  }, { signingKey: SEED });
  assert.equal(seen.length, 0);
  const unsigned = await withServer(ownerServer({}), (c) => c.deleteRun(42, RECORD_HASH).catch((err) => err));
  assert.ok(unsigned.result instanceof VerdifaxError);
  assert.match(unsigned.result.message, /deleteRun needs the owner key's request key in the signingKey client option/);
  assert.equal(unsigned.seen.length, 0);
});

// ── The returned record must seal what was sent ─────────────────

const OTHER_KEY = Buffer.alloc(32, 3);
const signatureFrom = (record, key) => ({ ...record.owner_signature, ...signOwner(key, { account: "account-7", change: record.action ?? "run.deleted", subject: "x" }) });
const MISMATCHES = {
  "a changed value": (record) => ("value" in record ? { ...record, value: record.value === "blocked" ? "allowed" : "blocked" } : { ...record, record_hash: "cd".repeat(32) }),
  "another run": (record) => ("run_id" in record ? { ...record, run_id: record.run_id + 1 } : { ...record, action: "setting.owner_replacement" }),
  "a different signature": (record) => ({ ...record, owner_signature: signatureFrom(record, OTHER_KEY) }),
  "another signed_at": (record) => ({ ...record, owner_signature: { ...record.owner_signature, signed_at: "2026-11-12T18:00:00Z" } }),
  "another nonce": (record) => ({ ...record, owner_signature: { ...record.owner_signature, nonce: "0b".repeat(16) } }),
  "another public key": (record) => ({ ...record, owner_signature: { ...record.owner_signature, public_key: OWNER_VECTOR.public_key } }),
  "no owner signature": ({ owner_signature: _dropped, ...record }) => record,
  "decided_by verdifax_admin": (record) => ({ ...record, decided_by: "verdifax_admin" }),
  "no record": () => undefined,
};

const CHANGES = {
  setAccountSetting: (c) => c.setAccountSetting("verdifax-deletion", "blocked"),
  deleteRun: (c) => c.deleteRun(42, RECORD_HASH),
};

for (const [method, call] of Object.entries(CHANGES)) {
  test(`${method} returns the record when it seals what was sent`, async () => {
    const { seen, result } = await withServer(sealingServer(), call, { signingKey: SEED });
    assert.equal(seen.length, 2);
    assert.equal(result.ok, true);
  });

  for (const [name, change] of Object.entries(MISMATCHES)) {
    test(`${method} throws VerdifaxError on a returned record with ${name}`, async () => {
      const { seen, result } = await withServer(sealingServer(change), (c) => call(c).catch((err) => err), { signingKey: SEED });
      assert.equal(seen.length, 2);
      assert.ok(result instanceof VerdifaxError, name);
      assert.ok(!(result instanceof APIError), name);
      assert.match(result.message, method === "setAccountSetting" ? /account change the server returned does not seal/ : /run deletion the server returned does not seal/);
    });
  }
}

test("setAccountSetting accepts a null account_change, the answer when the value was already set", async () => {
  const { result } = await withServer(
    ownerServer({ json: { ok: true, setting: "verdifax-deletion", value: "blocked", account_change: null } }),
    (c) => c.setAccountSetting("verdifax-deletion", "blocked"),
    { signingKey: SEED },
  );
  assert.equal(result.account_change, null);
});

// ── Admin ───────────────────────────────────────────────────────

test("adminDeleteRun posts no body to /admin/runs/{id}/delete and returns the answer", async () => {
  const answer = { ok: true, run_id: 42, deleted: true, run_deletion: { format: "verdifax.run-deletion.v1", decided_by: "verdifax_admin", run_id: 42, record_hash: RECORD_HASH } };
  const { seen, result } = await withServer(() => ({ json: answer }), (c) => c.adminDeleteRun(42), { apiKey: "admin" });
  assert.deepEqual(requests(seen), ["POST /admin/runs/42/delete"]);
  assert.equal(seen[0].raw, "");
  assert.equal(seen[0].headers["x-verdifax-key"], "admin");
  assert.deepEqual(result, answer);
});

test("adminReplaceOwnerKey posts no body to the account's number and returns no link or key", async () => {
  const answer = {
    ok: true,
    account_id: "account-7",
    claim_expires: "2026-11-15T18:00:00Z",
    account_change: { format: "verdifax.account-change.v1", action: "owner_key.replacement_requested", decided_by: "verdifax_admin", key_id: 0, value: "2026-11-15T18:00:00Z" },
    email: { ok: true, stage: "sent" },
  };
  const { seen, result } = await withServer(() => ({ json: answer }), (c) => c.adminReplaceOwnerKey(7), { apiKey: "admin" });
  assert.deepEqual(requests(seen), ["POST /admin/accounts/7/owner-key/replace"]);
  assert.equal(seen[0].raw, "");
  assert.deepEqual(result, answer);
});

test("the admin methods refuse an id that is not a whole number above zero, and are not retried", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const id of [0, -7, 2.5, "7", "account-7", null, NaN]) {
      await assert.rejects(c.adminDeleteRun(id), (err) => err instanceof VerdifaxError && /runId/.test(err.message));
      await assert.rejects(c.adminReplaceOwnerKey(id), (err) => err instanceof VerdifaxError && /accountId/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
  for (const call of [(c) => c.adminDeleteRun(1), (c) => c.adminReplaceOwnerKey(1)]) {
    const refused = await withServer(() => ({ status: 409, json: { ok: false, error: "blocked" } }), (c) => call(c).catch((err) => err), { maxRetries: 3 });
    assert.ok(refused.result instanceof APIError);
    assert.equal(refused.result.status, 409);
    assert.equal(refused.seen.length, 1);
  }
});

test("every new method needs an API key", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9", signingKey: SEED });
  for (const call of [
    () => c.setAccountSetting("verdifax-deletion", "blocked"),
    () => c.deleteRun(1, RECORD_HASH),
    () => c.adminDeleteRun(1),
    () => c.adminReplaceOwnerKey(1),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
});

test("getAccount keeps the two settings", async () => {
  const { result } = await withServer(() => ({ json: { ...ACCOUNT, owner_replacement: "blocked" } }), (c) => c.getAccount());
  assert.equal(result.owner_replacement, "blocked");
  assert.equal(result.verdifax_deletion, "allowed");
});

// ── Feed kinds ──────────────────────────────────────────────────

test("createWebhook takes account.changed and run.deleted, and names every kind in the server's order", async () => {
  const { seen, result } = await withServer(
    webhookSealer(SEED),
    async (c) => {
      await c.createWebhook("https://hooks.example.com/v", { types: ["account.changed", "run.deleted"], accountId: "account-7" });
      return c.createWebhook("https://hooks.example.com/v", { types: ["account.change"], accountId: "account-7" }).catch((err) => err);
    },
    { signingKey: SEED },
  );
  assert.deepEqual(seen[0].body.types, ["account.changed", "run.deleted"]);
  assert.equal(seen.length, 1);
  assert.ok(result instanceof VerdifaxError);
  assert.match(
    result.message,
    /\(run\.refused, run\.halted, run\.failed, policy\.changed, signoff\.recorded, approver\.registered, approver\.revoked, key\.created, key\.revoked, run\.published, run\.unpublished, chain\.gap, run\.sealed, chain\.interrupted, account\.changed, run\.deleted\)/,
  );
});

// ── Every run body holds only fields the server defines ─────────

// The server's executeRequest (verdifax-orchestrator/internal/api/server.go)
// and its nested types. The server refuses any other field with HTTP 400.
const PARITY = JSON.parse(readFileSync(new URL("./sdk-parity.json", import.meta.url), "utf8"));
const SERVER_FIELDS = {
  top: new Set(PARITY.execute_fields),
  request_signature: new Set(["signature", "signed_at", "nonce", "version"]),
  job: new Set(["job_id", "step_id", "previous_record_hashes", "external_previous", "final"]),
  policy_context: new Set(["actor_type", "mfa_satisfied", "session_age_seconds", "object_type", "object_id", "classification", "data_quality"]),
  data_quality: new Set(["source", "as_of", "checks"]),
  check: new Set(["name", "result"]),
  attested_context: new Set([
    "attested", "actor_id", "actor_role", "authorization_policy", "actor_signature", "model_provider", "model_name",
    "model_version", "model_temperature", "prompt_hash", "decision_kind", "decision_result", "decision_note",
  ]),
  reproducibility_context: new Set([
    "declared", "container_image_hash", "runtime_name", "runtime_version", "pinned_dependencies", "git_commit_sha", "random_seeds", "platform", "hash",
  ]),
};

function onlyServerFields(request, where) {
  const extra = (value, set, label) => {
    for (const name of Object.keys(value ?? {})) assert.ok(set.has(name), `${where}: ${label} holds ${name}, which the server does not define`);
  };
  extra(request, SERVER_FIELDS.top, "the request");
  extra(request.request_signature, SERVER_FIELDS.request_signature, "request_signature");
  extra(request.job, SERVER_FIELDS.job, "job");
  extra(request.policy_context, SERVER_FIELDS.policy_context, "policy_context");
  extra(request.policy_context?.data_quality, SERVER_FIELDS.data_quality, "data_quality");
  for (const check of request.policy_context?.data_quality?.checks ?? []) extra(check, SERVER_FIELDS.check, "a data check");
  extra(request.attested_context, SERVER_FIELDS.attested_context, "attested_context");
  extra(request.reproducibility_context, SERVER_FIELDS.reproducibility_context, "reproducibility_context");
}

test("every body the SDK sends to a run route holds only fields the server defines, signed or not", async () => {
  const program_id = "1".repeat(64);
  const registry_record_hash = "2".repeat(64);
  const row = {
    payload_text: "hello",
    program_id,
    route_id: "r",
    registry_record_hash,
    ai_output_text: "answer",
    attested_context: { actor_id: "a", model_name: "m" },
    reproducibility_context: { runtime_name: "node", random_seeds: ["s=1"] },
    policy_context: { actor_type: "agent", data_quality: { source: "crm", checks: [{ name: "fresh", result: "pass" }] } },
    expected_policy_hash: "3".repeat(64),
  };
  const sealed = { json: { ok: true, run_id: 1, record_hash: "4".repeat(64), results: [{ ok: true }] } };
  for (const signingKey of [undefined, SEED]) {
    const { seen } = await withServer(() => sealed, async (c) => {
      await c.execute(row);
      await c.attest(row);
      await c.attestClaudeResponse({ program_id, route_id: "r", registry_record_hash, prompt: "p", response: "r", govern: true });
      await c.attestOpenAIResponse({ program_id, route_id: "r", registry_record_hash, prompt: "p", response: "r" });
      await c.executeBatch([row, { ...row, job: { job_id: "j", step_id: "s", final: true } }]);
      await c.verifyDeterminism(row);
      await c.job("loan-1").step("intake", { payload_text: "x", program_id, route_id: "r", registry_record_hash });
    }, signingKey ? { signingKey } : {});
    assert.equal(seen.length, 7);
    for (const { url, body } of seen) {
      const rows = url === "/execute/batch" ? body.runs : [body];
      if (url === "/execute/batch") assert.deepEqual(Object.keys(body), ["runs"]);
      for (const sent of rows) {
        onlyServerFields(sent, `${url} ${signingKey ? "signed" : "unsigned"}`);
        if (signingKey) onlyServerFields(signedFields(sent), `${url} signed_request`);
      }
    }
  }
});
