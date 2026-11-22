// SDK 1.17.0, round 64 part 1: the data-use declaration and its keyed
// reference, the declared client, the new feed kinds and records, the
// account stop, the sign-off refusal during a stop, and a member key's tool
// allowlist. Driven by the shared vectors sdk-data-use-vector.json and
// sdk-account-stop-vector.json, copied unchanged from scripts/. The mock
// server listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  SignOffRefusedError,
  VerdifaxClient,
  VerdifaxError,
  accountStopSubject,
  hmacSha256Reference,
  ownerChangePreimage,
  pendingSignOffs,
  validateDataUse,
} from "../dist/index.mjs";
import { publicKeyObject } from "./signed-body.mjs";
import { publicKeyOfSeed, webhookSealer } from "./webhook-server.mjs";

const DATA_USE = JSON.parse(readFileSync(new URL("./sdk-data-use-vector.json", import.meta.url), "utf8"));
const STOP = JSON.parse(readFileSync(new URL("./sdk-account-stop-vector.json", import.meta.url), "utf8"));

const SEED = Buffer.from(STOP.signatures.seed_hex, "hex");
const PUBLIC_KEY = publicKeyOfSeed(SEED).toString("base64");
const ROW = { payload_text: "hello", program_id: "1".repeat(64), route_id: "r", registry_record_hash: "2".repeat(64) };
const SIGNAL = { signal_account: "account-7", signal_sequence: 9, signal_previous_hash: "e".repeat(64) };

async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, body });
      const { status = 200, json = { ok: true }, headers = {} } = answer?.(req, body, seen.length - 1) ?? {};
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      res.end(JSON.stringify(json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k", retryBaseDelayMs: 1, ...config });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const sealedRun = () => ({ json: { ok: true, run_id: 1, record_hash: "a".repeat(64) } });
const refusedNoRequest = async (call) => {
  const { seen } = await withServer(sealedRun, async (c) => {
    await assert.rejects(call(c), VerdifaxError);
  }, { signingKey: SEED });
  assert.equal(seen.length, 0);
};

// ── Data use (feature 6) ─────────────────────────────────────────

test("data-use codes are accepted and refused exactly as the shared vector lists, as purpose, basis and category", () => {
  for (const code of DATA_USE.code.accept) {
    assert.deepEqual(validateDataUse({ purpose: code, basis: code, categories: [code] }), { purpose: code, basis: code, categories: [code] });
  }
  for (const code of DATA_USE.code.refuse) {
    assert.throws(() => validateDataUse({ purpose: code, basis: "b" }), VerdifaxError, JSON.stringify(code));
    assert.throws(() => validateDataUse({ purpose: "p", basis: code }), VerdifaxError, JSON.stringify(code));
    assert.throws(() => validateDataUse({ purpose: "p", basis: "b", categories: [code] }), VerdifaxError, JSON.stringify(code));
  }
});

test("data-use references are accepted and refused exactly as the shared vector lists", () => {
  for (const reference of DATA_USE.reference.accept) {
    assert.equal(validateDataUse({ purpose: "p", basis: "b", reference }).reference, reference);
  }
  for (const reference of DATA_USE.reference.refuse) {
    assert.throws(() => validateDataUse({ purpose: "p", basis: "b", reference }), VerdifaxError, JSON.stringify(reference));
  }
});

test("data-use declarations are accepted and refused exactly as the shared vector lists, on the execute path", async () => {
  const accepted = DATA_USE.declarations.accept.map((c) => c.data_use);
  const { seen } = await withServer(sealedRun, async (c) => {
    for (const data_use of accepted) await c.execute({ ...ROW, policy_context: { data_use } });
    for (const { name, data_use } of DATA_USE.declarations.refuse) {
      assert.throws(() => validateDataUse(data_use), VerdifaxError, name);
      await assert.rejects(c.execute({ ...ROW, policy_context: { data_use } }), VerdifaxError, name);
      await assert.rejects(c.executeBatch([{ ...ROW, policy_context: { data_use } }]), VerdifaxError, name);
    }
  });
  assert.deepEqual(seen.map((r) => r.body.policy_context.data_use), accepted);
});

test("hmacSha256Reference computes the shared vector's references and refuses its bad inputs", () => {
  for (const { key_hex, id, reference } of DATA_USE.hmac_reference.accept) {
    const got = hmacSha256Reference(Buffer.from(key_hex, "hex"), id);
    assert.equal(got, reference);
    assert.equal(validateDataUse({ purpose: "p", basis: "b", reference: got }).reference, reference);
  }
  for (const { name, key_hex, id } of DATA_USE.hmac_reference.refuse) {
    assert.throws(() => hmacSha256Reference(Buffer.from(key_hex, "hex"), id), VerdifaxError, name);
  }
  assert.throws(() => hmacSha256Reference("a".repeat(64), "id"), VerdifaxError);
});

test("client_name and client_version are accepted and refused exactly as the shared vector lists, on every run path", async () => {
  const { seen } = await withServer(sealedRun, async (c) => {
    for (const value of DATA_USE.client_field.accept) {
      await c.execute({ ...ROW, attested_context: { actor_id: "a", client_name: value, client_version: value } });
    }
    for (const value of DATA_USE.client_field.refuse) {
      for (const name of ["client_name", "client_version"]) {
        const attested_context = { actor_id: "a", [name]: value };
        await assert.rejects(c.execute({ ...ROW, attested_context }), VerdifaxError, JSON.stringify(value));
        await assert.rejects(c.attest({ ...ROW, attested_context }), VerdifaxError, JSON.stringify(value));
        await assert.rejects(c.executeBatch([{ ...ROW, attested_context }]), VerdifaxError, JSON.stringify(value));
      }
    }
  });
  assert.equal(seen.length, DATA_USE.client_field.accept.length);
  assert.deepEqual(seen.map((r) => r.body.attested_context.client_name), DATA_USE.client_field.accept);
});

// ── Feed kinds and records ───────────────────────────────────────

test("a webhook may name every round 64 feed kind", async () => {
  const types = STOP.feed_kinds;
  const { seen } = await withServer(webhookSealer(SEED), (c) => c.createWebhook("https://hooks.example.com/in", { types }), { signingKey: SEED });
  assert.deepEqual(seen.at(-1).body.types, types);
  await refusedNoRequest((c) => c.createWebhook("https://hooks.example.com/in", { types: ["account.paused"] }));
});

test("a feed page with the round 64 kinds and an unknown kind is read as sent, and none counts as a sign-off", async () => {
  const kinds = [...STOP.feed_kinds, "kind.from.a.later.server"];
  const events = [
    { data: { kind: "run.sealed", sequence: 1, entry: { run_id: 10, signoff_required: true, setup_hash: "c".repeat(64) } } },
    ...kinds.map((kind, i) => ({
      specversion: "1.0",
      id: `account-7/${i + 2}`,
      type: `com.verdifax.${kind}`,
      data: {
        kind,
        sequence: i + 2,
        entry: kind === "signoff.refused" ? { target: { kind: "record", run_id: 10, digest: "d".repeat(64) }, decision: "approve" } : { format: "x" },
      },
    })),
  ];
  const page = { ok: true, events, next_after: events.length, newest: events.length };
  const { result } = await withServer(() => ({ json: page }), (c) => c.getSignals({ after: 0 }));
  assert.deepEqual(result.events.map((e) => e.data.kind), ["run.sealed", ...kinds]);
  assert.deepEqual(pendingSignOffs(result.events), [10]);
});

// ── Account stop (feature 3) ─────────────────────────────────────

test("accountStopSubject builds every subject of the shared vector and refuses its bad inputs", () => {
  const fields = (c) => ({
    action: c.action,
    keyId: c.key_id,
    signoffs: c.signoffs ?? undefined,
    webhooks: c.webhooks ?? undefined,
    liftsSequence: c.lifts_sequence ?? undefined,
    reason: c.reason ?? undefined,
  });
  for (const c of STOP.subjects) assert.equal(accountStopSubject(fields(c)), c.subject, c.name);
  for (const c of STOP.subject_refuse) assert.throws(() => accountStopSubject(fields(c)), VerdifaxError, c.name);
});

test("the shared vector's stop and resume signatures are the owner-change signatures of their subjects", () => {
  assert.equal(PUBLIC_KEY, STOP.signatures.public_key);
  const key = publicKeyObject(publicKeyOfSeed(SEED));
  for (const c of STOP.signatures.cases) {
    const pre = ownerChangePreimage({ account: c.account, change: c.change, subject: c.subject, signed_at: c.signed_at, nonce: c.nonce });
    assert.equal(pre.toString("hex"), c.preimage_hex);
    assert.ok(crypto.verify(null, pre, key, Buffer.from(c.signature, "base64")), c.name);
  }
  assert.deepEqual(STOP.changes, { stop: "account.stopped", resume: "account.resumed" });
});

/** A fake server for the stop routes: GET /account, GET /account/keys, GET
 *  /account/stop, and each stop or resume answered with the record the
 *  real server seals from what was sent. `change` edits the record. */
function stopServer({ keys = [{ id: 12, owner: true, revoked: false }], holds = [], change = (r) => r, decidedBy = "owner" } = {}) {
  return (req, body) => {
    if (req.method === "GET" && req.url === "/account") return { json: { ok: true, account_id: "account-7", id: 7 } };
    if (req.method === "GET" && req.url === "/account/keys") return { json: { ok: true, account_id: "account-7", keys } };
    if (req.method === "GET" && req.url === "/account/stop") {
      return { json: { ok: true, account_id: "account-7", stopped: holds.length > 0, holds, verdifax_stop: "allowed", runs_in_progress: 0 } };
    }
    const m = /^\/(?:admin\/accounts\/7|account)\/(stop|resume)$/.exec(req.url);
    if (req.method === "POST" && m) {
      const admin = req.url.startsWith("/admin");
      const record = {
        format: "verdifax.account-stop.v1",
        action: m[1],
        decided_by: admin ? "verdifax_admin" : decidedBy,
        runs_in_progress: 0,
        changed_at: "2026-11-18T12:00:01Z",
        signal: SIGNAL,
        account_stop_hash: "f".repeat(64),
      };
      if (!admin && body.owner_signature) record.key_id = 12;
      if (m[1] === "stop") record.scope = { signoffs: body.signoffs ?? "accept", webhooks: body.webhooks ?? "continue" };
      if (m[1] === "resume") record.lifts_sequence = body.lifts_sequence ?? 4;
      if (body.reason) record.reason_sha256 = crypto.createHash("sha256").update(body.reason, "utf8").digest("hex");
      if (body.owner_signature) record.owner_signature = { public_key: PUBLIC_KEY, ...body.owner_signature };
      else if (!admin) record.unsigned = "unsigned: the server's word that this account's key asked for the stop; no request-key signature came with it";
      return { json: { ok: true, account_id: "account-7", stopped: m[1] === "stop", holds: [], account_stop: change(record) } };
    }
    return { status: 404, json: { ok: false, error: "no route" } };
  };
}

function verifiesOwner(body, change, subject) {
  const { signature, signed_at, nonce } = body.owner_signature;
  const pre = ownerChangePreimage({ account: "account-7", change, subject, signed_at, nonce });
  return crypto.verify(null, pre, publicKeyObject(publicKeyOfSeed(SEED)), Buffer.from(signature, "base64"));
}

test("stopAccount signs the vector's subject with the owner key's request key and checks the sealed stop", async () => {
  const c = STOP.subjects[1];
  const { seen, result } = await withServer(stopServer(), (cl) =>
    cl.stopAccount({ signoffs: c.signoffs, webhooks: c.webhooks, reason: c.reason }), { signingKey: SEED });
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /account/keys", "GET /account", "POST /account/stop"]);
  const body = seen[2].body;
  assert.deepEqual(Object.keys(body), ["signoffs", "webhooks", "reason", "owner_signature"]);
  assert.ok(verifiesOwner(body, STOP.changes.stop, c.subject));
  assert.equal(result.account_stop.key_id, 12);
});

test("stopAccount with keyId and accountId reads nothing first, and the default scope is sent", async () => {
  const c = STOP.subjects[0];
  const { seen } = await withServer(stopServer(), (cl) => cl.stopAccount({ keyId: 12, accountId: "account-7" }), { signingKey: SEED });
  assert.deepEqual(seen.map((r) => r.url), ["/account/stop"]);
  assert.deepEqual(Object.keys(seen[0].body), ["signoffs", "webhooks", "owner_signature"]);
  assert.ok(verifiesOwner(seen[0].body, STOP.changes.stop, c.subject));
});

test("an unsigned stop sends no signature, reads nothing first, and must seal the unsigned statement", async () => {
  const { seen } = await withServer(stopServer(), (cl) => cl.stopAccount({ unsigned: true }));
  assert.deepEqual(seen.map((r) => r.url), ["/account/stop"]);
  assert.deepEqual(seen[0].body, { signoffs: "accept", webhooks: "continue" });
  await withServer(stopServer({ change: (r) => ({ ...r, unsigned: undefined }) }), (cl) =>
    assert.rejects(cl.stopAccount({ unsigned: true }), /unsigned statement/));
});

test("a signed stop with no signing key, or bad input, is refused before anything is sent", async () => {
  const { seen } = await withServer(stopServer(), async (cl) => {
    await assert.rejects(cl.stopAccount(), /unsigned: true/);
    await assert.rejects(cl.resumeAccount({ liftsSequence: 4 }), /resumeAccount needs/);
  });
  assert.equal(seen.length, 0);
  for (const options of [{ signoffs: "deny" }, { webhooks: "stop" }, { reason: "é".repeat(501) }, { unsigned: "yes" }, { keyId: 0 }]) {
    await refusedNoRequest((cl) => cl.stopAccount(options));
  }
  await refusedNoRequest((cl) => cl.resumeAccount({ liftsSequence: 0 }));
  await refusedNoRequest((cl) => cl.adminStopAccount(0));
  await refusedNoRequest((cl) => cl.adminResumeAccount(7, { liftsSequence: -1 }));
});

test("stopAccount refuses an account with other than one owner key, unless keyId is given", async () => {
  const two = [{ id: 12, owner: true, revoked: false }, { id: 13, owner: true, revoked: false }];
  await withServer(stopServer({ keys: two }), (cl) => assert.rejects(cl.stopAccount(), /pass keyId/), { signingKey: SEED });
  const revoked = [{ id: 11, owner: true, revoked: true }, { id: 12, owner: true, revoked: false }, { id: 20, owner: false, revoked: false }];
  await withServer(stopServer({ keys: revoked }), (cl) => cl.stopAccount(), { signingKey: SEED });
});

for (const [what, edit] of [
  ["another action", (r) => ({ ...r, action: "resume" })],
  ["Verdifax as the decider", (r) => ({ ...r, decided_by: "verdifax_admin" })],
  ["another scope", (r) => ({ ...r, scope: { signoffs: "accept", webhooks: "pause" } })],
  ["another reason", (r) => ({ ...r, reason_sha256: "0".repeat(64) })],
  ["another key", (r) => ({ ...r, key_id: 13 })],
  ["another signature", (r) => ({ ...r, owner_signature: { ...r.owner_signature, nonce: "0".repeat(32) } })],
  ["another public key", (r) => ({ ...r, owner_signature: { ...r.owner_signature, public_key: "A".repeat(43) + "=" } })],
  ["another format", (r) => ({ ...r, format: "verdifax.account-stop.v2" })],
]) {
  test(`stopAccount refuses a sealed stop with ${what}`, async () => {
    await withServer(stopServer({ change: edit }), (cl) =>
      assert.rejects(cl.stopAccount({ signoffs: "refuse", reason: "x" }), (err) => err instanceof VerdifaxError && !(err instanceof APIError)), { signingKey: SEED });
  });
}

test("resumeAccount reads the owner's stop from GET /account/stop and signs the vector's resume subject", async () => {
  const c = STOP.subjects[3];
  const holds = [
    { holder: "verdifax", stop_sequence: 3, stopped_at: "t", scope: { signoffs: "accept", webhooks: "continue" } },
    { holder: "owner", stop_sequence: c.lifts_sequence, stopped_at: "t", scope: { signoffs: "accept", webhooks: "continue" } },
  ];
  const { seen } = await withServer(stopServer({ holds }), (cl) => cl.resumeAccount(), { signingKey: SEED });
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /account/keys", "GET /account/stop", "GET /account", "POST /account/resume"]);
  assert.deepEqual(Object.keys(seen[3].body), ["lifts_sequence", "owner_signature"]);
  assert.equal(seen[3].body.lifts_sequence, c.lifts_sequence);
  assert.ok(verifiesOwner(seen[3].body, STOP.changes.resume, c.subject));
});

test("resumeAccount with a reason signs it, and refuses when no owner stop stands or the record differs", async () => {
  const c = STOP.subjects[4];
  const { seen } = await withServer(stopServer(), (cl) => cl.resumeAccount({ liftsSequence: c.lifts_sequence, reason: c.reason, keyId: 12 }), { signingKey: SEED });
  assert.ok(verifiesOwner(seen.at(-1).body, STOP.changes.resume, c.subject));
  await withServer(stopServer({ holds: [{ holder: "verdifax", stop_sequence: 3 }] }), (cl) =>
    assert.rejects(cl.resumeAccount(), /no owner stop stands/), { signingKey: SEED });
  await withServer(stopServer({ change: (r) => ({ ...r, lifts_sequence: 5 }) }), (cl) =>
    assert.rejects(cl.resumeAccount({ liftsSequence: 41 }), /lifts_sequence/), { signingKey: SEED });
  await withServer(stopServer({ change: (r) => ({ ...r, scope: { signoffs: "accept", webhooks: "continue" } }) }), (cl) =>
    assert.rejects(cl.resumeAccount({ liftsSequence: 41 }), VerdifaxError), { signingKey: SEED });
});

test("getAccountStop reads GET /account/stop", async () => {
  const { seen, result } = await withServer(stopServer(), (cl) => cl.getAccountStop());
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /account/stop"]);
  assert.equal(result.verdifax_stop, "allowed");
  assert.deepEqual(result.holds, []);
});

test("adminStopAccount and adminResumeAccount send Verdifax's stop and check it is sealed as Verdifax's", async () => {
  const { seen } = await withServer(stopServer(), async (cl) => {
    await cl.adminStopAccount(7, { signoffs: "refuse", webhooks: "pause", reason: "incident" });
    await cl.adminResumeAccount(7);
    await cl.adminResumeAccount(7, { liftsSequence: 4, reason: "fixed" });
  });
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["POST /admin/accounts/7/stop", "POST /admin/accounts/7/resume", "POST /admin/accounts/7/resume"]);
  assert.deepEqual(seen[0].body, { signoffs: "refuse", webhooks: "pause", reason: "incident" });
  assert.deepEqual(seen[1].body, {});
  assert.deepEqual(seen[2].body, { lifts_sequence: 4, reason: "fixed" });
  await withServer(stopServer({ change: (r) => ({ ...r, decided_by: "owner" }) }), (cl) =>
    assert.rejects(cl.adminStopAccount(7), VerdifaxError));
  await withServer(stopServer({ change: (r) => ({ ...r, lifts_sequence: 5 }) }), (cl) =>
    assert.rejects(cl.adminResumeAccount(7, { liftsSequence: 4 }), /another stop/));
});

test("setAccountSetting verdifax-stop signs the vector's change", async () => {
  const sealer = (req, body) => {
    if (req.url === "/account") return { json: { ok: true, account_id: "account-7" } };
    return { json: { ok: true, setting: "verdifax-stop", value: body.value, account_change: {
      format: "verdifax.account-change.v1", action: STOP.setting.change, decided_by: "owner", value: body.value,
      owner_signature: { public_key: PUBLIC_KEY, ...body.owner_signature } } } };
  };
  const { seen } = await withServer(sealer, (cl) => cl.setAccountSetting(STOP.setting.route, "blocked"), { signingKey: SEED });
  assert.equal(seen[1].url, `/account/settings/${STOP.setting.route}`);
  assert.ok(verifiesOwner(seen[1].body, STOP.setting.change, "blocked"));
});

// ── Sign-off refused during a stop ───────────────────────────────

const APPROVER = Buffer.alloc(32, 5);
const TARGET = { kind: "record", run_id: 10, digest: "d".repeat(64) };
function refusalServer({ edit = (r) => r, code = "ACCOUNT_STOPPED" } = {}) {
  return (req, body) => {
    if (req.method === "GET") return { json: { ok: true, chain_id: "account-7", newest_signoff_hash: "0".repeat(64), sequence: 0 } };
    const refusal = edit({
      format: "verdifax.signoff-refusal.v1", chain_id: "account-7", previous_signoff_hash: body.previous_signoff_hash, target: body.target,
      decision: body.decision, approver_key: body.approver_key, approver_id: 3, signature: body.signature, signed_at: body.signed_at,
      nonce: body.nonce, stop_sequence: 4, reason_code: "ACCOUNT_STOPPED", refused_at: "t", signal: SIGNAL, signoff_refusal_hash: "9".repeat(64),
    });
    return { status: 409, json: { ok: false, error: "the account is stopped", error_code: code, signoff_refusal: refusal, record_hash: refusal.signoff_refusal_hash } };
  };
}

test("a sign-off refused during a stop throws SignOffRefusedError with the sealed refusal, on both sign-off routes", async () => {
  for (const options of [{}, { asOwner: true }]) {
    const { result } = await withServer(refusalServer(), (cl) => cl.signOff(TARGET, "approve", APPROVER, options).catch((e) => e));
    assert.ok(result instanceof SignOffRefusedError);
    assert.ok(result instanceof APIError);
    assert.equal(result.status, 409);
    assert.equal(result.recordHash, "9".repeat(64));
    assert.equal(result.signoffRefusal.format, "verdifax.signoff-refusal.v1");
    assert.equal(result.signoffRefusal.stop_sequence, 4);
    assert.equal(typeof result.signoffRefusal.sealedJson, "string");
  }
});

test("a refusal that names another sign-off is refused, and any other 409 is a plain APIError", async () => {
  for (const edit of [(r) => ({ ...r, signature: "x" }), (r) => ({ ...r, nonce: "0".repeat(32) }), (r) => ({ ...r, format: "verdifax.signoff.v1" })]) {
    const { result } = await withServer(refusalServer({ edit }), (cl) => cl.signOff(TARGET, "approve", APPROVER).catch((e) => e));
    assert.ok(result instanceof VerdifaxError && !(result instanceof APIError), String(result));
  }
  const { result } = await withServer(refusalServer({ code: "CHAIN_MOVED" }), (cl) => cl.signOff(TARGET, "approve", APPROVER).catch((e) => e));
  assert.ok(result instanceof APIError && !(result instanceof SignOffRefusedError));
});

// ── Tool allowlist (feature 5) ───────────────────────────────────

function keyServer(edit = (tools) => tools) {
  return (req, body) => ({
    status: 201,
    json: { ok: true, id: 30, name: body.name, owner: false, secret: "s", ...(body.allowed_tools ? { allowed_tools: edit([...body.allowed_tools].sort()) } : {}) },
  });
}

test("createAccountKey sends each vector allowlist and checks the sealed, sorted list", async () => {
  for (const { allowed_tools, sealed } of STOP.allowlists.accept) {
    const { seen, result } = await withServer(keyServer(), (cl) => cl.createAccountKey("agent", { allowedTools: allowed_tools }));
    assert.deepEqual(seen[0].body, { name: "agent", allowed_tools });
    assert.deepEqual(result.allowed_tools, sealed);
  }
  const { seen } = await withServer(keyServer(), (cl) => cl.createAccountKey("plain"));
  assert.deepEqual(seen[0].body, { name: "plain" });
  await withServer(keyServer((t) => t.slice(1)), (cl) =>
    assert.rejects(cl.createAccountKey("agent", { allowedTools: ["get_record", "seal_decision"] }), /tool allowlist/));
});

test("createAccountKey refuses each vector allowlist the server refuses, and every never-granted name, before sending", async () => {
  const { seen } = await withServer(keyServer(), async (cl) => {
    for (const { name, allowed_tools } of STOP.allowlists.refuse) {
      await assert.rejects(cl.createAccountKey("agent", { allowedTools: allowed_tools }), VerdifaxError, name);
    }
    for (const power of STOP.never_granted) {
      await assert.rejects(cl.createAccountKey("agent", { allowedTools: [power] }), /can never be granted/, power);
    }
  });
  assert.equal(seen.length, 0);
  const { seen: sent } = await withServer(keyServer(), async (cl) => {
    for (const tool of [...STOP.tools, STOP.stop_permission]) await cl.createAccountKey("agent", { allowedTools: [tool] });
  });
  assert.equal(sent.length, STOP.tools.length + 1);
});

test("getAllowedTools reads the X-Verdifax-Allowed-Tools header of GET /stats as the vector lists", async () => {
  for (const { header, allowed_tools } of STOP.allowed_tools_header) {
    const headers = header === null ? {} : { "X-Verdifax-Allowed-Tools": header };
    const { seen, result } = await withServer(() => ({ json: { ok: true, total_runs: 0 }, headers }), (cl) => cl.getAllowedTools());
    assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /stats"]);
    assert.deepEqual(result, allowed_tools);
  }
  await withServer(() => ({ status: 403, json: { ok: false, error: "no" } }), (cl) => assert.rejects(cl.getAllowedTools(), APIError));
});
