// SDK 1.4.0: customer sign-off. The owner's approver routes, a signed
// decision on one exact result, and the reads of sign-offs for a member key
// and for the owner key. The mock server listens on localhost only; nothing
// leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  NotFoundError,
  VerdifaxClient,
  VerdifaxError,
  approverKeyProof,
  generateRequestKeyPair,
  signOffPreimage,
} from "../dist/index.mjs";
import { publicKeyObject, sha256 } from "./signed-body.mjs";

// The byte authority, copied unchanged from scripts/sdk-signature-vector.json.
const VECTOR = JSON.parse(readFileSync(new URL("./sdk-signature-vector.json", import.meta.url), "utf8"));
const SEED = Buffer.from(VECTOR.seed_hex, "hex");
const PUBLIC_KEY = Buffer.from(VECTOR.public_key, "base64");
const ZEROS = "0".repeat(64);
const NEWEST_HASH = "e".repeat(64);
const DIGEST = "a".repeat(64);
const RECEIPT_HASH = "b".repeat(64);
// A second key: the approver in the client tests, never the client's own.
const APPROVER = Buffer.alloc(32, 9);
const APPROVER_PUBLIC = approverKeyProof(APPROVER).public_key;

const NEWEST = { ok: true, chain_id: "account-7", newest_signoff_hash: NEWEST_HASH, sequence: 3 };
const RECORD_TARGET = { kind: "record", run_id: 42, digest: DIGEST };
const APPROVER_VIEW = {
  id: 5,
  public_key: APPROVER_PUBLIC,
  name: "Dana, credit review",
  account_id: "account-7",
  registered_at: "2026-11-07T12:00:00Z",
  revoked: false,
};
const RECORD = {
  format: "verdifax.signoff.v1",
  chain_id: "account-7",
  sequence: 4,
  previous_signoff_hash: NEWEST_HASH,
  target: RECORD_TARGET,
  decision: "approve",
  approver_key: APPROVER_PUBLIC,
  signature: "sig",
  signed_at: "2026-11-07T12:00:00Z",
  nonce: "0".repeat(32),
  recorded_at: "2026-11-07T12:00:00.5Z",
  signoff_hash: "f".repeat(64),
  anchor: { kind: "signoff", log_index: 12 },
};

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
      apiKey: "member",
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

/** The record a server makes from a submitted body. */
function recordFrom(body) {
  return { ...RECORD, ...body };
}

/** Answers the newest read with `newest` and the submit with `submit`,
 *  which by default echoes the submitted sign-off in its record. */
function signOffServer(newest = NEWEST, submit = (body) => ({ status: 201, json: { ok: true, signoff: recordFrom(body) } })) {
  return (req, body) => (req.method === "GET" ? { json: newest } : typeof submit === "function" ? submit(body) : submit);
}

/** Checks a submitted sign-off as the server does, written out
 *  independently of the SDK. */
function signOffVerifies(body, chainId, publicKey = Buffer.from(APPROVER_PUBLIC, "base64")) {
  const t = body.target;
  const signed = [
    "verdifax.signoff.v1",
    chainId,
    body.previous_signoff_hash,
    t.kind,
    String(t.run_id),
    t.digest,
    t.job_id ?? "",
    body.decision,
    body.note_hash ?? "",
    body.signed_at,
    body.nonce,
  ].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(publicKey), Buffer.from(body.signature, "base64"));
}

function privateKeyObject(seed) {
  const header = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([header, seed]), format: "der", type: "pkcs8" });
}

// ── The vector, byte for byte ───────────────────────────────────

const VECTOR_FIELDS = {
  chain_id: VECTOR.signoff_chain_id,
  previous_signoff_hash: VECTOR.signoff_previous_hash,
  target: { kind: VECTOR.signoff_target_kind, run_id: VECTOR.signoff_target_run_id, digest: VECTOR.signoff_target_digest },
  decision: VECTOR.signoff_decision,
  note_hash: VECTOR.signoff_note_hash,
  signed_at: VECTOR.signed_at,
  nonce: VECTOR.nonce,
};

test("vector: signOffPreimage", () => {
  assert.equal(signOffPreimage(VECTOR_FIELDS).toString("hex"), VECTOR.signoff_preimage_hex);
});

test("vector: the approver key's signature over signOffPreimage", () => {
  const preimage = signOffPreimage(VECTOR_FIELDS);
  const signature = crypto.sign(null, preimage, privateKeyObject(SEED)).toString("base64");
  assert.equal(signature, VECTOR.signoff_signature);
  const body = { ...VECTOR_FIELDS, signature };
  assert.ok(signOffVerifies(body, VECTOR.signoff_chain_id, PUBLIC_KEY));
  // Bound to the account, the place in the chain, the result and the decision.
  assert.ok(!signOffVerifies(body, "account-8", PUBLIC_KEY));
  assert.ok(!signOffVerifies({ ...body, previous_signoff_hash: NEWEST_HASH }, VECTOR.signoff_chain_id, PUBLIC_KEY));
  assert.ok(!signOffVerifies({ ...body, target: { ...body.target, run_id: 43 } }, VECTOR.signoff_chain_id, PUBLIC_KEY));
  assert.ok(!signOffVerifies({ ...body, target: { ...body.target, kind: "receipt" } }, VECTOR.signoff_chain_id, PUBLIC_KEY));
  assert.ok(!signOffVerifies({ ...body, decision: "reject" }, VECTOR.signoff_chain_id, PUBLIC_KEY));
  assert.ok(!signOffVerifies({ ...body, note_hash: "" }, VECTOR.signoff_chain_id, PUBLIC_KEY));
});

test("vector: approverKeyProof", () => {
  const proof = approverKeyProof(SEED);
  assert.equal(proof.public_key, VECTOR.public_key);
  const preimage = Buffer.from(`verdifax.approver-key.v1\0${proof.public_key}`, "utf8");
  assert.equal(preimage.toString("hex"), VECTOR.approver_proof_preimage_hex);
  assert.deepEqual(proof, { public_key: VECTOR.public_key, proof: VECTOR.approver_proof });
  assert.ok(crypto.verify(null, preimage, publicKeyObject(PUBLIC_KEY), Buffer.from(proof.proof, "base64")));
});

test("signOffPreimage puts a job target's job_id in its place", () => {
  const job = { ...VECTOR_FIELDS, target: { ...VECTOR_FIELDS.target, kind: "job", job_id: "loan-1" } };
  const parts = signOffPreimage(job).toString("utf8").split("\0");
  assert.equal(parts.length, 11);
  assert.deepEqual(parts.slice(3, 7), ["job", "42", DIGEST, "loan-1"]);
  assert.equal(signOffPreimage(VECTOR_FIELDS).toString("utf8").split("\0")[6], "");
});

// ── Approver keys ───────────────────────────────────────────────

test("registerApprover makes the proof from the approver's key and posts it to /account/approvers", async () => {
  const reply = { ok: true, ...APPROVER_VIEW };
  const { seen, result } = await withServer(() => ({ status: 201, json: reply }), (c) => c.registerApprover("Dana, credit review", APPROVER), {
    apiKey: "owner",
  });
  assert.deepEqual(requests(seen), ["POST /account/approvers"]);
  assert.equal(seen[0].headers["x-verdifax-key"], "owner");
  assert.deepEqual(seen[0].body, { public_key: APPROVER_PUBLIC, name: "Dana, credit review", proof: approverKeyProof(APPROVER).proof });
  assert.deepEqual(result, reply);
});

test("registerApprover sends the vector's proof for the vector's key", async () => {
  const { seen } = await withServer(() => ({ status: 201, json: { ok: true } }), (c) => c.registerApprover("vector", SEED));
  assert.deepEqual(seen[0].body, { public_key: VECTOR.public_key, name: "vector", proof: VECTOR.approver_proof });
});

test("registerApprover takes a proof made on the approver's own machine, and never a private key in the body", async () => {
  const proof = approverKeyProof(APPROVER);
  const { seen } = await withServer(() => ({ status: 201, json: { ok: true } }), (c) => c.registerApprover("Dana", proof));
  assert.deepEqual(seen[0].body, { public_key: proof.public_key, name: "Dana", proof: proof.proof });
  assert.ok(!seen[0].raw.includes(APPROVER.toString("base64")));
  assert.ok(!seen[0].raw.includes(APPROVER.toString("hex")));
});

test("registerApprover refuses a bad name, key or proof before sending", async () => {
  const good = approverKeyProof(APPROVER);
  const other = approverKeyProof(Buffer.alloc(32, 3));
  const { seen } = await withServer(undefined, async (c) => {
    for (const name of ["", "   ", undefined, null, 5, "x".repeat(201)]) {
      await assert.rejects(c.registerApprover(name, APPROVER), /registerApprover needs a name of at most 200 bytes/);
    }
    for (const approver of [
      undefined,
      null,
      "key",
      Buffer.alloc(31),
      {},
      { public_key: good.public_key },
      { public_key: good.public_key, proof: other.proof },
      { public_key: other.public_key, proof: good.proof },
      { public_key: "not base64!", proof: good.proof },
    ]) {
      await assert.rejects(c.registerApprover("Dana", approver), VerdifaxError);
    }
  });
  assert.equal(seen.length, 0);
});

test("registerApprover refuses the client's own request key as an approver key", async () => {
  const { seen, result } = await withServer(undefined, (c) => c.registerApprover("me", SEED).catch((err) => err), { signingKey: SEED });
  assert.ok(result instanceof VerdifaxError);
  assert.match(result.message, /must not be a request key in the same account/);
  assert.equal(seen.length, 0);
});

test("registerApprover passes on the server's refusal of a request key and is not retried", async () => {
  const { seen, result } = await withServer(
    () => ({ status: 409, json: { ok: false, error: "this key is a request key in the account; an approver key must be a different key" } }),
    (c) => c.registerApprover("Dana", APPROVER).catch((err) => err),
    { maxRetries: 3 },
  );
  assert.ok(result instanceof APIError);
  assert.equal(result.status, 409);
  assert.match(result.message, /request key in the account/);
  assert.equal(seen.length, 1);
});

test("listApprovers returns the account's approvers, revoked ones included", async () => {
  const revoked = { ...APPROVER_VIEW, id: 4, revoked: true, revoked_at: "2026-11-07T13:00:00Z" };
  const body = { ok: true, account_id: "account-7", approvers: [revoked, APPROVER_VIEW] };
  const { seen, result } = await withServer(() => ({ json: body }), (c) => c.listApprovers());
  assert.deepEqual(requests(seen), ["GET /account/approvers"]);
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, body);
  const empty = await withServer(() => ({ json: { ok: true, account_id: "account-7" } }), (c) => c.listApprovers());
  assert.deepEqual(empty.result, { ok: true, account_id: "account-7", approvers: [] });
});

test("revokeApprover sends DELETE /account/approvers/{id} and returns the revocation", async () => {
  const body = { ok: true, id: 5, revoked: true };
  const { seen, result } = await withServer(() => ({ json: body }), (c) => c.revokeApprover(5));
  assert.deepEqual(requests(seen), ["DELETE /account/approvers/5"]);
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, body);
});

test("revokeApprover maps an unknown approver to NotFoundError and refuses a bad id before sending", async () => {
  const { seen, result } = await withServer(
    () => ({ status: 404, json: { ok: false, error: "no such active approver in this account" } }),
    (c) => c.revokeApprover(9).catch((err) => err),
    { maxRetries: 3 },
  );
  assert.ok(result instanceof NotFoundError);
  assert.equal(seen.length, 1);
  const none = await withServer(undefined, async (c) => {
    for (const id of [0, -1, 1.5, NaN, "5", "../keys", undefined, null]) {
      await assert.rejects(c.revokeApprover(id), (err) => err instanceof VerdifaxError && /approverId/.test(err.message));
    }
  });
  assert.equal(none.seen.length, 0);
});

// ── Signing off ─────────────────────────────────────────────────

test("signOff reads the newest sign-off, signs over it and posts to /signoffs", async () => {
  const { seen, result } = await withServer(signOffServer(), (c) => c.signOff(RECORD_TARGET, "approve", APPROVER));
  assert.deepEqual(requests(seen), ["GET /signoffs/newest", "POST /signoffs"]);
  const body = seen[1].body;
  assert.deepEqual(Object.keys(body), ["previous_signoff_hash", "target", "decision", "approver_key", "signature", "signed_at", "nonce"]);
  assert.equal(body.previous_signoff_hash, NEWEST_HASH);
  assert.deepEqual(body.target, RECORD_TARGET);
  assert.equal(body.decision, "approve");
  assert.equal(body.approver_key, APPROVER_PUBLIC);
  assert.match(body.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(body.nonce, /^[0-9a-f]{32}$/);
  assert.ok(signOffVerifies(body, "account-7"));
  assert.ok(!signOffVerifies(body, "account-8"));
  // The SDK's own preimage gives the same bytes the check rebuilt.
  const preimage = signOffPreimage({ chain_id: "account-7", ...body, note_hash: "" });
  assert.ok(crypto.verify(null, preimage, publicKeyObject(Buffer.from(APPROVER_PUBLIC, "base64")), Buffer.from(body.signature, "base64")));
  assert.deepEqual(result, recordFrom(body));
});

test("signOff throws when the returned record does not carry what was sent", async () => {
  const otherSignature = crypto.sign(null, Buffer.from("other"), privateKeyObject(APPROVER)).toString("base64");
  const changes = [
    (b) => ({ ...b, signature: otherSignature }),
    (b) => ({ ...b, approver_key: VECTOR.public_key }),
    (b) => ({ ...b, decision: "reject" }),
    (b) => ({ ...b, previous_signoff_hash: ZEROS }),
    (b) => ({ ...b, target: { ...b.target, kind: "receipt" } }),
    (b) => ({ ...b, target: { ...b.target, run_id: 43 } }),
    (b) => ({ ...b, target: { ...b.target, digest: RECEIPT_HASH } }),
    (b) => ({ ...b, target: { ...b.target, job_id: "loan-1" } }),
    (b) => ({ ...b, target: undefined }),
  ];
  for (const change of changes) {
    const { seen, result } = await withServer(
      signOffServer(NEWEST, (body) => ({ status: 201, json: { ok: true, signoff: recordFrom(change(body)) } })),
      (c) => c.signOff(RECORD_TARGET, "approve", APPROVER).catch((err) => err),
    );
    assert.ok(result instanceof VerdifaxError, String(change));
    assert.match(result.message, /does not carry the signature, approver_key, decision, previous_signoff_hash and target that were sent/);
    assert.deepEqual(requests(seen), ["GET /signoffs/newest", "POST /signoffs"]);
  }
  for (const reply of [{ ok: true }, { ok: true, signoff: null }, { ok: true, signoff: RECORD }]) {
    const { result } = await withServer(signOffServer(NEWEST, { status: 201, json: reply }), (c) =>
      c.signOff(RECORD_TARGET, "approve", APPROVER).catch((err) => err),
    );
    assert.ok(result instanceof VerdifaxError);
  }
});

test("signOff accepts a returned job target that carries its job_id", async () => {
  const job = { kind: "job", run_id: 44, digest: DIGEST, job_id: "loan-1" };
  const { result } = await withServer(signOffServer(), (c) => c.signOff(job, "approve", APPROVER));
  assert.deepEqual(result.target, job);
});

test("signOff with asOwner uses the owner key's routes", async () => {
  const { seen } = await withServer(signOffServer(), (c) => c.signOff(RECORD_TARGET, "reject", APPROVER, { asOwner: true }), { apiKey: "owner" });
  assert.deepEqual(requests(seen), ["GET /account/signoffs/newest", "POST /account/signoffs"]);
  assert.equal(seen[1].body.decision, "reject");
  assert.ok(signOffVerifies(seen[1].body, "account-7"));
});

test("signOff on an account's first sign-off names 64 zeros", async () => {
  const { seen } = await withServer(signOffServer({ ...NEWEST, newest_signoff_hash: ZEROS, sequence: 0 }), (c) =>
    c.signOff(RECORD_TARGET, "approve", APPROVER),
  );
  assert.equal(seen[1].body.previous_signoff_hash, ZEROS);
  assert.ok(signOffVerifies(seen[1].body, "account-7"));
});

test("signOff sends a receipt target and a job target with only their own fields", async () => {
  const receipt = { kind: "receipt", run_id: 43, digest: RECEIPT_HASH };
  const job = { kind: "job", run_id: 44, digest: DIGEST, job_id: "loan-1" };
  const { seen } = await withServer(signOffServer(), async (c) => {
    await c.signOff(receipt, "reject", APPROVER);
    await c.signOff(job, "approve", APPROVER);
  });
  assert.deepEqual(seen[1].body.target, receipt);
  assert.deepEqual(seen[3].body.target, job);
  assert.ok(signOffVerifies(seen[1].body, "account-7"));
  assert.ok(signOffVerifies(seen[3].body, "account-7"));
});

test("signOff hashes the note here, and the note text never appears in a request body", async () => {
  const note = "Checked loan 1042 against the credit file. Café notes: income verified.";
  const { seen } = await withServer(signOffServer(), (c) => c.signOff(RECORD_TARGET, "approve", APPROVER, { note }));
  const body = seen[1].body;
  assert.equal(body.note_hash, sha256(note));
  assert.equal(body.note_hash, crypto.createHash("sha256").update(note, "utf8").digest("hex"));
  assert.ok(signOffVerifies(body, "account-7"));
  for (const request of seen) {
    assert.ok(!request.raw.includes(note), `${request.method} ${request.url} carried the note`);
    assert.ok(!request.raw.includes("Checked loan"), `${request.method} ${request.url} carried part of the note`);
    assert.ok(!request.url.includes("Checked"), `${request.url} carried the note`);
  }
  assert.ok(!Object.keys(body).includes("note"));
});

test("signOff never sends the approver's private key", async () => {
  const { seen } = await withServer(signOffServer(), (c) => c.signOff(RECORD_TARGET, "approve", APPROVER));
  for (const request of seen) {
    assert.ok(!request.raw.includes(APPROVER.toString("base64")));
    assert.ok(!request.raw.includes(APPROVER.toString("hex")));
  }
});

test("signOff refuses bad input before sending anything", async () => {
  const { seen } = await withServer(signOffServer(), async (c) => {
    const bad = [
      [undefined, "approve", APPROVER, {}, /target object/],
      [null, "approve", APPROVER, {}, /target object/],
      [[], "approve", APPROVER, {}, /target object/],
      [{ ...RECORD_TARGET, kind: "bundle" }, "approve", APPROVER, {}, /kind must be record, receipt or job/],
      [{ ...RECORD_TARGET, kind: undefined }, "approve", APPROVER, {}, /kind must be/],
      [{ ...RECORD_TARGET, run_id: 0 }, "approve", APPROVER, {}, /target.run_id/],
      [{ ...RECORD_TARGET, run_id: "42" }, "approve", APPROVER, {}, /target.run_id/],
      [{ ...RECORD_TARGET, run_id: 1.5 }, "approve", APPROVER, {}, /target.run_id/],
      [{ ...RECORD_TARGET, digest: "A".repeat(64) }, "approve", APPROVER, {}, /target.digest/],
      [{ ...RECORD_TARGET, digest: "a".repeat(63) }, "approve", APPROVER, {}, /target.digest/],
      [{ ...RECORD_TARGET, digest: undefined }, "approve", APPROVER, {}, /target.digest/],
      [{ ...RECORD_TARGET, job_id: "loan-1" }, "approve", APPROVER, {}, /job_id is for a job target only/],
      [{ kind: "job", run_id: 44, digest: DIGEST }, "approve", APPROVER, {}, /target.job_id/],
      [{ kind: "job", run_id: 44, digest: DIGEST, job_id: "loan 1" }, "approve", APPROVER, {}, /target.job_id/],
      [{ kind: "job", run_id: 44, digest: DIGEST, job_id: "a\0b" }, "approve", APPROVER, {}, /target.job_id/],
      [{ ...RECORD_TARGET, runId: 42 }, "approve", APPROVER, {}, /unknown field: runId/],
      [RECORD_TARGET, "approved", APPROVER, {}, /decision must be approve or reject/],
      [RECORD_TARGET, "APPROVE", APPROVER, {}, /decision must be approve or reject/],
      [RECORD_TARGET, undefined, APPROVER, {}, /decision must be approve or reject/],
      [RECORD_TARGET, "approve", undefined, {}, /signingKey must be the 32 raw bytes/],
      [RECORD_TARGET, "approve", Buffer.alloc(31), {}, /signingKey must be the 32 raw bytes/],
      [RECORD_TARGET, "approve", "key", {}, /signingKey must be the 32 raw bytes/],
      [RECORD_TARGET, "approve", APPROVER, { note: "" }, /note must be non-empty text/],
      [RECORD_TARGET, "approve", APPROVER, { note: 5 }, /note must be non-empty text/],
      [RECORD_TARGET, "approve", APPROVER, { asOwner: "yes" }, /asOwner must be true or false/],
    ];
    for (const [target, decision, key, options, message] of bad) {
      await assert.rejects(c.signOff(target, decision, key, options), (err) => err instanceof VerdifaxError && message.test(err.message), String(message));
    }
  });
  assert.equal(seen.length, 0);
});

test("signOff refuses a newest answer it cannot sign over, after reading it and before posting", async () => {
  for (const newest of [
    { ...NEWEST, chain_id: undefined },
    { ...NEWEST, chain_id: "api-key-7" },
    { ...NEWEST, chain_id: "account-0" },
    { ...NEWEST, newest_signoff_hash: undefined },
    { ...NEWEST, newest_signoff_hash: "E".repeat(64) },
  ]) {
    const { seen, result } = await withServer(signOffServer(newest), (c) => c.signOff(RECORD_TARGET, "approve", APPROVER).catch((err) => err));
    assert.ok(result instanceof VerdifaxError);
    assert.match(result.message, /chain_id|newest_signoff_hash/);
    assert.deepEqual(requests(seen), ["GET /signoffs/newest"]);
  }
});

test("a refused sign-off throws APIError with the server's message and is not retried", async () => {
  for (const status of [403, 409]) {
    const { seen, result } = await withServer(
      signOffServer(NEWEST, { status, json: { ok: false, error: "refused" } }),
      (c) => c.signOff(RECORD_TARGET, "approve", APPROVER).catch((err) => err),
      { maxRetries: 3 },
    );
    assert.ok(result instanceof APIError);
    assert.equal(result.status, status);
    assert.equal(result.path, "/signoffs");
    assert.equal(result.message, "refused");
    assert.equal(seen.length, 2);
  }
});

// ── Reading sign-offs ───────────────────────────────────────────

test("getNewestSignOff reads the member route, or the owner's with asOwner", async () => {
  const { seen, result } = await withServer(
    () => ({ json: NEWEST }),
    async (c) => [await c.getNewestSignOff(), await c.getNewestSignOff({ asOwner: true }), await c.getNewestSignOff({ asOwner: false })],
  );
  assert.deepEqual(requests(seen), ["GET /signoffs/newest", "GET /account/signoffs/newest", "GET /signoffs/newest"]);
  assert.deepEqual(result, [NEWEST, NEWEST, NEWEST]);
});

test("getSignOffs reads a run's sign-offs on the member route, or the owner's with asOwner", async () => {
  const later = { ...RECORD, sequence: 5, decision: "reject", previous_signoff_hash: RECORD.signoff_hash, signoff_hash: "1".repeat(64) };
  const { seen, result } = await withServer(
    () => ({ json: [RECORD, later] }),
    async (c) => [await c.getSignOffs(42), await c.getSignOffs(42, { asOwner: true })],
  );
  assert.deepEqual(requests(seen), ["GET /runs/42/signoffs", "GET /account/runs/42/signoffs"]);
  assert.deepEqual(result, [
    [RECORD, later],
    [RECORD, later],
  ]);
});

test("getSignOffs gives an empty list for none and refuses a bad run id or asOwner before sending", async () => {
  const empty = await withServer(() => ({ json: [] }), (c) => c.getSignOffs(42));
  assert.deepEqual(empty.result, []);
  const { seen } = await withServer(undefined, async (c) => {
    for (const id of [0, -1, 1.5, "42", undefined]) {
      await assert.rejects(c.getSignOffs(id), /runId/);
    }
    await assert.rejects(c.getSignOffs(42, { asOwner: 1 }), /getSignOffs asOwner must be true or false/);
    await assert.rejects(c.getNewestSignOff({ asOwner: "true" }), /getNewestSignOff asOwner must be true or false/);
  });
  assert.equal(seen.length, 0);
});

test("getSignOffHistory reads the account's whole chain", async () => {
  const { seen, result } = await withServer(() => ({ json: [RECORD] }), (c) => c.getSignOffHistory(), { apiKey: "owner" });
  assert.deepEqual(requests(seen), ["GET /account/signoffs/history"]);
  assert.deepEqual(result, [RECORD]);
});

test("the sign-off reads are retried as GETs", async () => {
  let calls = 0;
  const { result } = await withServer(
    () => (++calls === 1 ? { status: 503, json: {} } : { json: [RECORD] }),
    (c) => c.getSignOffHistory(),
  );
  assert.equal(calls, 2);
  assert.deepEqual(result, [RECORD]);
});

test("exportAccountRuns keeps the account's sign-offs", async () => {
  const body = { ok: true, to: "2026-12-01T00:00:00Z", total: 0, returned: 0, truncated: false, by_status: {}, runs: [], account_id: "account-7", signoffs: [RECORD] };
  const { result } = await withServer(() => ({ json: body }), (c) => c.exportAccountRuns(), { apiKey: "owner" });
  assert.deepEqual(result.signoffs, [RECORD]);
});

test("every sign-off method needs an API key", async () => {
  const { privateKey } = generateRequestKeyPair();
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  for (const call of [
    () => c.registerApprover("Dana", privateKey),
    () => c.listApprovers(),
    () => c.revokeApprover(1),
    () => c.getNewestSignOff(),
    () => c.getNewestSignOff({ asOwner: true }),
    () => c.signOff(RECORD_TARGET, "approve", privateKey),
    () => c.signOff(RECORD_TARGET, "approve", privateKey, { asOwner: true }),
    () => c.getSignOffs(1),
    () => c.getSignOffs(1, { asOwner: true }),
    () => c.getSignOffHistory(),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
});

test("the README states what a sign-off shows and does not show", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8").replace(/\s+/g, " ");
  for (const sentence of [
    "An approver key is registered by the account's owner, and it is never a request key in the same account.",
    "A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log.",
    "It does not show that the review was careful, that the result is right, or who the person is. A key is not an identity.",
    "A sign-off gates nothing on its own.",
    "A later sign-off on the same result supersedes the earlier one, and nothing is deleted.",
    "Verdifax did not review the result.",
    "Since v0.22.0, the verifier reads sign-offs",
    "It also checks that the record the server returns carries the signature, `approver_key`, `decision`, `previous_signoff_hash` and `target` that were sent, and throws `VerdifaxError` if not.",
  ]) {
    assert.ok(readme.includes(sentence), sentence);
  }
});

test("the sign-off types are exported", () => {
  for (const file of ["../dist/index.d.ts", "../dist/index.d.mts"]) {
    const exported = /export \{([^}]+)\}/.exec(readFileSync(new URL(file, import.meta.url), "utf8"))[1];
    const names = exported.split(",").map((name) => name.trim().replace(/^type /, "").split(" as ").pop());
    for (const name of [
      "Approver",
      "ApproverKeyProof",
      "ApproverList",
      "ApproverRegistration",
      "ApproverRevocation",
      "AsOwnerOptions",
      "NewestSignOff",
      "SignOffDecision",
      "SignOffOptions",
      "SignOffRecord",
      "SignOffTarget",
      "SignOffTargetKind",
      "approverKeyProof",
      "signOffPreimage",
    ]) {
      assert.ok(names.includes(name), `${file} does not export ${name}`);
    }
  }
});
