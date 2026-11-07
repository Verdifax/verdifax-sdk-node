// SDK 1.2.0: customer policies. The six policy routes, the activation
// signature, policy_context and expected_policy_hash on every path to a run,
// and no silently dropped request field. The mock server listens on localhost only; nothing leaves this
// machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  EXECUTE_FIELDS,
  VerdifaxClient,
  VerdifaxError,
  policyActivationApproval,
  policyActivationPreimage,
} from "../dist/index.mjs";
import { publicKeyObject, signedFields, verifiesV2 } from "./signed-body.mjs";

// The byte authority, copied unchanged from scripts/sdk-signature-vector.json.
const VECTOR = JSON.parse(readFileSync(new URL("./sdk-signature-vector.json", import.meta.url), "utf8"));
const SEED = Buffer.from(VECTOR.seed_hex, "hex");
const PUBLIC_KEY = Buffer.from(VECTOR.public_key, "base64");
const ZEROS = "0".repeat(64);
const DOC_HASH = "c".repeat(64);
const POLICY_HASH = "d".repeat(64);
const NEWEST = "e".repeat(64);
const ROW = { payload_text: "hello", program_id: "1".repeat(64), route_id: "r", registry_record_hash: "2".repeat(64) };
const ACTOR = { actor_id: "agent:loan-bot" };
const CONTEXT = {
  actor_type: "agent",
  mfa_satisfied: true,
  session_age_seconds: 120,
  object_type: "transaction",
  object_id: "loan-1042",
  classification: "CONFIDENTIAL",
};
const POLICY = {
  policy_id: "acme-loans",
  policy_version: "3",
  policy_hash: POLICY_HASH,
  document_hash: DOC_HASH,
  created_at: "2026-11-06T12:00:00Z",
};
const LIST = { ok: true, chain_id: "api-key-7", newest_activation_hash: NEWEST, active_document_hash: "", policies: [POLICY] };
const ACTIVATION = {
  format: "verdifax.policy.activation.v1",
  chain_id: "api-key-7",
  sequence: 2,
  previous_activation_hash: NEWEST,
  policy_id: "acme-loans",
  policy_version: "3",
  policy_hash: POLICY_HASH,
  document_hash: DOC_HASH,
  activated_at: "2026-11-06T12:00:01.5Z",
  activation_hash: "f".repeat(64),
};

/** Answers each request from `answer(request, body, index)`, which returns
 *  `{ status, json }`. A plain successful run by default. */
async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, raw, body });
      const { status = 200, json = { ok: true, run_id: seen.length } } = answer?.(req, body, seen.length - 1) ?? {};
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k", ...config });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

/** Answers GET /policies with LIST and the activation with `activate`. */
function policyServer(activate = { json: { ok: true, activation: ACTIVATION } }) {
  return (req) => (req.method === "GET" && req.url === "/policies" ? { json: LIST } : activate);
}

function activationVerifies(signature, fields, publicKey = PUBLIC_KEY) {
  const signed = [
    "verdifax.policy-activation.v1",
    fields.chain_id,
    fields.document_hash,
    fields.previous_activation_hash,
    signature.signed_at,
    signature.nonce,
  ].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(publicKey), Buffer.from(signature.signature, "base64"));
}

// ── The vector, byte for byte ───────────────────────────────────

test("vector: policyActivationPreimage", () => {
  const preimage = policyActivationPreimage({
    chain_id: VECTOR.activation_chain_id,
    document_hash: VECTOR.activation_document_hash,
    previous_activation_hash: VECTOR.activation_previous_hash,
    signed_at: VECTOR.signed_at,
    nonce: VECTOR.nonce,
  });
  assert.equal(preimage.toString("hex"), VECTOR.activation_preimage_hex);
});

test("vector: policyActivationApproval", () => {
  const fields = {
    chain_id: VECTOR.activation_chain_id,
    document_hash: VECTOR.activation_document_hash,
    previous_activation_hash: VECTOR.activation_previous_hash,
  };
  const approval = policyActivationApproval(SEED, fields, { signedAt: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.deepEqual(approval, { signature: VECTOR.activation_signature, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.ok(activationVerifies(approval, fields));
});

test("policyActivationApproval defaults to the current time and a fresh nonce", () => {
  const fields = { chain_id: "api-key-7", document_hash: DOC_HASH, previous_activation_hash: ZEROS };
  const a = policyActivationApproval(SEED, fields);
  const b = policyActivationApproval(SEED, fields);
  assert.match(a.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(a.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.nonce, b.nonce);
  assert.ok(activationVerifies(a, fields));
});

// ── The six methods ─────────────────────────────────────────────

test("uploadPolicy sends the exact text and returns the stored policy", async () => {
  // Spacing, key order, a trailing newline and non-ASCII text all reach the
  // server unchanged, because the server hashes the exact bytes.
  const document = '{ "policy_id":"acme-loans",  "policy_version": "3", "note": "café" }\n';
  const { seen, result } = await withServer(
    () => ({ status: 201, json: POLICY }),
    (c) => c.uploadPolicy(document),
  );
  assert.equal(seen.length, 1);
  assert.equal(`${seen[0].method} ${seen[0].url}`, "POST /policies");
  assert.equal(seen[0].raw, JSON.stringify({ document }));
  assert.deepEqual(seen[0].body, { document });
  assert.deepEqual(result, POLICY);
});

test("listPolicies returns the server's object", async () => {
  const { seen, result } = await withServer(() => ({ json: LIST }), (c) => c.listPolicies());
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /policies"]);
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, LIST);
});

test("getPolicy reads one document with its exact text", async () => {
  const stored = { ...POLICY, document: "exact text\n" };
  const { seen, result } = await withServer(() => ({ json: stored }), (c) => c.getPolicy(DOC_HASH));
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), [`GET /policies/${DOC_HASH}`]);
  assert.deepEqual(result, stored);
});

test("testPolicy sends inputs with a document or a document hash", async () => {
  const answer = { ok: true, sealed: false, outcome: "deny", fired_rule_id: "no-weekend", reason_code: "R7" };
  const inputs = { subject_type: "agent", verb: "approve", classification: "INTERNAL", rate_counts: { day: 3 } };
  const { seen, result } = await withServer(
    () => ({ json: answer }),
    async (c) => [
      await c.testPolicy({ inputs, document: "exact text" }),
      await c.testPolicy({ inputs, documentHash: DOC_HASH }),
    ],
  );
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["POST /policies/test", "POST /policies/test"]);
  assert.deepEqual(seen[0].body, { inputs, document: "exact text" });
  assert.deepEqual(seen[1].body, { inputs, document_hash: DOC_HASH });
  assert.deepEqual(result, [answer, answer]);
});

test("getPolicyHistory returns the list as the server sends it, oldest first", async () => {
  const first = { ...ACTIVATION, sequence: 1, previous_activation_hash: ZEROS, activation_hash: NEWEST };
  const history = [first, ACTIVATION];
  const { seen, result } = await withServer(() => ({ json: history }), (c) => c.getPolicyHistory());
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /policies/history"]);
  assert.deepEqual(result, history);
  assert.equal(JSON.stringify(result), JSON.stringify(history));
});

test("activatePolicy reads the chain, then names its newest change, unsigned without a key", async () => {
  const { seen, result } = await withServer(policyServer(), (c) => c.activatePolicy(DOC_HASH));
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /policies", `POST /policies/${DOC_HASH}/activate`]);
  assert.deepEqual(seen[1].body, { previous_activation_hash: NEWEST });
  assert.deepEqual(result, ACTIVATION);
});

test("activatePolicy on a first change names 64 zeros", async () => {
  const empty = { ok: true, chain_id: "api-key-7", newest_activation_hash: ZEROS, active_document_hash: "", policies: [POLICY] };
  const { seen } = await withServer(
    (req) => (req.method === "GET" ? { json: empty } : { json: { ok: true, activation: ACTIVATION } }),
    (c) => c.activatePolicy(DOC_HASH),
    { signingKey: SEED },
  );
  assert.equal(seen[1].body.previous_activation_hash, ZEROS);
  assert.ok(
    activationVerifies(seen[1].body.signature, {
      chain_id: "api-key-7",
      document_hash: DOC_HASH,
      previous_activation_hash: ZEROS,
    }),
  );
});

test("activatePolicy with a signing key signs the chain, document and previous change", async () => {
  const { seen, result } = await withServer(policyServer(), (c) => c.activatePolicy(DOC_HASH), { signingKey: SEED });
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["GET /policies", `POST /policies/${DOC_HASH}/activate`]);
  const body = seen[1].body;
  assert.deepEqual(Object.keys(body).sort(), ["previous_activation_hash", "signature"]);
  assert.equal(body.previous_activation_hash, NEWEST);
  assert.deepEqual(Object.keys(body.signature).sort(), ["nonce", "signature", "signed_at"]);
  assert.match(body.signature.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(body.signature.nonce, /^[0-9a-f]{32}$/);
  const fields = { chain_id: "api-key-7", document_hash: DOC_HASH, previous_activation_hash: NEWEST };
  assert.ok(activationVerifies(body.signature, fields));
  // The signature is bound to this chain, document and previous change.
  assert.ok(!activationVerifies(body.signature, { ...fields, chain_id: "api-key-8" }));
  assert.ok(!activationVerifies(body.signature, { ...fields, document_hash: POLICY_HASH }));
  assert.ok(!activationVerifies(body.signature, { ...fields, previous_activation_hash: ZEROS }));
  assert.deepEqual(result, ACTIVATION);
});

test("a 409 from activatePolicy throws APIError with the server's message and is not retried", async () => {
  const { seen, result } = await withServer(
    policyServer({ status: 409, json: { ok: false, error: "previous_activation_hash is not the newest change" } }),
    (c) => c.activatePolicy(DOC_HASH).catch((err) => err),
    { signingKey: SEED, maxRetries: 3, retryBaseDelayMs: 1 },
  );
  assert.ok(result instanceof APIError);
  assert.equal(result.status, 409);
  assert.equal(result.path, `/policies/${DOC_HASH}/activate`);
  assert.equal(result.message, "previous_activation_hash is not the newest change");
  assert.equal(seen.length, 2);
});

test("activatePolicy with a signing key refuses a chain with no chain_id before posting", async () => {
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, newest_activation_hash: ZEROS, active_document_hash: "", policies: [] } }),
    (c) => c.activatePolicy(DOC_HASH).catch((err) => err),
    { signingKey: SEED },
  );
  assert.ok(result instanceof VerdifaxError);
  assert.match(result.message, /chain_id/);
  assert.deepEqual(seen.map((r) => r.method), ["GET"]);
});

// ── Refused before sending ──────────────────────────────────────

test("uploadPolicy refuses anything that is not a string", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const document of [{ policy_id: "x" }, ["x"], 5, null, undefined, Buffer.from("x")]) {
      await assert.rejects(c.uploadPolicy(document), (err) => err instanceof VerdifaxError && /string/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

test("getPolicy and activatePolicy refuse a hash that is not 64 lowercase hex", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const hash of ["", "c".repeat(63), "C".repeat(64), "g".repeat(64), `${"c".repeat(63)}/`, "../history", undefined, 5]) {
      await assert.rejects(c.getPolicy(hash), VerdifaxError);
      await assert.rejects(c.activatePolicy(hash), VerdifaxError);
    }
  });
  assert.equal(seen.length, 0);
});

test("testPolicy refuses both or neither of document and documentHash", async () => {
  const inputs = { verb: "approve" };
  const { seen } = await withServer(undefined, async (c) => {
    const exactlyOne = (err) => err instanceof VerdifaxError && /exactly one/.test(err.message);
    await assert.rejects(c.testPolicy({ inputs }), exactlyOne);
    await assert.rejects(c.testPolicy({ inputs, document: "x", documentHash: DOC_HASH }), exactlyOne);
    await assert.rejects(c.testPolicy({ inputs, documentHash: "bad" }), VerdifaxError);
    await assert.rejects(c.testPolicy({ inputs, document: { policy_id: "x" } }), VerdifaxError);
    await assert.rejects(c.testPolicy({ document: "x" }), VerdifaxError);
    await assert.rejects(c.testPolicy({ inputs: [], document: "x" }), VerdifaxError);
  });
  assert.equal(seen.length, 0);
});

test("every policy method needs an API key", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  await assert.rejects(c.uploadPolicy("x"), APIKeyRequiredError);
  await assert.rejects(c.listPolicies(), APIKeyRequiredError);
  await assert.rejects(c.getPolicy(DOC_HASH), APIKeyRequiredError);
  await assert.rejects(c.testPolicy({ inputs: {}, document: "x" }), APIKeyRequiredError);
  await assert.rejects(c.getPolicyHistory(), APIKeyRequiredError);
  await assert.rejects(c.activatePolicy(DOC_HASH), APIKeyRequiredError);
});

// ── policy_context and expected_policy_hash on every run ────────

const POLICY_FIELDS = { attested_context: ACTOR, policy_context: CONTEXT, expected_policy_hash: POLICY_HASH };

function assertPolicyFields(request) {
  assert.deepEqual(request.policy_context, CONTEXT);
  assert.equal(request.expected_policy_hash, POLICY_HASH);
  assert.equal(request.attested_context.actor_id, ACTOR.actor_id);
}

async function everyRunPath(c) {
  await c.execute({ ...ROW, ...POLICY_FIELDS });
  await c.attest({ ...ROW, ...POLICY_FIELDS });
  await c.executeBatch([{ ...ROW, ...POLICY_FIELDS }, { ...ROW, payload_text: "second", ...POLICY_FIELDS }]);
  await c.verifyDeterminism({ ...ROW, ...POLICY_FIELDS });
  await c.job("loan-1").step("intake", { ...ROW, ...POLICY_FIELDS });
}

const RUN_PATHS = ["/execute", "/execute", "/execute/batch", "/execute/verify-determinism", "/execute"];

function sealedRun(_req, _body, index) {
  return { json: { ok: true, run_id: index + 1, record_hash: "a".repeat(64) } };
}

test("policy_context and expected_policy_hash are sent on every path to a run", async () => {
  const { seen } = await withServer(sealedRun, everyRunPath);
  assert.deepEqual(seen.map((r) => r.url), RUN_PATHS);
  for (const r of seen) {
    if (r.url === "/execute/batch") {
      assert.equal(r.body.runs.length, 2);
      r.body.runs.forEach(assertPolicyFields);
    } else {
      assertPolicyFields(r.body);
    }
  }
});

test("on a signed client both fields are inside signed_request", async () => {
  const { seen } = await withServer(sealedRun, everyRunPath, { signingKey: SEED });
  assert.deepEqual(seen.map((r) => r.url), RUN_PATHS);
  const bodies = seen.flatMap((r) => (r.url === "/execute/batch" ? r.body.runs : [r.body]));
  assert.equal(bodies.length, 6);
  for (const body of bodies) {
    assertPolicyFields(signedFields(body));
    assert.ok(verifiesV2(body, PUBLIC_KEY));
  }
});

test("the provider helpers send both fields", async () => {
  const args = {
    program_id: ROW.program_id,
    route_id: ROW.route_id,
    registry_record_hash: ROW.registry_record_hash,
    prompt: "p",
    response: "r",
    policy_context: { object_type: "text", classification: "PUBLIC" },
    expected_policy_hash: POLICY_HASH,
  };
  const { seen } = await withServer(sealedRun, async (c) => {
    await c.attestClaudeResponse(args);
    await c.attestOpenAIResponse(args);
  });
  for (const r of seen) {
    assert.deepEqual(r.body.policy_context, args.policy_context);
    assert.equal(r.body.expected_policy_hash, POLICY_HASH);
  }
});

test("both fields are left out when not given", async () => {
  const { seen } = await withServer(sealedRun, async (c) => {
    await c.execute(ROW);
    await c.attest(ROW);
    await c.execute({ ...ROW, policy_context: null, expected_policy_hash: null });
    await c.executeBatch([ROW]);
  });
  const bodies = seen.flatMap((r) => (r.url === "/execute/batch" ? r.body.runs : [r.body]));
  for (const body of bodies) {
    assert.ok(!("policy_context" in body));
    assert.ok(!("expected_policy_hash" in body));
  }
});

test("object facts need no attested actor, and a false or zero actor fact passes as the server reads it", async () => {
  const contexts = [
    { object_type: "code", object_id: "", classification: "TS_SCI" },
    { mfa_satisfied: false, session_age_seconds: 0 },
    {},
  ];
  const { seen } = await withServer(sealedRun, async (c) => {
    for (const policy_context of contexts) await c.execute({ ...ROW, policy_context });
  });
  assert.deepEqual(seen.map((r) => r.body.policy_context), contexts);
});

test("a 409 for another active policy throws the usual APIError", async () => {
  const { result } = await withServer(
    () => ({ status: 409, json: { ok: false, error: "a different policy is active than the one this request names" } }),
    (c) => c.execute({ ...ROW, expected_policy_hash: POLICY_HASH }).catch((err) => err),
    { signingKey: SEED },
  );
  assert.ok(result instanceof APIError);
  assert.equal(result.status, 409);
  assert.match(result.message, /different policy/);
  assert.equal(JSON.parse(result.signedRequest).expected_policy_hash, POLICY_HASH);
});

const BAD_FIELDS = [
  ["an unknown key", { policy_context: { ...CONTEXT, mfa: true } }, /unknown field: mfa/],
  ["an inherited name", { policy_context: { constructor: "x" } }, /unknown field: constructor/],
  ["a bad actor_type", { policy_context: { actor_type: "robot" } }, /actor_type/],
  ["an empty actor_type", { policy_context: { actor_type: "" } }, /actor_type/],
  ["a lowercase classification", { policy_context: { classification: "internal" } }, /classification/],
  ["a bad object_type", { policy_context: { object_type: "image" } }, /object_type/],
  ["a string mfa_satisfied", { policy_context: { mfa_satisfied: "true" } }, /mfa_satisfied/],
  ["a negative session_age_seconds", { policy_context: { session_age_seconds: -1 } }, /session_age_seconds/],
  ["a fractional session_age_seconds", { policy_context: { session_age_seconds: 1.5 } }, /session_age_seconds/],
  ["a string session_age_seconds", { policy_context: { session_age_seconds: "60" } }, /session_age_seconds/],
  ["an object_id over 256 bytes", { policy_context: { object_id: "a".repeat(257) } }, /object_id/],
  ["a 129-character object_id of 258 bytes", { policy_context: { object_id: "é".repeat(129) } }, /object_id/],
  ["a numeric object_id", { policy_context: { object_id: 7 } }, /object_id/],
  ["a null value", { policy_context: { classification: null } }, /classification/],
  ["a list", { policy_context: [] }, /object/],
  ["a string", { policy_context: "agent" }, /object/],
  ["actor_type with no attested actor", { policy_context: { actor_type: "user" } }, /attested actor/],
  ["mfa_satisfied with no attested actor", { policy_context: { mfa_satisfied: true } }, /attested actor/],
  ["session_age_seconds with no attested actor", { policy_context: { session_age_seconds: 30 } }, /attested actor/],
  [
    "an actor fact with an empty attested_context",
    { attested_context: { actor_id: "" }, policy_context: { actor_type: "user" } },
    /attested actor/,
  ],
  ["a short expected_policy_hash", { expected_policy_hash: "d".repeat(63) }, /expected_policy_hash/],
  ["an uppercase expected_policy_hash", { expected_policy_hash: "D".repeat(64) }, /expected_policy_hash/],
  ["an empty expected_policy_hash", { expected_policy_hash: "" }, /expected_policy_hash/],
];

for (const [name, fields, message] of BAD_FIELDS) {
  test(`${name} is refused on every path before sending`, async () => {
    const refused = (err) => err instanceof VerdifaxError && message.test(err.message);
    const { seen } = await withServer(
      sealedRun,
      async (c) => {
        await assert.rejects(c.execute({ ...ROW, ...fields }), refused);
        await assert.rejects(c.attest({ ...ROW, ...fields }), refused);
        await assert.rejects(c.executeBatch([ROW, { ...ROW, ...fields }]), refused);
        await assert.rejects(c.verifyDeterminism({ ...ROW, ...fields }), refused);
        await assert.rejects(c.job("loan-1").step("intake", { ...ROW, ...fields }), refused);
      },
      { signingKey: SEED },
    );
    assert.equal(seen.length, 0);
  });
}

test("the largest object_id and session age pass", async () => {
  const policy_context = { object_id: "é".repeat(128), session_age_seconds: Number.MAX_SAFE_INTEGER, actor_type: "system" };
  const { seen } = await withServer(sealedRun, (c) => c.execute({ ...ROW, attested_context: ACTOR, policy_context }));
  assert.deepEqual(seen[0].body.policy_context, policy_context);
});

// ── No silently dropped request field ───────────────────────────

// The central list: test/sdk-parity.json is a copy of
// scripts/sdk-parity.json, held identical to it by a replay rule.
const PARITY = new URL("./sdk-parity.json", import.meta.url);

test("EXECUTE_FIELDS equals execute_fields in sdk-parity.json", () => {
  const fromFile = JSON.parse(readFileSync(PARITY, "utf8")).execute_fields;
  assert.equal(new Set(EXECUTE_FIELDS).size, EXECUTE_FIELDS.length);
  assert.deepEqual([...EXECUTE_FIELDS].sort(), [...fromFile].sort());
});

test("EXECUTE_FIELDS cannot be changed at run time", () => {
  assert.ok(Object.isFrozen(EXECUTE_FIELDS));
});

const ATTESTED_KEYS = [
  "attested",
  "actor_id",
  "actor_role",
  "authorization_policy",
  "actor_signature",
  "model_provider",
  "model_name",
  "model_version",
  "model_temperature",
  "prompt_hash",
  "decision_kind",
  "decision_result",
  "decision_note",
];

async function refusedOnEveryRunPath(fields, message) {
  const refused = (err) => err instanceof VerdifaxError && message.test(err.message);
  const { seen } = await withServer(
    sealedRun,
    async (c) => {
      await assert.rejects(c.execute({ ...ROW, ...fields }), refused);
      await assert.rejects(c.attest({ ...ROW, ...fields }), refused);
      await assert.rejects(c.executeBatch([ROW, { ...ROW, ...fields }]), refused);
      await assert.rejects(c.verifyDeterminism({ ...ROW, ...fields }), refused);
      await assert.rejects(c.job("loan-1").step("intake", { ...ROW, ...fields }), refused);
    },
    { signingKey: SEED },
  );
  assert.equal(seen.length, 0);
}

for (const key of ["policyContext", "expected_policy", "payloadText", "Job", "constructor", "__proto__x"]) {
  test(`a top-level key ${key} is refused on every path, naming the key`, () =>
    refusedOnEveryRunPath({ [key]: "x" }, new RegExp(`unknown field: ${key}$`)));
}

test("a misspelt attested_context key is refused on every path, naming the key", () =>
  refusedOnEveryRunPath({ attested_context: { actor_id: "a", actorRole: "x" } }, /attested_context has an unknown field: actorRole$/));

test("a batch row names its index", async () => {
  const { seen, result } = await withServer(sealedRun, (c) =>
    c.executeBatch([ROW, ROW, { ...ROW, polcy_context: {} }]).catch((err) => err),
  );
  assert.ok(result instanceof VerdifaxError);
  assert.match(result.message, /runs\[2\] has an unknown field: polcy_context$/);
  assert.equal(seen.length, 0);
});

test("attest refuses the execute fields it does not take, instead of dropping them", async () => {
  const { seen } = await withServer(sealedRun, async (c) => {
    for (const key of ["request_signature", "signed_request"]) {
      await assert.rejects(c.attest({ ...ROW, [key]: "x" }), new RegExp(`attest request has an unknown field: ${key}$`));
    }
  });
  assert.equal(seen.length, 0);
});

test("every listed attested_context key reaches the server on every path", async () => {
  const attested_context = Object.fromEntries(ATTESTED_KEYS.map((key) => [key, key === "attested" ? true : `v-${key}`]));
  const { seen } = await withServer(sealedRun, async (c) => {
    await c.execute({ ...ROW, attested_context });
    await c.attest({ ...ROW, attested_context });
    await c.executeBatch([{ ...ROW, attested_context }]);
    await c.verifyDeterminism({ ...ROW, attested_context });
    await c.job("loan-1").step("intake", { ...ROW, attested_context });
  });
  const bodies = seen.flatMap((r) => (r.url === "/execute/batch" ? r.body.runs : [r.body]));
  assert.equal(bodies.length, 5);
  for (const body of bodies) assert.deepEqual(body.attested_context, attested_context);
});

test("unknown fields in a response are kept and do not throw", async () => {
  const reply = { ok: true, run_id: 4, record_hash: "a".repeat(64), added_by_a_newer_server: { x: 1 } };
  const { result } = await withServer(() => ({ json: reply }), (c) => c.execute(ROW));
  assert.deepEqual(result, reply);
});

test("a provider helper refuses a misspelt argument, naming it", async () => {
  const args = { ...ROW, prompt: "p", response: "r" };
  const { seen } = await withServer(sealedRun, async (c) => {
    for (const [method, label] of [["attestClaudeResponse", "attestClaudeResponse"], ["attestOpenAIResponse", "attestOpenAIResponse"]]) {
      for (const key of ["polcy_context", "goverm", "expectedPolicyHash", "provider"]) {
        await assert.rejects(
          c[method]({ ...args, [key]: "x" }),
          (err) => err instanceof VerdifaxError && err.message === `verdifax: ${label} arguments has an unknown field: ${key}`,
        );
      }
    }
  });
  assert.equal(seen.length, 0);
});

test("a provider helper still accepts a spread run request", async () => {
  // Every execute field is accepted. The helper sends its own payload and
  // attested_context, as before, and passes on job and the policy fields.
  const run = {
    ...ROW,
    ai_output_text: "ignored",
    attested_context: { actor_id: "ignored" },
    request_substance: { prompt: "ignored" },
    policy_context: { object_type: "text" },
    expected_policy_hash: POLICY_HASH,
  };
  const { seen } = await withServer(sealedRun, async (c) => {
    await c.attestClaudeResponse({ ...run, prompt: "p", response: "r" });
    await c.attestOpenAIResponse({ ...run, prompt: "p", response: "r" });
  });
  assert.equal(seen.length, 2);
  for (const [i, provider] of [[0, "anthropic"], [1, "openai"]]) {
    const body = seen[i].body;
    assert.equal(body.payload_text, JSON.stringify({ prompt: "p", provider, response: "r" }));
    assert.deepEqual(body.attested_context, { actor_role: "ai_assistant", model_provider: provider, attested: true });
    assert.ok(!("ai_output_text" in body));
    assert.ok(!("request_substance" in body));
    assert.deepEqual(body.policy_context, { object_type: "text" });
    assert.equal(body.expected_policy_hash, POLICY_HASH);
  }
});
