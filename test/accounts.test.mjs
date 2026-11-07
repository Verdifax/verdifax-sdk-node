// SDK 1.3.0: the account layer. The owner key's routes, the account policy
// signed over the account chain, and the two admin account routes. The mock
// server listens on localhost only; nothing leaves this machine.
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
  policyActivationApproval,
  policyActivationPreimage,
  requestKeyChangePreimage,
  requestKeyRegistrationBody,
} from "../dist/index.mjs";
import { publicKeyObject } from "./signed-body.mjs";

// The byte authority, copied unchanged from scripts/sdk-signature-vector.json.
const VECTOR = JSON.parse(readFileSync(new URL("./sdk-signature-vector.json", import.meta.url), "utf8"));
const SEED = Buffer.from(VECTOR.seed_hex, "hex");
const PUBLIC_KEY = Buffer.from(VECTOR.public_key, "base64");
const ZEROS = "0".repeat(64);
const DOC_HASH = "c".repeat(64);
const POLICY_HASH = "d".repeat(64);
const NEWEST = "e".repeat(64);
const CSV = "run_id,created_at,status\n1,2026-11-05T00:00:00Z,ok\n";

const ACCOUNT = {
  account_id: "account-7",
  id: 7,
  name: "Acme",
  tier: "trial",
  created_at: "2026-11-07T12:00:00Z",
  member_keys: 2,
  owner_keys: 1,
  chain_id: "account-7",
  identity: "the account number is a label Verdifax assigned, not a verified company identity",
  policy_scope: "an account policy is the customer's own; every key in the account must pass it on top of the key's own",
};
const KEY = {
  id: 12,
  name: "customer:loan-bot",
  account_id: "account-7",
  owner: false,
  tier: "trial",
  created_at: "2026-11-07T12:00:00Z",
  last_used_at: "0001-01-01T00:00:00Z",
  run_count: 0,
  revoked: false,
};
const CREATED_KEY = {
  ...KEY,
  ok: true,
  secret: "vfx_secret",
  request_key_required: true,
  hint: "Store this secret now, it will never be shown again.",
};
const POLICY = {
  policy_id: "acme-all",
  policy_version: "1",
  policy_hash: POLICY_HASH,
  document_hash: DOC_HASH,
  created_at: "2026-11-07T12:00:00Z",
};
const LIST = { ok: true, chain_id: "account-7", newest_activation_hash: NEWEST, active_document_hash: "", policies: [POLICY] };
const ACTIVATION = {
  format: "verdifax.policy.activation.v1",
  chain_id: "account-7",
  sequence: 2,
  previous_activation_hash: NEWEST,
  policy_id: "acme-all",
  policy_version: "1",
  policy_hash: POLICY_HASH,
  document_hash: DOC_HASH,
  activated_at: "2026-11-07T12:00:01.5Z",
  activation_hash: "f".repeat(64),
};

/** Answers each request from `answer(request, body, index)`, which returns
 *  `{ status, json }` or `{ status, type, text, headers }`. */
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
      const { status = 200, json = { ok: true }, type = "application/json", headers = {} } = reply;
      res.statusCode = status;
      res.setHeader("Content-Type", type);
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
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

/** Answers GET /account/policies with `list` and the activation with `activate`. */
function accountPolicyServer(list = LIST, activate = { json: { ok: true, activation: ACTIVATION } }) {
  return (req) => (req.method === "GET" && req.url === "/account/policies" ? { json: list } : activate);
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

const ACCOUNT_VECTOR_FIELDS = {
  chain_id: VECTOR.account_activation_chain_id,
  document_hash: VECTOR.activation_document_hash,
  previous_activation_hash: VECTOR.activation_previous_hash,
};

test("vector: policyActivationPreimage over the account chain", () => {
  assert.equal(VECTOR.account_activation_chain_id, "account-7");
  const preimage = policyActivationPreimage({ ...ACCOUNT_VECTOR_FIELDS, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.equal(preimage.toString("hex"), VECTOR.account_activation_preimage_hex);
});

test("vector: policyActivationApproval over the account chain", () => {
  const approval = policyActivationApproval(SEED, ACCOUNT_VECTOR_FIELDS, { signedAt: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.deepEqual(approval, { signature: VECTOR.account_activation_signature, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.ok(activationVerifies(approval, ACCOUNT_VECTOR_FIELDS));
  // The account signature is not the key chain's, and does not verify there.
  assert.notEqual(approval.signature, VECTOR.activation_signature);
  assert.ok(!activationVerifies(approval, { ...ACCOUNT_VECTOR_FIELDS, chain_id: VECTOR.activation_chain_id }));
});

// ── The account and its keys ────────────────────────────────────

test("getAccount reads GET /account with the owner key", async () => {
  const { seen, result } = await withServer(() => ({ json: { ok: true, ...ACCOUNT } }), (c) => c.getAccount());
  assert.deepEqual(requests(seen), ["GET /account"]);
  assert.equal(seen[0].headers["x-verdifax-key"], "owner");
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, { ok: true, ...ACCOUNT });
});

test("createAccountKey posts the name, and expires_at when given", async () => {
  const { seen, result } = await withServer(
    () => ({ status: 201, json: CREATED_KEY }),
    async (c) => [await c.createAccountKey("loan-bot"), await c.createAccountKey("nightly", { expiresAt: "2026-12-31" })],
  );
  assert.deepEqual(requests(seen), ["POST /account/keys", "POST /account/keys"]);
  assert.deepEqual(seen[0].body, { name: "loan-bot" });
  assert.deepEqual(seen[1].body, { name: "nightly", expires_at: "2026-12-31" });
  assert.deepEqual(result, [CREATED_KEY, CREATED_KEY]);
});

test("createAccountKey refuses a missing name before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const name of ["", "   ", undefined, null, 5]) {
      await assert.rejects(c.createAccountKey(name), (err) => err instanceof VerdifaxError && /name is required/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

test("listAccountKeys returns the account and its keys", async () => {
  const owner = { ...KEY, id: 11, owner: true, expires_at: "2027-01-01T00:00:00Z" };
  const body = { ok: true, account_id: "account-7", keys: [owner, KEY] };
  const { seen, result } = await withServer(() => ({ json: body }), (c) => c.listAccountKeys());
  assert.deepEqual(requests(seen), ["GET /account/keys"]);
  assert.deepEqual(result, body);
});

test("listAccountKeys gives an empty list when the server sends none", async () => {
  const { result } = await withServer(() => ({ json: { ok: true, account_id: "account-7" } }), (c) => c.listAccountKeys());
  assert.deepEqual(result, { ok: true, account_id: "account-7", keys: [] });
});

test("revokeAccountKey sends DELETE /account/keys/{id} and returns the revocation", async () => {
  const body = { ok: true, id: 12, revoked: true };
  const { seen, result } = await withServer(() => ({ json: body }), (c) => c.revokeAccountKey(12));
  assert.deepEqual(requests(seen), ["DELETE /account/keys/12"]);
  assert.equal(seen[0].body, undefined);
  assert.deepEqual(result, body);
});

test("revokeAccountKey maps a key outside the account to NotFoundError and is not retried", async () => {
  const { seen, result } = await withServer(
    () => ({ status: 404, json: { ok: false, error: "no such member key in this account" } }),
    (c) => c.revokeAccountKey(11).catch((err) => err),
    { maxRetries: 3 },
  );
  assert.ok(result instanceof NotFoundError);
  assert.equal(seen.length, 1);
});

test("revokeAccountKey refuses an id that is not a whole number above zero", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const id of [0, -1, 1.5, NaN, Infinity, "12", "../account", undefined, null]) {
      await assert.rejects(c.revokeAccountKey(id), (err) => err instanceof VerdifaxError && /keyId/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

// ── The owner key's request key ─────────────────────────────────

test("registerAccountRequestKey posts the public key and its proof to /account/request-key", async () => {
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, public_key: VECTOR.public_key } }),
    (c) => c.registerAccountRequestKey(),
    { signingKey: SEED },
  );
  assert.deepEqual(requests(seen), ["POST /account/request-key"]);
  assert.deepEqual(seen[0].body, requestKeyRegistrationBody(SEED));
  assert.equal(seen[0].body.public_key, VECTOR.public_key);
  assert.deepEqual(result, { ok: true, public_key: VECTOR.public_key });
});

test("registerAccountRequestKey needs a signing key and sends nothing without one", async () => {
  const { seen } = await withServer(undefined, (c) =>
    assert.rejects(c.registerAccountRequestKey(), /registerAccountRequestKey needs the signingKey client option/),
  );
  assert.equal(seen.length, 0);
});

test("clearAccountRequestKey sends the current key's approval, then the client stops signing", async () => {
  const { seen } = await withServer(
    () => ({ json: { ok: true } }),
    async (c) => {
      await c.clearAccountRequestKey();
      await assert.rejects(c.activateAccountPolicy(DOC_HASH), /signingKey/);
    },
    { signingKey: SEED },
  );
  assert.deepEqual(requests(seen), ["DELETE /account/request-key"]);
  assert.deepEqual(Object.keys(seen[0].body), ["change"]);
  const change = seen[0].body.change;
  const preimage = requestKeyChangePreimage({ new_public_key: "", signed_at: change.signed_at, nonce: change.nonce });
  assert.ok(crypto.verify(null, preimage, publicKeyObject(PUBLIC_KEY), Buffer.from(change.signature, "base64")));
});

test("clearAccountRequestKey with no signing key sends no body", async () => {
  const { seen } = await withServer(() => ({ json: { ok: true } }), (c) => c.clearAccountRequestKey());
  assert.deepEqual(requests(seen), ["DELETE /account/request-key"]);
  assert.equal(seen[0].raw, "");
});

// ── The account's runs ──────────────────────────────────────────

test("listAccountRuns pages GET /account/runs and returns runs and total", async () => {
  const run = { id: 3, status: "ok", route_id: "r" };
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, runs: [run], total: 9, limit: 5, offset: 10 } }),
    async (c) => [await c.listAccountRuns({ limit: 5, offset: 10 }), await c.listAccountRuns()],
  );
  assert.deepEqual(requests(seen), ["GET /account/runs?limit=5&offset=10", "GET /account/runs"]);
  assert.deepEqual(result[0], { runs: [run], total: 9 });
});

test("listAccountRuns gives an empty list when the server sends none", async () => {
  const { result } = await withServer(() => ({ json: { ok: true } }), (c) => c.listAccountRuns());
  assert.deepEqual(result, { runs: [], total: 0 });
});

test("exportAccountRuns sends the period and format=json and keeps the account fields", async () => {
  const body = {
    ok: true,
    to: "2026-12-01T00:00:00Z",
    total: 1,
    returned: 1,
    truncated: false,
    by_status: { ok: 1 },
    runs: [{ run_id: 1, status: "ok" }],
    account_id: "account-7",
    account_policy_documents: [{ ...POLICY, document: "exact text" }],
    account_policy_history: [ACTIVATION],
  };
  const { seen, result } = await withServer(
    () => ({ json: body }),
    (c) => c.exportAccountRuns({ from: "2026-11-01T00:00:00Z", to: "2026-12-01T00:00:00Z", job_id: "loan-1" }),
  );
  const url = new URL(seen[0].url, "http://x");
  assert.equal(seen[0].method, "GET");
  assert.equal(url.pathname, "/account/runs/export");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    from: "2026-11-01T00:00:00Z",
    to: "2026-12-01T00:00:00Z",
    job_id: "loan-1",
    format: "json",
  });
  assert.deepEqual(result, body);
});

test("exportAccountRunsCSV returns the CSV text unparsed with its counts", async () => {
  const { seen, result } = await withServer(
    () => ({ type: "text/csv; charset=utf-8", text: CSV, headers: { "X-Verdifax-Total": "12000", "X-Verdifax-Truncated": "true" } }),
    (c) => c.exportAccountRunsCSV({ from: "2026-11-01T00:00:00Z" }),
  );
  assert.deepEqual(requests(seen), ["GET /account/runs/export?from=2026-11-01T00%3A00%3A00Z&format=csv"]);
  assert.deepEqual(result, { csv: CSV, total: 12000, truncated: true });
});

test("exportAccountRunsCSV refuses a response without its counts", async () => {
  await assert.rejects(
    withServer(
      () => ({ type: "text/csv", text: CSV, headers: { "X-Verdifax-Total": "1" } }),
      (c) => c.exportAccountRunsCSV(),
    ),
    (err) => err instanceof VerdifaxError && /may be cut off/.test(err.message),
  );
});

test("the account export is retried as a GET", async () => {
  let calls = 0;
  const { result } = await withServer(
    () => (++calls === 1 ? { status: 503, json: {} } : { json: { ok: true, account_id: "account-7", runs: [] } }),
    (c) => c.exportAccountRuns(),
  );
  assert.equal(calls, 2);
  assert.equal(result.account_id, "account-7");
});

// ── The account's policy ────────────────────────────────────────

test("uploadAccountPolicy sends the exact text to /account/policies", async () => {
  const document = '{ "policy_id":"acme-all",  "note": "café" }\n';
  const { seen, result } = await withServer(() => ({ status: 201, json: POLICY }), (c) => c.uploadAccountPolicy(document));
  assert.deepEqual(requests(seen), ["POST /account/policies"]);
  assert.equal(seen[0].raw, JSON.stringify({ document }));
  assert.deepEqual(result, POLICY);
});

test("uploadAccountPolicy refuses anything that is not a string", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const document of [{ policy_id: "x" }, 5, null, undefined]) {
      await assert.rejects(c.uploadAccountPolicy(document), (err) => err instanceof VerdifaxError && /string/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

test("listAccountPolicies, getAccountPolicy and getAccountPolicyHistory read the account routes", async () => {
  const stored = { ...POLICY, document: "exact text\n" };
  const history = [{ ...ACTIVATION, sequence: 1, previous_activation_hash: ZEROS, activation_hash: NEWEST }, ACTIVATION];
  const { seen, result } = await withServer(
    (req) =>
      req.url === "/account/policies"
        ? { json: LIST }
        : req.url === "/account/policies/history"
          ? { json: history }
          : { json: stored },
    async (c) => [await c.listAccountPolicies(), await c.getAccountPolicy(DOC_HASH), await c.getAccountPolicyHistory()],
  );
  assert.deepEqual(requests(seen), [
    "GET /account/policies",
    `GET /account/policies/${DOC_HASH}`,
    "GET /account/policies/history",
  ]);
  assert.deepEqual(result, [LIST, stored, history]);
});

test("testAccountPolicy sends inputs with a document or a document hash", async () => {
  const answer = { ok: true, sealed: false, outcome: "allow", fired_rule_id: "default", reason_code: "" };
  const inputs = { subject_type: "agent", verb: "approve" };
  const { seen, result } = await withServer(
    () => ({ json: answer }),
    async (c) => [
      await c.testAccountPolicy({ inputs, document: "exact text" }),
      await c.testAccountPolicy({ inputs, documentHash: DOC_HASH }),
    ],
  );
  assert.deepEqual(requests(seen), ["POST /account/policies/test", "POST /account/policies/test"]);
  assert.deepEqual(seen[0].body, { inputs, document: "exact text" });
  assert.deepEqual(seen[1].body, { inputs, document_hash: DOC_HASH });
  assert.deepEqual(result, [answer, answer]);
});

test("testAccountPolicy refuses both or neither of document and documentHash, naming itself", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    const exactlyOne = (err) => err instanceof VerdifaxError && /testAccountPolicy needs exactly one/.test(err.message);
    await assert.rejects(c.testAccountPolicy({ inputs: {} }), exactlyOne);
    await assert.rejects(c.testAccountPolicy({ inputs: {}, document: "x", documentHash: DOC_HASH }), exactlyOne);
    await assert.rejects(c.testAccountPolicy({ document: "x" }), /testAccountPolicy needs inputs/);
  });
  assert.equal(seen.length, 0);
});

test("getAccountPolicy and activateAccountPolicy refuse a hash that is not 64 lowercase hex", async () => {
  const { seen } = await withServer(
    undefined,
    async (c) => {
      for (const hash of ["", "c".repeat(63), "C".repeat(64), "../history", undefined]) {
        await assert.rejects(c.getAccountPolicy(hash), VerdifaxError);
        await assert.rejects(c.activateAccountPolicy(hash), VerdifaxError);
      }
    },
    { signingKey: SEED },
  );
  assert.equal(seen.length, 0);
});

test("activateAccountPolicy reads the account chain, then signs the change over account-N", async () => {
  const { seen, result } = await withServer(accountPolicyServer(), (c) => c.activateAccountPolicy(DOC_HASH), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account/policies", `POST /account/policies/${DOC_HASH}/activate`]);
  const body = seen[1].body;
  assert.deepEqual(Object.keys(body).sort(), ["previous_activation_hash", "signature"]);
  assert.equal(body.previous_activation_hash, NEWEST);
  assert.deepEqual(Object.keys(body.signature).sort(), ["nonce", "signature", "signed_at"]);
  assert.match(body.signature.signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(body.signature.nonce, /^[0-9a-f]{32}$/);
  const fields = { chain_id: "account-7", document_hash: DOC_HASH, previous_activation_hash: NEWEST };
  assert.ok(activationVerifies(body.signature, fields));
  // Bound to the account chain: it does not verify over a key's chain.
  assert.ok(!activationVerifies(body.signature, { ...fields, chain_id: "api-key-7" }));
  assert.ok(!activationVerifies(body.signature, { ...fields, chain_id: "account-8" }));
  assert.ok(!activationVerifies(body.signature, { ...fields, document_hash: POLICY_HASH }));
  assert.ok(!activationVerifies(body.signature, { ...fields, previous_activation_hash: ZEROS }));
  assert.deepEqual(result, ACTIVATION);
});

test("activateAccountPolicy on a first change names 64 zeros", async () => {
  const { seen } = await withServer(
    accountPolicyServer({ ...LIST, newest_activation_hash: ZEROS }),
    (c) => c.activateAccountPolicy(DOC_HASH),
    { signingKey: SEED },
  );
  assert.equal(seen[1].body.previous_activation_hash, ZEROS);
  assert.ok(activationVerifies(seen[1].body.signature, { chain_id: "account-7", document_hash: DOC_HASH, previous_activation_hash: ZEROS }));
});

test("activateAccountPolicy without a signing key refuses before any request", async () => {
  const { seen, result } = await withServer(accountPolicyServer(), (c) => c.activateAccountPolicy(DOC_HASH).catch((err) => err));
  assert.ok(result instanceof VerdifaxError);
  assert.match(result.message, /activateAccountPolicy needs the owner key's request key in the signingKey client option/);
  assert.equal(seen.length, 0);
});

test("activateAccountPolicy refuses a chain that is not an account chain before posting", async () => {
  for (const chain_id of [undefined, "", "api-key-7", "account-", "account-0", "account-7x", " account-7"]) {
    const { seen, result } = await withServer(
      accountPolicyServer({ ...LIST, chain_id }),
      (c) => c.activateAccountPolicy(DOC_HASH).catch((err) => err),
      { signingKey: SEED },
    );
    assert.ok(result instanceof VerdifaxError, String(chain_id));
    assert.match(result.message, /account chain_id/);
    assert.deepEqual(requests(seen), ["GET /account/policies"]);
  }
});

test("a refused account change throws APIError with the server's message and is not retried", async () => {
  for (const status of [403, 409]) {
    const { seen, result } = await withServer(
      accountPolicyServer(LIST, { status, json: { ok: false, error: "refused" } }),
      (c) => c.activateAccountPolicy(DOC_HASH).catch((err) => err),
      { signingKey: SEED, maxRetries: 3 },
    );
    assert.ok(result instanceof APIError);
    assert.equal(result.status, status);
    assert.equal(result.path, `/account/policies/${DOC_HASH}/activate`);
    assert.equal(result.message, "refused");
    assert.equal(seen.length, 2);
  }
});

test("activatePolicy still acts on the key's own chain", async () => {
  const keyList = { ...LIST, chain_id: "api-key-7" };
  const { seen } = await withServer(
    (req) => (req.method === "GET" ? { json: keyList } : { json: { ok: true, activation: ACTIVATION } }),
    (c) => c.activatePolicy(DOC_HASH),
    { signingKey: SEED },
  );
  assert.deepEqual(requests(seen), ["GET /policies", `POST /policies/${DOC_HASH}/activate`]);
  assert.ok(activationVerifies(seen[1].body.signature, { chain_id: "api-key-7", document_hash: DOC_HASH, previous_activation_hash: NEWEST }));
});

// ── Admin: accounts ─────────────────────────────────────────────

test("adminCreateAccount posts the name, and tier and expires_at when given", async () => {
  const body = { ok: true, account: ACCOUNT, owner_key: { ...CREATED_KEY, id: 11, owner: true } };
  const { seen, result } = await withServer(
    () => ({ status: 201, json: body }),
    async (c) => [
      await c.adminCreateAccount("Acme"),
      await c.adminCreateAccount("Beta", { tier: "production", expiresAt: "2027-01-01" }),
    ],
  );
  assert.deepEqual(requests(seen), ["POST /admin/accounts", "POST /admin/accounts"]);
  assert.deepEqual(seen[0].body, { name: "Acme" });
  assert.deepEqual(seen[1].body, { name: "Beta", tier: "production", expires_at: "2027-01-01" });
  assert.deepEqual(result[0], body);
  assert.equal(result[0].owner_key.secret, "vfx_secret");
});

test("adminCreateAccount refuses a missing name before sending", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const name of ["", " ", undefined]) {
      await assert.rejects(c.adminCreateAccount(name), /name is required for adminCreateAccount/);
    }
  });
  assert.equal(seen.length, 0);
});

test("adminListAccounts returns the accounts", async () => {
  const { seen, result } = await withServer(() => ({ json: { ok: true, accounts: [ACCOUNT] } }), (c) => c.adminListAccounts());
  assert.deepEqual(requests(seen), ["GET /admin/accounts"]);
  assert.deepEqual(result, [ACCOUNT]);
  const empty = await withServer(() => ({ json: { ok: true } }), (c) => c.adminListAccounts());
  assert.deepEqual(empty.result, []);
});

test("adminCreateKey sends account_id only when accountId is given", async () => {
  const body = { ok: true, id: 12, name: "customer:loan-bot", secret: "s", hint: "h", account_id: "account-7" };
  const { seen, result } = await withServer(
    () => ({ status: 201, json: body }),
    async (c) => [await c.adminCreateKey("loan-bot"), await c.adminCreateKey("loan-bot", { accountId: 7 })],
  );
  assert.deepEqual(requests(seen), ["POST /admin/keys", "POST /admin/keys"]);
  assert.deepEqual(seen[0].body, { name: "loan-bot" });
  assert.deepEqual(seen[1].body, { name: "loan-bot", account_id: 7 });
  assert.equal(result[1].account_id, "account-7");
});

test("adminCreateKey refuses an accountId that is not a whole number above zero", async () => {
  const { seen } = await withServer(undefined, async (c) => {
    for (const accountId of [0, -3, 2.5, "7", "account-7", null, NaN]) {
      await assert.rejects(c.adminCreateKey("k", { accountId }), (err) => err instanceof VerdifaxError && /accountId/.test(err.message));
    }
  });
  assert.equal(seen.length, 0);
});

test("every account method needs an API key", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9", signingKey: SEED });
  for (const call of [
    () => c.getAccount(),
    () => c.createAccountKey("k"),
    () => c.listAccountKeys(),
    () => c.revokeAccountKey(1),
    () => c.registerAccountRequestKey(),
    () => c.clearAccountRequestKey(),
    () => c.listAccountRuns(),
    () => c.exportAccountRuns(),
    () => c.exportAccountRunsCSV(),
    () => c.uploadAccountPolicy("x"),
    () => c.listAccountPolicies(),
    () => c.getAccountPolicy(DOC_HASH),
    () => c.testAccountPolicy({ inputs: {}, document: "x" }),
    () => c.getAccountPolicyHistory(),
    () => c.activateAccountPolicy(DOC_HASH),
    () => c.adminCreateAccount("Acme"),
    () => c.adminListAccounts(),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
});
