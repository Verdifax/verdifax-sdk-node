// Every remaining route, the execute body fields, and the local helpers.
// The mock server listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import {
  APIError,
  APIKeyRequiredError,
  NotFoundError,
  CRES_ENGINE_VERSION,
  RUN_STATUSES,
  VerdifaxClient,
  VerdifaxError,
  captureEnvironment,
  cresReceiptHash,
  fromEnv,
  dcaeClosureHash,
  dseDispatchHash,
  formatProviderPayload,
} from "../dist/index.mjs";

// The vector shared by the four SDKs, so they cannot disagree.
const VECTOR_PROMPT = "Say \"hi\" to <b>&\n";
const VECTOR_RESPONSE = "caf\u00e9\t\\ / \u2028 \u0001 \u{1F600}";
const VECTOR_PAYLOAD = "{\"prompt\":\"Say \\\"hi\\\" to <b>&\\n\",\"provider\":\"anthropic\",\"response\":\"caf\u00e9\\t\\\\ / \u2028 \\u0001 \u{1F600}\"}";
const VECTOR_SHA256 = "3adc179eb067ac68d290b78eaf48442bab6f580fbf4198ce7a7a56cc9c632425";

const ROW = { payload_text: "hello", program_id: "1".repeat(64), route_id: "r", registry_record_hash: "2".repeat(64) };
const CONTEXT = { runtime_name: "node", runtime_version: "22.0.0", pinned_dependencies: ["a==1"], random_seeds: ["rng=1"] };

async function withServer(respond, run, config = { apiKey: "k" }) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : undefined });
      const { status = 200, text = "{\"ok\":true}" } = respond(req) ?? {};
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(text);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, retryBaseDelayMs: 1, ...config });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const ROUTES = [
  ["getOpenAPI", [], "/openapi.json"],
  ["getStats", [], "/stats"],
  ["listAttestations", [{ limit: 5, offset: 10 }], "/attestations?limit=5&offset=10"],
  ["listAttestations", [], "/attestations"],
  ["getAttestation", [7], "/attestations/7"],
  ["getAllowToken", [7], "/runs/7/allow-token"],
  ["getDenyReceipt", [7], "/runs/7/deny-receipt"],
  ["getCCVHaltReceipt", [7], "/runs/7/ccv-halt-receipt"],
  ["getMACCHaltReceipt", [7], "/runs/7/macc-halt-receipt"],
  ["getAivpT4HaltReceipt", [7], "/runs/7/aivp-t4-halt-receipt"],
  ["getAttestationGapReceipt", [7], "/runs/7/attestation-gap-receipt"],
  ["getCESAuditRecord", [7], "/runs/7/ces-audit-record"],
  ["getRunReport", [7], "/runs/7/report"],
  ["getRunArtifacts", [7], "/runs/7/artifacts"],
  ["getPublicBundle", [7], "/runs/7/bundle.json"],
  ["getPublicBundleByToken", ["a b/c"], "/public/runs/a%20b%2Fc/bundle.json"],
];

for (const [method, args, url] of ROUTES) {
  test(`${method} calls GET ${url}`, async () => {
    const { seen } = await withServer(
      () => ({ text: "{\"ok\":true,\"report\":{}}" }),
      (c) => c[method](...args),
    );
    assert.equal(seen[0].method, "GET");
    assert.equal(seen[0].url, url);
    assert.equal(seen[0].headers["x-verdifax-key"], "k");
  });
}

test("getRunReport returns the report", async () => {
  const { result } = await withServer(
    () => ({ text: "{\"ok\":true,\"report\":{\"run_id\":7}}" }),
    (c) => c.getRunReport(7),
  );
  assert.deepEqual(result, { run_id: 7 });
});

test("bundle methods return the exact text, so a large number survives", async () => {
  const text = "{\"input_nonce\": 1780000000123456789 ,\n \"hash\":\"a\"}";
  for (const call of [
    (c) => c.getRunArtifacts(7),
    (c) => c.getPublicBundle(7),
    (c) => c.getPublicBundleByToken("t"),
  ]) {
    const { result } = await withServer(() => ({ text }), call);
    assert.equal(result, text);
  }
});

test("public bundle routes and the API description need no key", async () => {
  const { seen } = await withServer(
    () => ({ text: "{}" }),
    async (c) => {
      await c.getPublicBundle(7);
      await c.getPublicBundleByToken("t");
      await c.getOpenAPI();
    },
    {},
  );
  assert.equal(seen.length, 3);
  for (const request of seen) assert.equal(request.headers["x-verdifax-key"], undefined);
});

test("authenticated routes need a key before any request", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  for (const call of [
    () => c.getStats(),
    () => c.listAttestations(),
    () => c.getAttestation(1),
    () => c.getRunArtifacts(1),
    () => c.getRunReport(1),
    () => c.getAttestationGapReceipt(1),
    () => c.getCESAuditRecord(1),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
});

test("a bad id or token is refused without a request", async () => {
  const { seen } = await withServer(
    () => ({}),
    async (c) => {
      await assert.rejects(c.getAttestation(0), VerdifaxError);
      await assert.rejects(c.getRunArtifacts(-1), VerdifaxError);
      await assert.rejects(c.getPublicBundle(0), VerdifaxError);
      await assert.rejects(c.getPublicBundleByToken(""), /token is required/);
    },
  );
  assert.equal(seen.length, 0);
});

test("new routes report the server's errors", async () => {
  await assert.rejects(
    withServer(
      () => ({ status: 404, text: "{\"error\":\"run not found\"}" }),
      (c) => c.getPublicBundleByToken("t"),
    ),
    NotFoundError,
  );
  await assert.rejects(
    withServer(
      () => ({ status: 503, text: "{\"error\":\"unsupported\"}" }),
      (c) => c.getAttestation(1),
      { apiKey: "k", maxRetries: 0 },
    ),
    (err) => err instanceof APIError && err.status === 503,
  );
});

test("reproducibility_context reaches execute, attest, batch and the determinism check", async () => {
  const { seen } = await withServer(
    () => ({ text: "{\"ok\":true}" }),
    async (c) => {
      await c.execute({ ...ROW, reproducibility_context: CONTEXT });
      await c.attest({ ...ROW, reproducibility_context: CONTEXT });
      await c.verifyDeterminism({ ...ROW, reproducibility_context: CONTEXT });
      await c.executeBatch([{ ...ROW, reproducibility_context: CONTEXT }]);
    },
  );
  assert.deepEqual(seen[0].body.reproducibility_context, { ...CONTEXT, declared: true });
  assert.deepEqual(seen[1].body.reproducibility_context, { ...CONTEXT, declared: true });
  assert.deepEqual(seen[2].body.reproducibility_context, { ...CONTEXT, declared: true });
  assert.deepEqual(seen[3].body.runs[0].reproducibility_context, { ...CONTEXT, declared: true });
});

test("execute sends no reproducibility_context when none is given", async () => {
  const { seen } = await withServer(
    () => ({}),
    (c) => c.execute(ROW),
  );
  assert.deepEqual(seen[0].body, ROW);
});

test("formatProviderPayload is the payload the helpers attest", async () => {
  const { seen } = await withServer(
    () => ({}),
    (c) => c.attestClaudeResponse({ ...ROW, prompt: "p", response: "r" }),
  );
  assert.equal(seen[0].body.payload_text, formatProviderPayload("anthropic", "p", "r"));
});

test("shared provider payload vector", () => {
  const payload = formatProviderPayload("anthropic", VECTOR_PROMPT, VECTOR_RESPONSE);
  assert.equal(payload, VECTOR_PAYLOAD);
  assert.equal(crypto.createHash("sha256").update(payload, "utf8").digest("hex"), VECTOR_SHA256);
  const plain = formatProviderPayload("openai", "p", "r");
  assert.equal(plain, "{\"prompt\":\"p\",\"provider\":\"openai\",\"response\":\"r\"}");
  assert.equal(
    crypto.createHash("sha256").update(plain, "utf8").digest("hex"),
    "f642f9972df7037832635f8bcf43675d1d1da9fb6e1af2667e53ca38717ce301",
  );
});

test("formatProviderPayload refuses text with no UTF-8 form", () => {
  assert.throws(() => formatProviderPayload("openai", "\ud800", "r"), VerdifaxError);
});

test("provider helpers send AI output for review only with govern", async () => {
  const { seen } = await withServer(
    () => ({}),
    async (c) => {
      await c.attestClaudeResponse({ ...ROW, prompt: "p", response: "r" });
      await c.attestOpenAIResponse({ ...ROW, prompt: "p", response: "r" });
      await c.attestClaudeResponse({ ...ROW, prompt: "p", response: "r", govern: true });
      await c.attestOpenAIResponse({ ...ROW, prompt: "p", response: "r", govern: true });
    },
  );
  assert.equal("ai_output_text" in seen[0].body, false);
  assert.equal("ai_output_text" in seen[1].body, false);
  assert.equal(seen[2].body.ai_output_text, "r");
  assert.equal(seen[3].body.ai_output_text, "r");
  assert.deepEqual(seen[0].body.attested_context, { actor_role: "ai_assistant", model_provider: "anthropic", attested: true });
});

test("the four execute blocks reach every path", async () => {
  const blocks = {
    request_substance: { prompt: { template_id: "t" }, origin: { client_app: "app" } },
    authorization_chain: { approvers: [{ actor_id: "a" }] },
    regulatory_scaffolding: { right_to_explanation: "yes" },
    causal_graph: { parent_run_id: 3 },
  };
  const { seen } = await withServer(
    () => ({ text: "{\"ok\":true}" }),
    async (c) => {
      await c.execute({ ...ROW, ...blocks });
      await c.attest({ ...ROW, ...blocks });
      await c.verifyDeterminism({ ...ROW, ...blocks });
      await c.executeBatch([{ ...ROW, ...blocks }]);
    },
  );
  for (const body of [seen[0].body, seen[1].body, seen[2].body, seen[3].body.runs[0]]) {
    for (const [name, value] of Object.entries(blocks)) assert.deepEqual(body[name], value);
  }
});

test("refuseCallerOriginHashes: origin hashes the server computes are refused without a request", async () => {
  const bad = { ...ROW, request_substance: { origin: { source_ip_hash: "x" } } };
  const worse = { ...ROW, request_substance: { origin: { user_agent_hash: "x" } } };
  const { seen } = await withServer(
    () => ({}),
    async (c) => {
      await assert.rejects(c.execute(bad), /computed by the server/);
      await assert.rejects(c.attest(worse), /computed by the server/);
      await assert.rejects(c.verifyDeterminism(bad), /computed by the server/);
    },
  );
  assert.equal(seen.length, 0);
});

test("withExecuteFlags, withAttestedFlag, withDeclaredFlag: attested and declared are derived on every path, on a copy", async () => {
  const req = {
    ...ROW,
    attested_context: { attested: false, actor_role: "reviewer" },
    reproducibility_context: { declared: false, runtime_name: "node" },
  };
  const original = JSON.stringify(req);
  const { seen } = await withServer(
    () => ({ text: "{\"ok\":true}" }),
    async (c) => {
      await c.execute(req);
      await c.verifyDeterminism(req);
      await c.executeBatch([req]);
      await c.execute({ ...ROW, attested_context: { attested: true, decision_note: "" }, reproducibility_context: { declared: true, random_seeds: [] } });
    },
  );
  for (const body of [seen[0].body, seen[1].body, seen[2].body.runs[0]]) {
    assert.equal(body.attested_context.attested, true);
    assert.equal(body.reproducibility_context.declared, true);
  }
  assert.equal(seen[3].body.attested_context.attested, false);
  assert.equal(seen[3].body.reproducibility_context.declared, false);
  assert.equal(JSON.stringify(req), original);
});

test("execute and the determinism check apply the strict validators", async () => {
  const { seen } = await withServer(
    () => ({}),
    async (c) => {
      await assert.rejects(c.execute({ ...ROW, program_id: "A".repeat(64) }), /lowercase hex/);
      await assert.rejects(c.execute({ ...ROW, route_id: "caf\u00e9" }), /non-printable/);
      await assert.rejects(c.verifyDeterminism({ ...ROW, registry_record_hash: "short" }), /64 hex/);
    },
  );
  assert.equal(seen.length, 0);
});

test("fromEnv reads VERDIFAX_BASE_URL first and VERDIFAX_API_URL as a fallback", async () => {
  const names = ["VERDIFAX_BASE_URL", "VERDIFAX_API_URL", "VERDIFAX_USER_AGENT", "VERDIFAX_MAX_RETRIES", "VERDIFAX_TIMEOUT_MS"];
  const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    process.env.VERDIFAX_API_URL = "http://fallback.invalid/";
    assert.equal(fromEnv().baseURL, "http://fallback.invalid");
    process.env.VERDIFAX_BASE_URL = "http://first.invalid";
    process.env.VERDIFAX_USER_AGENT = "agent/1";
    process.env.VERDIFAX_MAX_RETRIES = "0";
    process.env.VERDIFAX_TIMEOUT_MS = "5000";
    const client = fromEnv();
    assert.equal(client.baseURL, "http://first.invalid");
    assert.equal(client.userAgent, "agent/1");
    assert.equal(client.maxRetries, 0);
    assert.equal(client.timeoutMs, 5000);
  } finally {
    for (const name of names) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  }
});

test("RUN_STATUSES is the set the server uses", () => {
  assert.deepEqual([...RUN_STATUSES].sort(), [
    "aivp_t4_halt",
    "attestation_gap",
    "ccv_halt",
    "macc_halt",
    "ok",
    "pepg_deny",
    "probe",
    "stage_error",
  ]);
});

test("captureEnvironment records the runtime and the declared seeds", () => {
  const ctx = captureEnvironment({
    declaredSeeds: { torch: 1337, numpy: 42 },
    includeDependencies: false,
    includeGit: false,
    includeContainer: false,
  });
  assert.equal(ctx.declared, true);
  assert.equal(ctx.runtime_name, "node");
  assert.equal(ctx.runtime_version, process.versions.node);
  assert.match(ctx.platform, /^[a-z0-9]+\/[a-z0-9]+$/);
  assert.deepEqual(ctx.random_seeds, ["numpy=42", "torch=1337"]);
  assert.equal(ctx.pinned_dependencies, undefined);
  assert.equal(ctx.git_commit_sha, undefined);
  assert.equal(ctx.container_image_hash, undefined);
});

test("captureEnvironment reads this project's dependencies and commit", () => {
  const ctx = captureEnvironment();
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  const pin = `typescript==${lock.packages["node_modules/typescript"].version}`;
  assert.ok(ctx.pinned_dependencies.includes(pin));
  assert.match(ctx.git_commit_sha, /^[0-9a-f]{40}$/);
});

test("section0 hashes match the vectors the Go and Python code share", () => {
  assert.equal(
    dseDispatchHash({
      envelope_id: "env-fixture-v1-aaaaaaaaaaaaaaaa",
      sequence_id: "seq-fixture-v1-1",
      program_id: "1".repeat(64),
      registry_record_hash: "2".repeat(64),
    }),
    "e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b",
  );
  assert.equal(
    dcaeClosureHash({
      manifest_hash: "3".repeat(64),
      aer_hash: "4".repeat(64),
      envelope_id: "env-fixture-dcae-v1",
      zksp_binding_hash: "5".repeat(64),
      formal_verifier_status: "VERIFIED_SOUND_COMPLETE_ZK",
    }),
    "e34cee0fcc6ebf9eafc3ef5479fd0fffd5a4de5c60039ba42b009f0c05b8fc93",
  );
  const receipt = {
    envelope_id: "env-fixture-cres-v1",
    field_path: "request.payload.customer_email",
    deletion_clock: "2026-05-07T00:00:00.000000000Z",
    actor_id: "ops-fixture",
    ciphertext_hash_at_shred: "6".repeat(64),
    dsar_reference: "DSAR-FIXTURE-001",
  };
  const expected = "1bb128c1f86cc6c7d63d44cc49bbdfc1185c8105d5bc270838af63814901bee5";
  assert.equal(cresReceiptHash(receipt), expected);
  assert.equal(cresReceiptHash({ ...receipt, engine_version: CRES_ENGINE_VERSION }), expected);
  assert.notEqual(cresReceiptHash({ ...receipt, engine_version: "other" }), expected);
});

test("section0 refuses a value that is not 64 lowercase hex", () => {
  assert.throws(
    () => dseDispatchHash({ envelope_id: "e", sequence_id: "s", program_id: "A".repeat(64), registry_record_hash: "2".repeat(64) }),
    /section0/,
  );
  assert.throws(
    () => dcaeClosureHash({ manifest_hash: "short", aer_hash: "4".repeat(64), envelope_id: "e", zksp_binding_hash: "5".repeat(64), formal_verifier_status: "s" }),
    /section0/,
  );
  assert.throws(
    () => cresReceiptHash({ envelope_id: "e", field_path: "f", deletion_clock: "c", actor_id: "a", ciphertext_hash_at_shred: "x", dsar_reference: "d" }),
    VerdifaxError,
  );
});
