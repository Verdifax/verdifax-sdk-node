// SDK 1.1.0: request signature version 2, the job block and helper, key
// changes and the export filter. The mock server listens on localhost
// only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";

import {
  APIError,
  APIKeyRequiredError,
  VerdifaxClient,
  VerdifaxError,
  VerdifaxJob,
  generateRequestKeyPair,
  requestKeyChangeApproval,
  requestKeyChangePreimage,
  requestKeyRegistrationBody,
  requestSignaturePreimageV2,
  signRequest,
  signRequestV2,
  validateJobName,
} from "../dist/index.mjs";
import { publicKeyObject, sha256, signedFields, verifiesV2 } from "./signed-body.mjs";

// The byte authority, copied unchanged from scripts/sdk-signature-vector.json.
const VECTOR = JSON.parse(readFileSync(new URL("./sdk-signature-vector.json", import.meta.url), "utf8"));
const VECTOR_REQUEST = JSON.parse(VECTOR.signed_request);
const VECTOR_FIELDS = {
  payload_hash: VECTOR.payload_hash,
  program_id: VECTOR_REQUEST.program_id,
  route_id: VECTOR_REQUEST.route_id,
  registry_record_hash: VECTOR_REQUEST.registry_record_hash,
  signed_at: VECTOR.signed_at,
  nonce: VECTOR.nonce,
};
// no_job_preimage_hex hashes this literal text as its body, with the payload
// hello and no AI output (spec section 1).
const NO_JOB_BODY = "{\"payload_text\":\"hello\"}";

const SEED = Buffer.from(VECTOR.seed_hex, "hex");
const PUBLIC_KEY = Buffer.from(VECTOR.public_key, "base64");
const ROW = { payload_text: "hello", program_id: "1".repeat(64), route_id: "r", registry_record_hash: "2".repeat(64) };
const H1 = "a".repeat(64);
const H2 = "b".repeat(64);
const H3 = "c".repeat(64);
const H4 = "d".repeat(64);
const H5 = "e".repeat(64);
const BAD_NAMES = ["", "a".repeat(129), "a b", "a/b", "caf\u00e9", "a\n", "\na", undefined, null, 5, {}];

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
      seen.push({ method: req.method, url: req.url, raw, headers: req.headers, body });
      const { status = 200, json = { ok: true, run_id: seen.length }, hang = false } = answer?.(req, body, seen.length - 1) ?? {};
      if (hang) return; // Never answers. closeAllConnections ends it.
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

/** A server that gives each run the next hash in `hashes`. */
function sealing(hashes) {
  return (_req, _body, index) => ({ json: { ok: true, run_id: index + 1, record_hash: hashes[index] } });
}

function refused(recordHash, error = "policy denied") {
  return { status: 422, json: { ok: false, run_id: 9, error, error_stage: "PEPG", record_hash: recordHash } };
}

// ── The vector, byte for byte ───────────────────────────────────

test("vector: body_hash, payload_hash and ai_output_hash", () => {
  assert.equal(sha256(VECTOR.signed_request), VECTOR.body_hash);
  assert.equal(sha256(VECTOR_REQUEST.payload_text), VECTOR.payload_hash);
  assert.equal(sha256(VECTOR_REQUEST.ai_output_text), VECTOR.ai_output_hash);
});

test("vector: requestSignaturePreimageV2 with a job", () => {
  const preimage = requestSignaturePreimageV2({
    ...VECTOR_FIELDS,
    body_hash: VECTOR.body_hash,
    ai_output_hash: VECTOR.ai_output_hash,
    job: VECTOR_REQUEST.job,
  });
  assert.equal(preimage.toString("hex"), VECTOR.preimage_hex);
});

test("vector: requestSignaturePreimageV2 with no job", () => {
  const preimage = requestSignaturePreimageV2({
    ...VECTOR_FIELDS,
    body_hash: sha256(NO_JOB_BODY),
    ai_output_hash: "",
  });
  assert.equal(preimage.toString("hex"), VECTOR.no_job_preimage_hex);
});

test("vector: signRequestV2 reproduces the signed text and the signature", () => {
  const body = signRequestV2(SEED, VECTOR_REQUEST, { signedAt: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.deepEqual(body, {
    signed_request: VECTOR.signed_request,
    request_signature: { version: "2", signature: VECTOR.signature, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce },
  });
  assert.ok(verifiesV2(body, PUBLIC_KEY));
});

test("vector: the public key comes from the seed", () => {
  assert.equal(requestKeyRegistrationBody(SEED).public_key, VECTOR.public_key);
});

test("vector: requestKeyChangePreimage", () => {
  const preimage = requestKeyChangePreimage({ new_public_key: VECTOR.public_key, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.equal(preimage.toString("hex"), VECTOR.key_change_preimage_hex);
});

test("vector: requestKeyChangeApproval", () => {
  const change = requestKeyChangeApproval(SEED, VECTOR.public_key, { signedAt: VECTOR.signed_at, nonce: VECTOR.nonce });
  assert.deepEqual(change, { signature: VECTOR.key_change_signature, signed_at: VECTOR.signed_at, nonce: VECTOR.nonce });
});

// ── What a signed call sends ────────────────────────────────────

test("a signed execute sends signed_request and request_signature and nothing else", async () => {
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, run_id: 7, record_hash: H1 } }),
    (c) => c.execute({ ...ROW, ai_output_text: "the answer", attested_context: { actor_role: "x" } }),
    { signingKey: SEED },
  );
  const { body } = seen[0];
  assert.deepEqual(Object.keys(body).sort(), ["request_signature", "signed_request"]);
  assert.deepEqual(Object.keys(body.request_signature).sort(), ["nonce", "signature", "signed_at", "version"]);
  assert.equal(body.request_signature.version, "2");
  assert.match(body.request_signature.signed_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.match(body.request_signature.nonce, /^[0-9a-f]{32}$/);
  assert.ok(verifiesV2(body, PUBLIC_KEY));
  assert.deepEqual(JSON.parse(body.signed_request), {
    ...ROW,
    ai_output_text: "the answer",
    attested_context: { actor_role: "x", attested: true },
  });
  assert.equal(result.signed_request, body.signed_request);
  assert.equal(result.record_hash, H1);
});

test("the signed text survives the trip byte for byte, non-ASCII text included", async () => {
  const text = "caf\u00e9 \"quoted\" \\ \u4e16\u754c \u{1f600}\n";
  const { seen, result } = await withServer(null, (c) => c.execute({ ...ROW, payload_text: text, ai_output_text: text }), { signingKey: SEED });
  const { body } = seen[0];
  assert.ok(verifiesV2(body, PUBLIC_KEY));
  assert.equal(signedFields(body).payload_text, text);
  assert.equal(Buffer.byteLength(result.signed_request), Buffer.byteLength(body.signed_request));
  assert.equal(sha256(result.signed_request), sha256(body.signed_request));
});

test("signRequestV2 drops a request_signature from the request, and leaves the request alone", () => {
  const req = { ...ROW, request_signature: signRequest(SEED, ROW) };
  const before = JSON.stringify(req);
  const body = signRequestV2(SEED, req);
  assert.equal("request_signature" in JSON.parse(body.signed_request), false);
  assert.equal(JSON.stringify(req), before);
  assert.ok(verifiesV2(body, PUBLIC_KEY));
});

test("the two signRequestV2 defaults are fresh on each call", () => {
  const [a, b] = [signRequestV2(SEED, ROW), signRequestV2(SEED, ROW)];
  assert.notEqual(a.request_signature.nonce, b.request_signature.nonce);
});

test("no ai_output_text signs an empty hash, and so does empty text", async () => {
  const { seen } = await withServer(
    null,
    async (c) => {
      await c.execute(ROW);
      await c.execute({ ...ROW, ai_output_text: "" });
    },
    { signingKey: SEED },
  );
  for (const { body } of seen) assert.ok(verifiesV2(body, PUBLIC_KEY));
});

test("a signed determinism check sends the same shape and returns the signed text", async () => {
  const { seen, result } = await withServer(null, (c) => c.verifyDeterminism(ROW), { signingKey: SEED });
  assert.ok(verifiesV2(seen[0].body, PUBLIC_KEY));
  assert.equal(result.signed_request, seen[0].body.signed_request);
});

test("a determinism check refuses a job without a request, signed or not", async () => {
  for (const config of [{}, { signingKey: SEED }]) {
    const { seen } = await withServer(
      null,
      (c) => assert.rejects(c.verifyDeterminism({ ...ROW, job: { job_id: "j", step_id: "s" } }), VerdifaxError),
      config,
    );
    assert.equal(seen.length, 0);
  }
});

test("a batch with signed rows: each row has the signed shape and gets its text back", async () => {
  const rows = [
    { ...ROW, job: { job_id: "j", step_id: "a" } },
    { ...ROW, payload_text: "other", job: { job_id: "j", step_id: "b", previous_record_hashes: [H2, H1, H2], final: true } },
  ];
  const { seen, result } = await withServer(
    () => ({
      json: {
        ok: true,
        results: [
          { index: 0, ok: true, run_id: 1, record_hash: H1, duration_ms: 1 },
          { index: 1, ok: false, run_id: 2, record_hash: H2, error: "denied", duration_ms: 1 },
        ],
      },
    }),
    (c) => c.executeBatch(rows),
    { signingKey: SEED },
  );
  assert.deepEqual(Object.keys(seen[0].body), ["runs"]);
  const sent = seen[0].body.runs;
  for (const row of sent) assert.ok(verifiesV2(row, PUBLIC_KEY));
  assert.notEqual(sent[0].request_signature.nonce, sent[1].request_signature.nonce);
  assert.deepEqual(signedFields(sent[1]).job, { job_id: "j", step_id: "b", previous_record_hashes: [H1, H2], final: true });
  assert.deepEqual(result.results.map((r) => r.signed_request), sent.map((r) => r.signed_request));
  assert.deepEqual(result.results.map((r) => r.record_hash), [H1, H2]);
});

test("a signed row without a numbered result still returns the signed text by position", async () => {
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, results: [{ index: 0, ok: true }, { index: 0, ok: false, error: "shape" }] } }),
    (c) => c.executeBatch([ROW, ROW]),
    { signingKey: SEED },
  );
  assert.equal(result.results[1].signed_request, seen[0].body.runs[1].signed_request);
});

test("an unsigned call sends plain JSON and its result has no signed_request", async () => {
  const job = { job_id: "j", step_id: "s" };
  const { seen, result } = await withServer(
    (req) => (req.url === "/execute/batch" ? { json: { ok: true, results: [{ index: 0, ok: true }] } } : undefined),
    async (c) => [await c.execute({ ...ROW, job }), await c.executeBatch([{ ...ROW, job }])],
  );
  assert.deepEqual(seen[0].body, { ...ROW, job });
  assert.deepEqual(seen[1].body, { runs: [{ ...ROW, job }] });
  assert.equal("signed_request" in result[0], false);
  assert.equal("signed_request" in result[1].results[0], false);
});

// ── The job block ───────────────────────────────────────────────

test("the job block is sorted, without repeats, and leaves out empty lists and a false final", async () => {
  const job = { job_id: "j", step_id: "s", previous_record_hashes: [H2, H1, H2], external_previous: [H4, H3, H4], final: true };
  const original = JSON.stringify(job);
  const { seen } = await withServer(null, async (c) => {
    await c.execute({ ...ROW, job });
    await c.attest({ ...ROW, job: { job_id: "j", step_id: "t", previous_record_hashes: [], external_previous: [], final: false } });
    await c.execute({ ...ROW, job: null });
  });
  assert.deepEqual(seen[0].body.job, { job_id: "j", step_id: "s", previous_record_hashes: [H1, H2], external_previous: [H3, H4], final: true });
  assert.deepEqual(seen[1].body.job, { job_id: "j", step_id: "t" });
  assert.equal("job" in seen[2].body, false);
  assert.equal(JSON.stringify(job), original, "the caller's job changed");
});

test("a signed job signs the sorted lists", async () => {
  const { seen } = await withServer(
    null,
    (c) => c.attest({ ...ROW, job: { job_id: "j", step_id: "s", previous_record_hashes: [H2, H1], external_previous: [H4, H3], final: true } }),
    { signingKey: SEED },
  );
  const { body } = seen[0];
  assert.ok(verifiesV2(body, PUBLIC_KEY));
  assert.deepEqual(signedFields(body).job.previous_record_hashes, [H1, H2]);
  assert.deepEqual(signedFields(body).job.external_previous, [H3, H4]);
});

test("validateJobName takes every allowed character and the length limits", () => {
  for (const good of ["a", "a".repeat(128), "aZ09._:-"]) validateJobName(good, "job_id");
});

test("validateJobName refuses every other name and names the field", () => {
  for (const bad of BAD_NAMES) {
    assert.throws(() => validateJobName(bad, "step_id"), (err) => err instanceof VerdifaxError && /step_id/.test(err.message));
  }
});

test("invalid job names are refused client-side on every path", async () => {
  const { seen } = await withServer(null, async (c) => {
    for (const bad of BAD_NAMES) {
      for (const job of [{ job_id: bad, step_id: "s" }, { job_id: "j", step_id: bad }]) {
        await assert.rejects(c.execute({ ...ROW, job }), VerdifaxError);
        await assert.rejects(c.attest({ ...ROW, job }), VerdifaxError);
        await assert.rejects(c.executeBatch([ROW, { ...ROW, job }]), VerdifaxError);
      }
      assert.throws(() => c.job(bad), VerdifaxError);
      await assert.rejects(c.job("j").step(bad, ROW), VerdifaxError);
    }
  });
  assert.equal(seen.length, 0);
});

test("a malformed job block is refused client-side", async () => {
  const good = { job_id: "j", step_id: "s" };
  const { seen } = await withServer(null, async (c) => {
    for (const job of [
      "j",
      0,
      "",
      false,
      [good],
      { ...good, final: "false" },
      { ...good, final: 1 },
      { ...good, final: null },
      { ...good, previous_record_hashes: H1 },
      { ...good, previous_record_hashes: null },
      { ...good, previous_record_hashes: { 0: H1 } },
      { ...good, external_previous: [1] },
      { ...good, external_previous: H1 },
      { ...good, external_previous: null },
    ]) {
      await assert.rejects(c.execute({ ...ROW, job }), VerdifaxError);
      await assert.rejects(c.executeBatch([{ ...ROW, job }]), VerdifaxError);
    }
  });
  assert.equal(seen.length, 0);
});

test("a job block with an unknown field is refused client-side on every path, signed or not", async () => {
  for (const config of [{}, { signingKey: SEED }]) {
    const { seen } = await withServer(
      null,
      async (c) => {
        for (const extra of [{ previous_record_hash: [H1] }, { Final: true }, { constructor: 1 }, JSON.parse('{"__proto__": 1}')]) {
          const job = { job_id: "j", step_id: "s", ...extra };
          await assert.rejects(c.execute({ ...ROW, job }), /unknown field/);
          await assert.rejects(c.attest({ ...ROW, job }), /unknown field/);
          await assert.rejects(c.executeBatch([{ ...ROW, job }]), /unknown field/);
          await assert.rejects(c.attestClaudeResponse({ ...ROW, prompt: "p", response: "r", job }), /unknown field/);
        }
      },
      config,
    );
    assert.equal(seen.length, 0);
  }
});

test("a mistyped step option is refused without a request, so a typo cannot drop a link", async () => {
  const { seen } = await withServer(sealing([H1]), async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    for (const typo of [{ afer: ["a"] }, { After: ["a"] }, { external_prev: [H3] }, { Final: true }, { previous_record_hashes: [H1] }, { job: { job_id: "x", step_id: "y" } }, { constructor: 1 }]) {
      await assert.rejects(job.step("b", { ...ROW, ...typo }), /unknown field/);
    }
    assert.deepEqual(Object.keys(job.recordHashes), ["a"]);
  });
  assert.equal(seen.length, 1);
});

// ── The job helper ──────────────────────────────────────────────

test("client.job returns a VerdifaxJob with its id and an empty map, and makes no request", async () => {
  const { seen } = await withServer(null, async (c) => {
    const job = c.job("loan-1");
    assert.ok(job instanceof VerdifaxJob);
    assert.equal(job.jobId, "loan-1");
    assert.deepEqual(job.recordHashes, {});
  });
  assert.equal(seen.length, 0);
});

test("the first step follows nothing, and the next follows it by default", async () => {
  const { seen, result } = await withServer(sealing([H1, H2]), async (c) => {
    const job = c.job("j");
    const first = await job.step("first", ROW);
    await job.step("second", ROW);
    return { first, hashes: job.recordHashes };
  });
  assert.deepEqual(seen[0].body.job, { job_id: "j", step_id: "first" });
  assert.deepEqual(seen[1].body.job, { job_id: "j", step_id: "second", previous_record_hashes: [H1] });
  assert.equal(result.first.record_hash, H1);
  assert.deepEqual(result.hashes, { first: H1, second: H2 });
});

test("a branch and a join: two steps after one, then a final step with sorted hashes", async () => {
  // The later branch gets the smaller hash, so sorting has work to do.
  const { seen } = await withServer(sealing([H1, H3, H2, H4]), async (c) => {
    const job = c.job("j");
    await job.step("start", ROW);
    await job.step("left", { ...ROW, after: ["start"] });
    await job.step("right", { ...ROW, after: ["start"] });
    await job.step("join", { ...ROW, after: ["left", "right"], final: true });
  });
  assert.deepEqual(seen[1].body.job.previous_record_hashes, [H1]);
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H1]);
  assert.deepEqual(seen[3].body.job, { job_id: "j", step_id: "join", previous_record_hashes: [H2, H3], final: true });
});

test("after: [] starts another root step, and the next step follows that root", async () => {
  const { seen, result } = await withServer(sealing([H1, H2, H3]), async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    await job.step("root2", { ...ROW, after: [], external_previous: [H4, H3] });
    await job.step("c", ROW);
    return job.recordHashes;
  });
  assert.deepEqual(seen[1].body.job, { job_id: "j", step_id: "root2", external_previous: [H3, H4] });
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H2]);
  assert.deepEqual(result, { a: H1, root2: H2, c: H3 });
});

test("a step passes on everything attest takes and returns what attest returns", async () => {
  const context = { actor_role: "reviewer" };
  const { seen, result } = await withServer(
    sealing([H1]),
    (c) => c.job("j").step("s", { ...ROW, payload_text: undefined, payload: Buffer.from([1, 2]), ai_output_text: "out", attested_context: context, causal_graph: { a: 1 } }),
  );
  const { body } = seen[0];
  assert.equal(body.payload, "AQI=");
  assert.equal(body.ai_output_text, "out");
  assert.equal(body.attested_context.actor_role, "reviewer");
  assert.deepEqual(body.causal_graph, { a: 1 });
  for (const name of ["after", "final", "external_previous"]) assert.equal(name in body, false);
  assert.equal(result.record_hash, H1);
});

test("a step applies attest's checks", async () => {
  const { seen } = await withServer(null, (c) => assert.rejects(c.job("j").step("s", { ...ROW, program_id: "x" }), VerdifaxError));
  assert.equal(seen.length, 0);
});

test("a signed step signs its job and returns the signed text", async () => {
  const { seen, result } = await withServer(
    sealing([H1, H2]),
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      return job.step("b", { ...ROW, final: true });
    },
    { signingKey: SEED },
  );
  for (const { body } of seen) assert.ok(verifiesV2(body, PUBLIC_KEY));
  assert.deepEqual(signedFields(seen[1].body).job, { job_id: "j", step_id: "b", previous_record_hashes: [H1], final: true });
  assert.equal(result.signed_request, seen[1].body.signed_request);
});

test("a refused step is recorded, raises what attest raises, and later steps can follow it", async () => {
  const answer = (_req, _body, index) => [{ json: { ok: true, record_hash: H1 } }, refused(H2), { json: { ok: true, record_hash: H3 } }, { json: { ok: true, record_hash: H4 } }][index];
  const { seen, result } = await withServer(answer, async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    const error = await job.step("b", ROW).catch((err) => err);
    const hashAfterRefusal = job.recordHashes.b;
    await job.step("c", ROW);
    await job.step("d", { ...ROW, after: ["b"] });
    return { error, hashAfterRefusal };
  });
  const { error, hashAfterRefusal } = result;
  assert.ok(error instanceof APIError);
  assert.equal(error.status, 422);
  assert.equal(error.path, "/execute");
  assert.equal(error.message, "policy denied");
  assert.equal(error.recordHash, H2);
  assert.equal(hashAfterRefusal, H2);
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H2], "the default after follows the refused step");
  assert.deepEqual(seen[3].body.job.previous_record_hashes, [H2], "a later step can name the refused step");
});

test("the error a step raises is the error attest raises for the same answer", async () => {
  const { result } = await withServer(() => refused(H1), async (c) => [
    await c.attest(ROW).catch((err) => err),
    await c.job("j").step("s", ROW).catch((err) => err),
  ]);
  const [plain, stepped] = result;
  assert.equal(stepped.constructor, plain.constructor);
  for (const name of ["name", "status", "path", "message", "recordHash"]) assert.equal(stepped[name], plain[name]);
});

test("a signed refused run's error carries the signed text, kept out of everything a log prints", async () => {
  const secret = "secret payload text";
  const { seen, result } = await withServer(() => refused(H1), (c) => c.execute({ ...ROW, payload_text: secret }).catch((err) => err), { signingKey: SEED });
  assert.ok(result instanceof APIError);
  assert.equal(result.signedRequest, seen[0].body.signed_request);
  assert.ok(verifiesV2({ signed_request: result.signedRequest, request_signature: seen[0].body.request_signature }, PUBLIC_KEY));
  assert.equal(Object.keys(result).includes("signedRequest"), false);
  for (const text of [result.message, result.stack, String(result), inspect(result), JSON.stringify(result)]) {
    assert.equal(text.includes(secret), false);
  }
});

test("a halted signed determinism check carries the signed text too", async () => {
  const { seen, result } = await withServer(() => refused(H1), (c) => c.verifyDeterminism(ROW).catch((err) => err), { signingKey: SEED });
  assert.equal(result.signedRequest, seen[0].body.signed_request);
});

test("an unsigned refused run's error has no signed text, and neither does a failed batch", async () => {
  const unsigned = await withServer(() => refused(H1), (c) => c.execute(ROW).catch((err) => err));
  assert.equal(unsigned.result.signedRequest, undefined);
  const batch = await withServer(() => refused(H1), (c) => c.executeBatch([ROW, ROW]).catch((err) => err), { signingKey: SEED });
  assert.equal(batch.result.signedRequest, undefined);
});

test("signedRequests keeps each signed step's text, refused and halted steps included", async () => {
  const answer = (_req, _body, index) => [{ json: { ok: true, record_hash: H1 } }, refused(H2), { json: { ok: true, record_hash: H3 } }][index];
  const { seen, result } = await withServer(
    answer,
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      const error = await job.step("b", ROW).catch((err) => err);
      await job.step("c", { ...ROW, after: ["b"] });
      return { job, error };
    },
    { signingKey: SEED },
  );
  const { job, error } = result;
  assert.deepEqual(job.signedRequests, {
    a: seen[0].body.signed_request,
    b: seen[1].body.signed_request,
    c: seen[2].body.signed_request,
  });
  assert.equal(job.signedRequests.b, error.signedRequest);
  assert.deepEqual(Object.keys(job.signedRequests), Object.keys(job.recordHashes));
});

test("signedRequests is empty for an unsigned client and is a copy", async () => {
  await withServer(sealing([H1]), async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    assert.deepEqual(job.signedRequests, {});
  });
  await withServer(
    sealing([H1]),
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      delete job.signedRequests.a;
      assert.deepEqual(Object.keys(job.signedRequests), ["a"]);
    },
    { signingKey: SEED },
  );
});

test("signedRequests leaves out a step that left no record", async () => {
  await withServer(
    () => ({ status: 503, json: { ok: false, error: "busy" } }),
    async (c) => {
      const job = c.job("j");
      await assert.rejects(job.step("a", ROW), (err) => err instanceof APIError && typeof err.signedRequest === "string");
      assert.deepEqual(job.signedRequests, {});
    },
    { signingKey: SEED },
  );
});

test("logging a job does not print the signed text", async () => {
  const secret = "secret payload text";
  await withServer(
    sealing([H1]),
    async (c) => {
      const job = c.job("j");
      await job.step("a", { ...ROW, payload_text: secret });
      assert.equal(inspect(job, { depth: 8, showHidden: true }).includes(secret), false);
      assert.ok(job.signedRequests.a.includes(secret));
    },
    { signingKey: SEED },
  );
});

test("a step that left no record stays out of the map and can run again", async () => {
  const answer = (_req, _body, index) =>
    [
      { json: { ok: true, record_hash: H1 } },
      { status: 503, json: { ok: false, error: "busy" } },
      { json: { ok: true, record_hash: H2 } },
    ][index];
  const { seen, result } = await withServer(answer, async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    await assert.rejects(job.step("b", ROW), (err) => err instanceof APIError && err.recordHash === undefined);
    assert.deepEqual(job.recordHashes, { a: H1 });
    await job.step("b", ROW);
    return job.recordHashes;
  });
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H1]);
  assert.deepEqual(result, { a: H1, b: H2 });
});

test("a step that timed out is not recorded and does not advance the default after", async () => {
  const { seen, result } = await withServer(
    (_req, _body, index) => [{ json: { ok: true, record_hash: H1 } }, { hang: true }, { json: { ok: true, record_hash: H2 } }][index],
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      await assert.rejects(job.step("b", ROW), (err) => err instanceof VerdifaxError && !(err instanceof APIError));
      assert.deepEqual(job.recordHashes, { a: H1 });
      await job.step("b", ROW);
      return job.recordHashes;
    },
    { timeoutMs: 50 },
  );
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H1]);
  assert.deepEqual(result, { a: H1, b: H2 });
});

test("a step answered with a 409 is not recorded and does not advance the default after", async () => {
  const { seen, result } = await withServer(
    (_req, _body, index) =>
      [{ json: { ok: true, record_hash: H1 } }, { status: 409, json: { ok: false, error: "this step_id is already used in this job" } }, { json: { ok: true, record_hash: H2 } }][index],
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      await assert.rejects(job.step("b", ROW), (err) => err instanceof APIError && err.status === 409);
      await job.step("c", ROW);
      return { hashes: job.recordHashes, texts: job.signedRequests };
    },
    { signingKey: SEED },
  );
  assert.deepEqual(signedFields(seen[2].body).job.previous_record_hashes, [H1]);
  assert.deepEqual(Object.keys(result.hashes), ["a", "c"]);
  assert.deepEqual(Object.keys(result.texts), ["a", "c"]);
});

test("a step with no record_hash falls back to manifest_hash, top-level or in the manifest", async () => {
  const answers = [{ ok: true, manifest_hash: H1 }, { ok: true, manifest: { ManifestHash: H2 } }, { ok: true, record_hash: H3, manifest_hash: H4, manifest: { ManifestHash: H5 } }];
  const { seen, result } = await withServer(
    (_req, _body, index) => ({ json: answers[index] }),
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      await job.step("b", ROW);
      await job.step("c", ROW);
      return job.recordHashes;
    },
  );
  assert.deepEqual(result, { a: H1, b: H2, c: H3 });
  assert.deepEqual(seen[1].body.job.previous_record_hashes, [H1]);
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H2]);
});

test("a step with neither hash raises, stays out of the map and leaves the default after alone", async () => {
  const { seen } = await withServer(
    (_req, _body, index) => [{ json: { ok: true, record_hash: H1 } }, { json: { ok: true, run_id: 2 } }, { json: { ok: true, record_hash: H2 } }][index],
    async (c) => {
      const job = c.job("j");
      await job.step("a", ROW);
      await assert.rejects(job.step("b", ROW), (err) => err instanceof VerdifaxError && /no record_hash or manifest_hash/.test(err.message));
      assert.deepEqual(job.recordHashes, { a: H1 });
      await job.step("c", ROW);
    },
  );
  assert.deepEqual(seen[2].body.job.previous_record_hashes, [H1]);
});

test("an after naming an unknown step is refused without a request", async () => {
  const { seen } = await withServer(sealing([H1]), async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    await assert.rejects(job.step("b", { ...ROW, after: ["a", "nope"] }), (err) => err instanceof VerdifaxError && /nope/.test(err.message));
    await assert.rejects(job.step("b", { ...ROW, after: "a" }), VerdifaxError);
  });
  assert.equal(seen.length, 1);
});

test("step ids that are object member names work as plain step ids", async () => {
  const { seen, result } = await withServer(sealing([H1, H5]), async (c) => {
    const job = c.job("j");
    await assert.rejects(job.step("x", { ...ROW, after: ["constructor"] }), VerdifaxError);
    await assert.rejects(job.step("x", { ...ROW, after: ["__proto__"] }), VerdifaxError);
    await job.step("__proto__", ROW);
    await job.step("x", { ...ROW, after: ["__proto__"] });
    return job.recordHashes;
  });
  assert.deepEqual(seen[1].body.job.previous_record_hashes, [H1]);
  assert.equal(Object.keys(result).includes("__proto__"), true);
});

test("recordHashes is a copy", async () => {
  await withServer(sealing([H1]), async (c) => {
    const job = c.job("j");
    await job.step("a", ROW);
    job.recordHashes.a = "changed";
    delete job.recordHashes.a;
    assert.deepEqual(job.recordHashes, { a: H1 });
  });
});

test("a job helper prints no private key", async () => {
  const job = new VerdifaxClient({ baseURL: "http://127.0.0.1:1", signingKey: SEED }).job("j");
  const text = inspect(job, { depth: 8, showHidden: true });
  assert.equal(text.includes(SEED.toString("hex")), false);
  assert.equal(text.includes("<Buffer 00 01"), false);
});

// ── Provider helpers ────────────────────────────────────────────

for (const [name, provider] of [["attestClaudeResponse", "anthropic"], ["attestOpenAIResponse", "openai"]]) {
  const args = { ...ROW, payload_text: undefined, prompt: "p", response: "r" };

  test(`${name} accepts a job and returns record_hash, unsigned`, async () => {
    const job = { job_id: "j", step_id: "s", previous_record_hashes: [H2, H1, H2], final: false };
    const { seen, result } = await withServer(sealing([H3]), (c) => c[name]({ ...args, job }));
    assert.deepEqual(seen[0].body.job, { job_id: "j", step_id: "s", previous_record_hashes: [H1, H2] });
    assert.equal(seen[0].body.attested_context.model_provider, provider);
    assert.equal(result.record_hash, H3);
    assert.equal("signed_request" in result, false);
  });

  test(`${name} signs its job and returns record_hash and signed_request`, async () => {
    const job = { job_id: "j", step_id: "s", final: true };
    const { seen, result } = await withServer(sealing([H3]), (c) => c[name]({ ...args, job }), { signingKey: SEED });
    assert.ok(verifiesV2(seen[0].body, PUBLIC_KEY));
    assert.deepEqual(signedFields(seen[0].body).job, job);
    assert.equal(result.record_hash, H3);
    assert.equal(result.signed_request, seen[0].body.signed_request);
  });

  test(`${name} with no job sends none, and a refusal raises what attest raises`, async () => {
    const { seen, result } = await withServer(() => refused(H1), (c) => c[name](args).catch((err) => err), { signingKey: SEED });
    assert.equal("job" in signedFields(seen[0].body), false);
    assert.ok(result instanceof APIError);
    assert.equal(result.recordHash, H1);
    assert.equal(result.signedRequest, seen[0].body.signed_request);
  });
}

// ── Errors ──────────────────────────────────────────────────────

test("APIError carries recordHash from the error body, and has none otherwise", async () => {
  const { result } = await withServer(
    (_req, _body, index) => [refused(H1), { status: 422, json: { ok: false, error: "stage" } }, { status: 500, json: { record_hash: 5 } }][index],
    async (c) => [
      await c.execute(ROW).catch((err) => err),
      await c.execute(ROW).catch((err) => err),
      await c.execute(ROW).catch((err) => err),
    ],
  );
  assert.equal(result[0].recordHash, H1);
  assert.equal(result[1].recordHash, undefined);
  assert.equal(result[2].recordHash, undefined);
});

// ── Key changes ─────────────────────────────────────────────────

function verifiesChange(change, currentPublicKey, newPublicKey) {
  const signed = `verdifax.request-key-change.v1\0${newPublicKey}\0${change.signed_at}\0${change.nonce}`;
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(currentPublicKey), Buffer.from(change.signature, "base64"));
}

test("rotateRequestKey sends the new key, its proof and the current key's approval, then signs with the new key", async () => {
  const next = generateRequestKeyPair();
  const newPublic = next.publicKey.toString("base64");
  const { seen, result } = await withServer(
    (req) => (req.url === "/keys/request-key" ? { json: { ok: true, public_key: newPublic } } : undefined),
    async (c) => {
      const out = await c.rotateRequestKey(next.privateKey);
      await c.execute(ROW);
      return out;
    },
    { signingKey: SEED },
  );
  assert.deepEqual(result, { ok: true, public_key: newPublic });
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].url, "/keys/request-key");
  const { public_key, proof, change } = seen[0].body;
  assert.deepEqual(Object.keys(seen[0].body).sort(), ["change", "proof", "public_key"]);
  assert.deepEqual(Object.keys(change).sort(), ["nonce", "signature", "signed_at"]);
  assert.equal(public_key, newPublic);
  const proofText = Buffer.from(`verdifax.request-key.v1\0${newPublic}`, "utf8");
  assert.ok(crypto.verify(null, proofText, publicKeyObject(next.publicKey), Buffer.from(proof, "base64")), "the proof is by the new key");
  assert.ok(verifiesChange(change, PUBLIC_KEY, newPublic), "the change is by the current key");
  assert.ok(verifiesV2(seen[1].body, next.publicKey), "the next run is signed with the new key");
  assert.equal(verifiesV2(seen[1].body, PUBLIC_KEY), false);
});

test("a refused rotateRequestKey keeps the current key", async () => {
  const next = generateRequestKeyPair();
  const { seen } = await withServer(
    (req) => (req.url === "/keys/request-key" ? { status: 403, json: { ok: false, error: "the current request key must approve this change" } } : undefined),
    async (c) => {
      await assert.rejects(c.rotateRequestKey(next.privateKey), (err) => err instanceof APIError && err.status === 403);
      await c.execute(ROW);
    },
    { signingKey: SEED },
  );
  assert.ok(verifiesV2(seen[1].body, PUBLIC_KEY));
});

test("rotateRequestKey needs a current key, a good new key and an API key, without a request", async () => {
  const next = generateRequestKeyPair();
  const { seen } = await withServer(null, async (c) => {
    await assert.rejects(c.rotateRequestKey(next.privateKey), /current key/);
  });
  assert.equal(seen.length, 0);
  const signed = await withServer(
    null,
    async (c) => {
      await assert.rejects(c.rotateRequestKey(Buffer.alloc(5)), VerdifaxError);
    },
    { signingKey: SEED },
  );
  assert.equal(signed.seen.length, 0);
  const noKey = await withServer(
    null,
    async (c) => {
      await assert.rejects(c.rotateRequestKey(next.privateKey), APIKeyRequiredError);
    },
    { apiKey: "", signingKey: SEED },
  );
  assert.equal(noKey.seen.length, 0);
});

test("clearRequestKey sends the current key's approval of an empty key", async () => {
  const { seen } = await withServer(null, (c) => c.clearRequestKey(), { signingKey: SEED });
  assert.equal(seen[0].method, "DELETE");
  assert.equal(seen[0].url, "/keys/request-key");
  assert.deepEqual(Object.keys(seen[0].body), ["change"]);
  assert.deepEqual(Object.keys(seen[0].body.change).sort(), ["nonce", "signature", "signed_at"]);
  assert.equal(seen[0].headers["content-type"], "application/json");
  assert.ok(verifiesChange(seen[0].body.change, PUBLIC_KEY, ""));
});

test("after clearRequestKey the client sends unsigned requests, and a job step does too", async () => {
  const { seen, result } = await withServer(
    (req, _body, index) => (req.url === "/execute" ? { json: { ok: true, record_hash: index === 1 ? H1 : H2 } } : undefined),
    async (c) => {
      await c.clearRequestKey();
      const run = await c.execute(ROW);
      const job = c.job("j");
      await job.step("a", ROW);
      await assert.rejects(c.registerRequestKey(), /signingKey/);
      await assert.rejects(c.rotateRequestKey(generateRequestKeyPair().privateKey), /current key/);
      return { run, texts: job.signedRequests };
    },
    { signingKey: SEED },
  );
  assert.deepEqual(seen[1].body, ROW);
  assert.deepEqual(seen[2].body, { ...ROW, job: { job_id: "j", step_id: "a" } });
  assert.equal(seen.length, 3);
  assert.equal("signed_request" in result.run, false);
  assert.deepEqual(result.texts, {});
});

test("a second clearRequestKey after the first sends no body", async () => {
  const { seen } = await withServer(
    null,
    async (c) => {
      await c.clearRequestKey();
      await c.clearRequestKey();
    },
    { signingKey: SEED },
  );
  assert.ok(seen[0].body.change);
  assert.equal(seen[1].raw, "");
});

test("a refused clearRequestKey keeps the signing key", async () => {
  const { seen } = await withServer(
    (req) => (req.method === "DELETE" ? { status: 403, json: { ok: false, error: "the current request key must approve this change" } } : undefined),
    async (c) => {
      await assert.rejects(c.clearRequestKey(), (err) => err instanceof APIError && err.status === 403);
      await c.execute(ROW);
    },
    { signingKey: SEED },
  );
  assert.ok(verifiesV2(seen[1].body, PUBLIC_KEY));
});

test("adminClearRequestKey leaves this client's signing key alone", async () => {
  const { seen } = await withServer(
    null,
    async (c) => {
      await c.adminClearRequestKey(42);
      await c.execute(ROW);
    },
    { signingKey: SEED },
  );
  assert.ok(verifiesV2(seen[1].body, PUBLIC_KEY));
});

test("clearRequestKey with no signing key sends no body", async () => {
  const { seen } = await withServer(null, (c) => c.clearRequestKey());
  assert.equal(seen[0].method, "DELETE");
  assert.equal(seen[0].raw, "");
});

test("adminClearRequestKey calls DELETE /admin/keys/{id}/request-key with no body", async () => {
  const { seen, result } = await withServer(null, (c) => c.adminClearRequestKey(42), { signingKey: SEED });
  assert.equal(seen[0].method, "DELETE");
  assert.equal(seen[0].url, "/admin/keys/42/request-key");
  assert.equal(seen[0].headers["x-verdifax-key"], "k");
  assert.equal(seen[0].raw, "");
  assert.equal(result, undefined);
});

test("adminClearRequestKey refuses a bad id or no API key without a request", async () => {
  const { seen } = await withServer(null, (c) => assert.rejects(c.adminClearRequestKey(0), /keyId/));
  assert.equal(seen.length, 0);
  const noKey = await withServer(null, (c) => assert.rejects(c.adminClearRequestKey(1), APIKeyRequiredError), { apiKey: "" });
  assert.equal(noKey.seen.length, 0);
});

// ── Export ──────────────────────────────────────────────────────

test("exportRuns sends job_id and passes the new row fields through", async () => {
  const row = { run_id: 1, status: "ok", anchor_source: "bundle", job_id: "loan-1", step_id: "decide" };
  const { seen, result } = await withServer(
    () => ({ json: { ok: true, total: 1, returned: 1, truncated: false, by_status: { ok: 1 }, runs: [row] } }),
    (c) => c.exportRuns({ from: "2026-11-01T00:00:00Z", job_id: "loan-1" }),
  );
  const url = new URL(seen[0].url, "http://x");
  assert.deepEqual(Object.fromEntries(url.searchParams), { from: "2026-11-01T00:00:00Z", job_id: "loan-1", format: "json" });
  assert.deepEqual(result.runs, [row]);
});

test("exportRunsCSV sends job_id too, and neither sends it unasked", async () => {
  const { seen } = await withServer(
    (req, _body) => {
      if (req.url.includes("format=csv")) return { json: {} };
      return { json: { ok: true, runs: [] } };
    },
    async (c) => {
      await assert.rejects(c.exportRunsCSV({ job_id: "a b" }), /may be cut off/);
      await c.exportRuns();
    },
  );
  assert.equal(new URL(seen[0].url, "http://x").searchParams.get("job_id"), "a b");
  assert.equal(seen[1].url, "/runs/export?format=json");
});

// ── Docs and type names ─────────────────────────────────────────

test("the README states what a job map and a signature do not show", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  assert.ok(readme.includes("A job map covers what was sent. It cannot show a step that was never sent."));
  assert.ok(readme.includes("A signature shows who requested the run, not that they accepted the outcome."));
});

test("the new type names are exported: JobLink, JobStepOptions, RequestKeyChange, RequestSignatureV2, SignedRequestBody", () => {
  for (const file of ["../dist/index.d.ts", "../dist/index.d.mts"]) {
    const exported = /export \{([^}]+)\}/.exec(readFileSync(new URL(file, import.meta.url), "utf8"))[1];
    const names = exported.split(",").map((name) => name.trim().replace(/^type /, "").split(" as ").pop());
    for (const name of ["JobLink", "JobStepOptions", "RequestKeyChange", "RequestSignatureV2", "SignedRequestBody", "VerdifaxJob"]) {
      assert.ok(names.includes(name), `${file} does not export ${name}`);
    }
  }
});
