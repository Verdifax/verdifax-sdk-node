// The AI review's trace reaches the caller on a released run, with the
// sealed review in the manifest, and on a halted run, in the APIError, so
// the caller can keep it for verdifax-verify --aivp-trace.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { VerdifaxClient, APIError } from "../dist/index.mjs";

const TRACE = "1. The vault is always locked.\n\n2. The vault is never locked.";
const REVIEW = {
  formula: "aivp-review.v1", prompt_id: "statements-v1", model: "claude-opus-5-5", trace_hash: "c".repeat(64),
  checker_id: "keyword-v1", contradiction_mode: "record", contradiction_outcome: "recorded",
  finding: { node_a: "node-0001", node_b: "node-0002", term: "always", opposite: "never" },
};

async function withAnswer(status, answer, run) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(answer));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    return await run(new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k", retryBaseDelayMs: 1 }));
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const REQUEST = { program_id: "a".repeat(64), route_id: "r", registry_record_hash: "b".repeat(64), payload_text: "x", ai_output_text: "answer" };

test("a released run returns the trace and the sealed review", async () => {
  const res = await withAnswer(200, {
    ok: true, run_id: 7, duration_ms: 1, record_hash: "d".repeat(64), aivp_trace_text: TRACE,
    manifest: { ManifestHash: "d".repeat(64), AivpReviewForm: "aivp-review.v1", AivpReview: REVIEW },
  }, (c) => c.execute(REQUEST));
  assert.equal(res.aivp_trace_text, TRACE);
  assert.deepEqual(res.manifest.AivpReview, REVIEW);
});

test("a halted run's APIError carries the trace", async () => {
  await withAnswer(422, { ok: false, error: "aivp refused", record_hash: "e".repeat(64), aivp_trace_text: TRACE }, async (c) => {
    await assert.rejects(c.execute(REQUEST), (err) => err instanceof APIError && err.aivpTraceText === TRACE && err.recordHash === "e".repeat(64));
  });
});
