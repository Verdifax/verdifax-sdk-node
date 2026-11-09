// The account owner publishes the account's records: publishRun and
// unpublishRun post to the owner routes and hand back the server's answer
// unchanged, the sealed publication included (R130).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { VerdifaxClient, APIKeyRequiredError } from "../dist/index.mjs";

const PUBLICATION = {
  format: "verdifax.run-publication.v2",
  action: "run.published",
  decided_by: "owner",
  run_id: 41,
  record_hash: "a".repeat(64),
  job_id: "loan-1",
  step_id: "verdict",
  changed_at: "2026-11-08T20:00:00Z",
  signal: { signal_account: "account-7", signal_sequence: 9, signal_previous_hash: "b".repeat(64) },
  publication_hash: "c".repeat(64),
  later_field: "kept as sent",
};
const ANSWER = {
  ok: true,
  run_id: 41,
  public: true,
  public_bundle_url: "https://api.verdifax.com/public/runs/tok/bundle.json",
  verify_url: "https://verdifax.com/verify/?pt=tok",
  publication: PUBLICATION,
};

async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, raw, headers: req.headers });
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(answer));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "owner", retryBaseDelayMs: 1, ...config });
    const result = await run(client);
    return { seen, result };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test("publishRun and unpublishRun post to the owner routes and return the answer as sent", async () => {
  const { seen, result } = await withServer(ANSWER, async (c) => {
    const published = await c.publishRun(41);
    await c.unpublishRun(41);
    return published;
  });
  assert.deepEqual(seen.map((r) => `${r.method} ${r.url}`), ["POST /account/runs/41/publish", "POST /account/runs/41/unpublish"]);
  assert.equal(seen[0].headers["x-verdifax-key"], "owner");
  assert.equal(seen[0].raw, "");
  assert.deepEqual(result, ANSWER);
  assert.equal(result.publication.later_field, "kept as sent");
  assert.equal(result.publication.decided_by, "owner");
});

test("publishRun refuses a bad id and a client without a key before sending", async () => {
  const { seen } = await withServer(ANSWER, async (c) => {
    for (const bad of [0, -1, 1.5, "41", NaN]) {
      await assert.rejects(() => c.publishRun(bad));
      await assert.rejects(() => c.unpublishRun(bad));
    }
  });
  assert.equal(seen.length, 0);
  const keyless = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  await assert.rejects(() => keyless.publishRun(1), APIKeyRequiredError);
});

test("publishing a stopped run returns its receipt address and no bundle address (R156)", async () => {
  const STOPPED = {
    ok: true, run_id: 42, public: true,
    public_receipt_url: "https://api.verdifax.com/public/runs/tok/receipt.json",
    verify_url: "https://verdifax.com/verify/?pt=tok&record=receipt", publication: null,
  };
  const { result } = await withServer(STOPPED, (c) => c.publishRun(42));
  assert.equal(result.public_receipt_url, STOPPED.public_receipt_url);
  assert.equal(result.public_bundle_url, undefined);
});
