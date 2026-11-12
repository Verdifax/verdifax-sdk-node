// lenient asks the server to ignore or replace a value it cannot read;
// every list and search sends lenient=1 only when it is set.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { VerdifaxClient } from "../dist/index.mjs";

test("lists and searches send lenient=1 only when asked", async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(req.url);
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true, runs: [], total: 0, attestations: [] }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const c = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k" });
    await c.listRuns({ lenient: true });
    await c.listAccountRuns({ limit: 5, lenient: true });
    await c.searchRuns({ from: "2026-11-11", lenient: true });
    await c.listAttestations({ lenient: true });
    await c.listRuns({ limit: 5 });
    assert.deepEqual(seen, [
      "/runs?lenient=1",
      "/account/runs?limit=5&lenient=1",
      "/runs/search?from=2026-11-11&lenient=1",
      "/attestations?lenient=1",
      "/runs?limit=5",
    ]);
  } finally {
    server.close();
  }
});

test("the public sign-off routes need no key", async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, key: req.headers["x-verdifax-key"] ?? null });
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true, run_id: 7, read: true, signoffs: [], decision_in_force: { decision: "approve", run_id: 9, on: "job_final_step" } }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const c = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}` });
    const a = await c.getPublicSignOffByToken("a b");
    assert.equal(a.decision_in_force.run_id, 9);
    await c.getPublicSignOff(7);
    assert.deepEqual(seen, [
      { url: "/public/runs/a%20b/signoff.json", key: null },
      { url: "/runs/7/signoff.json", key: null },
    ]);
    await assert.rejects(c.getPublicSignOff(0));
    await assert.rejects(c.getPublicSignOffByToken(""));
  } finally {
    server.close();
  }
});
