// Search, evidence export, batch runs and the determinism check. The mock
// server listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";

import {
  APIError,
  APIKeyRequiredError,
  AuthError,
  MAX_BATCH_ROWS,
  NotFoundError,
  VerdifaxClient,
  VerdifaxError,
} from "../dist/index.mjs";

const SEED = Buffer.alloc(32, 1);
const PUBLIC_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const ROW = {
  payload_text: "hello",
  program_id: "1".repeat(64),
  route_id: "r",
  registry_record_hash: "2".repeat(64),
};
const CSV = "run_id,created_at,status\n1,2026-11-05T00:00:00Z,ok\n";

function verifies(body) {
  const header = Buffer.from("302a300506032b6570032100", "hex");
  const key = crypto.createPublicKey({
    key: Buffer.concat([header, Buffer.from(PUBLIC_KEY, "base64")]),
    format: "der",
    type: "spki",
  });
  const hash = crypto
    .createHash("sha256")
    .update(Buffer.from(body.payload_text, "utf8"))
    .digest("hex");
  const { signature, signed_at, nonce } = body.request_signature;
  const signed = [
    "verdifax.request.v1",
    hash,
    body.program_id,
    body.route_id,
    body.registry_record_hash,
    signed_at,
    nonce,
  ].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), key, Buffer.from(signature, "base64"));
}

async function withServer(respond, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : undefined });
      const { status = 200, type = "application/json", text = "{\"ok\":true}", headers = {} } = respond(req) ?? {};
      if (status === 0) {
        req.socket.destroy();
        return;
      }
      res.statusCode = status;
      res.setHeader("Content-Type", type);
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      res.end(text);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({
      baseURL: `http://127.0.0.1:${server.address().port}`,
      apiKey: "k",
      retryBaseDelayMs: 1,
      ...config,
    });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const json = (value, status = 200) => ({ status, text: JSON.stringify(value) });
const csvReply = (total, truncated) => ({
  type: "text/csv; charset=utf-8",
  text: CSV,
  headers: { "X-Verdifax-Total": String(total), "X-Verdifax-Truncated": String(truncated) },
});

test("getRun, verifyRun and listRuns keep their requests", async () => {
  const { seen } = await withServer(
    () => json({ ok: true, runs: [], total: 0 }),
    async (c) => {
      await c.getRun(7);
      await c.verifyRun(7);
      await c.listRuns({ limit: 5, offset: 10 });
    },
  );
  assert.deepEqual(
    seen.map((r) => `${r.method} ${r.url}`),
    ["GET /runs/7", "GET /runs/7/verify", "GET /runs?limit=5&offset=10"],
  );
});

test("searchRuns sends every filter and returns runs and total", async () => {
  const run = { id: 7, status: "ok", error_stage: "", execution_region: "us" };
  const { seen, result } = await withServer(
    () => json({ ok: true, total: 9, limit: 2, offset: 4, runs: [run] }),
    (c) =>
      c.searchRuns({
        manifest_hash: "ab",
        program_id: "1".repeat(64),
        route_id: "r 1",
        status: "ok",
        from: "2026-11-01T00:00:00+02:00",
        to: "2026-11-05T00:00:00Z",
        limit: 2,
        offset: 4,
      }),
  );
  const url = new URL(seen[0].url, "http://x");
  assert.equal(url.pathname, "/runs/search");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    manifest_hash: "ab",
    program_id: "1".repeat(64),
    route_id: "r 1",
    status: "ok",
    from: "2026-11-01T00:00:00+02:00",
    to: "2026-11-05T00:00:00Z",
    limit: "2",
    offset: "4",
  });
  assert.deepEqual(result, { runs: [run], total: 9 });
});

test("searchRuns with no filters sends no query", async () => {
  const { seen, result } = await withServer(
    () => json({ ok: true }),
    (c) => c.searchRuns(),
  );
  assert.equal(seen[0].url, "/runs/search");
  assert.deepEqual(result, { runs: [], total: 0 });
});

test("exportRuns sends from, to and format=json and returns the parsed body", async () => {
  const body = {
    ok: true,
    to: "2026-11-05T00:00:00Z",
    total: 1,
    returned: 1,
    truncated: false,
    by_status: { ok: 1 },
    runs: [{ run_id: 1, status: "ok" }],
  };
  const { seen, result } = await withServer(
    () => json(body),
    (c) => c.exportRuns({ from: "2026-11-01T00:00:00+02:00", to: "2026-11-05T00:00:00Z" }),
  );
  const url = new URL(seen[0].url, "http://x");
  assert.equal(seen[0].method, "GET");
  assert.equal(url.pathname, "/runs/export");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    from: "2026-11-01T00:00:00+02:00",
    to: "2026-11-05T00:00:00Z",
    format: "json",
  });
  assert.deepEqual(result, body);
});

test("exportRunsCSV returns the CSV text unparsed with its counts", async () => {
  const { seen, result } = await withServer(
    () => csvReply(1, false),
    (c) => c.exportRunsCSV({ from: "2026-11-01T00:00:00Z" }),
  );
  assert.equal(seen[0].url, "/runs/export?from=2026-11-01T00%3A00%3A00Z&format=csv");
  assert.deepEqual(result, { csv: CSV, total: 1, truncated: false });
});

test("exportRunsCSV reports a truncated export", async () => {
  const { result } = await withServer(
    () => csvReply(12000, true),
    (c) => c.exportRunsCSV(),
  );
  assert.equal(result.total, 12000);
  assert.equal(result.truncated, true);
});

test("exportRunsCSV refuses a response without its counts", async () => {
  for (const reply of [
    { type: "text/csv", text: CSV },
    { type: "text/csv", text: CSV, headers: { "X-Verdifax-Total": "1" } },
    { type: "text/csv", text: CSV, headers: { "X-Verdifax-Total": "x", "X-Verdifax-Truncated": "false" } },
    { type: "text/csv", text: CSV, headers: { "X-Verdifax-Total": "1", "X-Verdifax-Truncated": "maybe" } },
  ]) {
    await assert.rejects(
      withServer(
        () => reply,
        (c) => c.exportRunsCSV(),
      ),
      (err) => err instanceof VerdifaxError && /may be cut off/.test(err.message),
    );
  }
});

test("exportRunsCSV with no period sends only the format", async () => {
  const { seen } = await withServer(
    () => csvReply(1, false),
    (c) => c.exportRunsCSV(),
  );
  assert.equal(seen[0].url, "/runs/export?format=csv");
});

test("exportRunsCSV throws APIError on a refused time", async () => {
  await assert.rejects(
    withServer(
      () => json({ ok: false, error: "from must be an RFC 3339 time" }, 400),
      (c) => c.exportRunsCSV({ from: "yesterday" }),
    ),
    (err) => err instanceof APIError && err.status === 400 && /RFC 3339/.test(err.message),
  );
});

test("a failed export maps 401 to AuthError", async () => {
  await assert.rejects(
    withServer(
      () => json({ error: "bad key" }, 401),
      (c) => c.exportRuns(),
    ),
    AuthError,
  );
});

test("searchRuns maps 404 to NotFoundError", async () => {
  await assert.rejects(
    withServer(
      () => json({ error: "gone" }, 404),
      (c) => c.searchRuns({ status: "ok" }),
    ),
    NotFoundError,
  );
});

test("the export is retried as a GET", async () => {
  let calls = 0;
  const { result } = await withServer(
    () => (++calls === 1 ? json({}, 503) : csvReply(1, false)),
    (c) => c.exportRunsCSV(),
  );
  assert.equal(calls, 2);
  assert.equal(result.csv, CSV);
});

test("executeBatch posts {runs} and returns the results", async () => {
  const body = {
    ok: true,
    total: 2,
    successful: 1,
    failed: 1,
    duration_ms: 3,
    results: [
      { index: 0, ok: true, run_id: 1, manifest_hash: "a", duration_ms: 1 },
      { index: 1, ok: false, error: "route_id required", duration_ms: 0 },
    ],
  };
  const rows = [ROW, { ...ROW, route_id: "" }];
  const { seen, result } = await withServer(
    () => json(body),
    (c) => c.executeBatch(rows),
  );
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].url, "/execute/batch");
  assert.equal(seen[0].headers["x-verdifax-key"], "k");
  assert.deepEqual(seen[0].body, { runs: rows });
  assert.deepEqual(result, body);
});

test("a signed batch gives each row its own signature and nonce", async () => {
  const rows = [ROW, ROW, { ...ROW, payload_text: "other" }];
  const original = JSON.stringify(rows);
  const { seen } = await withServer(
    () => json({ ok: true, results: [] }),
    (c) => c.executeBatch(rows),
    { signingKey: SEED },
  );
  const sent = seen[0].body.runs;
  assert.equal(sent.length, 3);
  for (const row of sent) {
    assert.ok(verifies(row));
    assert.match(row.request_signature.nonce, /^[0-9a-f]{32}$/);
  }
  assert.equal(new Set(sent.map((r) => r.request_signature.nonce)).size, 3);
  assert.equal(new Set(sent.map((r) => r.request_signature.signature)).size, 3);
  assert.equal(JSON.stringify(rows), original);
});

test("a signed batch sends a row with missing fields for the server to report", async () => {
  const { seen } = await withServer(
    () => json({ ok: true, results: [] }),
    (c) => c.executeBatch([{ payload_text: "x" }]),
    { signingKey: SEED },
  );
  assert.ok(seen[0].body.runs[0].request_signature);
});

test("executeBatch accepts exactly 1,000 rows and refuses 1,001 without a request", async () => {
  assert.equal(MAX_BATCH_ROWS, 1000);
  const { seen } = await withServer(
    () => json({ ok: true, results: [] }),
    async (c) => {
      await c.executeBatch(Array(1000).fill(ROW));
      await assert.rejects(
        c.executeBatch(Array(1001).fill(ROW)),
        (err) => err instanceof VerdifaxError && /at most 1000 runs \(got 1001\)/.test(err.message),
      );
      await assert.rejects(c.executeBatch([]), /at least one run/);
    },
  );
  assert.equal(seen.length, 1);
  assert.equal(seen[0].body.runs.length, 1000);
});

test("executeBatch and verifyDeterminism are never retried", async () => {
  for (const call of [(c) => c.executeBatch([ROW]), (c) => c.verifyDeterminism(ROW)]) {
    let calls = 0;
    await assert.rejects(
      withServer(
        () => {
          calls += 1;
          return json({ error: "busy" }, 503);
        },
        call,
      ),
      (err) => err instanceof APIError && err.status === 503,
    );
    assert.equal(calls, 1);
  }
});

test("a dropped connection on a POST is not retried", async () => {
  let calls = 0;
  await assert.rejects(
    withServer(
      () => {
        calls += 1;
        return { status: 0 };
      },
      (c) => c.executeBatch([ROW]),
      { signingKey: SEED },
    ),
    /HTTP transport/,
  );
  assert.equal(calls, 1);
});

test("verifyDeterminism posts the request and returns the comparison", async () => {
  const run = { run_id: 1, manifest_hash: "a", bundle_hash: "b", duration_ms: 1, status: "ok" };
  const body = {
    ok: true,
    deterministic: true,
    first: run,
    second: { ...run, run_id: 2 },
    diff: { differs: false, manifest_hash_differs: false, bundle_hash_differs: false },
  };
  const { seen, result } = await withServer(
    () => json(body),
    (c) => c.verifyDeterminism(ROW),
  );
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].url, "/execute/verify-determinism");
  assert.deepEqual(seen[0].body, ROW);
  assert.deepEqual(result, body);
});

test("a signed verifyDeterminism carries one signature", async () => {
  const { seen } = await withServer(
    () => json({ ok: true }),
    (c) => c.verifyDeterminism(ROW),
    { signingKey: SEED },
  );
  assert.equal(seen.length, 1);
  assert.ok(verifies(seen[0].body));
});

test("verifyDeterminism refuses an incomplete request without a request", async () => {
  const { seen } = await withServer(
    () => json({ ok: true }),
    async (c) => {
      await assert.rejects(c.verifyDeterminism({ ...ROW, payload_text: "" }), /payload or payload_text/);
      await assert.rejects(c.verifyDeterminism({ ...ROW, route_id: "" }), /are required/);
    },
  );
  assert.equal(seen.length, 0);
});

test("the new methods need an API key", async () => {
  const c = new VerdifaxClient({ baseURL: "http://127.0.0.1:9" });
  for (const call of [
    () => c.searchRuns(),
    () => c.exportRuns(),
    () => c.exportRunsCSV(),
    () => c.executeBatch([ROW]),
    () => c.verifyDeterminism(ROW),
  ]) {
    await assert.rejects(call(), APIKeyRequiredError);
  }
});
