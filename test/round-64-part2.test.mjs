// SDK 1.17.0, round 64 part 2: the board summary and response-time routes,
// their record types and the rule in force. Driven by the shared vectors
// sdk-board-summary-vector.json (answers built by the server's own code) and
// sdk-rule-in-force-vector.json, copied unchanged from scripts/. The mock
// server listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";

import { APIError, NotFoundError, VerdifaxClient, VerdifaxError, ruleInForce } from "../dist/index.mjs";

const BOARD = JSON.parse(readFileSync(new URL("./sdk-board-summary-vector.json", import.meta.url), "utf8"));
const RULE = JSON.parse(readFileSync(new URL("./sdk-rule-in-force-vector.json", import.meta.url), "utf8"));

async function withServer(answer, run) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : undefined });
      const { status = 200, json, bytes, type = "application/json" } = answer(req) ?? {};
      res.statusCode = status;
      res.setHeader("Content-Type", type);
      res.end(bytes ?? JSON.stringify(json ?? { ok: true }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k", retryBaseDelayMs: 1, maxRetries: 0 });
    return { seen, result: await run(client) };
  } catch (err) {
    err.seen = seen;
    throw err;
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const FROM = "2026-11-01T00:00:00Z";
const TO = "2026-11-02T00:00:00Z";

// ── POST /account/summaries ───────────────────────────────────────

for (const [name, status] of [["create_answer", 201], ["reused_answer", 200]]) {
  test(`createSummary sends {from, to} and returns the ${name} as sealed`, async () => {
    const { seen, result } = await withServer(() => ({ status, json: BOARD[name] }), (cl) => cl.createSummary(FROM, TO));
    assert.deepEqual(seen, [{ method: "POST", url: "/account/summaries", body: { from: FROM, to: TO } }]);
    assert.equal(result.reused, BOARD[name].reused);
    assert.equal(result.id, 1);
    assert.deepEqual(JSON.parse(result.summary.sealedJson), BOARD.summary);
    assert.equal(result.summary.summary_hash, BOARD.summary.summary_hash);
  });
}

test("createSummary refuses an answer that is not a sealed summary", async () => {
  const broken = [
    { ...BOARD.create_answer, summary: { ...BOARD.summary, format: "verdifax.period-summary.v2" } },
    { ...BOARD.create_answer, summary: { ...BOARD.summary, summary_hash: "A".repeat(64) } },
    { ...BOARD.create_answer, id: 0 },
    { ...BOARD.create_answer, reused: "no" },
  ];
  for (const json of broken) {
    await assert.rejects(withServer(() => ({ status: 201, json }), (cl) => cl.createSummary(FROM, TO)), VerdifaxError);
  }
});

test("createSummary refuses an empty or missing time before sending", async () => {
  for (const [from, to] of [["", TO], [FROM, ""], [undefined, TO], [FROM, 7]]) {
    const err = await withServer(() => ({}), (cl) => cl.createSummary(from, to)).catch((e) => e);
    assert.ok(err instanceof VerdifaxError);
    assert.equal(err.seen.length, 0);
  }
});

test("createSummary passes the server's refusal through", async () => {
  await assert.rejects(
    withServer(() => ({ status: 422, json: { error: "a summary is made for a period that ended at least 15 minutes ago" } }), (cl) =>
      cl.createSummary(FROM, TO),
    ),
    (err) => err instanceof APIError && err.status === 422,
  );
});

// ── GET /account/summaries and /account/summaries/{id} ─────────────

test("listSummaries reads the list, with limit only when given", async () => {
  const { seen, result } = await withServer(() => ({ json: BOARD.list_answer }), async (cl) => [await cl.listSummaries(), await cl.listSummaries(5)]);
  assert.deepEqual(seen.map((r) => r.url), ["/account/summaries", "/account/summaries?limit=5"]);
  assert.equal(result[0].summaries[0].summary_hash, BOARD.summary.summary_hash);
  assert.equal(result[0].summaries[0].on_public_log, true);
});

test("listSummaries refuses a bad limit and an answer with no list", async () => {
  for (const limit of [0, -1, 1.5, "5"]) {
    const err = await withServer(() => ({}), (cl) => cl.listSummaries(limit)).catch((e) => e);
    assert.ok(err instanceof VerdifaxError);
    assert.equal(err.seen.length, 0);
  }
  await assert.rejects(withServer(() => ({ json: { limit: 50 } }), (cl) => cl.listSummaries()), VerdifaxError);
});

test("getSummary returns the summary with its exact text", async () => {
  const { seen, result } = await withServer(() => ({ json: BOARD.summary }), (cl) => cl.getSummary(1));
  assert.equal(seen[0].url, "/account/summaries/1");
  assert.deepEqual(JSON.parse(result.sealedJson), BOARD.summary);
  assert.deepEqual(result.figures.map((f) => f.name), BOARD.summary.figures.map((f) => f.name));
  await assert.rejects(withServer(() => ({ json: { ...BOARD.summary, format: "x" } }), (cl) => cl.getSummary(1)), VerdifaxError);
  await assert.rejects(withServer(() => ({}), (cl) => cl.getSummary(0)), VerdifaxError);
});

test("getSummaryHead returns the head the summary names, with its exact text", async () => {
  const { seen, result } = await withServer(() => ({ json: BOARD.summary_head }), (cl) => cl.getSummaryHead(4));
  assert.equal(seen[0].url, "/account/summaries/4/head");
  assert.equal(result.head_statement_hash, BOARD.summary.head_statement_hash);
  assert.deepEqual(JSON.parse(result.sealedJson), BOARD.summary_head);
  await assert.rejects(withServer(() => ({ json: BOARD.summary }), (cl) => cl.getSummaryHead(4)), VerdifaxError);
  await assert.rejects(withServer(() => ({}), (cl) => cl.getSummaryHead(0)), VerdifaxError);
});

test("createSummary refuses a head that is not the one its summary names", async () => {
  const answer = { ...BOARD.create_answer, head: { ...BOARD.create_answer.head, sequence: 31 } };
  await assert.rejects(
    withServer(() => ({ status: 201, json: answer }), (cl) => cl.createSummary(FROM, TO)),
    /not the one its summary names/,
  );
});

test("downloadSummaryReport returns the PDF's bytes and refuses anything else", async () => {
  const pdf = Buffer.from("%PDF-1.7\nsummary\n%%EOF\n", "latin1");
  const { seen, result } = await withServer(() => ({ bytes: pdf, type: "application/pdf" }), (cl) => cl.downloadSummaryReport(3));
  assert.equal(seen[0].url, "/account/summaries/3/report.pdf");
  assert.deepEqual(result, pdf);
  await assert.rejects(
    withServer(() => ({ bytes: Buffer.from("<html>"), type: "text/html" }), (cl) => cl.downloadSummaryReport(3)),
    VerdifaxError,
  );
  await assert.rejects(
    withServer(() => ({ status: 404, json: { error: "no such summary in this account" } }), (cl) => cl.downloadSummaryReport(3)),
    NotFoundError,
  );
  await assert.rejects(withServer(() => ({}), (cl) => cl.downloadSummaryReport(-2)), VerdifaxError);
});

// ── GET /account/signoffs/response-times ──────────────────────────

test("getResponseTimes sends from, to, target and pack, and returns the report", async () => {
  const { seen, result } = await withServer(() => ({ json: BOARD.response_times }), async (cl) => [
    await cl.getResponseTimes(FROM, TO),
    await cl.getResponseTimes(FROM, TO, { target: 900, pack: true }),
    await cl.getResponseTimes(FROM, TO, { pack: false }),
  ]);
  const queries = seen.map((r) => Object.fromEntries(new URL(r.url, "http://x").searchParams));
  assert.deepEqual(queries, [{ from: FROM, to: TO }, { from: FROM, to: TO, target: "900", pack: "1" }, { from: FROM, to: TO }]);
  assert.ok(seen.every((r) => r.url.startsWith("/account/signoffs/response-times?")));
  const report = result[0];
  assert.equal(report.form, "verdifax.response-times.v1");
  assert.equal(report.request_target, 900);
  assert.equal(report.results[0].first_signoff.log_seconds, BOARD.response_times.results[0].first_signoff.log_seconds);
  assert.equal(report.aggregates.results, BOARD.response_times.aggregates.results);
  assert.deepEqual(JSON.parse(report.sealedJson), BOARD.response_times);
});

test("getResponseTimes refuses bad arguments before sending, and a report of another form", async () => {
  const bad = [
    ["", TO, {}],
    [FROM, undefined, {}],
    [FROM, TO, { target: 0 }],
    [FROM, TO, { target: 31622401 }],
    [FROM, TO, { target: 1.5 }],
    [FROM, TO, { pack: "1" }],
    [FROM, TO, { targt: 5 }],
  ];
  for (const [from, to, options] of bad) {
    const err = await withServer(() => ({}), (cl) => cl.getResponseTimes(from, to, options)).catch((e) => e);
    assert.ok(err instanceof VerdifaxError, JSON.stringify(options));
    assert.equal(err.seen.length, 0);
  }
  const { result } = await withServer(() => ({ json: BOARD.response_times }), (cl) => cl.getResponseTimes(FROM, TO, { target: 31622400 }));
  assert.equal(result.form, "verdifax.response-times.v1");
  await assert.rejects(
    withServer(() => ({ json: { ...BOARD.response_times, form: "verdifax.response-times.v2" } }), (cl) => cl.getResponseTimes(FROM, TO)),
    VerdifaxError,
  );
});

// ── the record samples read as the types name them ────────────────

test("the round 64 target records carry the fields their types name", () => {
  const passed = BOARD.target_passed;
  assert.equal(passed.format, "verdifax.signoff-target-passed.v1");
  for (const name of ["result_kind", "run_id", "result_sequence", "result_hash", "source", "within", "compare", "notice", "start_basis", "start", "deadline", "statement", "stated_at", "signal", "target_passed_hash"]) {
    assert.ok(name in passed, name);
  }
  assert.deepEqual(Object.keys(BOARD.run_sealed.signoff_target).sort(), ["compare", "notice", "within"]);
  assert.deepEqual(Object.keys(BOARD.receipt_context.response_target).sort(), ["compare", "notice", "within"]);
  for (const name of ["form", "account", "from", "to", "counting_rules", "head_sequence", "head", "results", "aggregates"]) {
    assert.ok(name in BOARD.response_times, name);
  }
});

// ── rule in force (sdk-rule-in-force-vector.json) ─────────────────

for (const c of RULE.cases) {
  test(`ruleInForce: ${c.name}`, () => {
    if (c.expected_error) {
      assert.throws(() => ruleInForce(c.document, c.policy_history ?? undefined), VerdifaxError);
      return;
    }
    assert.deepEqual(ruleInForce(c.document, c.policy_history ?? undefined), c.expected);
    assert.deepEqual(ruleInForce(JSON.stringify(c.document), c.policy_history === null ? null : JSON.stringify(c.policy_history)), c.expected);
  });
}

test("ruleInForce refuses a history that is not a list and a document that is not JSON", () => {
  const record = RULE.cases[0].document;
  assert.throws(() => ruleInForce(record, { history: [] }), VerdifaxError);
  assert.throws(() => ruleInForce("{not json"), VerdifaxError);
  assert.throws(() => ruleInForce(null), VerdifaxError);
});

test("ruleInForce asks for the policy history by name when a refusal needs it", () => {
  const needy = RULE.cases.find((c) => c.name === "a refusal that names no change needs the policy history");
  assert.throws(() => ruleInForce(needy.document), /pass policyHistory/);
});

test("ruleInForce reads only policy changes from a history", () => {
  const base = RULE.cases.find((c) => c.name === "with the history, the change in force at the refusal's clock");
  const other = {
    format: "verdifax.chain-interrupted.v1",
    chain_id: "api-key-7",
    sequence: 9,
    policy_hash: base.document.attestation_gap_receipt.policy_hash,
    activation_hash: "9".repeat(64),
    activated_at: "2026-11-10T12:15:00Z",
  };
  assert.deepEqual(ruleInForce(base.document, [...base.policy_history, other]), base.expected);
});
