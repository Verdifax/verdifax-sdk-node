// A report request may carry the AI's answer (round 56, F4).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { VerdifaxClient, APIError, VerdifaxError } from "../dist/index.mjs";

function startReportMock(seen) {
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : null;
      seen.push({ method: req.method, url: req.url, body });
      if (body && body.ai_output_text === "wrong") {
        res.statusCode = 422;
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify({ error: "supplied answer refused: nothing was printed" }));
      }
      res.setHeader("Content-Type", "application/pdf");
      res.end("%PDF-report");
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() }),
    ),
  );
}

test("reports carry the answer when given, and the public report goes by token", async () => {
  const seen = [];
  const mock = await startReportMock(seen);
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    assert.equal((await c.downloadAuditPDF(7, "brief", { aiOutputText: "the answer" })).toString(), "%PDF-report");
    await c.downloadPublicAuditPDF("a b", "legal");
    await c.downloadPublicAuditPDF("tok", "comprehensive", { aiOutputText: "the answer" });
    assert.deepEqual(seen, [
      { method: "POST", url: "/runs/7/report.pdf", body: { format: "brief", ai_output_text: "the answer" } },
      { method: "GET", url: "/public/runs/a%20b/report.pdf?format=legal", body: null },
      { method: "POST", url: "/public/runs/tok/report.pdf", body: { format: "comprehensive", ai_output_text: "the answer" } },
    ]);
    await assert.rejects(c.downloadAuditPDF(7, "brief", { aiOutputText: "wrong" }), (err) => {
      assert.ok(err instanceof APIError);
      assert.equal(err.status, 422);
      assert.match(err.message, /nothing was printed/);
      return true;
    });
    await assert.rejects(c.downloadAuditPDF(7, "brief", { aiOutputText: "" }), VerdifaxError);
    await assert.rejects(c.downloadPublicAuditPDF(""), VerdifaxError);
    const anonymous = new VerdifaxClient({ baseURL: mock.url });
    await anonymous.downloadPublicAuditPDF("tok");
  } finally {
    mock.close();
  }
});
