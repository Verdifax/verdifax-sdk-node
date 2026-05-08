// Extended test suite — covers every method beyond the MVP five.
// Run via:  npm run build && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import {
  VerdifaxClient,
  fromEnv,
  validateHex64,
  validateRouteId,
  VerdifaxError,
} from "../dist/index.mjs";

// ── Mock orchestrator for extended endpoints ────────────────────

function startExtendedMock() {
  const server = http.createServer((req, res) => {
    const send = (status, body) => {
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
    };
    const url = req.url || "";

    if (req.method === "POST" && url === "/execute") {
      return send(200, {
        ok: true,
        run_id: 200,
        manifest: {
          EnvelopeID: "env-extended",
          EnvelopeHash: "ee" + "aa".repeat(31),
          ManifestHash: "ff" + "bb".repeat(31),
          EraseStatus: "intact",
        },
        duration_ms: 5,
      });
    }

    if (req.method === "GET" && url.startsWith("/runs?")) {
      return send(200, {
        ok: true,
        total: 2,
        runs: [
          { id: 200, status: "ok", manifest_hash: "a".repeat(64) },
          { id: 201, status: "pepg_deny", manifest_hash: "b".repeat(64) },
        ],
      });
    }

    if (req.method === "GET" && url === "/runs") {
      return send(200, { ok: true, total: 0, runs: [] });
    }

    if (
      req.method === "GET" &&
      /^\/runs\/\d+\/(allow-token|deny-receipt|ccv-halt-receipt|macc-halt-receipt|aivp-t4-halt-receipt)$/.test(
        url,
      )
    ) {
      return send(200, {
        envelope_id: "env-test",
        sealed_hash: "c".repeat(64),
      });
    }

    if (req.method === "GET" && /^\/runs\/\d+\/deletion-receipts$/.test(url)) {
      return send(200, {
        ok: true,
        run_id: 200,
        count: 1,
        receipts: [
          {
            preimage_version: "verdifax.cres.v1",
            envelope_id: "env-test",
            field_path: "request.email",
            deletion_clock: "2026-05-07T12:00:00.000000000Z",
            actor_id: "ops-test",
            ciphertext_hash_at_shred: "a".repeat(64),
            engine_version: "verdifax-cres/1.0.0",
            receipt_hash: "d".repeat(64),
          },
        ],
      });
    }

    if (req.method === "GET" && /^\/runs\/\d+\/report\.pdf/.test(url)) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/pdf");
      res.end("%PDF-1.7\n% mock for SDK test\n%%EOF\n");
      return;
    }

    if (req.method === "POST" && url === "/admin/erase") {
      return send(200, {
        ok: true,
        deletion_receipt: {
          preimage_version: "verdifax.cres.v1",
          envelope_id: "env-test",
          field_path: "request.email",
          deletion_clock: "2026-05-07T12:00:00.000000000Z",
          actor_id: "ops-test",
          ciphertext_hash_at_shred: "a".repeat(64),
          engine_version: "verdifax-cres/1.0.0",
          receipt_hash: "e".repeat(64),
        },
      });
    }

    if (req.method === "POST" && url === "/dcae/verify") {
      return send(200, {
        verified: false,
        failure_reason: "missing_fields",
        engine_version: "verdifax-dcae/1.0.0",
      });
    }

    if (req.method === "POST" && url === "/admin/keys") {
      return send(201, {
        ok: true,
        id: 7,
        name: "test-key",
        secret: "vfx_test_secret",
        hint: "Store once",
      });
    }

    if (req.method === "GET" && url === "/admin/keys") {
      return send(200, {
        ok: true,
        keys: [
          { id: 1, name: "first", created_at: "2026-05-01T00:00:00Z", run_count: 0, revoked: false },
          { id: 2, name: "second", created_at: "2026-05-05T00:00:00Z", run_count: 5, revoked: false },
        ],
      });
    }

    if (req.method === "DELETE" && /^\/admin\/keys\/\d+$/.test(url)) {
      return send(200, { ok: true });
    }

    send(404, { ok: false, error: "mock route not implemented" });
  });

  return new Promise((resolve) => {
    server.listen(0, () => {
      const port = server.address().port;
      resolve({ url: `http://localhost:${port}`, close: () => server.close() });
    });
  });
}

// ── Tests ───────────────────────────────────────────────────────

test("validateHex64 accepts canonical input", () => {
  validateHex64("a".repeat(64), "f"); // no throw
  assert.throws(() => validateHex64("ABCDEF", "f"), VerdifaxError);
  assert.throws(() => validateHex64("g".repeat(64), "f"), VerdifaxError);
});

test("validateRouteId enforces non-empty + ASCII", () => {
  validateRouteId("good-route");
  assert.throws(() => validateRouteId(""), VerdifaxError);
  assert.throws(() => validateRouteId("bad\x00route"), VerdifaxError);
});

test("attest() rejects both payload variants", async () => {
  const c = new VerdifaxClient({ apiKey: "k" });
  await assert.rejects(
    c.attest({
      payload: Buffer.from("x"),
      payload_text: "y",
      program_id: "a".repeat(64),
      route_id: "r",
      registry_record_hash: "b".repeat(64),
    }),
    VerdifaxError,
  );
});

test("attest() with Buffer auto-base64s the payload", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const res = await c.attest({
      payload: Buffer.from("hello"),
      program_id: "a".repeat(64),
      route_id: "r",
      registry_record_hash: "b".repeat(64),
    });
    assert.equal(res.run_id, 200);
  } finally {
    mock.close();
  }
});

test("listRuns returns the page + total", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const { runs, total } = await c.listRuns({ limit: 10 });
    assert.equal(total, 2);
    assert.equal(runs.length, 2);
  } finally {
    mock.close();
  }
});

test("getAllowToken returns the sealed artifact", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const t = await c.getAllowToken(200);
    assert.equal(t.envelope_id, "env-test");
  } finally {
    mock.close();
  }
});

test("listDeletionReceipts reads the CRES audit trail", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const rs = await c.listDeletionReceipts(200);
    assert.equal(rs.length, 1);
    assert.equal(rs[0].engine_version, "verdifax-cres/1.0.0");
  } finally {
    mock.close();
  }
});

test("adminErase happy path", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const r = await c.adminErase({
      run_id: 200,
      field_path: "request.email",
      ciphertext_hash: "a".repeat(64),
      dsar_reference: "DSAR-2026-001",
    });
    assert.ok(r.receipt_hash);
  } finally {
    mock.close();
  }
});

test("adminErase rejects bad ciphertext_hash", async () => {
  const c = new VerdifaxClient({ apiKey: "k" });
  await assert.rejects(
    c.adminErase({
      run_id: 200,
      field_path: "f",
      ciphertext_hash: "tooshort",
    }),
    VerdifaxError,
  );
});

test("dcaeVerify works without auth", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url }); // no apiKey
    const v = await c.dcaeVerify({
      envelope_id: "env-test",
      envelope_hash: "a".repeat(64),
      aer_hash: "b".repeat(64),
      zksp_binding_hash: "c".repeat(64),
      formal_verifier_status: "VERIFIED_SOUND_COMPLETE_ZK",
      manifest_hash: "d".repeat(64),
    });
    assert.equal(v.engine_version, "verdifax-dcae/1.0.0");
  } finally {
    mock.close();
  }
});

test("adminCreateKey returns the secret once", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "bootstrap-key" });
    const r = await c.adminCreateKey("test-key");
    assert.ok(r.secret);
    assert.equal(r.id, 7);
  } finally {
    mock.close();
  }
});

test("adminListKeys returns metadata-only list", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const keys = await c.adminListKeys();
    assert.equal(keys.length, 2);
  } finally {
    mock.close();
  }
});

test("adminRevokeKey hits the DELETE path", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    await c.adminRevokeKey(1);
  } finally {
    mock.close();
  }
});

test("downloadAuditPDF streams %PDF- magic bytes", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const buf = await c.downloadAuditPDF(200, "comprehensive");
    assert.ok(buf.subarray(0, 5).equals(Buffer.from("%PDF-")));
  } finally {
    mock.close();
  }
});

test("fromEnv builds a client from env vars", () => {
  process.env.VERDIFAX_BASE_URL = "https://example.com";
  process.env.VERDIFAX_API_KEY = "test-env-key";
  process.env.VERDIFAX_TIMEOUT_MS = "5000";
  const c = fromEnv();
  assert.ok(c instanceof VerdifaxClient);
  delete process.env.VERDIFAX_BASE_URL;
  delete process.env.VERDIFAX_API_KEY;
  delete process.env.VERDIFAX_TIMEOUT_MS;
});

test("fromEnv rejects malformed VERDIFAX_TIMEOUT_MS", () => {
  process.env.VERDIFAX_TIMEOUT_MS = "not-a-number";
  assert.throws(fromEnv, VerdifaxError);
  delete process.env.VERDIFAX_TIMEOUT_MS;
});

test("attestClaudeResponse round-trips with AIVP-T4 wiring", async () => {
  const mock = await startExtendedMock();
  try {
    const c = new VerdifaxClient({ baseURL: mock.url, apiKey: "k" });
    const res = await c.attestClaudeResponse({
      program_id: "a".repeat(64),
      route_id: "support-conversation",
      registry_record_hash: "b".repeat(64),
      prompt: "What is 2+2?",
      response: "2+2 equals 4.",
    });
    assert.equal(res.manifest.EraseStatus, "intact");
  } finally {
    mock.close();
  }
});
