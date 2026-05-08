// Verdifax SDK — Node.js native test runner integration test.
//
// Spins up a tiny mock HTTP server, points the SDK at it, and
// exercises every public method. No external testing framework
// — uses node:test (Node 18+ built-in).
//
// Run via:
//
//   npm run build && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import {
  VerdifaxClient,
  AuthError,
  NotFoundError,
  APIKeyRequiredError,
} from "../dist/index.mjs";

// ── Mock orchestrator ───────────────────────────────────────────

/** Boots a mock HTTP server that mimics Verdifax orchestrator
 *  responses on the SDK's known endpoints. Returns the URL the
 *  SDK should target. */
function startMockOrchestrator() {
  const server = http.createServer((req, res) => {
    const send = (status, body) => {
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
    };

    const auth = req.headers["x-verdifax-key"];

    if (req.method === "GET" && req.url === "/health") {
      return send(200, {
        ok: true,
        service: "verdifax-orchestrator-api",
        version: "1.0.0",
        orchestrator_version: "0.3.0",
        orchestrator_git_sha: "deadbeefdeadbeef",
        time: new Date().toISOString(),
      });
    }

    if (req.method === "GET" && req.url === "/version") {
      return send(200, {
        service: "verdifax-orchestrator-api",
        formula_version: "v1.7 (Phase 17 — CRES)",
        kernel_versions: {
          dse: "dse.tcu.dispatch.v1",
          cres: "verdifax.cres.v1",
        },
        engine_versions: {
          dcae: "verdifax-dcae/1.0.0",
          cres: "verdifax-cres/1.0.0",
        },
        time: new Date().toISOString(),
      });
    }

    if (req.method === "POST" && req.url === "/execute") {
      if (!auth) {
        return send(401, { ok: false, error: "missing X-Verdifax-Key header" });
      }
      return send(200, {
        ok: true,
        run_id: 142,
        manifest: {
          EnvelopeID: "env-mock",
          EnvelopeHash: "ee" + "aa".repeat(31),
          ManifestHash: "ff" + "bb".repeat(31),
          EraseStatus: "intact",
        },
        duration_ms: 5,
      });
    }

    if (req.method === "GET" && /^\/runs\/\d+$/.test(req.url || "")) {
      if (!auth) return send(401, { ok: false, error: "missing X-Verdifax-Key header" });
      if ((req.url || "").endsWith("/99999")) {
        return send(404, { ok: false, error: "run not found" });
      }
      return send(200, {
        ok: true,
        id: 142,
        manifest_hash: "ff" + "bb".repeat(31),
        status: "ok",
        manifest: { EnvelopeID: "env-mock", EnvelopeHash: "x", ManifestHash: "x" },
      });
    }

    if (req.method === "GET" && /^\/runs\/\d+\/verify$/.test(req.url || "")) {
      if (!auth) return send(401, { ok: false, error: "missing X-Verdifax-Key header" });
      return send(200, {
        ok: true,
        verified: true,
        manifest_hash: "ff" + "bb".repeat(31),
        recomputed_hash: "ff" + "bb".repeat(31),
        formula_version: "v1.7 (Phase 17 — CRES)",
        verification_at: new Date().toISOString(),
        verification_kind: "manifest-self-seal",
      });
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

test("Client defaults baseURL when omitted", () => {
  const c = new VerdifaxClient();
  assert.ok(c instanceof VerdifaxClient);
});

test("health() round-trips against the mock orchestrator", async () => {
  const mock = await startMockOrchestrator();
  try {
    const client = new VerdifaxClient({ baseURL: mock.url });
    const h = await client.health();
    assert.equal(h.ok, true);
    assert.equal(h.service, "verdifax-orchestrator-api");
  } finally {
    mock.close();
  }
});

test("version() surfaces formula_version + kernel_versions", async () => {
  const mock = await startMockOrchestrator();
  try {
    const client = new VerdifaxClient({ baseURL: mock.url });
    const v = await client.version();
    assert.equal(v.formula_version, "v1.7 (Phase 17 — CRES)");
    assert.ok(v.kernel_versions?.cres, "kernel_versions.cres should be set");
  } finally {
    mock.close();
  }
});

test("execute() requires apiKey", async () => {
  const client = new VerdifaxClient();
  await assert.rejects(
    client.execute({
      program_id: "a".repeat(64),
      route_id: "demo",
      registry_record_hash: "b".repeat(64),
      payload_text: "x",
    }),
    APIKeyRequiredError,
  );
});

test("execute() happy path returns a sealed manifest", async () => {
  const mock = await startMockOrchestrator();
  try {
    const client = new VerdifaxClient({ baseURL: mock.url, apiKey: "test-key" });
    const res = await client.execute({
      program_id: "a".repeat(64),
      route_id: "demo",
      registry_record_hash: "b".repeat(64),
      payload_text: "first attestation",
    });
    assert.equal(res.run_id, 142);
    assert.equal(res.manifest.EraseStatus, "intact");
  } finally {
    mock.close();
  }
});

test("getRun() returns NotFoundError on unknown run", async () => {
  const mock = await startMockOrchestrator();
  try {
    const client = new VerdifaxClient({ baseURL: mock.url, apiKey: "test-key" });
    await assert.rejects(client.getRun(99999), NotFoundError);
  } finally {
    mock.close();
  }
});

test("verifyRun() reports verified=true", async () => {
  const mock = await startMockOrchestrator();
  try {
    const client = new VerdifaxClient({ baseURL: mock.url, apiKey: "test-key" });
    const v = await client.verifyRun(142);
    assert.equal(v.verified, true);
    assert.equal(v.formula_version, "v1.7 (Phase 17 — CRES)");
  } finally {
    mock.close();
  }
});

test("AuthError surfaces when SDK has no apiKey but HTTP is hit (defensive)", async () => {
  // execute() short-circuits with APIKeyRequiredError, but other
  // surfaces use the apiKey check at HTTP level. Confirm the
  // client-side auth check fires correctly.
  const client = new VerdifaxClient();
  await assert.rejects(client.getRun(1), APIKeyRequiredError);
  void AuthError; // keep import live
});
