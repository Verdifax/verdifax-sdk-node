// Round 62: the owner adds and removes a webhook only with a record in the
// account's feed, signed by the owner key's request key over webhookValue: the
// SHA-256 of the address and the kinds, never the address. The mock server
// listens on localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { readFileSync } from "node:fs";

import { VerdifaxClient, VerdifaxError, WEBHOOK_DELETED, WEBHOOK_SUBSCRIBED, webhookValue } from "../dist/index.mjs";
import { publicKeyObject } from "./signed-body.mjs";
import { expectedWebhookValue, publicKeyOfSeed, webhookSealer } from "./webhook-server.mjs";

const VECTOR = JSON.parse(readFileSync(new URL("./sdk-webhook-change-vector.json", import.meta.url), "utf8"));
const SEED = Buffer.alloc(32, 9);
const URL_ = "https://hooks.example.com/verdifax?token=s3cret";
const LISTED = { id: 3, url: URL_, types: ["run.refused"], created_at: "2026-11-13T12:00:00Z" };

async function withServer(answer, run, config = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, body });
      const { status = 200, json = { ok: false, error: "not found" } } = answer(req, body, seen.length - 1) ?? { status: 404 };
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "owner", retryBaseDelayMs: 1, ...config });
    return { seen, result: await run(client) };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

const requests = (seen) => seen.map((r) => `${r.method} ${r.url}`);

function ownerVerifies(signature, change, subject) {
  const signed = ["verdifax.owner-change-signature.v1", "account-7", change, subject, signature.signed_at, signature.nonce].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(publicKeyOfSeed(SEED)), Buffer.from(signature.signature, "base64"));
}

test("webhookValue matches the shared vector", () => {
  assert.deepEqual([WEBHOOK_SUBSCRIBED, WEBHOOK_DELETED], [VECTOR.changes.subscribe, VECTOR.changes.delete]);
  for (const c of VECTOR.cases) assert.equal(webhookValue(c.url, c.types ?? []), c.value, c.name);
  assert.equal(webhookValue(URL_, ["run.refused", "account.changed"]), expectedWebhookValue(URL_, ["account.changed", "run.refused"]));
});

test("createWebhook reads the account, signs the subscription and checks the record", async () => {
  const { seen, result } = await withServer(webhookSealer(SEED), (c) => c.createWebhook(URL_, { types: ["run.refused"] }), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account", "POST /account/webhooks"]);
  assert.deepEqual(Object.keys(seen[1].body), ["url", "types", "owner_signature"]);
  const value = expectedWebhookValue(URL_, ["run.refused"]);
  assert.ok(ownerVerifies(seen[1].body.owner_signature, "webhook.subscribed", value));
  assert.ok(!ownerVerifies(seen[1].body.owner_signature, "webhook.deleted", value));
  assert.equal(result.account_change.value, value);
  assert.ok(!JSON.stringify(result.account_change).includes("s3cret"));
});

test("webhook changes need the signing key and send nothing without it", async () => {
  const { seen, result } = await withServer(webhookSealer(SEED, { listed: [LISTED] }), async (c) => [
    await c.createWebhook(URL_).catch((err) => err),
    await c.deleteWebhook(3).catch((err) => err),
  ]);
  assert.deepEqual(seen, []);
  for (const err of result) assert.ok(err instanceof VerdifaxError && /signingKey/.test(err.message), String(err));
});

test("a record that does not carry what was sent is refused", async () => {
  for (const [field, value] of [["action", "webhook.deleted"], ["value", "sha256=" + "0".repeat(64) + " kinds=all"], ["decided_by", "verdifax_admin"]]) {
    const { result } = await withServer(
      webhookSealer(SEED, { change: (record) => ({ ...record, [field]: value }) }),
      (c) => c.createWebhook(URL_, { accountId: "account-7" }).catch((err) => err),
      { signingKey: SEED },
    );
    assert.ok(result instanceof VerdifaxError, `${field}: ${result}`);
  }
});

test("deleteWebhook reads the subscription and signs its value", async () => {
  const { seen, result } = await withServer(webhookSealer(SEED, { listed: [LISTED] }), (c) => c.deleteWebhook(3), { signingKey: SEED });
  assert.deepEqual(requests(seen), ["GET /account/webhooks", "GET /account", "DELETE /account/webhooks/3"]);
  assert.deepEqual(Object.keys(seen[2].body), ["owner_signature"]);
  assert.ok(ownerVerifies(seen[2].body.owner_signature, "webhook.deleted", expectedWebhookValue(URL_, ["run.refused"])));
  assert.equal(result.deleted, true);
});

test("deleteWebhook of no such subscription sends no removal", async () => {
  const { seen, result } = await withServer(webhookSealer(SEED, { listed: [LISTED] }), (c) => c.deleteWebhook(4).catch((err) => err), { signingKey: SEED });
  assert.ok(result instanceof VerdifaxError && /no webhook 4/.test(result.message));
  assert.ok(seen.every((r) => r.method !== "DELETE"));
});

test("the 1.16.0 changelog entry comes first, and no dash longer than a hyphen", () => {
  const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
  assert.match(changelog, /^# Changelog\n\n## 1\.16\.0\n/);
  assert.ok(changelog.includes("The user agent is `verdifax-sdk-node/1.16.0`."));
  for (const file of ["../src/signals.ts", "../src/client.ts", "../src/types.ts", "../README.md", "../CHANGELOG.md", "./webhook-changes.test.mjs", "./webhook-server.mjs"]) {
    assert.ok(!/[\u2013\u2014]/.test(readFileSync(new URL(file, import.meta.url), "utf8")), `${file} has an en or em dash`);
  }
});
