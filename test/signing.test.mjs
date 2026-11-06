// Optional customer request signing. The mock server listens on
// localhost only; nothing leaves this machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { inspect } from "node:util";

import {
  VerdifaxClient,
  VerdifaxError,
  generateRequestKeyPair,
  requestKeyRegistrationBody,
  requestSignaturePreimage,
  signRequest,
} from "../dist/index.mjs";
import { publicKeyObject, signedFields, verifiesV2 } from "./signed-body.mjs";

// The vector shared by the four SDKs, so they cannot disagree.
const SEED = Buffer.alloc(32, 1);
const PROGRAM_ID = "1".repeat(64);
const ROUTE_ID = "r";
const REGISTRY_RECORD_HASH = "2".repeat(64);
const SIGNED_AT = "2026-11-05T00:00:00Z";
const NONCE = "00112233445566778899aabbccddeeff";
const PAYLOAD_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const PUBLIC_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const PROOF = "Vc0TtZ8UbLQgWVnUcwSFPzl3jMn1neQqYQEpbepGa7IYfJJ7kh5QcU0FT5tC5EDoAJNDZNxkLA2Dtf2JHsppBA==";
const SIGNATURE = "PWKn9IplkfrPmXSN+EfJX7aUPoRR0GHqjCvOLG2l1BAvPgupr7ZsJGNujNh6Wk2w/Y1zRaBVeNqOZ1QVrrBvCw==";

const INPUTS = { program_id: PROGRAM_ID, route_id: ROUTE_ID, registry_record_hash: REGISTRY_RECORD_HASH };

function verifies(body, publicKey = Buffer.from(PUBLIC_KEY, "base64")) {
  return verifiesV2(body, publicKey);
}

async function withServer(config, run, respond = { ok: true, run_id: 7 }) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, raw, headers: req.headers, body: raw ? JSON.parse(raw) : undefined });
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(respond));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "k", ...config });
    await run(client);
    return seen;
  } finally {
    server.close();
  }
}

test("shared vector: version 1 signature", () => {
  const signed = signRequest(SEED, { payload_text: "hello", ...INPUTS }, { signedAt: SIGNED_AT, nonce: NONCE });
  assert.deepEqual(signed, { signature: SIGNATURE, signed_at: SIGNED_AT, nonce: NONCE });
});

test("shared vector: version 1 signed bytes", () => {
  const preimage = requestSignaturePreimage({
    payload_hash: PAYLOAD_HASH,
    program_id: PROGRAM_ID,
    route_id: ROUTE_ID,
    registry_record_hash: REGISTRY_RECORD_HASH,
    signed_at: SIGNED_AT,
    nonce: NONCE,
  });
  const expected = `verdifax.request.v1\0${PAYLOAD_HASH}\0${PROGRAM_ID}\0r\0${REGISTRY_RECORD_HASH}\0${SIGNED_AT}\0${NONCE}`;
  assert.equal(preimage.toString("utf8"), expected);
});

test("shared vector: proof", () => {
  assert.deepEqual(requestKeyRegistrationBody(SEED), { public_key: PUBLIC_KEY, proof: PROOF });
  const message = Buffer.from(`verdifax.request-key.v1\0${PUBLIC_KEY}`, "utf8");
  assert.ok(crypto.verify(null, message, publicKeyObject(Buffer.from(PUBLIC_KEY, "base64")), Buffer.from(PROOF, "base64")));
});

test("an unsigned client sends no request_signature", async () => {
  const seen = await withServer({}, (c) => c.execute({ payload_text: "hello", ...INPUTS }));
  assert.equal("request_signature" in seen[0].body, false);
});

test("execute signs, and the signature verifies", async () => {
  const req = { payload_text: "hello", ...INPUTS };
  const seen = await withServer({ signingKey: SEED }, (c) => c.execute(req));
  const { body } = seen[0];
  assert.ok(verifies(body));
  assert.match(body.request_signature.signed_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.match(body.request_signature.nonce, /^[0-9a-f]{32}$/);
  assert.equal("request_signature" in req, false, "execute changed the caller's request");
});

test("attest signs text", async () => {
  const seen = await withServer({ signingKey: SEED }, (c) => c.attest({ payload_text: "hello", ...INPUTS }));
  assert.ok(verifies(seen[0].body));
});

test("attest hashes the base64 string as sent, not the decoded bytes", async () => {
  const bytes = Buffer.from([0xff, 0xfe, 0x00]);
  const seen = await withServer({ signingKey: SEED }, (c) => c.attest({ payload: bytes, ...INPUTS }));
  assert.equal(signedFields(seen[0].body).payload, "//4A");
  assert.ok(verifies(seen[0].body));
});

test("attest signs a Uint8Array payload", async () => {
  const seen = await withServer({ signingKey: SEED }, (c) => c.attest({ payload: new Uint8Array([1, 2, 3]), ...INPUTS }));
  assert.ok(verifies(seen[0].body));
});

for (const [name, call] of [
  ["attestClaudeResponse", (c) => c.attestClaudeResponse({ ...INPUTS, prompt: "p", response: "caf\u00e9 \u{1f600}" })],
  ["attestOpenAIResponse", (c) => c.attestOpenAIResponse({ ...INPUTS, prompt: "p", response: "caf\u00e9 \u{1f600}" })],
]) {
  test(`${name} signs`, async () => {
    const seen = await withServer({ signingKey: SEED }, call);
    assert.ok(verifies(seen[0].body));
  });
}

test("non-ASCII text hashes its UTF-8 bytes", async () => {
  const text = "caf\u00e9 \u4e16\u754c \u{1f600}";
  const seen = await withServer({ signingKey: SEED }, (c) => c.execute({ payload_text: text, ...INPUTS }));
  assert.equal(signedFields(seen[0].body).payload_text, text);
  assert.ok(verifies(seen[0].body));
});

test("non-empty payload_text wins over payload, and an empty one does not", async () => {
  const seen = await withServer({ signingKey: SEED }, async (c) => {
    await c.execute({ payload_text: "text", payload: "aGVsbG8=", ...INPUTS });
    await c.execute({ payload_text: "", payload: "aGVsbG8=", ...INPUTS });
  });
  assert.ok(verifies(seen[0].body));
  assert.ok(verifies(seen[1].body));
});

test("the nonce differs between calls", async () => {
  const req = { payload_text: "hello", ...INPUTS };
  const seen = await withServer({ signingKey: SEED }, async (c) => {
    await c.execute(req);
    await c.execute(req);
  });
  const [a, b] = seen.map((s) => s.body.request_signature);
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.signature, b.signature);
});

test("registerRequestKey sends the public key and proof, and clearRequestKey clears it", async () => {
  const seen = await withServer(
    { signingKey: SEED },
    async (c) => {
      assert.deepEqual(await c.registerRequestKey(), { ok: true, public_key: PUBLIC_KEY });
      await c.clearRequestKey();
    },
    { ok: true, public_key: PUBLIC_KEY },
  );
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].url, "/keys/request-key");
  assert.deepEqual(seen[0].body, { public_key: PUBLIC_KEY, proof: PROOF });
  assert.equal(seen[1].method, "DELETE");
  assert.equal(seen[1].url, "/keys/request-key");
});

test("registerRequestKey needs a signing key", async () => {
  const seen = await withServer({}, async (c) => {
    await assert.rejects(() => c.registerRequestKey(), VerdifaxError);
  });
  assert.equal(seen.length, 0);
});

test("generateRequestKeyPair returns raw keys that work", async () => {
  const { publicKey, privateKey } = generateRequestKeyPair();
  assert.equal(publicKey.length, 32);
  assert.equal(privateKey.length, 32);
  const seen = await withServer({ signingKey: privateKey }, (c) => c.execute({ payload_text: "hello", ...INPUTS }));
  assert.ok(verifies(seen[0].body, publicKey));
});

test("a bad signing key is refused without echoing it", () => {
  for (const bad of [new Uint8Array(0), Buffer.from("short"), Buffer.alloc(33), "00".repeat(32)]) {
    assert.throws(
      () => new VerdifaxClient({ signingKey: bad }),
      (err) => err instanceof VerdifaxError && !err.message.includes("00".repeat(32)) && !err.message.includes("short"),
    );
  }
});

test("the private key is not printed or sent", async () => {
  const secrets = [SEED.toString("hex"), SEED.toString("base64")];
  const client = new VerdifaxClient({ baseURL: "http://127.0.0.1:1", signingKey: SEED });
  for (const text of [inspect(client, { depth: 8, showHidden: true }), JSON.stringify(client)]) {
    for (const secret of secrets) assert.equal(text.includes(secret), false);
    assert.equal(text.includes("<Buffer 01 01"), false);
  }
  const seen = await withServer({ signingKey: SEED }, async (c) => {
    await c.registerRequestKey();
    await c.execute({ payload_text: "hello", ...INPUTS });
  });
  for (const { raw, headers } of seen) {
    for (const secret of secrets) {
      assert.equal(raw.includes(secret), false);
      assert.equal(JSON.stringify(headers).includes(secret), false);
    }
  }
});
