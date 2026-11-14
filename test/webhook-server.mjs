// Round 62: a fake server for webhook changes. It answers each change with the
// record the real server seals, carrying what was sent, under the public key of
// the client's signing key. The value is written out here, independently of the
// SDK. Listens nowhere itself; the tests' withServer does.
import crypto from "node:crypto";

const PKCS8_ED25519_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");

export function publicKeyOfSeed(seed) {
  const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_HEADER, seed]), format: "der", type: "pkcs8" });
  return crypto.createPublicKey(key).export({ format: "der", type: "spki" }).subarray(12);
}

export function expectedWebhookValue(url, types = []) {
  const kinds = [...types].sort().join(",") || "all";
  return `sha256=${crypto.createHash("sha256").update(url, "utf8").digest("hex")} kinds=${kinds}`;
}

/** Answers GET /account, GET /account/webhooks (with `listed`), and each
 *  webhook change with its sealed record; `change` edits the record, to make a
 *  mismatch. Anything else is left to `other`. */
export function webhookSealer(seed, { listed = [], change = (record) => record, other = () => undefined } = {}) {
  const publicKey = publicKeyOfSeed(seed).toString("base64");
  const record = (action, value, body) => ({
    format: "verdifax.account-change.v1",
    action,
    decided_by: "owner",
    key_id: 0,
    value,
    changed_at: "2026-11-13T12:00:01Z",
    owner_signature: { public_key: publicKey, ...body.owner_signature },
    signal: { account: "account-7", sequence: 12 },
    account_change_hash: "a".repeat(64),
  });
  return (req, body, i) => {
    if (req.method === "GET" && req.url === "/account") return { json: { ok: true, account_id: "account-7", id: 7 } };
    if (req.method === "GET" && req.url === "/account/webhooks") return { json: { ok: true, webhooks: listed } };
    if (req.method === "POST" && req.url === "/account/webhooks") {
      const sealed = change(record("webhook.subscribed", expectedWebhookValue(body.url, body.types ?? []), body));
      return { status: 201, json: { ok: true, id: 3, url: body.url, types: body.types ?? [], created_at: "2026-11-13T12:00:00Z", secret: "whsec_x", hint: "h", account_change: sealed } };
    }
    const end = /^\/account\/webhooks\/(\d+)$/.exec(req.url);
    if (req.method === "DELETE" && end) {
      const hook = listed.find((h) => h.id === Number(end[1]));
      const sealed = change(record("webhook.deleted", expectedWebhookValue(hook.url, hook.types), body));
      return { json: { ok: true, id: hook.id, deleted: true, account_change: sealed } };
    }
    return other(req, body, i);
  };
}
