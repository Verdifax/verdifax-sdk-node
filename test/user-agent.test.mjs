// The default User-Agent names the package's real version (round 43:
// every release through 0.2.7 sent verdifax-sdk-node/0.2.0, so the server
// could not tell a 30-second-timeout client from a fixed one).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { VerdifaxClient } from "../dist/index.mjs";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("the default User-Agent is verdifax-sdk-node/<package version>", async () => {
  let seen;
  const server = http.createServer((req, res) => {
    seen = req.headers["user-agent"];
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true, service: "verdifax-orchestrator-api" }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const c = new VerdifaxClient({ baseURL: `http://127.0.0.1:${server.address().port}`, apiKey: "x" });
    await c.health();
    assert.equal(seen, `verdifax-sdk-node/${version}`);
  } finally {
    server.close();
  }
});
