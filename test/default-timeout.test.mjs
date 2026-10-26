// The default request timeout outlasts a slow sealed run: 30 seconds made
// the client report an error for a run the server went on to seal
// (readiness run 259, October 26, 2026).
import { test } from "node:test";
import assert from "node:assert/strict";
import { VerdifaxClient } from "../dist/index.mjs";

test("default timeout is at least 90 seconds", () => {
  const c = new VerdifaxClient({ baseURL: "https://api.verdifax.com", apiKey: "x" });
  assert.ok(c.timeoutMs >= 90_000, `default timeout ${c.timeoutMs} ms`);
});
