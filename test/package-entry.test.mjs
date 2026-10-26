// Every entry point package.json names must exist in the built package
// and load: v0.2.3 shipped "require": "./dist/index.cjs", which the build
// never produced, so require("verdifax") failed for every CommonJS user.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));

function paths(node) {
  if (typeof node === "string") return [node];
  return Object.values(node).flatMap(paths);
}

test("every path package.json points to exists in the build", () => {
  for (const p of [pkg.main, pkg.module, pkg.types, ...paths(pkg.exports)].filter(Boolean)) {
    assert.ok(existsSync(new URL(`../${p}`, import.meta.url)), `missing ${p}`);
  }
});

test("require() and import both load the client", async () => {
  const require = createRequire(import.meta.url);
  const cjs = require("..");
  const esm = await import("verdifax");
  for (const mod of [cjs, esm]) {
    assert.equal(typeof mod.VerdifaxClient, "function");
    assert.equal(typeof new mod.VerdifaxClient({ baseURL: "https://api.verdifax.com", apiKey: "x" }).execute, "function");
  }
});
