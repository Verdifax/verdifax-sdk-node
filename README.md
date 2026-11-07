# verdifax (Node.js / TypeScript SDK)

The official Node.js SDK for the [Verdifax](https://verdifax.com)
orchestrator REST API. TypeScript-native, ships dual CJS+ESM,
zero runtime dependencies (uses native `fetch` from Node 22+).

## Install

```bash
npm install verdifax
# or
yarn add verdifax
# or
pnpm add verdifax
```

Requires Node 22 or newer.

## Quickstart

On a trial key, register a request key first and give the client that key: see [Request signing](#request-signing). Without it, a trial key refuses the run.

```typescript
import { VerdifaxClient } from "verdifax";

const client = new VerdifaxClient({
  baseURL: "https://api.verdifax.com",
  apiKey: process.env.VERDIFAX_API_KEY!,
});

// Attest a decision through the pipeline.
const run = await client.execute({
  program_id: "1111111111111111111111111111111111111111111111111111111111111111",
  route_id: "demo-attestation",
  registry_record_hash: "2222222222222222222222222222222222222222222222222222222222222222",
  payload_text: "first attestation",
});

console.log(`Sealed run ${run.run_id}, manifest hash ${run.manifest.ManifestHash}`);

// Verify the seal recomputes correctly.
const v = await client.verifyRun(run.run_id);
if (v.verified) {
  console.log("✓ Manifest hash recomputes.");
}
```

## What this SDK covers

| Method | Endpoint | Auth |
| --- | --- | --- |
| `client.health()` | `GET /health` | none |
| `client.version()` | `GET /version` | none |
| `client.getOpenAPI()` | `GET /openapi.json` | none |
| `client.getStats()` | `GET /stats` | required |
| `client.execute(req)` | `POST /execute` | required |
| `client.attest(req)` | `POST /execute` | required |
| `client.attestClaudeResponse(args)` | `POST /execute` | required |
| `client.attestOpenAIResponse(args)` | `POST /execute` | required |
| `client.executeBatch(runs)` | `POST /execute/batch` | required |
| `client.verifyDeterminism(req)` | `POST /execute/verify-determinism` | required |
| `client.getRun(id)` | `GET /runs/{id}` | required |
| `client.verifyRun(id)` | `GET /runs/{id}/verify` | required |
| `client.listRuns(params)` | `GET /runs` | required |
| `client.searchRuns(params)` | `GET /runs/search` | required |
| `client.exportRuns(params)` | `GET /runs/export` | required |
| `client.exportRunsCSV(params)` | `GET /runs/export?format=csv` | required |
| `client.getRunArtifacts(id)` | `GET /runs/{id}/artifacts` | required |
| `client.getRunReport(id)` | `GET /runs/{id}/report` | required |
| `client.downloadAuditPDF(id, format)` | `GET /runs/{id}/report.pdf` | required |
| `client.getAllowToken(id)` | `GET /runs/{id}/allow-token` | required |
| `client.getDenyReceipt(id)` | `GET /runs/{id}/deny-receipt` | required |
| `client.getCCVHaltReceipt(id)` | `GET /runs/{id}/ccv-halt-receipt` | required |
| `client.getMACCHaltReceipt(id)` | `GET /runs/{id}/macc-halt-receipt` | required |
| `client.getAivpT4HaltReceipt(id)` | `GET /runs/{id}/aivp-t4-halt-receipt` | required |
| `client.getAttestationGapReceipt(id)` | `GET /runs/{id}/attestation-gap-receipt` | required |
| `client.getCESAuditRecord(id)` | `GET /runs/{id}/ces-audit-record` | required |
| `client.listDeletionReceipts(id)` | `GET /runs/{id}/deletion-receipts` | required |
| `client.listAttestations(params)` | `GET /attestations` | required |
| `client.getAttestation(id)` | `GET /attestations/{id}` | required |
| `client.getPublicBundle(id)` | `GET /runs/{id}/bundle.json` | none |
| `client.getPublicBundleByToken(token)` | `GET /public/runs/{token}/bundle.json` | none |
| `client.dcaeVerify(bundle)` | `POST /dcae/verify` | none |
| `client.registerRequestKey()` | `POST /keys/request-key` | required |
| `client.rotateRequestKey(newSigningKey)` | `POST /keys/request-key` | required |
| `client.clearRequestKey()` | `DELETE /keys/request-key` | required |
| `client.adminCreateKey(name)` | `POST /admin/keys` | admin |
| `client.adminListKeys()` | `GET /admin/keys` | admin |
| `client.adminRevokeKey(id)` | `DELETE /admin/keys/{id}` | admin |
| `client.adminClearRequestKey(id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `client.adminErase(req)` | `POST /admin/erase` | admin |

`client.job(jobId)` returns a [job helper](#jobs) and makes no request until a step runs.

These functions make no request: `captureEnvironment`, `formatProviderPayload`, `signRequest`, `signRequestV2`, `requestKeyRegistrationBody`, `requestKeyChangeApproval`, `requestKeyChangePreimage`, `requestSignaturePreimage`, `requestSignaturePreimageV2`, `generateRequestKeyPair`, `validateHex64`, `validateJobName`, `validateRouteId`, `dseDispatchHash`, `dcaeClosureHash` and `cresReceiptHash`. `RUN_STATUSES` lists every run status the server uses.

`getRunArtifacts`, `getPublicBundle` and `getPublicBundleByToken` return the exact JSON text the server sent, so you can save it and check it with `verdifax-verify`.

## Versioning

From 1.0, a breaking change needs a new major version.

## Settings

`new VerdifaxClient(config)` takes these options. `fromEnv()` reads the same settings from the environment.

| Setting | Option | Environment variable | Default |
| --- | --- | --- | --- |
| Base URL | `baseURL` | `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL` | `https://api.verdifax.com` |
| API key | `apiKey` | `VERDIFAX_API_KEY` | none |
| Timeout | `timeoutMs` | `VERDIFAX_TIMEOUT_MS` | 90 seconds |
| User agent | `userAgent` | `VERDIFAX_USER_AGENT` | `verdifax-sdk-node/<version>` |
| Retries | `maxRetries` | `VERDIFAX_MAX_RETRIES` | 3 |
| First retry delay | `retryBaseDelayMs` | none | 200 ms |

GET, HEAD and OPTIONS requests are retried after a network failure or an HTTP 429, 502, 503 or 504, with exponential backoff and full jitter. POST is never retried.

## Batch runs

`executeBatch(runs)` sends up to 1,000 runs in one request and refuses more before sending anything. A row that fails comes back in `results` with `ok: false`, so the call does not throw for it.

```typescript
const batch = await client.executeBatch([
  { program_id, route_id, registry_record_hash, payload_text: "first" },
  { program_id, route_id, registry_record_hash, payload_text: "second" },
]);

for (const row of batch.results) {
  console.log(row.index, row.ok, row.ok ? row.run_id : row.error);
}
```

The client's timeout covers the whole batch, so raise `timeoutMs` for a large one. A batch is one POST and it is never retried. After a timeout the server may have run some or all of the rows, so list your runs before you send them again.

## Jobs

A job links several runs into one map: each step names the records it directly follows, so work can split into branches and join again. `client.job(jobId)` returns a helper that keeps the map for you.

```typescript
const job = client.job("loan-1042");
const run = { program_id, route_id, registry_record_hash };

await job.step("intake", { ...run, payload_text: "application received" });

// Two branches after one step.
await job.step("credit", { ...run, payload_text: "credit check", after: ["intake"] });
await job.step("income", { ...run, payload_text: "income check", after: ["intake"] });

// A final step joining them.
await job.step("decide", {
  ...run,
  payload_text: "decision",
  after: ["credit", "income"],
  final: true,
});

console.log(job.recordHashes); // step id to record hash
console.log(job.signedRequests); // step id to signed text, when the client signs
```

`job.step(stepId, options)` takes everything `attest` takes, plus `after`, `external_previous` and `final`, and returns what `attest` returns. `after` lists step ids in this job. Without it, a step follows the one run just before it through this helper, and the first step follows nothing. An `after` that names an unknown step throws a `VerdifaxError` before anything is sent.

A refused or halted step stays in the map, so a later step can follow it. `job.step` records its hash and signed text, then throws the same `APIError` that `attest` throws, with the hash in `err.recordHash`. A step that sealed nothing, such as a timeout or a 409, is not in the map and does not move the default `after`, so it can run again under the same id. To run branches at the same time, give each one its `after`. An empty `after` starts another root step.

A successful step records `record_hash`, or `manifest_hash` if the response has no `record_hash`. If it has neither, `job.step` throws a `VerdifaxError`, so the map never silently gets a gap. A mistyped option such as `afer` is refused before sending, so a typo cannot silently drop a link.

`execute`, `attest` and each row of `executeBatch` also take a `job` block directly: `{ job_id, step_id, previous_record_hashes, external_previous, final }`. Results carry `record_hash`. `job_id` and `step_id` are 1 to 128 letters, digits, `.`, `_`, `:` or `-`, and any other name is refused before sending. The SDK sorts both lists and removes repeats, and refuses unknown fields, a `final` that is not true or false, and hash lists that are not lists. A determinism check runs twice, so `verifyDeterminism` refuses a job.

The server refuses a step in a closed job, a repeated step id, and a final step that leaves a branch with no step after it. To check a whole job, save each record in one folder and run `verdifax-verify --job FOLDER`.

A job map covers what was sent. It cannot show a step that was never sent.

## Evidence export

`exportRuns` lists the runs the server holds for your key in a period, failures included, with up to 10,000 rows per export. `exportRunsCSV` returns the same rows as raw CSV text.

```typescript
const period = { from: "2026-11-01T00:00:00Z", to: "2026-12-01T00:00:00Z" };

const evidence = await client.exportRuns(period);
console.log(evidence.total, evidence.truncated, evidence.by_status);

const { csv, total, truncated } = await client.exportRunsCSV(period);
if (truncated) {
  console.log(`The CSV holds part of ${total} runs. Use a narrower period.`);
}
```

Pass `job_id` in the period to export one job. JSON rows also carry `anchor_source` (`bundle`, `receipt` or `none`), and `job_id` and `step_id` when the run is a job step.

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `truncated`. `exportRunsCSV` reads `total` and `truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and throws if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Provider helpers

`attestClaudeResponse` and `attestOpenAIResponse` attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `formatProviderPayload` builds that text. All four Verdifax SDKs produce the same bytes. A helper call from an earlier version used a different payload, so it gave a different hash for the same text; records already stored are not touched.

```typescript
await client.attestClaudeResponse({
  program_id,
  route_id,
  registry_record_hash,
  prompt: "What is the boiling point of water?",
  response: "100 C at sea level.",
  govern: true,
});
```

Both helpers take the same optional `job` block as `attest` and return `record_hash` and `signed_request` the same way.

`govern` is false by default, which changes earlier behavior. Set `govern: true` to also send the response text as `ai_output_text` for the AIVP review, which runs on Anthropic in production. Without it, the AI output text is not sent for review.

## Optional execute fields

`execute`, `attest`, `executeBatch` and `verifyDeterminism` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. Each is recorded as supplied and Verdifax does not check it. The client derives `attested` and `declared` from the fields you provide. Leave out `request_substance.origin.source_ip_hash` and `user_agent_hash`: the server computes them. `execute`, `attest` and `verifyDeterminism` refuse them before sending, and a batch row that sets them fails in `results`.

`execute`, `attest` and `verifyDeterminism` check that `program_id` and `registry_record_hash` are 64 lowercase hex characters and that `route_id` is 1 to 256 printable ASCII characters.

## Environment capture

`captureEnvironment()` records the Node version, the platform, the packages under `node_modules`, the git commit and any seeds you declare. Pass the result as `reproducibility_context` on `execute`, `attest`, `executeBatch` or `verifyDeterminism`. Detection is best effort, and a value it cannot read is left out. The server records these values as given and does not check them.

## Determinism check

`verifyDeterminism(req)` runs one payload twice on the server and compares the manifest hashes. `deterministic` is true when both runs ended `ok` and the two hashes match. Both runs are recorded, with the status `probe`.

## Authentication

Every authenticated endpoint expects the API key in the
`X-Verdifax-Key` header. The client injects it automatically when
the config carries `apiKey`.

Provision an API key via:

```bash
curl -X POST https://api.verdifax.com/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "node-sdk-prod"}'
```

The response carries the secret **once**, store it immediately.

## Error handling

The SDK throws typed errors so callers can `instanceof` to
discriminate:

```typescript
import { VerdifaxClient, AuthError, NotFoundError, APIError } from "verdifax";

try {
  await client.getRun(142);
} catch (err) {
  if (err instanceof NotFoundError) {
    // run doesn't exist (or belongs to a different key)
  } else if (err instanceof AuthError) {
    // missing or invalid API key
  } else if (err instanceof APIError) {
    // every other non-2xx, err.status carries the HTTP code
  }
}
```

## Request signing

A trial key, which is what a pilot receives, needs a request key: it seals nothing until one is registered, and the key can then be replaced but not cleared. On a production key, request signing is optional, and a client with no signing key sends the same requests as before.

You can register an Ed25519 public key on your API key, so that each run must also be signed with a private key that only you hold. The key pair is created on your machine, and Verdifax receives only the public key.

```typescript
import { writeFileSync } from "node:fs";
import { VerdifaxClient, generateRequestKeyPair } from "verdifax";

// Run once, then store privateKey as a secret.
const { privateKey } = generateRequestKeyPair();

const client = new VerdifaxClient({
  apiKey: process.env.VERDIFAX_API_KEY!,
  signingKey: privateKey, // the 32 raw bytes, as a Buffer or Uint8Array
});

await client.registerRequestKey(); // sends the public key with its proof

// execute, attest, attestClaudeResponse, attestOpenAIResponse, executeBatch
// and verifyDeterminism now sign.
const run = await client.execute({
  program_id: "1111111111111111111111111111111111111111111111111111111111111111",
  route_id: "demo-attestation",
  registry_record_hash: "2222222222222222222222222222222222222222222222222222222222222222",
  payload_text: "first signed attestation",
});

// The exact text that was signed. Keep it for verdifax-verify --request FILE.
writeFileSync("signed-request.json", run.signed_request!);

// The current key approves the change, and this client then signs with the new key.
await client.rotateRequestKey(generateRequestKeyPair().privateKey);

await client.clearRequestKey(); // stops requiring signatures, and this client stops signing
```

A signed call serializes the request once and signs that exact text, using signature version 2, so the signature covers the whole request. It sends `signed_request` and `request_signature` and nothing else, and a batch row has the same shape. The result carries the text as `signed_request`, on each row for a batch. A refused or halted run throws the usual `APIError`, with the text in `err.signedRequest`. It holds your payload, so it stays out of the error message and logging the error does not print it: read it by name.

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. An API key alone cannot replace or clear a registered key: `rotateRequestKey` and `clearRequestKey` send the current key's approval. After a successful `clearRequestKey` the client drops its signing key and sends unsigned requests, because the server refuses a signed run on an API key with no registered key. To sign again, create a client with a `signingKey` and register it. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

A signature shows who requested the run, not that they accepted the outcome.

## Trust model

This SDK only mediates HTTP I/O, it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify)
CLI, v0.17.2 or later (signed binaries with SLSA provenance on its GitHub
Releases), which checks both audit bundles and deny or halt receipts.

## License

MIT, see [LICENSE](LICENSE).
