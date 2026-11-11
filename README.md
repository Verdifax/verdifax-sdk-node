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
| `client.downloadAuditPDF(id, format, { aiOutputText })` | `GET /runs/{id}/report.pdf`, or `POST` with the AI's answer, printed when its SHA-256 is the sealed hash | required |
| `client.downloadPublicAuditPDF(token, format, { aiOutputText })` | `GET` or `POST /public/runs/{token}/report.pdf` | none |
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
| `client.uploadPolicy(document)` | `POST /policies` | required |
| `client.listPolicies()` | `GET /policies` | required |
| `client.getPolicy(documentHash)` | `GET /policies/{document_hash}` | required |
| `client.testPolicy({ inputs, document?, documentHash? })` | `POST /policies/test` | required |
| `client.getPolicyHistory()` | `GET /policies/history` | required |
| `client.activatePolicy(documentHash)` | `POST /policies/{document_hash}/activate` | required |
| `client.getAccount()` | `GET /account` | owner key |
| `client.createAccountKey(name, { expiresAt? })` | `POST /account/keys` | owner key |
| `client.listAccountKeys()` | `GET /account/keys` | owner key |
| `client.revokeAccountKey(id)` | `DELETE /account/keys/{id}` | owner key |
| `client.registerAccountRequestKey()` | `POST /account/request-key` | owner key |
| `client.clearAccountRequestKey()` | `DELETE /account/request-key` | owner key |
| `client.listAccountRuns(params)` | `GET /account/runs` | owner key |
| `client.exportAccountRuns(params)` | `GET /account/runs/export` | owner key |
| `client.exportAccountRunsCSV(params)` | `GET /account/runs/export?format=csv` | owner key |
| `client.uploadAccountPolicy(document)` | `POST /account/policies` | owner key |
| `client.listAccountPolicies()` | `GET /account/policies` | owner key |
| `client.getAccountPolicy(documentHash)` | `GET /account/policies/{document_hash}` | owner key |
| `client.testAccountPolicy({ inputs, document?, documentHash? })` | `POST /account/policies/test` | owner key |
| `client.getAccountPolicyHistory()` | `GET /account/policies/history` | owner key |
| `client.activateAccountPolicy(documentHash)` | `POST /account/policies/{document_hash}/activate` | owner key |
| `client.registerApprover(name, approver)` | `POST /account/approvers` | owner key |
| `client.listApprovers()` | `GET /account/approvers` | owner key |
| `client.revokeApprover(id)` | `DELETE /account/approvers/{id}` | owner key |
| `client.getSignOffHistory()` | `GET /account/signoffs/history` | owner key |
| `client.getNewestSignOff({ asOwner? })` | `GET /signoffs/newest`, or `GET /account/signoffs/newest` with `asOwner` | required, or owner key |
| `client.signOff(target, decision, approverKey, { note?, asOwner? })` | `POST /signoffs`, or `POST /account/signoffs` with `asOwner` | required, or owner key |
| `client.getSignOffs(runId, { asOwner? })` | `GET /runs/{id}/signoffs`, or `GET /account/runs/{id}/signoffs` with `asOwner` | required, or owner key |
| `client.getSignals({ after?, limit?, wait?, asOwner? })` | `GET /signals`, or `GET /account/signals` with `asOwner` | feed key, or owner key |
| `client.followSignals({ after?, wait?, asOwner? })` | `GET /signals` page after page, or `GET /account/signals` with `asOwner` | feed key, or owner key |
| `client.createFeedKey(name, { expiresAt? })` | `POST /account/feed-keys` | owner key |
| `client.revokeFeedKey(id)` | `DELETE /account/feed-keys/{id}` | owner key |
| `client.createWebhook(url, { types? })` | `POST /account/webhooks` | owner key |
| `client.listWebhooks()` | `GET /account/webhooks` | owner key |
| `client.deleteWebhook(id)` | `DELETE /account/webhooks/{id}` | owner key |
| `client.listWebhookDeliveries(id, { limit? })` | `GET /account/webhooks/{id}/deliveries` | owner key |
| `client.getFailureReceipt(id)` | `GET /runs/{id}/failure-receipt` | required |
| `client.adminCreateKey(name, { accountId? })` | `POST /admin/keys` | admin |
| `client.adminListKeys()` | `GET /admin/keys` | admin |
| `client.adminRevokeKey(id)` | `DELETE /admin/keys/{id}` | admin |
| `client.adminClearRequestKey(id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `client.adminCreateAccount(name, { tier?, expiresAt? })` | `POST /admin/accounts` | admin |
| `client.adminListAccounts()` | `GET /admin/accounts` | admin |
| `client.adminErase(req)` | `POST /admin/erase` | admin |

`client.job(jobId)` returns a [job helper](#jobs) and makes no request until a step runs.

These functions make no request: `captureEnvironment`, `formatProviderPayload`, `signRequest`, `signRequestV2`, `requestKeyRegistrationBody`, `requestKeyChangeApproval`, `requestKeyChangePreimage`, `policyActivationApproval`, `policyActivationPreimage`, `signOffPreimage`, `approverKeyProof`, `verifyWebhook`, `signalEventHash`, `requestSignaturePreimage`, `requestSignaturePreimageV2`, `generateRequestKeyPair`, `validateHex64`, `validateJobName`, `validateRouteId`, `dseDispatchHash`, `dcaeClosureHash` and `cresReceiptHash`. `RUN_STATUSES` lists every run status the server uses, and `EXECUTE_FIELDS` lists every top-level key a run request may hold.

`getRunArtifacts`, `getPublicBundle` and `getPublicBundleByToken` return the exact JSON text the server sent, so you can save it and check it with `verdifax-verify`.

## Versioning

From 1.0, a breaking change needs a new major version. See [CHANGELOG.md](CHANGELOG.md) for what each release added.

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

## Policies

A policy is your own set of rules that decides whether a run is allowed or refused, from the facts the run declares. You upload its exact text, test it on sample inputs, then activate it. Each change is one more link in a chain of changes on the public log.

```typescript
import { readFileSync, writeFileSync } from "node:fs";

// Upload the exact text. Nothing changes until it is activated.
const stored = await client.uploadPolicy(readFileSync("policy.json", "utf8"));

// See which rule would fire on sample inputs. This seals nothing.
const trial = await client.testPolicy({
  documentHash: stored.document_hash,
  inputs: { subject_type: "agent", verb: "approve-loan", object_type: "transaction", classification: "CONFIDENTIAL" },
});
console.log(trial.outcome, trial.fired_rule_id, trial.reason_code);

// Make it the policy in force. With a signingKey the request key signs the change.
const change = await client.activatePolicy(stored.document_hash);

// A run declares the facts the rules read, and can name the policy it expects.
await client.attest({
  program_id,
  route_id,
  registry_record_hash,
  payload_text: "approve loan 1042",
  attested_context: { actor_id: "agent:loan-bot" },
  policy_context: {
    actor_type: "agent",
    mfa_satisfied: true,
    object_type: "transaction",
    object_id: "loan-1042",
    classification: "CONFIDENTIAL",
  },
  expected_policy_hash: change.policy_hash,
});

// Roll back by activating an earlier document.
await client.activatePolicy(earlierDocumentHash);

// Save the chain of changes and check it with verdifax-verify --policy-history policy-history.json.
writeFileSync("policy-history.json", (await client.getPolicyHistory()).sealedJson);
```

`uploadPolicy` sends the string it is given unchanged, because the server hashes the exact text, and it refuses anything that is not a string. `getPolicy` returns a stored document with its exact text. `testPolicy` takes exactly one of `document` and `documentHash`. `listPolicies` returns the documents, `chain_id`, the newest change as `newest_activation_hash` (64 zeros when there is none yet) and the document in force as `active_document_hash` (empty under the built-in policy).

`activatePolicy` reads `listPolicies` first and names the newest change as the one it follows. With the `signingKey` option it sends the request key's signature over the chain, the document and that change, which the server requires while a request key is registered. Rolling back is activating an earlier document: it is one more change, so the change it undoes stays on the record. An HTTP 409 means another change came first or the document is not yet effective. It throws the usual `APIError` and is not retried. `getPolicyHistory` returns the changes oldest first, in the form `verdifax-verify --policy-history FILE` reads.

`execute`, `attest`, each row of `executeBatch`, `verifyDeterminism`, `job.step` and the provider helpers take `policy_context` and `expected_policy_hash`. `policy_context` holds only `actor_type` (`agent`, `user`, `service` or `system`), `mfa_satisfied` (true or false), `session_age_seconds` (a whole number, not negative), `object_type` (`text`, `transaction`, `code`, `data`, `model` or `file`), `object_id` (at most 256 bytes) and `classification` (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET` or `TS_SCI`). Any other key or value is refused before sending, because a misspelt key would be dropped and a rule on it would read its zero value. `actor_type`, `mfa_satisfied` and `session_age_seconds` describe the attested actor, so a run that sets one of them must also send `attested_context` with the actor, such as its `actor_id`. `expected_policy_hash` is 64 lowercase hex characters: when another policy is active the server refuses the run with HTTP 409. Both fields are inside `signed_request` on a signed client.

Verdifax did not write, review or approve your policy. A pass means the rules ran, not that they are good rules.

A policy judges what you declared. It cannot show the declared facts are true.

A refusal stops the action only if your system waits for the answer.

## Accounts

An account is a company on Verdifax. Every API key belongs to one account for life. An account has an owner key, which manages the account: it creates and revokes the member keys, sets the account policy and reads the account's runs. The member keys are the keys that run things.

```typescript
import { readFileSync, writeFileSync } from "node:fs";
import { VerdifaxClient, generateRequestKeyPair } from "verdifax";

// Verdifax creates the account and its first owner key.
const admin = new VerdifaxClient({ apiKey: process.env.VERDIFAX_ADMIN_KEY! });
const { account, owner_key } = await admin.adminCreateAccount("Acme", { tier: "production" });
console.log(account.account_id, owner_key.secret); // the secret is shown once

// The owner registers a request key, which must sign every account policy change.
const { privateKey } = generateRequestKeyPair();
const owner = new VerdifaxClient({ apiKey: owner_key.secret, signingKey: privateKey });
await owner.registerAccountRequestKey();

// The owner creates member keys. Each one stays in the account for life.
const member = await owner.createAccountKey("loan-bot");
console.log(member.id, member.secret); // the secret is shown once

// The owner loads, tests and activates the account policy, signed by its request key.
const stored = await owner.uploadAccountPolicy(readFileSync("account-policy.json", "utf8"));
await owner.testAccountPolicy({ documentHash: stored.document_hash, inputs: { verb: "approve-loan" } });
await owner.activateAccountPolicy(stored.document_hash);

// The owner exports the runs of every key in the account, with the account policy and its changes.
const evidence = await owner.exportAccountRuns({ from: "2026-11-01T00:00:00Z", to: "2026-12-01T00:00:00Z" });
writeFileSync("account-runs.json", evidence.sealedJson);
```

An owner key cannot run anything. Every route that needs a key refuses it, apart from the `/account` routes, so give the member keys to the systems that run things.

The account number, such as `account-7`, is a label Verdifax assigned. It is not a verified company identity.

An account policy is the customer's own. Verdifax did not write, review or approve it. Every key in the account must pass the account policy on top of its own policy, and a run is admitted only when both allow it.

The account's view covers the runs its keys made through Verdifax. It does not cover runs made elsewhere.

`activateAccountPolicy` reads `listAccountPolicies` first, names the newest change as the one it follows and signs the change over the account's chain, `account-N`, with the same signature `activatePolicy` uses. The server refuses an unsigned account policy change, so `activateAccountPolicy` needs the `signingKey` option, set to the owner key's registered request key, and refuses before sending anything without it. It also refuses a `chain_id` that is not of the form `account-N`. The other account policy methods take and return what the matching key policy methods do. `getAccountPolicyHistory` returns the account's changes oldest first, in the form `verdifax-verify --policy-history FILE` reads.

`exportAccountRuns` and `exportAccountRunsCSV` take the same period and `job_id` as `exportRuns` and check the CSV counts the same way. The JSON form also carries `account_id`, and `account_policy_documents` and `account_policy_history` once the account has loaded a policy. `listAccountRuns` pages like `listRuns`. `revokeAccountKey` revokes a member key, and a key in another account, or an owner key, throws `NotFoundError`. `adminCreateKey(name, { accountId })` puts a new customer key in an existing account, by its number.

## Sign-off

A sign-off is an approver's decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step. The approver signs it on their own machine with an approver key, and Verdifax links it to the account's previous sign-off and logs it on the public log.

```typescript
import { writeFileSync } from "node:fs";
import { VerdifaxClient, approverKeyProof, generateRequestKeyPair } from "verdifax";

// The approver creates a key on their own machine and keeps the private key.
const approverKey = generateRequestKeyPair().privateKey;
const proof = approverKeyProof(approverKey); // { public_key, proof }, safe to hand to the owner

// The account's owner registers the approver key.
const owner = new VerdifaxClient({ apiKey: process.env.VERDIFAX_OWNER_KEY! });
await owner.registerApprover("credit review", proof);

// Any key in the account submits the approver's signed decision on one exact result.
const member = new VerdifaxClient({ apiKey: process.env.VERDIFAX_API_KEY! });
const bundle = JSON.parse(await member.getRunArtifacts(1042));
const signOff = await member.signOff(
  { kind: "record", run_id: 1042, digest: bundle.bundle_anchor.anchored_digest },
  "approve",
  approverKey,
  { note: "Checked against the loan file." }, // only its SHA-256 is sent
);
console.log(signOff.sequence, signOff.signoff_hash);

// Save the run's sign-offs and check them with verdifax-verify --signoff signoffs.json.
writeFileSync("signoffs.json", (await member.getSignOffs(1042)).sealedJson);

// The owner saves the account's whole chain for verdifax-verify --signoff-history.
writeFileSync("signoff-history.json", (await owner.getSignOffHistory()).sealedJson);
```

An approver key is registered by the account's owner, and it is never a request key in the same account. The server refuses to register a key that is, so the key that requested a run cannot sign it off. `registerApprover` takes the approver's signing key, from which it makes the proof on this machine, or the `{ public_key, proof }` that `approverKeyProof` made on the approver's own machine, so the owner need not hold the approver's private key. It refuses a proof that does not verify before sending. `revokeApprover` revokes a key, and its earlier sign-offs stay on the record. `listApprovers` lists revoked keys too.

`signOff` reads `getNewestSignOff` first for the account's chain, `account-N`, and its newest sign-off, then signs over them, the target, the decision, the note's hash, the time and a fresh nonce. The approver's private key is never sent. The target's `digest` is what the result's public-log entry covers: for a record, the `bundle_anchor.anchored_digest` of the bundle `getRunArtifacts` returns; for a receipt, its hash; for a job, the final step's record digest, read the same way as a record's, with `job_id`. The note is hashed on your machine and only its SHA-256 is sent and signed: the note's text never reaches Verdifax, so keep it yourself. `signOff` refuses a bad target, decision, key or note before sending anything. It also checks that the record the server returns carries the signature, `approver_key`, `decision`, `previous_signoff_hash` and `target` that were sent, and throws `VerdifaxError` if not. An HTTP 409 means another sign-off came first or the target is not this account's result: it throws the usual `APIError` and is not retried.

With `asOwner: true`, `signOff`, `getNewestSignOff` and `getSignOffs` use the owner key's `/account` routes. `getSignOffs` returns a run's sign-offs oldest first, in the form `verdifax-verify --signoff FILE` reads: for a member key, a run it made; with `asOwner`, any run of the account. `getSignOffHistory` returns the account's whole chain, oldest first, in the form `verdifax-verify --signoff-history FILE` reads, and `exportAccountRuns` carries the same chain as `signoffs`. The SDK returns `signoffs` as the server sent it, without checking it: check it with `verdifax-verify --signoff-history`.

A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show that the review was careful, that the result is right, or who the person is. A key is not an identity.

A sign-off gates nothing on its own.

A later sign-off on the same result supersedes the earlier one, and nothing is deleted.

Verdifax did not review the result.

Since v0.22.0, the verifier reads sign-offs with `--signoff` and `--signoff-history`.

## Signal feed

The signal feed is every control signal Verdifax recorded for the account, in order: refused, halted and failed runs, policy changes, sign-offs, approver keys registered and revoked, and keys created and revoked. Each event is a CloudEvent that carries its sealed entry, its place in the feed and the hash of the event before it. The feed cannot show a signal Verdifax never recorded.

A feed key reads the feed and nothing else. The account's owner creates one with `createFeedKey` and revokes it with `revokeFeedKey`, and the owner key reads the same feed with `asOwner: true`.

```typescript
import { writeFileSync } from "node:fs";
import { SignalFeedError, VerdifaxClient } from "verdifax";

const owner = new VerdifaxClient({ apiKey: process.env.VERDIFAX_OWNER_KEY! });
const { secret } = await owner.createFeedKey("grc reader"); // shown this once

const feed = new VerdifaxClient({ apiKey: secret });
let after = 0; // the last sequence your system stored
try {
  for await (const event of feed.followSignals({ after })) {
    console.log(event.data.sequence, event.type, event.data.reason ?? "");
    after = event.data.sequence;
  }
} catch (err) {
  if (!(err instanceof SignalFeedError)) throw err;
  after = err.lastSequence; // follow again from here and nothing is lost
}

// Save a page and check it with verdifax-verify --signals signals.json.
writeFileSync("signals.json", (await feed.getSignals({ limit: 500 })).sealedJson);
```

`followSignals` reads page after page and starts each read at the previous page's `next_after`, so it never skips an event, and it refuses a page that would skip or go back. When there is no new event, each read waits up to `wait` seconds (default 25) on the server. A failed read is retried like any GET. If it still fails, `followSignals` throws `SignalFeedError`, whose `lastSequence` is the last sequence it handed out and whose `cause` is the error the read threw. It runs until you stop it with `break` or `return`. `getSignals` reads one page: `after` is the last sequence read (default 0), `limit` is 1 to 500 and `wait` is 0 to 25 seconds. The timeout of a signals call is at least its wait plus 30 seconds, whatever the client's `timeoutMs`. Bad options are refused before anything is sent.

The owner key subscribes an https address with `createWebhook(url, { types })`, at most ten per account. `types` are the kinds to deliver, each once; empty or left out takes every kind. The secret, `whsec_` and base64, is in the result this once. Each delivery is signed under the Standard Webhooks scheme. Check it with `verifyWebhook` before you use it, passing the body exactly as received:

```typescript
import http from "node:http";
import { verifyWebhook } from "verdifax";

http
  .createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const event = verifyWebhook(req.headers, Buffer.concat(chunks), process.env.VERDIFAX_WEBHOOK_SECRET!);
        console.log(event.data.sequence, event.type);
        res.statusCode = 204;
      } catch (err) {
        console.error((err as Error).message); // names the check that failed, never the secret
        res.statusCode = 400;
      }
      res.end();
    });
  })
  .listen(8080);
```

`verifyWebhook` reads the `webhook-id`, `webhook-timestamp` and `webhook-signature` headers without regard to case. It refuses a timestamp more than `toleranceSeconds` (default 300) from `now` in either direction, accepts the delivery when any one `v1` signature matches, compares in constant time and returns the parsed CloudEvent. It throws `VerdifaxError` naming the check that failed, and never puts the secret in a message.

A webhook delivery is a copy: the pull feed and the public log are the record. A delivery can fail or arrive more than once, so store `data.sequence` and read the feed from the last one you stored. `listWebhookDeliveries(id, { limit })` shows each delivery's status and attempts, newest first. `deleteWebhook` ends a subscription, and its events stay in the feed.

`getFailureReceipt(runId)` returns a failed run's sealed failure receipt, in the form `verdifax-verify` reads. A run that failed before failure receipts were sealed has none, and the call throws `NotFoundError`.

`signalEventHash(kind, entryHash, { account, sequence, previousSignalHash })` recomputes an event's `event_hash`, the hash the next event names. It makes no request.

`verdifax-verify --signals FILE` checks a saved feed: each entry as its own kind, that the place each entry seals is the event's place, and that the numbers and links run without a gap.

## Exact records

Every object and list the SDK parses from the server's JSON answer carries `sealedJson`: its exact text as the server sent it. A method that returns part of an answer, such as the `activation` of a policy change or the `runs` of a run list, returns that part with its own `sealedJson`. Methods that return text, such as `getRunArtifacts` and the CSV exports, return it exactly. JavaScript rounds a number above 2^53, so a record parsed and written back with `JSON.stringify` could stop matching its hash; `sealedJson` keeps every field and every digit. Save `sealedJson` for `verdifax-verify`. It is read-only and not enumerable, so `JSON.stringify`, `Object.keys` and spreading never include it. `parseSealed(text)` reads text you hold, such as a saved file, the same way.

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

The server ignores a key it does not know, so a misspelt field would be dropped with no error. The client refuses it instead, before sending: a run request for `execute`, `attest`, `verifyDeterminism`, `job.step` or a row of `executeBatch` with a top-level key outside `EXECUTE_FIELDS`, or an `attested_context` key outside `attested`, `actor_id`, `actor_role`, `authorization_policy`, `actor_signature`, `model_provider`, `model_name`, `model_version`, `model_temperature`, `prompt_hash`, `decision_kind`, `decision_result` and `decision_note`, throws a `VerdifaxError` naming the key. `attest` also refuses `request_signature` and `signed_request`, which it does not send. `attestClaudeResponse` and `attestOpenAIResponse` accept their own argument names and every name in `EXECUTE_FIELDS`, so a run request spread into the arguments keeps working, and refuse any other key the same way. Responses are not checked this way: a field a newer server adds is kept and does not throw.

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
