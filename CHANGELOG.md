# Changelog

## 1.16.0

Webhook changes signed by the owner and sealed in the feed.

- From verifier v0.35.0's server release on, a webhook is added and removed only with its record in the account's feed: an `account.changed` event, `webhook.subscribed` or `webhook.deleted`, decided by the owner and signed by the owner key's request key over the webhook's value, `sha256=` and the SHA-256 of the address exactly as sent, then ` kinds=` and the kinds sorted and joined with commas, or `all`. The record never holds the address, which can carry a token, so Verdifax, which never holds the owner's request key, cannot add a destination for the account's events. The server refuses an address not sent in the form it stores, with a 400 naming that form.
- `createWebhook(url, { types, accountId })` and `deleteWebhook(id, { accountId })` sign the change with the `signingKey` option, the owner key's request key, and throw `VerdifaxError` before anything is sent without it. `deleteWebhook` reads the subscription from `listWebhooks()` and signs its value; an id the account holds no live webhook with throws before the removal is sent. Both check the record in the answer, now typed as `account_change` on `CreatedWebhook` and `WebhookDeletion`: it must carry the change, the value, `decided_by` owner and the signature sent, or they throw `VerdifaxError`. A webhook body is sent as the address, the kinds when named, then the owner's signature, the same in every SDK.
- `webhookValue(url, types)`, `WEBHOOK_SUBSCRIBED` and `WEBHOOK_DELETED` are exported; `webhookValue` makes no request. The shared vector `sdk-webhook-change-vector.json` fixes the value for the four SDKs, the server and the verifier, and a test here reads it.
- The owner-replacement setting's description now says that, from verifier v0.35.0's server release on, Verdifax also cannot clear the owner key's request key while the owner blocks owner-key replacement.
- The user agent is `verdifax-sdk-node/1.16.0`.

## 1.15.0

The feed head, and sealed request-key changes.

- A page of the signal feed that reaches the feed's end now carries the feed's head statement in `head`, a `FeedHead` (`verdifax.feed-head.v1`): the account, the feed's highest event (`sequence`), that event's hash (`head_hash`), `stated_at`, `head_statement_hash` and its public-log `anchor`. `getSignals` keeps it with its exact text in `sealedJson`, so a saved page carries it to `verdifax-verify --signals`, which then says the feed is complete as of the log's time for that entry.
- `followSignals` never hands out the head as an event. It returns a `SignalFollower`, whose `head` is the newest head kept, and the new `onHead` option is called with each newer head kept. A head is kept only when its `sequence` is its page's `next_after` and its `head_hash` is the `event_hash` of the last event the caller finished, and only once the caller has moved past every event on that page, so it never states the feed beyond the events the caller handled. Before the caller finishes an event in a follow, the last event's hash is the new `afterEventHash` option, the `event_hash` saved with event `after`, so a follower resuming at the feed's end keeps the head it is served; without it, no head is kept until the caller finishes an event. A head already kept, read again while the feed is idle, is not passed again.
- `RunDeletion` carries `log_entries`, the deleted record's public-log entries, and `job_links`, a `DeletedJobLinks`: a deleted job step's own `previous_record_hashes`, `external_previous` and `final`, present (even when empty) on the tombstone of a job step deleted since this server release and absent on one written before. `SignalEventData` carries `deleted`, the tombstone served in place of the entry of an event whose entry is a record that was deleted, the receipt event of a refused, halted or failed run, and its `entry` is typed as possibly null. An event that is its own sealed record, such as `run.sealed`, keeps its entry.
- The `account.changed` feed kind now also records each request key of a key in a customer's account: `request_key.registered` when the key's holder registers its first request key, `request_key.rotated` when it replaces it, and `request_key.cleared` decided by `owner` when it clears it. The value of a registered or rotated key is its base64 public key. A rotation and a holder's clear carry `request_key_approval`, a `RequestKeyApproval`: the replaced key's `public_key`, `signature`, `signed_at` and `nonce` over the change, the same approval `rotateRequestKey` and `clearRequestKey` already send. A clear by Verdifax carries none. `AccountChangeAction` lists every action in the server's order.
- `rotateAccountRequestKey(newSigningKey)` replaces the owner key's request key at `POST /account/request-key`, as `rotateRequestKey` does for a key's own: the new key's proof and the current key's approval are sent, and the client signs with the new key only after the server accepts it. A refusal leaves it with its current key.
- `SignalFeedError` carries `afterEventHash`, the `event_hash` of event `lastSequence`, or the `afterEventHash` the follow was given before the caller finished an event, and is absent when there is neither. A caller follows again with both values.
- `registerRequestKey`, `rotateRequestKey`, `clearRequestKey`, `registerAccountRequestKey`, `rotateAccountRequestKey` and `clearAccountRequestKey` pass on the server's HTTP 409, "the request key changed since this change was signed", as an `APIError` with status 409 and the server's message. After it, `rotateRequestKey`, `rotateAccountRequestKey` and `clearRequestKey` keep the client's current key.
- `pendingSignOffs` and the follow loop read the new account changes like any other event.
- `pendingSignOffs` now refuses, with `VerdifaxError`, a `run.sealed` or `run.deleted` entry that does not name a whole number above zero: a null entry, 0, a negative or fractional number, or a string. Earlier releases accepted run 0. The shared pending sign-offs vector holds all four SDKs to this.
- The user agent is `verdifax-sdk-node/1.15.0`.

## 1.14.0

The owner's blocks on Verdifax, run deletion, and owner-key replacement.

- `setAccountSetting(setting, value, { accountId })` sets one of the owner's blocks on Verdifax with `PUT /account/settings/{setting}`: `owner-replacement`, which while `blocked` stops Verdifax replacing the owner key, or `verdifax-deletion`, which while `blocked` stops Verdifax deleting a record. `value` is `allowed` or `blocked`. The owner key's request key signs the change over the account's label, read from `getAccount` unless `accountId` is given. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. Without the `signingKey` option it throws `VerdifaxError` before sending. A value already set changes nothing, and `account_change` is then null. Otherwise the change the server returns must seal the action and value sent, `decided_by` owner and the signature sent under the client's request key, or the call throws `VerdifaxError`.
- `deleteRun(runId, recordHash, { accountId })` deletes one of the account's records with `POST /account/runs/{id}/delete`, signed the same way over the run and its record hash. The tombstone the server returns must seal the run, the record hash, `decided_by` owner and the signature sent, or the call throws `VerdifaxError`. It stays in the signal feed as a `run.deleted` event. A public record must be withdrawn first with `unpublishRun`.
- `adminDeleteRun(runId)` deletes a record as Verdifax's decision, and `adminReplaceOwnerKey(accountId)` starts the replacement of a lost owner key, emailing a one-time link to the address on file. Its result never holds the link or a key. The server refuses both with an `APIError` (409) while the owner blocks them.
- `ownerChangePreimage` builds the bytes the owner key's request key signs for an owner change, `verdifax.owner-change-signature.v1`. It makes no request. The SDK signs them itself in `setAccountSetting` and `deleteRun`.
- `pendingSignOffs(events)` leaves out a run whose deletion is in the events given: a `run.deleted` event for that run, wherever it stands, removes it from the list.
- `getAccount()` and `adminListAccounts()` carry `owner_replacement` and `verdifax_deletion`, each `allowed` or `blocked`.
- The signal feed has two more kinds, `account.changed` (an `AccountChange`, `verdifax.account-change.v1`) and `run.deleted` (a `RunDeletion`, `verdifax.run-deletion.v1`), and `createWebhook` accepts both. A key change may now be `verdifax.key-change.v2`, which also seals who decided in `decided_by`.
- The server now refuses a field it does not define in a run request with an `APIError` (400) naming it. Every body the SDK sends holds only fields the server defines, and a test checks it on every run path, signed and unsigned.
- The user agent is `verdifax-sdk-node/1.14.0`.

## 1.13.0

Sign-off read as the verifier reads it, and the sign-off history's head statement.

- `pendingSignOffs(events)` reads the decision in force as `verdifax-verify` does: the latest job sign-off on a run governs when there is one, and otherwise the latest record sign-off. A run approved by a sign-off on its whole job is no longer listed, and one whose job was rejected is, even when the step carries its own approval.
- `getPublicSignOff` and `getPublicSignOffByToken`: `decision_in_force` names the kind of sign-off in force (`signed_as`), its place (`sequence`) and time (`signed_at`) and, when the job's decision governs, the result's own latest decision (`own_decision`). It is null for a step whose job's sign-offs could not be read.
- `getSignOffHistory()` ends with the chain's head statement, `SignOffHeadRecord` (`verdifax.signoff-head.v1`), anchored on the public log. `verdifax-verify --signoff-history` reports the history complete as of that entry's time, and requires the head when a rule requires a person's sign-off, since v0.31.0.
- The server now refuses a request that gives a query value more than once with an `APIError` (400). The SDK gives each value once.
- The user agent is `verdifax-sdk-node/1.13.0`.

## 1.12.0

Data-quality declarations, pending sign-offs, public sign-offs, and requests read strictly.

- `policy_context` takes `data_quality`: where the data came from (`source`), the time it describes (`as_of`, read as strictly as the server reads it) and the checks you ran on it (`checks`, each a `name` and a `result` of `pass`, `fail` or `warn`). It is sealed with the other policy values, and a policy's `data_quality` condition can require and test it. Verdifax judges none of it. The SDK checks it before sending, with the shared data-quality vector every SDK and the server test.
- `pendingSignOffs(events)` lists, in feed order, the runs whose allowing rule requires a person's sign-off and on which no approval is in force. It makes no request.
- `getPublicSignOff(id)` and `getPublicSignOffByToken(token)` read the sign-off a published run's audit report prints, and for a step of a job, the job's decision in force. No API key needed. Types `PublicSignOff`, `PublicJobSignOff` and `PublicSignOffAnswer`.
- `downloadAuditPDF` and `downloadPublicAuditPDF` take `{ fallback: "comprehensive" }`. The server now refuses a report format it does not know with an `APIError` (400); the fallback asks for the comprehensive report instead.
- `listRuns`, `searchRuns`, `listAccountRuns` and `listAttestations` take `lenient`. The server now refuses a value it cannot read, such as a date in `searchRuns`, with an `APIError` (400); `lenient: true` asks it to ignore or replace the value instead.
- The user agent is `verdifax-sdk-node/1.12.0`.

## 1.11.0

Interrupted sign-offs and policy changes, exact records, and time limits.

- The signal feed carries a new kind, `chain.interrupted` (`ChainInterruptedRecord`): a sign-off or policy change whose public-log entry was never confirmed has its place closed by a sealed, anchored record naming the entry it would have made. `verdifax-verify --signals`, `--signoff-history` and `--policy-history` accept a skipped place through one since v0.29.0. `getSignOffHistory`, `getPolicyHistory` and `getAccountPolicyHistory` return lists that may hold restore gaps and interrupted records in place.
- Every object and list the SDK parses from the server's JSON answer carries `sealedJson`, its exact text as the server sent it, read-only and never written by `JSON.stringify`. JavaScript rounds a number above 2^53, so save `sealedJson` for `verdifax-verify`; the README's examples do. `parseSealed(text)` reads text you hold the same way, and the types `Sealed` and `SealedList` describe it.
- Each test has a 60-second limit, and every CI job has its own time limit.

## 1.10.0

Successful runs in the feed, restore gaps, a required AI review, reports that print the AI's answer, and the account's time zone.

- The signal feed carries two new kinds: `run.sealed` (`RunSealedRecord`), a successful run's record naming the run and the exact record it sealed, and `chain.gap` (`RestoreGapRecord`), a restore gap that names the places a chain skips after a restore from backup. `verdifax-verify --signals` reads both since v0.28.0. `getSignOffHistory` returns `(SignOffRecord | RestoreGapRecord)[]`.
- `testPolicy` and `testAccountPolicy` take `aiOutputDeclared: true` to test a policy whose `ai_review` sets `"required": true`: the server refuses, with reason `ai_review_required`, a step under the requirement that declares no AI output.
- `downloadAuditPDF(id, format, { aiOutputText })` sends the AI's exact answer, and the report prints it on its first page, marked as supplied, only when its SHA-256 is the hash the record seals; other text throws an `APIError` (422) with the server's reason. `downloadPublicAuditPDF(token, format, { aiOutputText })` reads a published record's audit PDF with no key. Options type `AuditPDFOptions`.
- `setAccountTimeZone(timeZone)` (owner key) sets the second time zone the account's audit PDFs show beside UTC: an IANA zone, `"none"` for UTC alone, or `""` for the server region's zone (`AccountTimeZone`).

## 1.9.0

The AI review says what it found, and the trace that proves it comes back to you.

- When an account's AI review runs on a step's AI output, the record seals what it found: the review setup (prompt and model), the SHA-256 of the trace it checked, the checker, what the account policy chose a contradiction finding does (`halt` or `record`), the outcome (`clean`, `halted` or `recorded`) and the finding (two trace nodes and the opposing terms). Verdifax returns the trace once and does not store it; keep it to re-run the check with `verdifax-verify --aivp-trace` (or `--aivp-traces` for a job), since v0.27.0.
- `ExecuteResponse.aivp_trace_text` and each batch row's `aivp_trace_text` hold the trace of a released run; `APIError.aivpTraceText` holds it for a run the review halted. `manifest.AivpReview` (types `AivpReview`, `AivpFinding`) is the sealed review.

## 1.8.0

A publication says who decided.

- A run publication is now `verdifax.run-publication.v2` and seals who decided: `owner`, the account's owner key, or `verdifax_admin`, a Verdifax admin key, which can withdraw any public record and publish only records it made itself. Every change to a record's public state, Verdifax's included, is now sealed in the feed of the record's account. `RunPublication.decided_by` carries it. Publications sealed before v2 are v1, carry no `decided_by`, and were the owner's. `verdifax-verify --signals` reads v2 since v0.26.0.

## 1.7.0

A published stopped run is served as its sealed receipt.

- `PublicationResult` has `public_receipt_url`, the address of a stopped run's receipt while it is public, `/public/runs/{token}/receipt.json`; a stopped run has no bundle address, so `public_bundle_url` is absent for it. `verdifax-verify` checks the receipt address as it checks a saved receipt.
- `getPublicReceiptByToken(token)` reads a published stopped run's sealed receipt from `GET /public/runs/{token}/receipt.json`, as the exact text the server sent, with no key.

## 1.6.0

The account owner publishes the account's records.

- `publishRun(runId)` makes a record made by any key of the account public on its random link with `POST /account/runs/{id}/publish`, and `unpublishRun(runId)` withdraws it with `/unpublish`, keeping the link for a later publish. Both need the owner key and answer a `PublicationResult`: the run's public state, its links while public, and the `RunPublication` the call sealed (`null` when the run was already in the asked state). A publication, `verdifax.run-publication.v1`, names the run, its record hash, its job and step and the time, with its place in the account's signal feed. The service's admin key cannot publish another key's record.
- Signal kinds `run.published` and `run.unpublished`; `verdifax-verify --signals` reads them since v0.24.0.
- Types `RunPublication` and `PublicationResult`.

## 1.5.0

Adds the signal feed: every control signal Verdifax recorded for the account, in order, each with its sealed entry. The kinds are refused, halted and failed runs, policy changes, sign-offs, approver keys registered and revoked, and keys created and revoked. The feed cannot show a signal Verdifax never recorded.

- `getSignals({ after, limit, wait, asOwner })` reads one page of the feed, and `followSignals({ after, wait, asOwner })` is an async generator that reads page after page from `next_after`, never skips, waits on the server when there is no new event and retries a failed read like any GET. When a read still fails it throws `SignalFeedError`, whose `lastSequence` is the last sequence it handed out, so the feed is never lost. With `asOwner: true` both read the owner key's `/account/signals`. A signals call's timeout is at least its wait plus 30 seconds.
- Feed keys: `createFeedKey(name, { expiresAt })` and `revokeFeedKey(id)`, with the owner key. A feed key reads the feed and nothing else.
- Webhooks: `createWebhook(url, { types })`, `listWebhooks`, `deleteWebhook(id)` and `listWebhookDeliveries(id, { limit })`, with the owner key. A webhook delivery is a copy: the pull feed and the public log are the record.
- `verifyWebhook(headers, body, secret, { toleranceSeconds, now })` checks a delivery under the Standard Webhooks scheme: the `whsec_` secret, the `webhook-id` and `webhook-timestamp` headers, a timestamp within the tolerance (default 300 seconds) and any one `v1` signature in `webhook-signature`, compared in constant time. It returns the CloudEvent, or throws naming the check that failed, and never puts the secret in a message.
- `getFailureReceipt(runId)` returns a failed run's sealed failure receipt.
- `signalEventHash(kind, entryHash, { account, sequence, previousSignalHash })` recomputes an event's hash and makes no request.
- Every argument listed above is checked before anything is sent.
- Types for the events, pages, feed keys, webhooks and deliveries.
- The default User-Agent is `verdifax-sdk-node/1.5.0`.

`verdifax-verify --signals` checks a saved feed.

Every existing method behaves as before.

## 1.4.0

Adds customer sign-off. An approver signs a decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step.

- Owner key methods: `registerApprover`, `listApprovers`, `revokeApprover` and `getSignOffHistory`. `registerApprover` takes the approver's signing key and makes the proof on this machine, or the `{ public_key, proof }` that `approverKeyProof` made on the approver's own machine, and refuses a proof that does not verify before sending.
- `signOff(target, decision, approverKey, { note, asOwner })` reads the account's newest sign-off, hashes the note on this machine, signs with the approver key and submits. The note's text and the approver's private key are never sent. Bad input is refused before anything is sent, and the record the server returns must carry the signature, `approver_key`, `decision`, `previous_signoff_hash` and `target` that were sent.
- `getSignOffs(runId, { asOwner })` and `getNewestSignOff({ asOwner })`. With `asOwner: true`, `signOff`, `getSignOffs` and `getNewestSignOff` use the owner key's `/account` routes.
- Helpers `signOffPreimage` and `approverKeyProof`, which make no request.
- Types for the sign-off record, its target, the approver and the newest sign-off, and `signoffs` on `AccountRunsExport`, returned as the server sent it.
- The default User-Agent is `verdifax-sdk-node/1.4.0`.

An approver key is registered by the account's owner and is never a request key in the same account. A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show that the review was careful, that the result is right, or who the person is: a key is not an identity. It gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result. Since v0.22.0, the verifier reads sign-offs.

Every existing method behaves as before.

## 1.3.0

Adds the account layer. An account is a company on Verdifax, and every API key belongs to one account for life. The account's owner key manages the account and cannot run anything.

- Owner key methods: `getAccount`, `createAccountKey`, `listAccountKeys`, `revokeAccountKey`, `registerAccountRequestKey`, `clearAccountRequestKey`, `listAccountRuns`, `exportAccountRuns` and `exportAccountRunsCSV`.
- Account policy methods: `uploadAccountPolicy`, `listAccountPolicies`, `getAccountPolicy`, `testAccountPolicy`, `getAccountPolicyHistory` and `activateAccountPolicy`. Every key in the account must pass the account policy on top of its own, and a run is admitted only when both allow it. `activateAccountPolicy` signs the change with the owner key's request key over the account chain `account-N`, using the same signature as `activatePolicy`, and refuses to send without a `signingKey`.
- Admin methods: `adminCreateAccount` and `adminListAccounts`. `adminCreateKey` takes an optional `accountId`, sent as `account_id`, to put a customer key in an existing account.
- Types for the new responses, and `account_id`, `policy_documents`, `policy_history`, `account_policy_documents` and `account_policy_history` on `RunsExport`.
- `api_key_id` on `ExportRow` and `RunSummary`: the key that requested the run, so an account's export can be grouped by key.
- `DeterminismRun.receipt` and `DeterminismDiff.reason`: the server now compares two refused or halted replays by the manifest hashes they sealed, returns each sealed receipt, and says why there is no verdict when neither replay sealed a record.
- The default User-Agent is `verdifax-sdk-node/1.3.0`.

The account number is a label Verdifax assigned, not a verified company identity. An account policy is the customer's own: Verdifax did not write, review or approve it. The account's view covers the runs its keys made through Verdifax, not runs made elsewhere.

Every existing method behaves as before.

Earlier releases are listed on the GitHub Releases page.
