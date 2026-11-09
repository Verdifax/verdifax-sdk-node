# Changelog

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
