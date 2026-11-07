# Changelog

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
