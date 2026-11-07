# Changelog

## 1.3.0

Adds the account layer. An account is a company on Verdifax, and every API key belongs to one account for life. The account's owner key manages the account and cannot run anything.

- Owner key methods: `getAccount`, `createAccountKey`, `listAccountKeys`, `revokeAccountKey`, `registerAccountRequestKey`, `clearAccountRequestKey`, `listAccountRuns`, `exportAccountRuns` and `exportAccountRunsCSV`.
- Account policy methods: `uploadAccountPolicy`, `listAccountPolicies`, `getAccountPolicy`, `testAccountPolicy`, `getAccountPolicyHistory` and `activateAccountPolicy`. Every key in the account must pass the account policy on top of its own, and a run is admitted only when both allow it. `activateAccountPolicy` signs the change with the owner key's request key over the account chain `account-N`, using the same signature as `activatePolicy`, and refuses to send without a `signingKey`.
- Admin methods: `adminCreateAccount` and `adminListAccounts`. `adminCreateKey` takes an optional `accountId`, sent as `account_id`, to put a customer key in an existing account.
- Types for the new responses, and `account_id`, `policy_documents`, `policy_history`, `account_policy_documents` and `account_policy_history` on `RunsExport`.
- `api_key_id` on `ExportRow` and `RunSummary`: the key that requested the run, so an account's export can be grouped by key.
- The default User-Agent is `verdifax-sdk-node/1.3.0`.

The account number is a label Verdifax assigned, not a verified company identity. An account policy is the customer's own: Verdifax did not write, review or approve it. The account's view covers the runs its keys made through Verdifax, not runs made elsewhere.

Every existing method behaves as before.

Earlier releases are listed on the GitHub Releases page.
- `DeterminismRun.receipt` and `DeterminismDiff.reason`: the server now compares two refused or halted replays by the manifest hashes they sealed, returns each sealed receipt, and says why there is no verdict when neither replay sealed a record.
