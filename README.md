# verdifax (Node.js / TypeScript SDK)

The official Node.js SDK for the [Verdifax](https://verdifax.com)
orchestrator REST API. TypeScript-native, ships dual CJS+ESM,
zero runtime dependencies (uses native `fetch` from Node 18+).

## Install

```bash
npm install verdifax
# or
yarn add verdifax
# or
pnpm add verdifax
```

Requires Node 18 or newer.

## Quickstart

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
  console.log("✓ Manifest hash recomputes — run is intact.");
}
```

## What this SDK covers

| Method | Endpoint | Auth |
| --- | --- | --- |
| `client.health()` | `GET /health` | none |
| `client.version()` | `GET /version` | none |
| `client.execute(req)` | `POST /execute` | required |
| `client.getRun(id)` | `GET /runs/{id}` | required |
| `client.verifyRun(id)` | `GET /runs/{id}/verify` | required |

The full HTTP surface (every endpoint, deletion-receipt list,
DCAE verify, admin endpoints) is documented in the
[OpenAPI spec](https://github.com/Verdifax/verdifax-orchestrator/blob/main/openapi/verdifax.yaml).
This SDK ships the canonical operations; broader coverage lands
as integrators ask.

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

The response carries the secret **once** — store it immediately.

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
    // every other non-2xx — err.status carries the HTTP code
  }
}
```

## Trust model

This SDK only mediates HTTP I/O — it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the [`verdifax-pepg-verify`](https://github.com/Verdifax/verdifax-orchestrator/tree/main/cmd/verdifax-pepg-verify)
CLI (signed binary distributed via GitHub Releases).

## License

MIT — see [LICENSE](LICENSE).
