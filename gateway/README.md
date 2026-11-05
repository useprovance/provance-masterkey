# Provance-hosted Masterkey gateway

Provance fork: [useprovance/provance-masterkey](https://github.com/useprovance/provance-masterkey), based on upstream `Must-be-Ash/masterkey` at `b6aa0b1696a649a8644929ab1d1e9d641edf2904`, branch `provance/hosted-gateway`. Original MIT attribution is retained. Review: [gateway PR #1](https://github.com/useprovance/provance-masterkey/pull/1), [API PR #1](https://github.com/useprovance/provance-nodes/pull/1), [client PR #1](https://github.com/useprovance/provance-client/pull/1). Public production deployment has not been performed.

This private Node entry point reuses Masterkey's catalog without exposing the upstream Next app, CDP login, MongoDB agent, OAuth server or unrestricted wallet tools. Users keep their existing Provance login. Ordinary users never receive gateway service tokens, wallet keys or database credentials.

## Runtime

- API/worker signs short-lived Ed25519 identity with an exact owner, audience, call ID and canonical request hash. Gateway holds the identity public key.
- A dedicated PostgreSQL role grants only narrow call/evidence/recovery functions. TLS verifies the official Supabase CA and hostname.
- Durable approval includes a fingerprint of the reviewed provider policy. SQL checks it at call creation and financial dispatch; changed endpoint/recipient/network/asset/schema/ceiling/review/extension policy blocks old consent. The gateway requires policy-approval schema version 1.
- Atomic call claims prevent duplicate dispatch. Verified receipts settle once; uncertain outcomes keep their reservations.
- The production payment adapter implements x402 v2 Base USDC EIP-3009. It signs exactly one recipient/amount/nonce, persists evidence before transmitting it, and never retries payment automatically. It does not call Sponge `paidFetch`.
- Provider requests use a reviewed static manifest, JSON schema validation, public DNS pinning, no redirects and bounded responses. Only synchronous read operations are supported in this release.
- Optional `bazaar` discovery and `agentkit` identity hints may be ignored only when explicitly listed in a provider's fingerprinted `ignoredExtensions`. No identity challenge is signed or registration/discount flow attempted. Unknown or required extensions remain blocked.
- Reconciliation checks exact transfer and authorization events or finalized expiry with an unused nonce. A special atomic close can finalize a dispatch that never persisted authorization, while blocking any late worker from sending payment.

The paid `providers.json` has **no enabled providers**. Separately, `free-providers.json` enables **12 reviewed free routes**: BlockRun symbol/price/history/voice discovery, advisory output screening and official Exa MCP search. These run without a wallet even while the payment switch is off. The disabled paid Exa example remains unverified for settlement. The dedicated fee payer is unfunded; payment flags/limits remain off/zero. No funds moved.

Free calls use the signed `free:execute` scope, a version-2 zero-fee policy with no
network/asset/recipient, a live worker lease and the exact saved input approval.
Restricted PostgreSQL functions claim each step once and persist its result for
replay. They never create a financial reservation or invoke payment/identity
signing. HTTP 402, redirects, provider errors and unexpected payloads fail at zero;
there is no automatic paid fallback. Free providers can be disabled in their own
manifest; the payment switch controls paid routes only.

## Local development

From the sibling API checkout:

```sh
node scripts/setup-masterkey-gateway.cjs
```

The API gets the dedicated identity private key in its ignored `.env`; gateway gets the public key in ignored `.env.gateway`. Existing keys are preserved, files use mode 0600, and no secret is printed. Fee-payer credentials are separate from this identity bridge. Restart processes after changing environment files.

From this checkout:

```sh
npm run gateway:install
npm run gateway:dev
npm run gateway:build
npm run gateway:test
```

Local address: `127.0.0.1:4010`. Production starts `node dist-gateway/main.js`; provide environment through the host/Compose configuration. `gateway:start` does not automatically read `.env.gateway`. `node --env-file=.env.gateway dist-gateway/main.js` is available for a local compiled check.

Production dependency installation uses `gateway/package-lock.json`, separate from upstream's full website/agent dependency graph. Docker runs as non-root and excludes credential files. The minimal production dependency audit reported zero vulnerabilities when checked; this is not an application security audit.

## Endpoints

| Endpoint | Authority | Purpose |
| --- | --- | --- |
| `GET /health` | None | Process/configuration liveness |
| `GET /ready` | None | Restricted ledger availability |
| `GET /v1/capabilities` | `catalog:read` | Reviewed operation availability and platform switch state |
| `GET /v1/services?q=&offset=` | `catalog:read` | Visible catalog summaries, pages of 50 |
| `POST /v1/calls` | Exact `call:execute` token | One durable, bounded service dispatch |
| `POST /v1/free` | Exact `free:execute` token | One approval-bound free read; zero fees, no signer |
| `GET /v1/calls/:id` | Matching call token | Owner-scoped durable outcome |
| `POST /v1/reconcile` | Exact `call:reconcile` token issued only by operator API | Independently verified outcome recovery; no arbitrary amount/refund field |

There is no fallback to public masterkey.sh and no exposed upstream `/oauth`, `/mcp`, `/api/auth` or wallet/agent routes. External public MCP access would need its own consent/auth integration; it is not exposed by this private gateway.

## Activation requirements

Use the environment examples under `gateway/`. Set a trusted HTTPS Base RPC and a dedicated production fee-payer key. Review the candidate provider's current endpoint, recipient, exact protocol and schema; fill `reviewedAt` and explicitly enable its manifest entry only after testing. Never use a customer trading key or grant an agent a general signing tool.

Apply all migrations in the launch document, configure an explicit operator allowlist, and choose platform/account/run limits. Wallet funding and a paid staging check require separate owner authorization; they are not implied by building an image or browsing the catalog. Optional Stripe credits use the API's billing configuration.

Full current configuration, validation, migration order and remaining launch gates: `../provance-nodes/docs/MASTERKEY_LAUNCH.md`. Production Compose/Caddy templates are in `../provance-nodes/deployment/` beside both repositories. The API now persists jobs, approvals and event streams, and handles credit billing, private output archives and operator controls.

## Current verification and operator tooling

See `../provance-nodes/docs/MASTERKEY_COMPLETION.md` for the 2026-11-03 completion report.
The remaining Masterkey code gaps are closed; Stellar wallet/payment work was deferred.
The full suite has 111 passing tests, including 27 gateway tests. Current images build,
and a disposable-ledger restore verifies 13 runtime/financial tables. Actual free
workflow evidence is in `../provance-nodes/docs/MASTERKEY_PROVANCE_WORKFLOW_TEST.md`.
CI is configured in each repository and PR check status is shown on the linked
reviews. Public production deployment has not been performed.

`gateway/reviews/exa-unpaid-quote.json` records a real unpaid Exa quote for 0.007 USDC
under a $0.01 maximum. It has `paidSettlementVerified: false`. The fee wallet was
verified at zero USDC and no provider is enabled. Repeat the quote without loading
a wallet or authorizing payment:

```sh
node gateway/node_modules/tsx/dist/cli.mjs gateway/review-provider.ts \
  --manifest gateway/providers.example.json --service exa \
  --input gateway/reviews/exa-input.json --output gateway/reviews/exa-unpaid-quote.json
```

From the sibling API, `pnpm run check:masterkey` verifies core readiness and reports
paid configuration gates; append `--require-paid` for a paid-launch exit check.
These commands do not enable providers or raise limits. Explicit operator selection,
funding and an authorized bounded paid staging test remain operator inputs.

Routine tests mock provider/signing/settlement calls. The separate local
`pnpm run test:masterkey-live-free` command in the API runs real free providers
through Provance's queue, approvals, worker, gateway, saved results and event
replay. The sibling SQL test fixtures target only disposable PostgreSQL on
127.0.0.1:55439. No real paid call or direct browser UI check was performed.
