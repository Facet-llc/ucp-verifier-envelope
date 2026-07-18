# Fidacy risk-verdict vectors (the risk half of the envelope)

Conformance vectors for the **transaction-risk** attestation in this envelope, the
`com.fidacy.trust_verdict` signal. They let anyone verify the risk half offline
without asking Fidacy anything.

Two attestations, two jobs. Facet's `kya+jwt` says **who the agent is** (identity,
agent-scoped, ES256 over P-256). The Fidacy verdict says **whether this
transaction is within policy** (risk, session-scoped, EdDSA over JCS bytes). They
are independent siblings: each is resolved by its own `kid` against its own
issuer's JWKS, neither issuer online at verify time, and neither can rewrite the
other's claim. That is the whole point of an envelope that dispatches on `alg`
rather than assuming one signature format.

## What's here

| file | what it is |
|---|---|
| `vector-valid.json` | a **real production verdict**, signed by the live Fidacy engine. Verifies against the live JWKS at `https://api.fidacy.com/.well-known/jwks.json`. |
| `vectors/vectors.json` | five deterministic vectors (valid, expired, bad-signature, rotated-key, wrong-session) against a fixed test JWKS |
| `vectors/test-jwks.json` | the fixed test key set the five vectors verify against |
| `gen-vectors.mjs` | regenerates the five vectors, each self-validated by the published `@fidacy/verify` |

## Reproduce it (zero trust in us)

```bash
npm i
node gen-vectors.mjs
# valid          -> verifies
# expired        -> rejected 'expired'
# bad-signature  -> rejected 'invalid_signature'
# rotated-key    -> rejected 'unknown_kid'
# wrong-session  -> signature verifies; the session mismatch is a consumer check
```

And confirm the real production verdict against the live key set:

```js
import { readFileSync } from "node:fs";
import { verifyRiskPayload } from "@fidacy/verify";
const { jws } = JSON.parse(readFileSync("./vector-valid.json", "utf8"));
const jwks = await (await fetch("https://api.fidacy.com/.well-known/jwks.json")).json();
console.log(await verifyRiskPayload(jws, { jwks })); // { valid: true, claims: { decision: "deny", ... } }
```

## The shape (risk side)

- Envelope: compact JWS (RFC 7515), `header.payload.signature`.
- Signature: EdDSA (Ed25519) over the RFC 8785 (JCS) canonical bytes of the payload.
- Protected header: `{ "alg": "EdDSA", "kid": "<key id>", "typ": "application/vc+jws" }`.
- Claims (JCS-sorted): `issuer`, `subject`, `decision` (`approve`|`review`|`deny`),
  `score` (0..100), `signals`, `model_version`, `policy_version`, `assessed_at`.
- Scope: session-scoped. Bind the verdict to the checkout session; the
  `wrong-session` vector shows the consumer-side check.
- JWKS: `https://api.fidacy.com/.well-known/jwks.json`.
- Verifier: [`@fidacy/verify`](https://www.npmjs.com/package/@fidacy/verify) (npm, Apache-2.0).

## Neutrality (normative)

A verifier MUST NOT issue a **risk** verdict for a transaction to which it is a
party, where a party is anyone who meters, settles, or takes a fee on it. Identity
is unaffected, because it holds independently of the flow: a rail can attest who an
agent is on a rail it operates. Fidacy takes no fee, settles nothing, holds no
funds, so it is a non-party to the risk verdicts it issues. The clause applies to
Fidacy too.

## Canonical spec

The signal binding, schemas, and the signed-payload format live in the open Fidacy
spec (Apache-2.0), which is the source of truth for this half:

- Binding + URI: https://fidacy.com/ucp/extensions/trust-verdict/v1
- Spec + schemas: https://github.com/fidacy/fidacy-open/tree/main/spec
- Grew out of [UCP #534](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
  (the envelope) and [#535](https://github.com/Universal-Commerce-Protocol/ucp/discussions/535)
  (the external-verifier role).
