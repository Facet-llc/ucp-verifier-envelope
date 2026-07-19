# Facet KYA identity vectors (the identity half of the envelope)

Conformance vectors for the **agent-identity** attestation in this envelope, the
Facet KYA (`typ kya+jwt`). They let anyone verify the identity half offline
without asking Facet anything.

Two attestations, two jobs. Facet's KYA says **who the agent is** (identity,
agent-scoped, ES256 over P-256, a plain RFC 7519 JWT). Fidacy's verdict says
**whether this transaction is within policy** (risk, session-scoped, EdDSA over
JCS bytes). They are independent siblings: each is resolved by its own `kid`
against its own issuer's JWKS, neither issuer online at verify time, and neither
can rewrite the other's claim. That is the whole point of an envelope that
dispatches on `alg` rather than assuming one signature format.

## What's here

| file | what it is |
|---|---|
| `vector-valid.json` | a **real KYA**, minted from the live Facet issuer via the public self-serve path (no secret). Verifies against the live JWKS at `https://issuer.facet.llc/.well-known/jwks.json`. |
| `vectors/vectors.json` | five deterministic vectors (valid, expired, bad-signature, rotated-key, wrong-audience) against a fixed test JWKS |
| `vectors/test-jwks.json` | the fixed test key set the five vectors verify against |
| `gen-vectors.mjs` | regenerates the five vectors, each self-validated with the standard `jose` library |
| `mint-live-kya.mjs` | re-mints `vector-valid.json` from the live issuer over the public enroll + `private_key_jwt` flow |

## Reproduce it (zero trust in us)

```bash
npm i
node gen-vectors.mjs
# valid          -> verifies
# expired        -> rejected ERR_JWT_EXPIRED
# bad-signature  -> rejected ERR_JWS_SIGNATURE_VERIFICATION_FAILED
# rotated-key    -> rejected ERR_JWKS_NO_MATCHING_KEY
# wrong-audience -> signature verifies BY DESIGN; the audience mismatch is a consumer check
```

No Facet-specific package is required. A Facet KYA is a plain RFC 7519 ES256 JWT,
so it verifies with any JOSE library against the issuer's published JWKS; the
vectors self-validate with `jose`. The production Terminal verifier
(`@facet/kya-verifier`) layers policy on top (typ pinning, the tier-based TTL
ceiling, single-use nonce for pay-capable tokens), none of which changes the
signature these vectors exercise.

**Why `wrong-audience`, not `wrong-session`.** A Facet KYA is an identity bearer,
agent-scoped, reusable across requests, not bound to any one checkout. So the
identity analog of the risk half's `wrong-session` is `wrong-audience`: an
authentic, untampered KYA minted for a *different* verifier. The verifier's job
is authenticity, is this a genuine, unmodified `issuer.facet.llc` identity
token? The consumer's job is scope, was it minted for *me*? The consumer MUST
compare the claim's `aud` to its own id and reject on mismatch; `gen-vectors.mjs`
demonstrates that check. Same separation of authenticity from scope the envelope
itself makes between identity and risk.

And confirm the real token against the live key set:

```js
import { readFileSync } from "node:fs";
import { jwtVerify, createRemoteJWKSet } from "jose";
const { token } = JSON.parse(readFileSync("./vector-valid.json", "utf8"));
const jwks = createRemoteJWKSet(new URL("https://issuer.facet.llc/.well-known/jwks.json"));
const { payload } = await jwtVerify(token, jwks, { typ: "kya+jwt", issuer: "https://issuer.facet.llc" });
console.log(payload); // { iss, aud, aid, iat, nbf, exp, apd, tier: "self" }
```

`vector-valid.json` carries a real 1h TTL (tier `self` tokens are short-lived by
design), so run `node mint-live-kya.mjs` to mint a fresh, currently-valid one.
Its signature and `kid` keep verifying against the live JWKS for as long as that
key is published; the 1h window is a production policy, not a property of the
signature.

## The shape (identity side)

- Envelope: compact JWS (RFC 7515) / JWT (RFC 7519), `header.payload.signature`.
- Signature: ES256 (ECDSA over EC P-256), standard base64url signing input, not
  a canonicalization scheme.
- Protected header: `{ "alg": "ES256", "kid": "<key id>", "typ": "kya+jwt" }`.
- Claims: `iss`, `aud`, `aid`, `iat`, `nbf`, `exp`, optional `apd` (agent
  platform handle), optional `nonce` (single-use, pay-capable tokens only),
  optional `tier` (`self` for self-enrolled agents, absent means vetted).
- `aid` is the agent's cryptographic identity, an RFC 7638 thumbprint of the
  agent's own key (`facet:agent:<thumbprint>`), never PII.
- Scope: agent-scoped. The `aud` binds the token to a verifier; the
  `wrong-audience` vector shows the consumer-side check.
- JWKS: `https://issuer.facet.llc/.well-known/jwks.json`.
- Discovery: `https://issuer.facet.llc/.well-known/openid-configuration`.

## Canonical spec

The KYA claim set, the issuer, and the enrollment / mint flow are served by the
live Facet issuer and its discovery document:

- Issuer + JWKS: https://issuer.facet.llc
- KYAPay is the published identity spec the KYA conforms to; `issuer.facet.llc`
  is Facet's default issuer, advertised in a Terminal's `agents.txt`.
- Grew out of [UCP #534](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
  (the envelope) and [#535](https://github.com/Universal-Commerce-Protocol/ucp/discussions/535)
  (the external-verifier role).
