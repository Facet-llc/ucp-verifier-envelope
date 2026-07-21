# Claim type: identity (`llc.facet.kya`)

The identity profile of the [verifier-attestation envelope](../envelope.md): the
Facet KYA, a signed statement of **who an agent is**. Agent-scoped, reusable
across requests, verifiable offline by anyone against the issuer's published keys.

The conformance vectors and generators for this profile live in
[`../../facet-identity/`](../../facet-identity/) and are the normative reference
for everything below. This file is the prose spec; the vectors are the test.

## Signal

| | |
|---|---|
| signal key | `llc.facet.kya` |
| claim type | identity |
| scope | agent (not bound to any one checkout) |
| envelope | compact JWS (RFC 7515) / JWT (RFC 7519) |
| alg | ES256 (ECDSA over EC P-256) |
| `typ` | `kya+jwt` |
| issuer | `https://issuer.facet.llc` |
| JWKS | `https://issuer.facet.llc/.well-known/jwks.json` |
| discovery | `https://issuer.facet.llc/.well-known/openid-configuration` |

A KYA is a plain RFC 7519 ES256 JWT, so it verifies with any JOSE library against
the issuer's published JWKS. No Facet-specific package is required to check a
signature.

## Protected header

```json
{ "alg": "ES256", "kid": "<key id>", "typ": "kya+jwt" }
```

The `kid` selects a key within the issuer's pinned JWKS. The `typ` MUST be
`kya+jwt` and MUST match the envelope entry `format`.

## Claims

| claim | required | meaning |
|---|---|---|
| `iss` | yes | `https://issuer.facet.llc` (or another issuer the merchant pins). |
| `aud` | yes | The verifier the token was minted for. The consumer pins this (see scope). |
| `aid` | yes | The agent's cryptographic identity: `facet:agent:<thumbprint>`, an RFC 7638 JWK thumbprint of the agent's own key. Never PII. |
| `iat` | yes | Issued-at. |
| `nbf` | yes | Not-before. |
| `exp` | yes | Expiry. Tier `self` tokens are short-lived (1h) by production policy; the signature and `kid` keep verifying against the live JWKS regardless. |
| `apd` | no | Agent platform handle. |
| `tier` | no | `self` for self-enrolled agents; absent means a vetted agent. |
| `nonce` | no | Single-use value, present only on pay-capable tokens (see envelope section 6). |

## Scope: authenticity vs consumer check

The verifier's job is **authenticity**: is this a genuine, unmodified
`issuer.facet.llc` identity token, resolved by `kid` against the pinned JWKS and
signature-checked. The consumer's job is **scope**: was it minted for me. The
consumer MUST compare the `aud` claim to its own id and reject on mismatch.

Because identity is agent-scoped rather than session-scoped, the identity analog
of a session-scoped verdict's `wrong-session` failure is `wrong-audience`: an
authentic, untampered KYA minted for a different verifier. The signature verifies
by design; the audience mismatch is a consumer rejection, not a signature
failure.

## Conformance vectors

Five deterministic vectors against a fixed test JWKS
([`../../facet-identity/vectors/`](../../facet-identity/vectors/)), each
self-validated with the standard `jose` library, plus a real live-signed token
(`vector-valid.json`) that verifies against the live issuer JWKS.

| vector | expected verdict |
|---|---|
| `valid` | verifies |
| `expired` | rejected, `expired` (`ERR_JWT_EXPIRED`) |
| `bad-signature` | rejected, `invalid_signature` (`ERR_JWS_SIGNATURE_VERIFICATION_FAILED`) |
| `rotated-key` | rejected, `unknown_kid` (`ERR_JWKS_NO_MATCHING_KEY`) |
| `wrong-audience` | signature verifies by design; consumer rejects on `aud` mismatch |

Reproduce, with zero trust in Facet:

```bash
cd facet-identity
npm i
node gen-vectors.mjs      # regenerates and self-validates the five vectors
node mint-live-kya.mjs     # mints a fresh live KYA over the public enroll + private_key_jwt flow
```

## Notes

- `KYAPay` is the published identity spec the KYA conforms to; `issuer.facet.llc`
  is Facet's default issuer, advertised in a Terminal's `agents.txt`.
- The production Terminal verifier layers policy on top of the signature check
  (typ pinning, a tier-based TTL ceiling, single-use nonce for pay-capable
  tokens). None of that changes the signature these vectors exercise, so a plain
  JOSE verification against the pinned JWKS is sufficient for envelope conformance.
