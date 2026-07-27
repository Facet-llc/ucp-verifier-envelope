# Claim type: risk (`com.fidacy.trust_verdict`)

The risk profile of the [verifier-attestation envelope](../envelope.md): the
Fidacy trust verdict, a signed statement of **whether a transaction is within
policy**. Session-scoped, issued before execution, verifiable offline by anyone
against the issuer's published keys.

The conformance vectors and generators for this profile live in
[`../../fidacy-risk/`](../../fidacy-risk/) and are the normative reference for
everything below. This file is the prose spec; the vectors are the test.

## Signal

| | |
|---|---|
| signal key | `com.fidacy.trust_verdict` |
| claim type | risk |
| scope | session (bound to one checkout, not to the agent) |
| envelope | compact JWS (RFC 7515) |
| alg | EdDSA (Ed25519) over RFC 8785 (JCS) canonical bytes |
| `typ` | `application/vc+jws` |
| issuer | `did:web:fidacy.com` |
| JWKS | `https://api.fidacy.com/.well-known/jwks.json` |
| verifier library | [`@fidacy/verify`](https://www.npmjs.com/package/@fidacy/verify) (npm, Apache-2.0) |

The signature is EdDSA over the JCS-canonical bytes of the payload rather than
over the base64url segment, so a verdict survives re-serialisation: any party that
holds the claims can recompute the exact signed bytes. `@fidacy/verify` implements
this, and the algorithm is fully specified here, so no Fidacy package is required
to check a signature.

## Protected header

```json
{ "alg": "EdDSA", "kid": "<key id>", "typ": "application/vc+jws" }
```

The `kid` selects a key within the issuer's pinned JWKS. The `typ` MUST be
`application/vc+jws` and MUST match the envelope entry `format`.

## Claims

Serialised JCS-sorted, which is the order below.

| claim | required | meaning |
|---|---|---|
| `assessed_at` | yes | RFC 3339 instant the verdict was decided. |
| `decision` | yes | `approve`, `review` or `deny`. The only field a consumer is required to act on. |
| `exp` | no | Expiry. Absent means the verdict does not self-expire and the consumer's own freshness window governs (see envelope section 6). |
| `issuer` | yes | `did:web:fidacy.com#<kid>` (or another issuer the merchant pins). |
| `model_version` | yes | The scoring model that produced `score`. See [decision provenance](../decision-provenance.md). |
| `policy_version` | yes | The policy revision in force when the verdict was decided. See [decision provenance](../decision-provenance.md). |
| `score` | yes | Integer 0..100. Advisory: it explains the decision, it does not replace it. |
| `signals` | yes | Object naming what drove the decision, e.g. `{ "rule": "payee_not_in_allowlist" }`. Never PII. |
| `subject` | yes | The agent the verdict is about, e.g. `agent:demo-northwind`. |

A `deny` is signed exactly like an `approve`. A profile where only the positive
case is attestable cannot settle a dispute, because the interesting question after
the fact is almost always what was refused.

## Scope: authenticity vs consumer check

The verifier's job is **authenticity**: is this a genuine, unmodified
`did:web:fidacy.com` verdict, resolved by `kid` against the pinned JWKS and
signature-checked. The consumer's job is **scope**: is it about the transaction in
front of me. The consumer MUST bind the verdict to the checkout session in hand
and reject on mismatch.

Because risk is session-scoped rather than agent-scoped, the risk analog of an
identity profile's `wrong-audience` failure is `wrong-session`: an authentic,
untampered verdict about a different checkout. The signature verifies by design;
the session mismatch is a consumer rejection, not a signature failure. Collapsing
scope into the verifier would silently skip the check whenever anyone verifies out
of band.

## Neutrality (normative)

A verifier MUST NOT issue a **risk** verdict for a transaction to which it is a
party, where a party is anyone who meters, settles, or takes a fee on it.

Identity is unaffected, because it holds independently of the flow: a rail can
attest who an agent is on a rail it operates. Risk is different, because a risk
verdict is an opinion about whether the flow should proceed, and an opinion issued
by a beneficiary of the flow is not evidence a counterparty can rely on.

The clause binds Fidacy on the same terms as anyone else. Fidacy takes no fee on
the transactions it assesses, settles nothing and holds no funds, which is what
makes it a non-party to its own verdicts. A future issuer that does take a fee is
excluded by this clause, not grandfathered by it.

## Conformance vectors

Five deterministic vectors against a fixed test JWKS
([`../../fidacy-risk/vectors/`](../../fidacy-risk/vectors/)), each self-validated
by the published `@fidacy/verify`, plus a real production verdict
(`vector-valid.json`) signed by the live engine that verifies against the live
JWKS.

| vector | expected verdict |
|---|---|
| `valid` | verifies |
| `expired` | rejected, `expired` |
| `bad-signature` | rejected, `invalid_signature` |
| `rotated-key` | rejected, `unknown_kid` |
| `wrong-session` | signature verifies by design; consumer rejects on session mismatch |

Reproduce, with zero trust in Fidacy:

```bash
cd fidacy-risk
npm i
node gen-vectors.mjs      # regenerates and self-validates the five vectors
```

And confirm the real production verdict against the live key set:

```js
import { readFileSync } from "node:fs";
import { verifyRiskPayload } from "@fidacy/verify";
const { jws } = JSON.parse(readFileSync("./vector-valid.json", "utf8"));
const jwks = await (await fetch("https://api.fidacy.com/.well-known/jwks.json")).json();
console.log(await verifyRiskPayload(jws, { jwks })); // { valid: true, claims: { decision: "deny", ... } }
```

## Notes

- The signal binding, schemas and the signed-payload format live in the open
  Fidacy spec (Apache-2.0), which is the source of truth for this half:
  [binding + URI](https://fidacy.com/ucp/extensions/trust-verdict/v1),
  [spec + schemas](https://github.com/fidacy/fidacy-open/tree/main/spec).
- The production engine layers policy on top of the signature (mandate caps, payee
  allow-list, duplicate-invoice and look-alike checks). None of that changes the
  signature these vectors exercise, so a plain EdDSA verification over the JCS
  bytes against the pinned JWKS is sufficient for envelope conformance.
- `did:web:fidacy.com` resolves to the same key material as the JWKS endpoint, so
  a consumer that already resolves DIDs has a second path to the same pin.
