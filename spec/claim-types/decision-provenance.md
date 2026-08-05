# Claim type: decision-provenance (`com.fidacy.decision_provenance`)

The after-the-fact profile of the [verifier-attestation envelope](../envelope.md):
a signed receipt that **a specific decision existed, with exactly this content, at
this moment, and was not rewritten afterwards**. Record-scoped, issued after the
decision, verifiable years later by a party who trusts nobody's server logs.

Identity answers who the agent is. Risk answers whether the transaction should
proceed. This answers neither, and it is the only one of the three whose consumer
is usually a stranger reading it long after everyone involved has moved on:
auditors, insurers, dispute processes.

The conformance vectors and generators for this profile live in
[`../../fidacy-provenance/`](../../fidacy-provenance/) and are the normative
reference for everything below. This file is the prose spec; the vectors are the
test.

## Signal

| | |
|---|---|
| signal key | `com.fidacy.decision_provenance` |
| claim type | decision-provenance |
| scope | record (bound to one decision record, not to a session or an agent) |
| envelope | compact JWS (RFC 7515) |
| alg | EdDSA (Ed25519) over RFC 8785 (JCS) canonical bytes |
| `typ` | `fidacy-artifact-receipt+jws` |
| issuer | `did:web:fidacy.com` |
| JWKS | `https://api.fidacy.com/.well-known/jwks.json` |
| verifier library | none required; any JOSE implementation |

This profile deliberately specifies no vendor verifier. Identity and risk are
checked at decision time by software that already depends on a library. A
provenance receipt is opened years later by whoever is holding the dispute, using
whatever JOSE implementation they already have. A profile that needs the issuer's
package to be readable has not solved the problem it exists for.

## Protected header

```json
{ "alg": "EdDSA", "kid": "<key id>", "typ": "fidacy-artifact-receipt+jws" }
```

The `typ` MUST be `fidacy-artifact-receipt+jws` and a verifier MUST reject a
receipt carrying any other value. The pin is not decoration: a receipt and a risk
verdict are both EdDSA over JCS bytes from the same issuer under the same key, so
without it one could be presented as the other. `wrong-typ` is a conformance
vector for exactly this reason.

## Claims

Serialised JCS-sorted, which is the order below.

| claim | required | meaning |
|---|---|---|
| `artifactId` | yes | Issuer-side id of the anchored record. |
| `audit.hash` | yes | The chain entry's hash, which commits to every prior entry. |
| `audit.seq` | yes | Position of this attestation in the issuer's hash-chained audit. |
| `digest` | yes | The audit-leaf digest the chain entry commits to. |
| `kind` | yes | Record kind: `custom`, `conversation`, `invoice`, … |
| `org` | yes | Issuing account scope. |
| `sha256` | yes | SHA-256 of the decision-record bytes. The record itself is NEVER uploaded; the issuer sees only this hash. |
| `subject` | yes | The agent or mandate the decision was about. |
| `ts` | yes | RFC 3339 instant of attestation. |
| `v` | yes | Format version, `fidacy.artifact.v1`. |

There is no `exp`. Identity credentials are right to expire, because a stale
answer to "who is this agent" is worse than none. A receipt that expires answers
nothing in a dispute two quarters later, which is the only moment it is ever read.
Freshness is not a property this claim type wants.

## Scope: authenticity vs consumer check

The verifier's job is **authenticity**: is this a genuine, unmodified
`did:web:fidacy.com` receipt, resolved by `kid` against the pinned JWKS,
signature-checked, `typ` pinned. The consumer's job is **correspondence**: does it
attest the document I am holding. The consumer MUST hash the record bytes in hand
and compare against the `sha256` claim, rejecting on mismatch.

The provenance analog of the identity profile's `wrong-audience` and the risk
profile's `wrong-session` is `content-mismatch`: an authentic, untampered receipt
about a different document. The signature verifies by design. Collapsing
correspondence into the verifier would silently skip the check whenever anyone
verifies out of band, which for this claim type is the normal case rather than the
exception.

## Anchoring (normative)

Existence-by-time MUST be provable without trusting the issuer. A signature proves
who said it; it does not prove when, because the issuer holds the key and can
restate a timestamp. This profile therefore requires a second, issuer-independent
leg: the hash chain's head is committed to an external public ledger on a schedule,
and `audit.seq` locates the receipt inside a checkpoint range that the ledger
timestamps.

Fidacy anchors to Bitcoin via OP_RETURN; the live checkpoint is public at
`https://fidacy-core.vercel.app/v1/anchor/latest` and the trail is walkable at
`https://fidacy.com/proof`. Any ledger with equivalent properties satisfies this
clause. What the clause forbids is a profile whose only evidence of time is the
issuer's own word.

A receipt is verifiable on the signature leg immediately and on the anchoring leg
once the covering checkpoint confirms. Both states are legitimate and a consumer
SHOULD be told which one it is looking at.

## Neutrality (normative)

An issuer MUST NOT attest the decision record of a transaction to which it is a
party, where a party is anyone who operates, meters, settles, or takes a fee on it.

This is the same clause as the risk profile's, and it bites harder here. A rail
attesting to its own decision log is precisely what the after-the-fact consumer
distrusts: the dispute is usually with the rail. See
[envelope section 8](../envelope.md#8-conformance).

## Conformance vectors

Five deterministic vectors against a fixed test JWKS
([`../../fidacy-provenance/vectors/`](../../fidacy-provenance/vectors/)), each
self-validated with plain `jose`, plus a real production receipt
(`vector-valid.json`) signed by the live engine that verifies against the live
JWKS.

| vector | expected verdict |
|---|---|
| `valid` | verifies |
| `bad-signature` | rejected, signature verification failed |
| `rotated-key` | rejected, no matching key for `kid` |
| `wrong-typ` | rejected, `typ` not the pinned value |
| `content-mismatch` | signature verifies by design; consumer rejects on `sha256` mismatch |

Reproduce, with zero trust in Fidacy:

```bash
cd fidacy-provenance
npm i
node gen-vectors.mjs      # regenerates and self-validates the five vectors
```

And confirm the real production receipt against the live key set:

```js
import { readFileSync } from "node:fs";
import { compactVerify, createRemoteJWKSet } from "jose";
const { receipt } = JSON.parse(readFileSync("./vector-valid.json", "utf8"));
const JWKS = createRemoteJWKSet(new URL("https://api.fidacy.com/.well-known/jwks.json"));
const { payload, protectedHeader } = await compactVerify(receipt, JWKS);
console.log(protectedHeader.typ, JSON.parse(new TextDecoder().decode(payload)));
```

The committed `vector-valid.json` is a receipt the production engine signed on
2026-07-19 for audit seq 158, covered by checkpoint 29. It verifies today against
the live JWKS, which is the claim this profile makes about its own longevity, made
falsifiable.

## Notes

- The signal binding, schemas and the signed-payload format live in the open
  Fidacy spec (Apache-2.0), which is the source of truth for this half:
  [spec + schemas](https://github.com/fidacy/fidacy-open/tree/main/spec).
- The record bytes never leave the issuing side. Everything in this profile is
  checkable from a hash, which is what makes it usable for records nobody is
  willing to hand over: contracts, claim files, conversation transcripts.
- `did:web:fidacy.com` resolves to the same key material as the JWKS endpoint, so
  a consumer that already resolves DIDs has a second path to the same pin.
