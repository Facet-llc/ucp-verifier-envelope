# Fidacy decision-provenance vectors (the after-the-fact half of the envelope)

Conformance vectors for the **decision-provenance** attestation in this envelope,
the `com.fidacy.decision_provenance` signal. They let anyone verify this half
offline without asking Fidacy anything, and without installing anything of ours.

Three attestations, three jobs. Facet's `kya+jwt` says **who the agent is**
(identity, agent-scoped, ES256 over P-256). The Fidacy verdict says **whether this
transaction is within policy** (risk, session-scoped, EdDSA over JCS bytes). A
provenance receipt says **that this decision existed with exactly this content at
this moment** (record-scoped, EdDSA over JCS bytes, no expiry). The first two are
read at decision time by software. This one is read years later by a person who
trusts nobody, which is why it pins no vendor library and why it carries a second,
issuer-independent leg for time.

## What's here

| file | what it is |
|---|---|
| `vector-valid.json` | a **real production receipt**, signed by the live Fidacy engine on 2026-07-19 for audit seq 158. Verifies today against the live JWKS at `https://api.fidacy.com/.well-known/jwks.json`. |
| `vectors/vectors.json` | five deterministic vectors (valid, bad-signature, rotated-key, wrong-typ, content-mismatch) against a fixed test JWKS |
| `vectors/test-jwks.json` | the fixed test key set the five vectors verify against |
| `vectors/decision-record.json` | the record the test receipt attests, committed so a cold reader can recompute the `sha256` claim |
| `gen-vectors.mjs` | regenerates the five vectors, each self-validated with plain `jose` |

## Reproduce it (zero trust in us)

```bash
npm i
node gen-vectors.mjs
# valid            -> verifies
# bad-signature    -> rejected, ERR_JWS_SIGNATURE_VERIFICATION_FAILED
# rotated-key      -> rejected, ERR_JWKS_NO_MATCHING_KEY
# wrong-typ        -> rejected, typ
# content-mismatch -> signature verifies by design; consumer rejects on sha256 mismatch
```

Verify the COMMITTED vectors (no regeneration, what the CI gate runs):

```
npm i && node verify.mjs
```

Exit 0 iff all 8 assertions hold, both layers, offline.

`content-mismatch` verifying is not a hole. The verifier answers "is this receipt
real and untampered". The consumer answers "does it attest the document in my
hand" by hashing those bytes and comparing to the `sha256` claim. The generator
demonstrates that second check rather than describing it. Same separation as
`wrong-session` on the risk side and `wrong-audience` on the identity side.

## The record never leaves

The issuer sees a hash, never the record. That is what makes this usable for the
documents nobody will hand over: contracts, claim files, conversation transcripts.
`vectors/decision-record.json` is committed here only so the vectors are
reproducible; in production nothing of the sort is uploaded.

## Two legs, and why

A signature proves who said it. It does not prove *when*, because the issuer holds
the key. So `audit.seq` locates the receipt inside a hash-chained log whose head is
committed to Bitcoin on a schedule; the ledger, not Fidacy, timestamps it. Live
checkpoint at `https://fidacy-core.vercel.app/v1/anchor/latest`, walkable trail at
`https://fidacy.com/proof`.

Profile: [`../spec/claim-types/decision-provenance.md`](../spec/claim-types/decision-provenance.md).
