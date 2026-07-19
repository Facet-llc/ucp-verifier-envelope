# cross-verify: the envelope, run end to end

One checkout. Two live-signed verdicts from two production issuers, verified
offline in a single run:

| signal | claim | alg | typ | JWKS |
|---|---|---|---|---|
| `llc.facet.kya` | identity | ES256 (P-256) | `kya+jwt` | issuer.facet.llc |
| `com.fidacy.trust_verdict` | risk | EdDSA (Ed25519) | `application/vc+jws` | api.fidacy.com |

```bash
npm i
node cross-verify.mjs
```

The script mints a fresh Facet KYA through the public self-serve path (same
flow as `facet-identity/mint-live-kya.mjs`, no secret), loads the real Fidacy
production verdict (`fidacy-vector-valid.json`, same file as
`fidacy-risk/vector-valid.json`), composes the envelope, then verifies each
half against its issuer's live JWKS: two kid lookups, two JWKS fetches,
dispatch on `alg`, neither issuer online at verify time. It ends with the
consumer-side scope checks (aud for identity, subject for risk), the part
that is deliberately not the verifier's job.

## The envelope shape (field-name proposal)

`envelope.json` is a real run's output and doubles as the concrete field-name
proposal for #534: a `signals` map keyed by reverse-domain signal name, each
entry carrying

```jsonc
{
  "format": "<typ of the JWS>",
  "jws": "<compact JWS, the source of truth>",
  "kid": "<protected-header kid, convenience copy>",
  "provider_jwks": "<issuer JWKS URL — NON-NORMATIVE convenience hint>"
}
```

`provider_jwks` is non-normative: the envelope names the issuer, and key
resolution is out of band, from the pinned source in each claim type's public
spec (ours pins the canonical JWKS URL and the issuer is a did:web; Facet's
pins issuer.facet.llc), seeded into the verifier's trust list. A hint pointing
anywhere else simply fails verification against the pinned source and MUST NOT
override it. Everything outside `jws` is an untrusted convenience hint until the signature
verifies. Adding a third issuer is adding one more entry; nothing else changes.

Honest note on the committed `envelope.json`: the KYA inside it was minted live
and carries Facet's 1h TTL by design, so its temporal window lapses. Its
signature and kid remain verifiable against the live JWKS for as long as the
key is published; re-run `node cross-verify.mjs` to mint a fresh one and
reproduce the full 4/4 from scratch.
