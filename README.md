# ucp-verifier-envelope

Joint reference implementation for a shared UCP Signals envelope carrying independently verifiable third-party attestations, one identity verdict, one risk verdict, riding the same `signals` array.

Grew out of two discussions on [Universal-Commerce-Protocol/ucp](https://github.com/Universal-Commerce-Protocol/ucp):

- [#534, a standard envelope for third-party verifier attestations](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
- [#535, a neutral External Verifier role and a standard trust-signal](https://github.com/Universal-Commerce-Protocol/ucp/discussions/535)

## Goal

Demonstrate the whole proposal end to end: a real checkout where an agent presents two independently signed verdicts, an identity attestation (Facet) and a transaction-risk attestation (Fidacy), each verified offline by the merchant against its issuer's own published keys, with no cooperation from either issuer required at verify time.

## Contributors

- Facet (`issuer.facet.llc`), agent identity, ES256 / compact JWS
- Fidacy (`com.fidacy.trust_verdict`), transaction risk, EdDSA / JCS-canonical

## Spec

- [`spec/envelope.md`](spec/envelope.md), the envelope: the `signals` map, the
  four entry fields (`jws`, `format`, `kid`, `provider_jwks`), the trust model,
  key resolution and the merchant allow-list, the verification steps, replay, and
  conformance.
- [`spec/claim-types/identity.md`](spec/claim-types/identity.md), the identity
  profile (`llc.facet.kya`), keyed to the vectors in `facet-identity/`.
- [`spec/claim-types/risk.md`](spec/claim-types/risk.md), the risk profile
  (`com.fidacy.trust_verdict`), keyed to the vectors in `fidacy-risk/`.
- [`spec/policy-and-model-versioning.md`](spec/policy-and-model-versioning.md), what
  `policy_version` and `model_version` are for, and why a claim type that carries
  a judgement rather than a fact has to sign them.

## Status

Field names settled in [#534](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
and written up in `spec/`. Two independent claim types (identity, ES256; risk,
EdDSA) verify under the envelope end to end, reproducible via
[`cross-verify/`](cross-verify/). Conformance vectors (valid, expired,
wrong-session / wrong-audience, bad signature, rotated key) from both sides are
in-tree.

## Contributing

Open to anyone building a verifier or issuer in this space. Open an issue or a PR.
