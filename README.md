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

## Status

Just started. Conformance vectors (valid, expired, wrong-session, bad signature, rotated key) from both sides land here as the envelope's field names settle in #534.

## Contributing

Open to anyone building a verifier or issuer in this space. Open an issue or a PR.
