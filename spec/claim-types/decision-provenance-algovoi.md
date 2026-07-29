# Claim type: decision-provenance (`com.algovoi.decision_provenance`)

AlgoVoi's decision-provenance profile for the verifier-attestation envelope: a
signed statement of **which AI decision was made, on what inputs, under what policy
and model version**, bound to a specific UCP checkout session. Issued by
`did:web:algovoi.com`.

The conformance vectors and generators for this profile live in
[`../../algovoi-provenance/`](../../algovoi-provenance/) and are the normative
reference for everything below. This file is the prose spec; the vectors are the test.

## Signal

| | |
|---|---|
| signal key | `com.algovoi.decision_provenance` |
| claim type | decision-provenance |
| scope | session (bound to one checkout, not to the agent) |
| envelope | compact JWS (RFC 7515) |
| alg | ML-DSA-65 (RFC 9964) over RFC 8785 (JCS) canonical bytes |
| `typ` | `application/vc+jws` |
| issuer | `did:web:algovoi.com` |
| JWKS | not yet published (pre-interoperability; see below) |
| verifier | `pqcrypto.sign.ml_dsa_65.verify` primitive (pre-interoperability; see below) |

The signature is ML-DSA-65 over the JCS-canonical bytes of the payload (RFC 8785)
rather than over the base64url segment, so a credential survives re-serialisation:
any party holding the claims can recompute the exact signed bytes and verify without
contacting AlgoVoi. The algorithm is fully specified here; no AlgoVoi package is
required.

## Protected header

```json
{ "alg": "ML-DSA-65", "kid": "<key id>", "typ": "application/vc+jws" }
```

Hybrid vectors additionally carry `"cty": "hybrid"`. The `kid` selects a key from
the issuer's JWKS. The `typ` MUST be `application/vc+jws` and MUST match the
envelope entry `format`.

## Claims

Serialised JCS-sorted.

| claim | required | meaning |
|---|---|---|
| `iss` | yes | `did:web:algovoi.com` (the issuer DID). |
| `sub` | yes | Agent identifier, e.g. `agent://ucp-shopper/7f3a`. |
| `aud` | yes | Merchant endpoint the credential is addressed to. |
| `iat` | yes | Unix timestamp when the credential was issued. |
| `exp` | yes | Expiry. A consumer MUST reject a credential with `exp` in the past. |
| `cnf` | no | RFC 7800 confirmation claim; present only in hybrid vectors. `cnf.jkt` is the RFC 7638 JWK thumbprint of the bound Ed25519 key. |
| `claim.decision` | yes | The decision made, e.g. `authorize_checkout`. |
| `claim.policy_version` | yes | Policy revision in force when the decision was made. |
| `claim.model_version` | yes | AI model version that produced the decision. |
| `claim.ucp_checkout_session` | yes | UCP checkout session identifier (consumer MUST check this). |
| `claim.cited_inputs` | yes | Array of inputs cited by the model. Each entry: `id` (input identifier), `source` (URL or scheme), `trust` (`trusted` or `untrusted`), `digest` (e.g. `sha256:<hex>`). |

A decision the AI model made to *deny* is signed exactly like an authorize. A
profile where only the positive case is attestable cannot settle a dispute, because
the question at audit time is almost always what was refused.

## Scope: authenticity vs consumer check

The verifier's job is **authenticity**: is this a genuine, unmodified
`did:web:algovoi.com` credential, resolved by `kid` against the issuer JWKS and
ML-DSA signature-checked?

The consumer's job is **scope**: is this credential about the transaction in hand?
The consumer MUST check that `claim.ucp_checkout_session` matches the session it
holds, and that `exp` is in the future. A credential that passes the verifier but
fails the scope check is an authentic credential about a different transaction;
session mismatch is a consumer rejection, not a verifier failure.

Collapsing scope into the verifier would silently skip the check for out-of-band
verification flows.

## Anchoring (normative)

A **decision-provenance** credential MUST be anchored to an external timestamp
source before the checkout session closes, so that existence-by-time is provable
independently of the issuer. Acceptable mechanisms include: a qualified RFC 3161
timestamp over the compact JWS, inclusion in a transparency log, or a blockchain
anchor. The anchor MUST be obtainable without AlgoVoi participation.

A credential without an independent anchor does not satisfy this clause even if
`iat` is correct: `iat` is self-asserted and not verifiably time-bound.

This requirement exists because AI decision provenance is only useful in disputes
that arise after the fact. If the issuer can retroactively adjust the claimed
decision time, the credential cannot settle the dispute.

## Neutrality (normative)

The issuer of a **decision-provenance** credential MUST faithfully represent the AI
decision and cited inputs as they occurred. Selective omission of cited inputs,
alteration of the `decision` field, or post-hoc modification of `model_version` or
`policy_version` constitutes a violation of this clause.

The same constraint binds AlgoVoi on the same terms as any other issuer. A party
that issues decision-provenance credentials must have no financial incentive to
misrepresent the decision they attest. AlgoVoi takes no position in the underlying
transaction and receives no fee contingent on the decision outcome, which is what
makes its attestation non-self-serving. A future issuer that benefits from the
attested decision is excluded by this clause, not grandfathered by it.

## Conformance vectors

Seven deterministic vectors against a fixed test JWKS
([`../../algovoi-provenance/vectors/`](../../algovoi-provenance/vectors/)),
generated and verified by the Python scripts in that directory.

| vector | verifier result | consumer result | what it tests |
|---|---|---|---|
| `valid` | authentic | accept | baseline: good sig, right session, not expired |
| `expired` | authentic | reject (scope) | exp in the past; consumer check, not a verifier failure |
| `wrong-session` | authentic | reject (scope) | session mismatch; consumer check, not a verifier failure |
| `rotated-key` | reject | — | kid absent from JWKS |
| `bad-signature` | reject | — | one bit flipped in the decoded ML-DSA signature bytes |
| `hybrid-classical-valid-pqc-invalid` | reject | — | Ed25519 co-sig passes, ML-DSA corrupted; catches fallback to classical half |
| `hybrid-substituted-classical-pqc-invalid` | reject | — | attacker's Ed25519 substituted; cnf.jkt mismatch detected |

Reproduce:

```
cd decision-provenance
pip install pqcrypto cryptography rfc8785
python gen_vectors.py   # regenerates vectors/test-jwks.json and vectors/vectors.json
python verify.py        # 7/7 PASS required; exits non-zero on any mismatch
```

**Python, not npm.** The two existing profiles use `.mjs` generators; this profile
uses Python. The `pqcrypto` package is the only ML-DSA-65 Python implementation
available today; the install is straightforward.

Keys and signatures differ on each run (ML-DSA sign is randomised). The fixed
epoch (`NOW = 1_753_600_000`) makes payload bytes reproducible across runs.
Outcomes are stable regardless of which key pair was generated.

## Pre-interoperability status

Verification uses `pqcrypto.sign.ml_dsa_65.verify`, not a stock JOSE library.
No mainstream JOSE stack (including jwcrypto) ships AKP/ML-DSA support yet.
RFC 9964 registers ML-DSA-65 as `alg: "ML-DSA-65"` in the JOSE algorithm registry;
the key type is `kty: "AKP"`.

This profile graduates to full interoperability the day a published third-party JOSE
library verifies these vectors cold, without the pqcrypto primitive.

The Ed25519 classical half of the hybrid vectors verifies via PyCA `cryptography`,
a mainstream library, so the hybrid co-signature path is fully interoperable today.

A live JWKS at `https://algovoi.com/.well-known/jwks.json` will be published when
the first production issuer is deployed.

## Notes

- The signing-input rule is RFC 7515 compact JWS with an RFC 8785 (JCS) canonical
  payload: `ASCII(BASE64URL(header_json) + "." + BASE64URL(JCS(payload_json)))`.
  This is the same construction used for the Ed25519 profiles, so the two stacks
  interoperate on signing input before any JOSE library ships AKP.
- `kid` is an RFC 7638-style SHA-256 thumbprint over `{alg, kty, pub}` — a
  convention, not mandated by RFC 9964.
- RFC 9964 AKP private keys carry a 32-byte ML-DSA seed in the `priv` member.
  `pqcrypto.generate_keypair()` returns a 4032-byte expanded secret key, so no
  spec-faithful `priv` is emitted; only public JWKs appear in the test JWKS.
- `did:web:algovoi.com` will resolve to the same key material as the JWKS endpoint
  once the production JWKS is live.
