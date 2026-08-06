#!/usr/bin/env python
"""Generate ML-DSA-65 decision-provenance JWS conformance vectors (RFC 9964 / RFC 7515).

Writes to vectors/test-jwks.json and vectors/vectors.json relative to this script.
Python, not npm — `python gen_vectors.py`. Requires: pqcrypto, cryptography, rfc8785.

Algorithm: ML-DSA-65, registered JOSE `alg` value per RFC 9964 (ML-DSA for JOSE).
Public keys are emitted as RFC 9964 AKP JWKs (kty "AKP").

NOTE on private-key format: RFC 9964 AKP private keys carry the 32-byte ML-DSA
seed in the `priv` member. `pqcrypto.sign.ml_dsa_65.generate_keypair()` returns
an *expanded* 4032-byte secret key, NOT the bare 32-byte seed, so we cannot emit
a spec-faithful `priv` member. We publish only public JWKs (verification vectors).
"""
import base64
import hashlib
import json
import os

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pqcrypto.sign.ml_dsa_65 import generate_keypair
from pqcrypto.sign.ml_dsa_65 import sign as mldsa_sign

ALG = "ML-DSA-65"
TYP = "application/vc+jws"
OUTDIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.join(OUTDIR, "vectors")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def akp_jwk(pub: bytes) -> dict:
    return {"alg": ALG, "kty": "AKP", "pub": b64u(pub)}


def kid_thumbprint(pub: bytes) -> str:
    """RFC 7638-style thumbprint over canonical AKP JWK members (alg, kty, pub)."""
    members = {"alg": ALG, "kty": "AKP", "pub": b64u(pub)}
    return b64u(hashlib.sha256(rfc8785.dumps(members)).digest())


def ed25519_jwk_thumbprint(pub_raw: bytes) -> str:
    """RFC 7638 JWK thumbprint for OKP/Ed25519 (crv, kty, x — lexicographic)."""
    members = {"crv": "Ed25519", "kty": "OKP", "x": b64u(pub_raw)}
    return b64u(hashlib.sha256(rfc8785.dumps(members)).digest())


def make_jws(header: dict, payload: dict, sk: bytes):
    """Return (compact_jws, signing_input, raw_sig).

    RFC 7515: signing_input = ASCII(b64u(utf8(header)) + "." + b64u(jcs(payload))).
    Payload is JCS-canonicalized (RFC 8785) before base64url encoding.
    """
    header_b64 = b64u(rfc8785.dumps(header))
    payload_b64 = b64u(rfc8785.dumps(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = mldsa_sign(sk, signing_input)
    return f"{header_b64}.{payload_b64}.{b64u(sig)}", signing_input, sig


def base_payload(session_id: str, iat: int, exp: int) -> dict:
    return {
        "aud": "https://merchant.example/ucp",
        "claim": {
            "cited_inputs": [
                {
                    "digest": "sha256:" + hashlib.sha256(b"sku-4471").hexdigest(),
                    "id": "input:catalog/sku-4471",
                    "source": "https://merchant.example/catalog",
                    "trust": "trusted",
                },
                {
                    "digest": "sha256:" + hashlib.sha256(b"promo").hexdigest(),
                    "id": "input:webscrape/promo-banner",
                    "source": "https://untrusted-blog.example/deal",
                    "trust": "untrusted",
                },
            ],
            "decision": "authorize_checkout",
            "model_version": "algovoi-decider-1.4.2",
            "policy_version": "ucp-policy-2026.07",
            "ucp_checkout_session": session_id,
        },
        "exp": exp,
        "iat": iat,
        "iss": "did:web:algovoi.com",
        "sub": "agent://ucp-shopper/7f3a",
    }


def main():
    os.makedirs(VECTORS_DIR, exist_ok=True)

    NOW = 1_753_600_000  # fixed epoch (~2025-07-27); makes payload bytes reproducible
    HOUR = 3600
    SESSION = "ucp_sess_9c2e0f4a"

    pk_new, sk_new = generate_keypair()
    pk_old, sk_old = generate_keypair()

    ed_sk = Ed25519PrivateKey.generate()
    ed_pub_raw = ed_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ed_jkt = ed25519_jwk_thumbprint(ed_pub_raw)

    ed_sk_atk = Ed25519PrivateKey.generate()
    ed_pub_raw_atk = ed_sk_atk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    kid_new = kid_thumbprint(pk_new)
    kid_old = kid_thumbprint(pk_old)

    jwks = {"keys": [{**akp_jwk(pk_new), "kid": kid_new}]}
    jwks_path = os.path.join(VECTORS_DIR, "test-jwks.json")
    with open(jwks_path, "w", encoding="utf-8") as f:
        json.dump(jwks, f, indent=2, sort_keys=True)
    print(f"wrote {jwks_path}")

    header_new = {"alg": ALG, "kid": kid_new, "typ": TYP}
    header_old = {"alg": ALG, "kid": kid_old, "typ": TYP}
    hyb_header = {"alg": ALG, "cty": "hybrid", "kid": kid_new, "typ": TYP}

    vectors = {}
    sig_len_example = None

    # 1. VALID
    pl = base_payload(SESSION, NOW, NOW + HOUR)
    jws, _, sig = make_jws(header_new, pl, sk_new)
    sig_len_example = len(sig)
    vectors["valid"] = {
        "expected_session": SESSION,
        "jws": jws,
        "name": "valid",
        "note": "authentic ML-DSA-65 signature, session matches, not expired",
        "now": NOW,
        "overall_expected": "accept",
        "verification_expected": "authentic",
    }

    # 2. EXPIRED — authentic sig; consumer rejects on scope (exp in past)
    pl = base_payload(SESSION, NOW - 2 * HOUR, NOW - HOUR)
    jws, _, _ = make_jws(header_new, pl, sk_new)
    vectors["expired"] = {
        "expected_session": SESSION,
        "jws": jws,
        "name": "expired",
        "note": "authentic signature; consumer rejects because exp is in the past",
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "consumer",
        "reject_reason": "scope",
        "verification_expected": "authentic",
    }

    # 3. WRONG-SESSION — authentic sig; consumer rejects on scope (session mismatch)
    pl = base_payload("ucp_sess_DEADBEEF", NOW, NOW + HOUR)
    jws, _, _ = make_jws(header_new, pl, sk_new)
    vectors["wrong-session"] = {
        "expected_session": SESSION,
        "jws": jws,
        "name": "wrong-session",
        "note": "authentic signature; consumer rejects because ucp_checkout_session != the one in hand",
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "consumer",
        "reject_reason": "scope",
        "verification_expected": "authentic",
    }

    # 4. ROTATED-KEY — verifier rejects (kid absent from JWKS)
    pl = base_payload(SESSION, NOW, NOW + HOUR)
    jws, _, _ = make_jws(header_old, pl, sk_old)
    vectors["rotated-key"] = {
        "expected_session": SESSION,
        "jws": jws,
        "name": "rotated-key",
        "note": "signed by rotated-out key; kid absent from JWKS",
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "verifier",
        "reject_reason": "unknown-kid",
        "verification_expected": "reject",
    }

    # 5. BAD-SIGNATURE — bit-flip in decoded sig bytes (not a base64 char)
    pl = base_payload(SESSION, NOW, NOW + HOUR)
    header_b64 = b64u(rfc8785.dumps(header_new))
    payload_b64 = b64u(rfc8785.dumps(pl))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = bytearray(mldsa_sign(sk_new, signing_input))
    sig[0] ^= 0x01
    jws = f"{header_b64}.{payload_b64}.{b64u(bytes(sig))}"
    vectors["bad-signature"] = {
        "expected_session": SESSION,
        "jws": jws,
        "name": "bad-signature",
        "note": "one bit flipped in DECODED signature bytes (not a base64 char)",
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "verifier",
        "reject_reason": "signature",
        "verification_expected": "reject",
    }

    # 6. HYBRID: Ed25519 co-sig verifies, ML-DSA corrupted
    # cnf.jkt binds the classical key inside PQC-signed payload (RFC 7800).
    # Catches a verifier that silently falls back to the classical half.
    pl = base_payload(SESSION, NOW, NOW + HOUR)
    pl["cnf"] = {"jkt": ed_jkt}
    header_b64 = b64u(rfc8785.dumps(hyb_header))
    payload_b64 = b64u(rfc8785.dumps(pl))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    ed_sig = ed_sk.sign(signing_input)
    bad_mldsa = bytearray(mldsa_sign(sk_new, signing_input))
    bad_mldsa[0] ^= 0x01
    jws = f"{header_b64}.{payload_b64}.{b64u(bytes(bad_mldsa))}"
    vectors["hybrid-classical-valid-pqc-invalid"] = {
        "ed25519_pub": b64u(ed_pub_raw),
        "ed25519_sig": b64u(ed_sig),
        "expected_session": SESSION,
        "jws": jws,
        "name": "hybrid-classical-valid-pqc-invalid",
        "note": (
            "Ed25519 co-sig verifies and cnf.jkt matches ed25519_pub, "
            "but ML-DSA signature is corrupted. "
            "Catches a verifier that silently falls back to the classical half."
        ),
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "verifier",
        "reject_reason": "pqc-signature",
        "verification_expected": "reject",
    }

    # 7. HYBRID: attacker's Ed25519 pair substituted, cnf.jkt names original key
    # Classical co-sig verifies against the attacker's key, but cnf.jkt mismatch
    # is detected. Catches a verifier that falls back without checking cnf binding.
    pl7 = base_payload(SESSION, NOW, NOW + HOUR)
    pl7["cnf"] = {"jkt": ed_jkt}
    payload_b64_7 = b64u(rfc8785.dumps(pl7))
    signing_input_7 = f"{header_b64}.{payload_b64_7}".encode("ascii")
    ed_sig_atk = ed_sk_atk.sign(signing_input_7)
    bad_mldsa_7 = bytearray(mldsa_sign(sk_new, signing_input_7))
    bad_mldsa_7[0] ^= 0x01
    jws7 = f"{header_b64}.{payload_b64_7}.{b64u(bytes(bad_mldsa_7))}"
    vectors["hybrid-substituted-classical-pqc-invalid"] = {
        "ed25519_pub": b64u(ed_pub_raw_atk),
        "ed25519_sig": b64u(ed_sig_atk),
        "expected_session": SESSION,
        "jws": jws7,
        "name": "hybrid-substituted-classical-pqc-invalid",
        "note": (
            "Attacker substitutes their own Ed25519 pair; classical co-sig verifies "
            "against the attacker's key, but cnf.jkt in the PQC-signed payload names "
            "the original key — mismatch detected. ML-DSA also corrupted. "
            "Catches a verifier that falls back to Ed25519 without checking cnf.jkt."
        ),
        "now": NOW,
        "overall_expected": "reject",
        "reject_layer": "verifier",
        "reject_reason": "cnf-mismatch",
        "verification_expected": "reject",
    }

    combined = {
        "claim_type": "decision-provenance",
        "envelope": (
            "compact JWS (RFC 7515), ML-DSA-65 (RFC 9964) over RFC 8785 (JCS) "
            "canonical bytes, kid in protected header, RFC 9964 AKP JWK"
        ),
        "signal": "com.algovoi.decision_provenance",
        "test_jwks": "test-jwks.json",
        "vectors": vectors,
        "verify": "python verify.py  # pqcrypto ml_dsa_65 primitive; pre-interoperability",
    }
    vectors_path = os.path.join(VECTORS_DIR, "vectors.json")
    with open(vectors_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, sort_keys=True)
    print(f"wrote {vectors_path}")

    print()
    print("summary:")
    print(f"  ML-DSA-65 public key : {len(pk_new)} bytes")
    print(f"  ML-DSA-65 signature  : {sig_len_example} bytes")
    print(f"  header alg/typ       : {ALG} / {TYP}")
    print(f"  jwk kty/alg          : AKP / {ALG}")
    print(f"  signal               : com.algovoi.decision_provenance")


if __name__ == "__main__":
    main()
