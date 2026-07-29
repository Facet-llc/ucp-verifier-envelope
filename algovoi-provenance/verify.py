#!/usr/bin/env python
"""Verify ML-DSA-65 decision-provenance JWS conformance vectors.

Two-layer verification model:
  VERIFIER layer  -- signature authentic (ML-DSA check; cnf.jkt + Ed25519 for hybrid).
  CONSUMER layer  -- scope checks (expiry, session binding).

An authentic credential rejected at the consumer layer is NOT a verifier failure.
Vectors capture both layers separately so the distinction is explicit and testable.

Reads vectors/vectors.json and vectors/test-jwks.json relative to this script.
Python, not npm -- `python verify.py`. Requires: pqcrypto, cryptography, rfc8785.

For each vector:
  1. Split compact JWS into header_b64.payload_b64.sig_b64.
  2. signing_input = ASCII(header_b64 + "." + payload_b64).
  3. Verify ML-DSA-65 over signing_input against the JWKS key named by header.kid.
  4. For hybrid vectors: verify cnf.jkt binding and Ed25519 co-signature.
  5. Consumer scope: exp not in the past; ucp_checkout_session matches.
"""
import base64
import hashlib
import json
import os

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pqcrypto.sign.ml_dsa_65 import verify as mldsa_verify

OUTDIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.join(OUTDIR, "vectors")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ed25519_jwk_thumbprint(pub_raw: bytes) -> str:
    """RFC 7638 JWK thumbprint for OKP/Ed25519 (crv, kty, x -- lexicographic)."""
    members = {"crv": "Ed25519", "kty": "OKP", "x": b64u(pub_raw)}
    return b64u(hashlib.sha256(rfc8785.dumps(members)).digest())


def load_jwks():
    with open(os.path.join(VECTORS_DIR, "test-jwks.json"), encoding="utf-8") as f:
        jwks = json.load(f)
    return {k["kid"]: b64u_dec(k["pub"]) for k in jwks["keys"] if k.get("kty") == "AKP"}


def check_pqc(jws: str, jwks_by_kid: dict):
    """Returns (ok: bool, detail: str). ok=False on any ML-DSA failure."""
    try:
        header_b64, payload_b64, sig_b64 = jws.split(".")
    except ValueError:
        return False, "malformed JWS"
    header = json.loads(b64u_dec(header_b64))
    pub = jwks_by_kid.get(header.get("kid"))
    if pub is None:
        return False, "kid not in JWKS"
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        ok = bool(mldsa_verify(pub, signing_input, b64u_dec(sig_b64)))
        return (True, "") if ok else (False, "ML-DSA verify returned False")
    except Exception as exc:
        return False, f"ML-DSA exception: {exc}"


def check_cnf_and_classical(jws: str, ed_sig_b64: str, ed_pub_b64: str):
    """Returns (ok: bool, detail: str) for the cnf.jkt binding + Ed25519 co-sig.

    Steps:
      1. Decode payload; require cnf.jkt.
      2. Compute Ed25519 JWK thumbprint of ed_pub; must match cnf.jkt.
         Mismatch means the classical key was substituted -- reject.
      3. Verify Ed25519 signature over the signing input.
    """
    try:
        header_b64, payload_b64, _ = jws.split(".")
        payload = json.loads(b64u_dec(payload_b64))
        expected_jkt = payload.get("cnf", {}).get("jkt")
        if not expected_jkt:
            return False, "no cnf.jkt in payload"
        ed_pub_raw = b64u_dec(ed_pub_b64)
        if ed25519_jwk_thumbprint(ed_pub_raw) != expected_jkt:
            return False, "cnf.jkt mismatch (classical key substituted)"
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        Ed25519PublicKey.from_public_bytes(ed_pub_raw).verify(
            b64u_dec(ed_sig_b64), signing_input
        )
        return True, ""
    except InvalidSignature:
        return False, "Ed25519 signature invalid"
    except Exception as exc:
        return False, str(exc)


def verifier_layer(v: dict, jwks_by_kid: dict):
    """Returns (authentic: bool, detail: str).

    Hybrid vectors require both PQC and cnf-bound classical to pass.
    """
    pqc_ok, pqc_detail = check_pqc(v["jws"], jwks_by_kid)
    if "ed25519_pub" not in v:
        return pqc_ok, pqc_detail
    cnf_ok, cnf_detail = check_cnf_and_classical(
        v["jws"], v["ed25519_sig"], v["ed25519_pub"]
    )
    if pqc_ok and cnf_ok:
        return True, ""
    parts = [d for d in [pqc_detail if not pqc_ok else "", cnf_detail if not cnf_ok else ""] if d]
    return False, "; ".join(parts)


def consumer_layer(jws: str, expected_session: str, now: int) -> bool:
    _, payload_b64, _ = jws.split(".")
    payload = json.loads(b64u_dec(payload_b64))
    if payload.get("exp", 0) < now:
        return False
    return payload.get("claim", {}).get("ucp_checkout_session") == expected_session


def try_stock_jose():
    try:
        import jwcrypto  # noqa: F401
        from jwcrypto import common as _c
        has_akp = any("AKP" in str(getattr(_c, n, "")) for n in dir(_c))
        return None, "jwcrypto present but no AKP/ML-DSA support" if not has_akp else "no AKP path"
    except Exception:
        return None, "jwcrypto not importable"


def main():
    jwks_by_kid = load_jwks()
    with open(os.path.join(VECTORS_DIR, "vectors.json"), encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    all_pass = True
    for name, v in data["vectors"].items():
        auth, auth_detail = verifier_layer(v, jwks_by_kid)
        scope_ok = consumer_layer(v["jws"], v["expected_session"], v["now"])

        verif_actual = "authentic" if auth else "reject"
        verif_expected = v.get(
            "verification_expected",
            "authentic" if v["overall_expected"] == "accept" else "reject",
        )
        verif_pass = verif_actual == verif_expected
        overall_actual = "accept" if (auth and scope_ok) else "reject"
        overall_pass = overall_actual == v["overall_expected"]

        ok = verif_pass and overall_pass
        all_pass = all_pass and ok
        rows.append({
            "name": v["name"],
            "verif_expected": verif_expected,
            "verif_actual": verif_actual,
            "verif_pass": verif_pass,
            "scope_ok": scope_ok,
            "overall_expected": v["overall_expected"],
            "overall_actual": overall_actual,
            "overall_pass": overall_pass,
            "ok": ok,
            "detail": auth_detail,
        })

    def _row(r, fields, widths):
        return "  ".join(str(r[f]).ljust(widths[i]) for i, f in enumerate(fields))

    vw = [46, 18, 18, 8, 35]
    print("VERIFIER LAYER")
    print("  ".join(h.ljust(vw[i]) for i, h in enumerate(
        ["vector", "verif_expected", "verif_actual", "v_pass", "detail"])))
    print("-" * (sum(vw) + 2 * (len(vw) - 1)))
    for r in rows:
        cells = {
            "vector": r["name"], "verif_expected": r["verif_expected"],
            "verif_actual": r["verif_actual"],
            "v_pass": "PASS" if r["verif_pass"] else "FAIL",
            "detail": r["detail"],
        }
        print("  ".join(str(cells[f]).ljust(vw[i])
                        for i, f in enumerate(["vector", "verif_expected", "verif_actual", "v_pass", "detail"])))

    cw = [46, 9, 18, 15, 8]
    print("\nCONSUMER LAYER")
    print("  ".join(h.ljust(cw[i]) for i, h in enumerate(
        ["vector", "scope_ok", "overall_expected", "overall_actual", "result"])))
    print("-" * (sum(cw) + 2 * (len(cw) - 1)))
    for r in rows:
        cells = {
            "vector": r["name"], "scope_ok": str(r["scope_ok"]),
            "overall_expected": r["overall_expected"], "overall_actual": r["overall_actual"],
            "result": "PASS" if r["overall_pass"] else "FAIL",
        }
        print("  ".join(str(cells[f]).ljust(cw[i])
                        for i, f in enumerate(["vector", "scope_ok", "overall_expected", "overall_actual", "result"])))

    _, reason = try_stock_jose()
    print(f"\nstock JOSE cross-check: NONE ({reason}); "
          f"verification via pqcrypto ml_dsa_65.verify (pre-interoperability, expected)")

    result = "YES" if all_pass else "NO"
    print(f"\nall vectors consistent (both layers match expected): {result}")
    raise SystemExit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
