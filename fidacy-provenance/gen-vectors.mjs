#!/usr/bin/env node
/**
 * Conformance vectors for the decision-provenance claim type: the after-the-fact
 * half of the UCP external-verifier envelope
 * (Universal-Commerce-Protocol/ucp #534 / #535, use case in #56).
 *
 * A cold reader reproduces this half without asking Fidacy: a fixed TEST keypair,
 * its JWKS, and five vectors, each self-validated with plain `jose`. No vendor
 * verifier, zero network, deterministic forever.
 *
 *   npm i && node gen-vectors.mjs
 *
 * Why plain jose and not @fidacy/verify: identity and risk are checked at
 * decision time by software that already trusts a library. A provenance receipt
 * is opened years later by an auditor, an insurer or opposing counsel, who will
 * reach for whatever JOSE implementation they already have. A profile that needs
 * the issuer's package to be readable has not solved the problem it exists for.
 *
 * The five outcomes:
 *   valid            -> verifies
 *   bad-signature    -> rejected, signature (signature byte flipped)
 *   rotated-key      -> rejected, unknown kid (kid absent from the JWKS)
 *   wrong-typ        -> rejected, typ (header typ not the pinned value)
 *   content-mismatch -> signature verifies BY DESIGN; the consumer rejects
 *                       because sha256(record bytes) != the receipt's sha256.
 *                       Authenticity is the verifier's job, correspondence to a
 *                       document in hand is the consumer's.
 *
 * Production shape: compact JWS, EdDSA (Ed25519), kid in the protected header,
 * typ fidacy-artifact-receipt+jws, payload keys JCS-sorted. This test signer
 * matches it. A real production receipt, verifiable against the LIVE JWKS at
 * https://api.fidacy.com/.well-known/jwks.json, is in vector-valid.json.
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportJWK, CompactSign, compactVerify, calculateJwkThumbprint, createLocalJWKSet } from "jose";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "vectors");
mkdirSync(OUT, { recursive: true });

const TYP = "fidacy-artifact-receipt+jws";

// RFC 8785 (JCS) minimal: recursively sorted keys, no whitespace.
function jcs(value) {
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}
const bytes = (obj) => new TextEncoder().encode(jcs(obj));
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");

// Two test keys: the active one is published in the JWKS; the rotated one is not.
const active = await generateKeyPair("Ed25519", { extractable: true });
const rotated = await generateKeyPair("Ed25519", { extractable: true });
const activePubJwk = await exportJWK(active.publicKey);
const rotatedPubJwk = await exportJWK(rotated.publicKey);
const activeKid = await calculateJwkThumbprint(activePubJwk, "sha256");
const rotatedKid = await calculateJwkThumbprint(rotatedPubJwk, "sha256");
activePubJwk.kid = activeKid;
rotatedPubJwk.kid = rotatedKid;
const testJwks = { keys: [{ ...activePubJwk, use: "sig", alg: "EdDSA" }] };
writeFileSync(join(OUT, "test-jwks.json"), JSON.stringify(testJwks, null, 2));
const JWKS = createLocalJWKSet(testJwks);

// The decision record the receipt attests. It is NEVER uploaded: the issuer sees
// only its hash, which is the whole point of the content-hash model in envelope
// section 7. Committed here so a cold reader can recompute the digest.
const RECORD = {
  decision: "deny",
  mandate: "mandate:demo-northwind-q3",
  payee: "supplier:evil",
  rule: "payee_not_in_allowlist",
  ts: "2026-07-19T00:27:11.402Z",
};
const RECORD_BYTES = bytes(RECORD);
const RECORD_SHA256 = sha256hex(RECORD_BYTES);
writeFileSync(join(OUT, "decision-record.json"), JSON.stringify(RECORD, null, 2));

function baseClaims(overrides = {}) {
  return {
    artifactId: "00000000-0000-4000-8000-0000000000f1",
    audit: { hash: "9a5fa9f42c01d6be3e2a6a7b57399d52bbea7c71fce71bee9674a830d886bc4e", seq: 158 },
    digest: "53a5027d77b06a448a09da339d9093470607bc523c3a5c4ef8568918f1806014",
    kind: "custom",
    org: "61e8a3ed-4226-4ef3-bbc5-42fc939164d5",
    sha256: RECORD_SHA256,
    subject: "agent:demo-northwind",
    ts: "2026-07-19T00:27:19.120Z",
    v: "fidacy.artifact.v1",
    ...overrides,
  };
}
async function sign(claims, key, kid, typ = TYP) {
  return new CompactSign(bytes(claims)).setProtectedHeader({ alg: "EdDSA", kid, typ }).sign(key);
}

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`); };

// A conformant verifier for this profile: signature over the pinned JWKS, and the
// typ pinned. Everything else is the consumer's.
async function verify(jws) {
  const { payload, protectedHeader } = await compactVerify(jws, JWKS);
  if (protectedHeader.typ !== TYP) { const e = new Error("typ"); e.code = "typ"; throw e; }
  return { claims: JSON.parse(new TextDecoder().decode(payload)), protectedHeader };
}
async function expectValid(jws, label) {
  try { await verify(jws); ok(true, label); }
  catch (e) { ok(false, label, `threw ${e.code ?? e.message}`); }
}
// The codes are jose's own, not ours: a reader with any JOSE implementation gets
// the same two rejections under whatever names that library uses. Asserting on
// jose's codes here keeps the vector honest about which library produced them.
async function expectReject(jws, code, label) {
  try { await verify(jws); ok(false, label, "verified but should have failed"); }
  catch (e) { ok(e.code === code, label, e.code ?? e.message); }
}

const vectors = {};

// 1) valid
const vValid = await sign(baseClaims(), active.privateKey, activeKid);
vectors.valid = { jws: vValid, expect: "valid" };
await expectValid(vValid, "valid -> verifies");

// 2) bad-signature: flip a bit in the DECODED signature bytes, not in the text.
//
// Editing the last base64url character does not reliably corrupt anything. An
// Ed25519 signature is 64 bytes, which is 86 base64url characters, so the final
// character carries only 2 significant bits and its other 4 are padding. Only
// "A", "Q", "g" and "w" can legally appear there, and rewriting an "A" to a "B"
// touches padding alone: both spellings decode to the same 64 bytes and the
// signature is still genuine. That is the porting gotcha the identity and risk
// generators both shipped with; it is fixed there and never present here.
const parts = vValid.split(".");
const sigBytes = Buffer.from(parts[2], "base64url");
sigBytes[0] ^= 0x01;
parts[2] = sigBytes.toString("base64url");
const vBadSig = parts.join(".");
vectors["bad-signature"] = { jws: vBadSig, expect: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" };
await expectReject(vBadSig, "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "bad-signature -> rejected (signature)");

// 3) rotated-key: signed by a kid absent from the published JWKS
const vRotated = await sign(baseClaims(), rotated.privateKey, rotatedKid);
vectors["rotated-key"] = { jws: vRotated, expect: "ERR_JWKS_NO_MATCHING_KEY" };
await expectReject(vRotated, "ERR_JWKS_NO_MATCHING_KEY", "rotated-key -> rejected (unknown kid)");

// 4) wrong-typ: authentic signature, wrong header typ. The typ is pinned because
// a receipt and a risk verdict are both EdDSA over JCS bytes from the same issuer
// and the same key; without the pin, one could be presented as the other.
const vWrongTyp = await sign(baseClaims(), active.privateKey, activeKid, "application/vc+jws");
vectors["wrong-typ"] = { jws: vWrongTyp, expect: "typ" };
await expectReject(vWrongTyp, "typ", "wrong-typ -> rejected 'typ'");

// 5) content-mismatch: signature is VALID BY DESIGN. The receipt is authentic; it
// simply attests a different document than the one the consumer is holding. This
// is the provenance analog of the risk profile's wrong-session and the identity
// profile's wrong-audience: authenticity and correspondence are different
// questions, and collapsing them into the verifier would silently skip the check
// the moment anyone verifies out of band.
const CONTENT_MISMATCH_NOTE =
  "NOT A HOLE, by design: the signature verifies because the receipt is authentic. " +
  "The verifier proves authenticity, not correspondence. The consumer MUST hash the " +
  "record bytes in hand and compare against the receipt's sha256 claim, rejecting on " +
  "mismatch (gen-vectors.mjs demonstrates that check).";
const TAMPERED = { ...RECORD, payee: "supplier:acme" };
const TAMPERED_SHA256 = sha256hex(bytes(TAMPERED));
vectors["content-mismatch"] = {
  jws: vValid,
  presented_record: TAMPERED,
  expect: "signature valid; consumer rejects on sha256 mismatch",
  note: CONTENT_MISMATCH_NOTE,
};
const { claims } = await verify(vValid);
ok(claims.sha256 === RECORD_SHA256, "content-mismatch -> receipt commits to the original record");
ok(TAMPERED_SHA256 !== claims.sha256, "content-mismatch -> consumer sees sha256(presented) != receipt.sha256", TAMPERED_SHA256.slice(0, 16) + "…");
console.log(`NOTE  content-mismatch verifying is intentional: ${CONTENT_MISMATCH_NOTE}`);

writeFileSync(join(OUT, "vectors.json"), JSON.stringify({
  claim_type: "decision-provenance",
  signal: "com.fidacy.decision_provenance",
  envelope: `compact JWS, EdDSA (Ed25519) over RFC 8785 (JCS) bytes, kid in protected header, typ ${TYP}`,
  test_jwks: "test-jwks.json",
  record: "decision-record.json",
  record_sha256: RECORD_SHA256,
  verify: "plain jose -> compactVerify(jws, createLocalJWKSet(testJwks)), then pin typ",
  vectors,
}, null, 2));

console.log(`\nconformance vectors: ${pass} pass, ${fail} fail`);
console.log(`written -> vectors/ (vectors.json + test-jwks.json + decision-record.json)`);
process.exit(fail === 0 ? 0 : 1);
