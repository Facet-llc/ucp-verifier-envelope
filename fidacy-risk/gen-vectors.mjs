#!/usr/bin/env node
/**
 * Conformance vectors for the risk-verdict claim type: the Fidacy half of the
 * UCP external-verifier envelope (Universal-Commerce-Protocol/ucp #534 / #535).
 *
 * A cold reader reproduces the risk half without asking Fidacy: a fixed TEST
 * keypair, its JWKS, and five vectors, each self-validated against the real,
 * published `@fidacy/verify` (npm) with the test JWKS injected. Zero network,
 * deterministic forever.
 *
 *   npm i && node gen-vectors.mjs
 *
 * The five outcomes mirror `@fidacy/verify`'s own reason codes:
 *   valid          -> { valid: true }
 *   expired        -> FidacyVerificationError 'expired'   (exp in the past)
 *   bad-signature  -> 'invalid_signature'                 (signature byte flipped)
 *   rotated-key    -> 'unknown_kid'                       (kid absent from the JWKS)
 *   wrong-session  -> verify() returns VALID; the SESSION MISMATCH is a
 *                     consumer-layer check (the merchant compares the claim's
 *                     subject to the checkout in hand). @fidacy/verify proves
 *                     authenticity, not scope.
 *
 * Production shape: compact JWS, EdDSA (Ed25519) over RFC 8785 (JCS) bytes, kid
 * in the protected header, typ application/vc+jws. This test signer matches it.
 * A real production verdict, verifiable against the LIVE JWKS at
 * https://api.fidacy.com/.well-known/jwks.json, is in vector-valid.json.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportJWK, CompactSign, calculateJwkThumbprint } from "jose";
import { verifyRiskPayload, FidacyVerificationError } from "@fidacy/verify";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "vectors");
mkdirSync(OUT, { recursive: true });

// RFC 8785 (JCS) minimal: recursively sorted keys, no whitespace. Exact for the
// flat, string/number claim sets used here (matches the engine's canonicalBytes).
function jcs(value) {
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}
const bytes = (obj) => new TextEncoder().encode(jcs(obj));

// Two test keys: the active one is published in the JWKS; the rotated one is not.
const active = await generateKeyPair("Ed25519", { extractable: true });
const rotated = await generateKeyPair("Ed25519", { extractable: true });
const activePubJwk = await exportJWK(active.publicKey);
const rotatedPubJwk = await exportJWK(rotated.publicKey);
const activeKid = await calculateJwkThumbprint(activePubJwk, "sha256");
const rotatedKid = await calculateJwkThumbprint(rotatedPubJwk, "sha256");
activePubJwk.kid = activeKid;
rotatedPubJwk.kid = rotatedKid;
// The published test JWKS contains ONLY the active key (rotated-key is absent).
const testJwks = { keys: [{ ...activePubJwk, use: "sig", alg: "EdDSA" }] };
writeFileSync(join(OUT, "test-jwks.json"), JSON.stringify(testJwks, null, 2));

const ISSUER = `did:web:fidacy.com#${activeKid}`;
function baseClaims(overrides = {}) {
  return {
    issuer: ISSUER,
    subject: "agent:demo-northwind",
    decision: "deny",
    score: 50,
    signals: { rule: "payee_not_in_allowlist" },
    model_version: "fidacy-risk-0.1.0",
    policy_version: "none",
    assessed_at: "2026-07-18T12:00:00.000Z",
    ...overrides,
  };
}
async function sign(claims, key, kid) {
  return new CompactSign(bytes(claims))
    .setProtectedHeader({ alg: "EdDSA", kid, typ: "application/vc+jws" })
    .sign(key);
}

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`); };
async function expectValid(jws, label) {
  try { const r = await verifyRiskPayload(jws, { jwks: testJwks }); ok(r.valid === true, label); }
  catch (e) { ok(false, label, `threw ${e.code ?? e.message}`); }
}
async function expectReject(jws, code, label, verifyOpts = {}) {
  try { await verifyRiskPayload(jws, { jwks: testJwks, ...verifyOpts }); ok(false, label, "verified but should have failed"); }
  catch (e) { ok(e instanceof FidacyVerificationError && e.code === code, label, e.code ?? e.message); }
}

const vectors = {};

// 1) valid
const vValid = await sign(baseClaims(), active.privateKey, activeKid);
vectors.valid = { jws: vValid, expect: "valid" };
await expectValid(vValid, "valid -> verifies");

// 2) expired: forward-compat exp in the past
const vExpired = await sign(baseClaims({ exp: 1000000000 }), active.privateKey, activeKid); // 2001
vectors.expired = { jws: vExpired, expect: "expired" };
await expectReject(vExpired, "expired", "expired -> rejected 'expired'");

// 3) bad-signature: flip the last char of the signature segment
const parts = vValid.split(".");
parts[2] = parts[2].slice(0, -1) + (parts[2].slice(-1) === "A" ? "B" : "A");
const vBadSig = parts.join(".");
vectors["bad-signature"] = { jws: vBadSig, expect: "invalid_signature" };
await expectReject(vBadSig, "invalid_signature", "bad-signature -> rejected 'invalid_signature'");

// 4) rotated-key: signed by a kid absent from the published JWKS
const vRotated = await sign(baseClaims({ issuer: `did:web:fidacy.com#${rotatedKid}` }), rotated.privateKey, rotatedKid);
vectors["rotated-key"] = { jws: vRotated, expect: "unknown_kid" };
await expectReject(vRotated, "unknown_kid", "rotated-key -> rejected 'unknown_kid'");

// 5) wrong-session: signature is VALID BY DESIGN; the session binding is a
// consumer check. The verifier answers "is this verdict real and untampered?";
// the consumer answers "is it about the checkout in front of me?". Authenticity
// and scope are different questions, and collapsing them into the verifier
// would silently skip the scope check the moment anyone verifies out of band.
const WRONG_SESSION_NOTE =
  "NOT A HOLE, by design: the signature verifies because the verdict is authentic. " +
  "The verifier proves authenticity, not scope. The consumer MUST compare the " +
  "claim's subject to the checkout session in hand and reject on mismatch " +
  "(gen-vectors.mjs demonstrates that check). Same separation as identity vs risk.";
const vWrongSession = await sign(baseClaims({ subject: "session:cs_OTHER" }), active.privateKey, activeKid);
vectors["wrong-session"] = {
  jws: vWrongSession,
  expect: "signature valid; consumer rejects on session mismatch",
  note: WRONG_SESSION_NOTE,
};
await expectValid(vWrongSession, "wrong-session -> signature verifies (session checked by consumer)");
const r = await verifyRiskPayload(vWrongSession, { jwks: testJwks });
ok(r.claims.subject !== "session:cs_THIS_CHECKOUT", "wrong-session -> consumer sees subject != presented session", r.claims.subject);
console.log(`NOTE  wrong-session verifying is intentional: ${WRONG_SESSION_NOTE}`);

writeFileSync(join(OUT, "vectors.json"), JSON.stringify({
  claim_type: "risk",
  signal: "com.fidacy.trust_verdict",
  envelope: "compact JWS, EdDSA (Ed25519) over RFC 8785 (JCS) bytes, kid in protected header, typ application/vc+jws",
  test_jwks: "test-jwks.json",
  verify: "npm @fidacy/verify -> verifyRiskPayload(jws, { jwks })",
  vectors,
}, null, 2));

console.log(`\nconformance vectors: ${pass} pass, ${fail} fail`);
console.log(`written -> vectors/ (vectors.json + test-jwks.json)`);
process.exit(fail === 0 ? 0 : 1);
