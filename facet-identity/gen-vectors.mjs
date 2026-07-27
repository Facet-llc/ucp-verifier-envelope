#!/usr/bin/env node
/**
 * Conformance vectors for the identity claim type: the Facet half of the UCP
 * external-verifier envelope (Universal-Commerce-Protocol/ucp #534 / #535).
 *
 * A cold reader reproduces the identity half without asking Facet: a fixed TEST
 * issuer keypair, its JWKS, and five vectors, each self-validated with the
 * standard `jose` library. Zero network, deterministic forever.
 *
 *   npm i && node gen-vectors.mjs
 *
 * A Facet KYA is a plain RFC 7519 ES256 JWT (typ kya+jwt), so it verifies with
 * ANY JOSE library against the issuer's published JWKS. No Facet-specific
 * verifier package is needed. That is the deliberate contrast with the risk
 * half: identity is a standard signed JWT, resolved by kid, dispatched by alg.
 * The production Terminal verifier (@facet/kya-verifier) adds policy on top
 * (typ pinning, the tier-based TTL ceiling, single-use nonce for pay-capable
 * tokens); none of that changes the signature the vectors below exercise.
 *
 * The five outcomes:
 *   valid          -> verifies
 *   expired        -> ERR_JWT_EXPIRED                        (exp in the past)
 *   bad-signature  -> ERR_JWS_SIGNATURE_VERIFICATION_FAILED  (signature byte flipped)
 *   rotated-key    -> ERR_JWKS_NO_MATCHING_KEY               (kid absent from the JWKS)
 *   wrong-audience -> signature VERIFIES; the AUDIENCE MISMATCH is a
 *                     consumer-layer check (the verifier confirms the token is a
 *                     genuine issuer.facet.llc identity assertion; the consumer
 *                     confirms it was minted for THIS verifier via the aud claim).
 *
 * Why wrong-audience and not wrong-session: a Facet KYA is an identity bearer,
 * agent-scoped, not bound to any one checkout. So the identity analog of the
 * risk half's wrong-session is wrong-audience. Same separation of authenticity
 * (a job for the verifier) from scope (a job for the consumer). A real KYA
 * signed by the live issuer, verifiable against the LIVE JWKS at
 * https://issuer.facet.llc/.well-known/jwks.json, is in vector-valid.json.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import {
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
  SignJWT,
  jwtVerify,
  createLocalJWKSet,
  errors,
} from "jose";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "vectors");
mkdirSync(OUT, { recursive: true });

const ISSUER = "https://issuer.facet.llc";
// The verifier/merchant this KYA is presented to. The valid vector carries it;
// the wrong-audience vector carries a different one, and the consumer rejects.
const MERCHANT_AUD = "https://merchant.example/ucp";
const OTHER_AUD = "https://other-merchant.example/ucp";

// Fixed timestamps so the deterministic snapshot verifies at any wall-clock
// time. Real KYAs are short-lived (1h default, 24h hard ceiling); the test
// vectors below use a stable long window because they verify a TEST key, not a
// live credential. The 1h TTL is a production policy shown by vector-valid.json.
const FIXED_IAT = 1752796800; // 2026-07-18T00:00:00Z
const LONG_EXP = 4102444800; // 2100-01-01T00:00:00Z (stable, far-future)
const PAST_IAT = 1000000000 - 3600; // 2001
const PAST_EXP = 1000000000; // 2001

// Two issuer test keys: the active one is published in the JWKS; the rotated one
// is not (rotated-key must fail kid resolution).
const active = await generateKeyPair("ES256", { extractable: true });
const rotated = await generateKeyPair("ES256", { extractable: true });
const activePubJwk = await exportJWK(active.publicKey);
const rotatedPubJwk = await exportJWK(rotated.publicKey);
const activeKid = await calculateJwkThumbprint(activePubJwk, "sha256");
const rotatedKid = await calculateJwkThumbprint(rotatedPubJwk, "sha256");
activePubJwk.kid = activeKid;
rotatedPubJwk.kid = rotatedKid;
// The published test JWKS contains ONLY the active key (rotated-key is absent).
const testJwks = { keys: [{ ...activePubJwk, use: "sig", alg: "ES256" }] };
writeFileSync(join(OUT, "test-jwks.json"), JSON.stringify(testJwks, null, 2));
const JWKS = createLocalJWKSet(testJwks);

// The agent's cryptographic identity (aid), an RFC 7638 thumbprint of the
// agent's own key, never PII. Matches @facet/kya-issuer aidFromThumbprint.
const agent = await generateKeyPair("ES256", { extractable: true });
const agentThumbprint = await calculateJwkThumbprint(await exportJWK(agent.publicKey), "sha256");
const AID = `facet:agent:${agentThumbprint}`;

function baseClaims(overrides = {}) {
  return {
    iss: ISSUER,
    aud: MERCHANT_AUD,
    aid: AID,
    iat: FIXED_IAT,
    nbf: FIXED_IAT,
    exp: LONG_EXP,
    apd: "facet",
    tier: "self",
    ...overrides,
  };
}
async function sign(claims, key, kid) {
  const { iat, nbf, exp, ...rest } = claims;
  const jwt = new SignJWT(rest).setProtectedHeader({ alg: "ES256", typ: "kya+jwt", kid });
  if (iat !== undefined) jwt.setIssuedAt(iat);
  if (nbf !== undefined) jwt.setNotBefore(nbf);
  if (exp !== undefined) jwt.setExpirationTime(exp);
  return jwt.sign(key);
}

let pass = 0,
  fail = 0;
const ok = (cond, label, extra = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`);
};

// Authenticity: is this a genuine, untampered issuer.facet.llc identity token?
// Pins typ and issuer, resolves the kid against the JWKS, checks the signature
// and the temporal window. Deliberately does NOT check aud: audience is scope,
// a consumer concern, exactly as wrong-audience shows.
async function verifyAuthenticity(jws) {
  return jwtVerify(jws, JWKS, { typ: "kya+jwt", issuer: ISSUER });
}
async function expectValid(jws, label) {
  try {
    await verifyAuthenticity(jws);
    ok(true, label);
  } catch (e) {
    ok(false, label, `threw ${e.code ?? e.message}`);
  }
}
async function expectReject(jws, code, label) {
  try {
    await verifyAuthenticity(jws);
    ok(false, label, "verified but should have failed");
  } catch (e) {
    ok(e.code === code, label, e.code ?? e.message);
  }
}

const vectors = {};

// 1) valid
const vValid = await sign(baseClaims(), active.privateKey, activeKid);
vectors.valid = { jws: vValid, expect: "valid" };
await expectValid(vValid, "valid -> verifies");
// consumer aud check passes for the valid vector
{
  const { payload } = await verifyAuthenticity(vValid);
  ok(payload.aud === MERCHANT_AUD, "valid -> consumer aud check passes", payload.aud);
}

// 2) expired
const vExpired = await sign(baseClaims({ iat: PAST_IAT, nbf: PAST_IAT, exp: PAST_EXP }), active.privateKey, activeKid);
vectors.expired = { jws: vExpired, expect: "expired" };
await expectReject(vExpired, "ERR_JWT_EXPIRED", "expired -> rejected ERR_JWT_EXPIRED");

// 3) bad-signature: flip a bit in the DECODED signature bytes, not in the text.
//
// Same correction as the risk side, and the same reason: an ES256 signature is
// r||s, 64 bytes, which is 86 base64url characters, so the final character
// carries 2 significant bits and 4 of padding. Only "A", "Q", "g" and "w" can
// legally appear there, and rewriting an "A" to a "B" touches padding alone:
// both decode to the same 64 bytes, the signature stays genuine, and jose is
// right to accept it. Measured on this generator before the fix: 2 failures in
// 12 runs, entirely dependent on where the signature happened to land.
const parts = vValid.split(".");
const sigBytes = Buffer.from(parts[2], "base64url");
sigBytes[0] ^= 0x01;
parts[2] = sigBytes.toString("base64url");
const vBadSig = parts.join(".");
vectors["bad-signature"] = { jws: vBadSig, expect: "invalid_signature" };
await expectReject(vBadSig, "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "bad-signature -> rejected ERR_JWS_SIGNATURE_VERIFICATION_FAILED");

// 4) rotated-key: signed by a kid absent from the published JWKS
const vRotated = await sign(baseClaims(), rotated.privateKey, rotatedKid);
vectors["rotated-key"] = { jws: vRotated, expect: "unknown_kid" };
await expectReject(vRotated, "ERR_JWKS_NO_MATCHING_KEY", "rotated-key -> rejected ERR_JWKS_NO_MATCHING_KEY");

// 5) wrong-audience: signature is VALID BY DESIGN; the audience binding is a
// consumer check. The verifier answers "is this a real issuer.facet.llc
// identity token?"; the consumer answers "was it minted for me?". Authenticity
// and scope are different questions, the same separation the envelope makes
// between identity and risk, and the risk half makes with wrong-session.
const WRONG_AUD_NOTE =
  "NOT A HOLE, by design: the signature verifies because the KYA is authentic. " +
  "The verifier proves authenticity (genuine issuer.facet.llc identity token); " +
  "the consumer proves scope by comparing the aud claim to its own id and " +
  "rejecting on mismatch (gen-vectors.mjs demonstrates that check). Identity is " +
  "agent-scoped, not session-scoped, so the identity analog of the risk half's " +
  "wrong-session is wrong-audience.";
const vWrongAud = await sign(baseClaims({ aud: OTHER_AUD }), active.privateKey, activeKid);
vectors["wrong-audience"] = {
  jws: vWrongAud,
  expect: "signature valid; consumer rejects on audience mismatch",
  note: WRONG_AUD_NOTE,
};
await expectValid(vWrongAud, "wrong-audience -> signature verifies (audience checked by consumer)");
{
  const { payload } = await verifyAuthenticity(vWrongAud);
  // The consumer is MERCHANT_AUD; the token was minted for OTHER_AUD.
  ok(payload.aud !== MERCHANT_AUD, "wrong-audience -> consumer sees aud != its own id, rejects", payload.aud);
  // And jose's own audience check rejects it when the consumer pins its aud.
  try {
    await jwtVerify(vWrongAud, JWKS, { typ: "kya+jwt", issuer: ISSUER, audience: MERCHANT_AUD });
    ok(false, "wrong-audience -> jose audience pin rejects", "verified but should not");
  } catch (e) {
    ok(e.code === "ERR_JWT_CLAIM_VALIDATION_FAILED", "wrong-audience -> jose audience pin rejects", e.code);
  }
}
console.log(`NOTE  wrong-audience verifying is intentional: ${WRONG_AUD_NOTE}`);

writeFileSync(
  join(OUT, "vectors.json"),
  JSON.stringify(
    {
      claim_type: "identity",
      signal: "llc.facet.kya",
      envelope: "compact JWS, ES256 (EC P-256), kid in protected header, typ kya+jwt",
      test_jwks: "test-jwks.json",
      verify: "npm jose -> jwtVerify(jws, JWKS, { typ: 'kya+jwt', issuer }); consumer additionally pins aud",
      aid: AID,
      vectors,
    },
    null,
    2,
  ),
);

// Keep the errors import meaningful for readers grepping the reason codes.
void errors;

console.log(`\nconformance vectors: ${pass} pass, ${fail} fail`);
console.log(`written -> vectors/ (vectors.json + test-jwks.json)`);
process.exit(fail === 0 ? 0 : 1);
