#!/usr/bin/env node
/**
 * First end-to-end cross-verification of the UCP external-verifier envelope
 * (Universal-Commerce-Protocol/ucp #534 / #535).
 *
 * One checkout. Two independently signed verdicts in the same signals array:
 *
 *   llc.facet.kya            identity  ES256 (P-256)   typ kya+jwt
 *   com.fidacy.trust_verdict risk      EdDSA (Ed25519) typ application/vc+jws
 *
 * Both are LIVE-signed credentials from each issuer's production system. Both
 * verify offline: two kid lookups, two JWKS fetches, no issuer online at
 * verify time, no vendor-specific trust.
 *
 *   npm i && node cross-verify.mjs
 *
 * Steps:
 *   1. mint a fresh Facet KYA via the public self-serve path (enroll + mint)
 *   2. load the real Fidacy production verdict (fidacy-vector-valid.json)
 *   3. compose the envelope: one UCP checkout, both signals as siblings
 *   4. verify the identity half with plain jose against the live Facet JWKS
 *   5. verify the risk half with @fidacy/verify against the live Fidacy JWKS
 *   6. run the consumer-side scope checks (aud for identity, subject/session
 *      for risk), the part that is deliberately NOT the verifier's job
 */
import { readFileSync, writeFileSync } from "node:fs";
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
  decodeProtectedHeader,
  decodeJwt,
} from "jose";
import { verifyRiskPayload } from "@fidacy/verify";

const HERE = dirname(fileURLToPath(import.meta.url));
const FACET_ISSUER = "https://issuer.facet.llc";
const FACET_JWKS_URI = `${FACET_ISSUER}/.well-known/jwks.json`;
const FIDACY_JWKS_URI = "https://api.fidacy.com/.well-known/jwks.json";
const MERCHANT_AUD = "https://merchant.example/ucp";
const now = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------- 1) identity
// Mint a fresh live KYA exactly as facet-identity/mint-live-kya.mjs does
// (public self-serve path, no secret), agent named for this cross-check.
const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
const publicJwk = await exportJWK(publicKey);
const proof = await new SignJWT({ purpose: "enroll", jti: randomUUID() })
  .setProtectedHeader({ alg: "ES256" })
  .setAudience(FACET_ISSUER)
  .setIssuedAt(now())
  .sign(privateKey);
const enrollRes = await fetch(`${FACET_ISSUER}/v1/enroll`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    public_jwk: publicJwk,
    proof,
    agent_name: "fidacy-cross-verify-demo",
    provider: "facet",
  }),
});
const enroll = await enrollRes.json();
if (!enrollRes.ok) throw new Error(`enroll failed ${enrollRes.status}: ${JSON.stringify(enroll)}`);
const aid = enroll.aid;
console.log(`[identity] enrolled  aid=${aid}`);

const t = now();
const clientAssertion = await new SignJWT({ jti: randomUUID() })
  .setProtectedHeader({ alg: "ES256", kid: aid })
  .setIssuer(aid)
  .setSubject(aid)
  .setAudience(FACET_ISSUER)
  .setIssuedAt(t)
  .setExpirationTime(t + 120)
  .sign(privateKey);
const mintRes = await fetch(`${FACET_ISSUER}/v1/tokens`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ client_assertion: clientAssertion, audience: MERCHANT_AUD }),
});
const mint = await mintRes.json();
if (!mintRes.ok) throw new Error(`mint failed ${mintRes.status}: ${JSON.stringify(mint)}`);
const kya = mint.token;
console.log(`[identity] minted    kid=${mint.kid} tier=${mint.tier}`);

// ------------------------------------------------------------------- 2) risk
// The real Fidacy production verdict (same file as fidacy-risk/vector-valid.json).
const fidacyVector = JSON.parse(readFileSync(join(HERE, "fidacy-vector-valid.json"), "utf8"));
const verdictJws = fidacyVector.jws;

// -------------------------------------------------------------- 3) envelope
const envelope = {
  id: "checkout_cross_verify_demo",
  total: { amount: "42.99", currency: "EUR" },
  signals: {
    "llc.facet.kya": {
      format: "kya+jwt",
      jws: kya,
      kid: decodeProtectedHeader(kya).kid,
      provider_jwks: FACET_JWKS_URI,
    },
    "com.fidacy.trust_verdict": {
      format: "application/vc+jws",
      jws: verdictJws,
      kid: fidacyVector.signingKeyId,
      provider_jwks: FIDACY_JWKS_URI,
    },
  },
};
writeFileSync(join(HERE, "envelope.json"), JSON.stringify(envelope, null, 2) + "\n");
console.log(`[envelope] written -> envelope.json (both signals as independent siblings)`);

// ------------------------------------------------- 4+5) verify, per-issuer JWKS
// The merchant's moves: for each signal, fetch that issuer's JWKS once, then
// verify offline, dispatching on alg. Snapshot both key sets first to prove no
// issuer interaction happens during verification.
const facetJwks = createLocalJWKSet(await (await fetch(envelope.signals["llc.facet.kya"].provider_jwks)).json());
const fidacyJwks = await (await fetch(envelope.signals["com.fidacy.trust_verdict"].provider_jwks)).json();

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`); };

// identity half: plain jose, ES256, typ + issuer pinned (authenticity only)
const { payload: kyaClaims, protectedHeader: kyaHeader } = await jwtVerify(
  envelope.signals["llc.facet.kya"].jws, facetJwks, { typ: "kya+jwt", issuer: FACET_ISSUER },
);
ok(kyaHeader.alg === "ES256", `identity verifies  alg=${kyaHeader.alg} kid=${kyaHeader.kid}`);

// risk half: @fidacy/verify, EdDSA over JCS bytes
const risk = await verifyRiskPayload(envelope.signals["com.fidacy.trust_verdict"].jws, { jwks: fidacyJwks });
ok(risk.valid === true, `risk verifies      alg=EdDSA kid=${envelope.signals["com.fidacy.trust_verdict"].kid}`);

// ------------------------------------------------------- 6) consumer scope checks
ok(kyaClaims.aud === MERCHANT_AUD, `identity scope: aud matches this consumer`, String(kyaClaims.aud));
ok(typeof risk.claims.subject === "string" && risk.claims.subject.length > 0,
  `risk scope: subject present for session binding`, risk.claims.subject);

console.log(`\none envelope, two issuers, two algs: ${pass} pass, ${fail} fail`);
console.log(`identity: iss=${kyaClaims.iss} aid=${kyaClaims.aid} tier=${kyaClaims.tier}`);
console.log(`risk:     iss=${risk.claims.issuer.slice(0, 24)}... decision=${risk.claims.decision} score=${risk.claims.score}`);
void decodeJwt;
process.exit(fail === 0 ? 0 : 1);
