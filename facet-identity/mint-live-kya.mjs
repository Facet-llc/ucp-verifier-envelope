#!/usr/bin/env node
/**
 * Mint a REAL Facet KYA from the live issuer and write it to vector-valid.json,
 * the identity analog of the risk half's real production verdict. No Facet
 * secret is used: this drives the PUBLIC self-serve path exactly as any agent
 * would, so anyone can reproduce a genuine, live-signed identity token.
 *
 *   npm i && node mint-live-kya.mjs
 *
 * Flow (issuer.facet.llc, private_key_jwt auth):
 *   1. generate a P-256 agent keypair locally
 *   2. POST /v1/enroll  with a proof-of-possession JWS -> receive the aid
 *   3. POST /v1/tokens  with a client_assertion JWS    -> receive the KYA
 *   4. verify the KYA offline against the LIVE JWKS, then write vector-valid.json
 *
 * The token is a tier "self" credential with a 1h TTL (Facet identity tokens are
 * short-lived by design). Its signature and kid verify against the live JWKS for
 * as long as that key is published; the 1h window is a production policy. Re-run
 * this to mint a fresh, currently-valid one.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import {
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
  SignJWT,
  jwtVerify,
  createRemoteJWKSet,
  decodeProtectedHeader,
  decodeJwt,
} from "jose";

const HERE = dirname(fileURLToPath(import.meta.url));
const ISSUER = "https://issuer.facet.llc";
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;
const MERCHANT_AUD = "https://merchant.example/ucp";

const now = () => Math.floor(Date.now() / 1000);

async function main() {
  // 1) local agent keypair + aid (RFC 7638 thumbprint, never PII)
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey); // { kty, crv, x, y }
  const thumbprint = await calculateJwkThumbprint(publicJwk, "sha256");
  const expectedAid = `facet:agent:${thumbprint}`;

  // 2) enroll: prove possession of the key being enrolled
  const proof = await new SignJWT({ purpose: "enroll", jti: randomUUID() })
    .setProtectedHeader({ alg: "ES256" })
    .setAudience(ISSUER)
    .setIssuedAt(now())
    .sign(privateKey);

  const enrollRes = await fetch(`${ISSUER}/v1/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      public_jwk: publicJwk,
      proof,
      agent_name: "facet-ucp-verifier-envelope-demo",
      provider: "facet",
    }),
  });
  const enroll = await enrollRes.json();
  if (!enrollRes.ok) throw new Error(`enroll failed ${enrollRes.status}: ${JSON.stringify(enroll)}`);
  const aid = enroll.aid;
  if (aid !== expectedAid) console.warn(`note: issuer aid ${aid} != locally derived ${expectedAid}`);
  console.log(`enrolled  aid=${aid}  already=${enroll.already_enrolled}`);

  // 3) mint: authenticate the mint with a private_key_jwt client assertion
  const t = now();
  const clientAssertion = await new SignJWT({ jti: randomUUID() })
    .setProtectedHeader({ alg: "ES256", kid: aid })
    .setIssuer(aid)
    .setSubject(aid)
    .setAudience(ISSUER)
    .setIssuedAt(t)
    .setExpirationTime(t + 120)
    .sign(privateKey);

  const mintRes = await fetch(`${ISSUER}/v1/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_assertion: clientAssertion, audience: MERCHANT_AUD }),
  });
  const mint = await mintRes.json();
  if (!mintRes.ok) throw new Error(`mint failed ${mintRes.status}: ${JSON.stringify(mint)}`);
  const token = mint.token;
  console.log(`minted    kid=${mint.kid}  tier=${mint.tier}  exp=${mint.expiresAt}`);

  // 4) verify offline against the LIVE JWKS, then write the vector
  const remoteJwks = createRemoteJWKSet(new URL(JWKS_URI));
  const { payload, protectedHeader } = await jwtVerify(token, remoteJwks, {
    typ: "kya+jwt",
    issuer: ISSUER,
  });
  console.log(`verified  against live JWKS  aud=${payload.aud}  aid=${payload.aid}`);

  const out = {
    _comment:
      "A REAL Facet KYA minted from the live issuer via the public self-serve path (no secret). " +
      "Verifies offline against https://issuer.facet.llc/.well-known/jwks.json by the kid in the " +
      "protected header. tier 'self' tokens carry a 1h TTL by design; re-run `node mint-live-kya.mjs` " +
      "to mint a fresh, currently-valid one. Authenticity (signature + kid resolves in the live JWKS) " +
      "holds for as long as that key is published.",
    token,
    protected_header: decodeProtectedHeader(token),
    claims: decodeJwt(token),
    jwks_uri: JWKS_URI,
    minted_at: new Date().toISOString(),
  };
  writeFileSync(join(HERE, "vector-valid.json"), JSON.stringify(out, null, 2) + "\n");
  console.log(`written   -> vector-valid.json`);
  void protectedHeader;
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
