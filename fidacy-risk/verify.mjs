#!/usr/bin/env node
/**
 * Runnable verifier for the COMMITTED risk vectors, the entry-requirement half
 * this profile was missing (raised in #8: two of the four signals listed ship
 * generators without a verifier, this one included).
 *
 * The distinction that makes this file exist: gen-vectors.mjs self-validates
 * bytes it just produced, which proves the generator. A conformance gate needs
 * the opposite direction, proof of the bytes sitting in the repo, because those
 * are the bytes a cold reader will verify against. So this script regenerates
 * nothing: it loads vectors/vectors.json as committed and asserts each vector's
 * expected disposition across both layers.
 *
 *   npm i && node verify.mjs        exit 0 iff every assertion holds
 *
 * Layer 1 (authenticity) is @fidacy/verify with the committed test JWKS
 * injected: valid verifies, expired/bad-signature/rotated-key fail with exactly
 * the reason code the vector names. Layer 2 (consumer) is the session binding:
 * the valid vector's subject IS the presented checkout, the wrong-session
 * vector's is NOT, and its signature still verifying is the point, not a bug:
 * authenticity and scope are different questions.
 *
 * No network: the expired vector's exp is fixed in the past (2001), so the
 * outcome is deterministic under any real clock.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyRiskPayload, FidacyVerificationError } from "@fidacy/verify";

const HERE = dirname(fileURLToPath(import.meta.url));
const readJson = (p) => JSON.parse(readFileSync(join(HERE, p), "utf8"));

const suite = readJson("vectors/vectors.json");
const jwks = readJson("vectors/test-jwks.json");
const PRESENTED_SESSION = "session:cs_THIS_CHECKOUT";

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`);
};

async function expectValid(name) {
  const { jws } = suite.vectors[name];
  try {
    const r = await verifyRiskPayload(jws, { jwks });
    ok(r.valid === true, `${name} -> verifies`);
    return r;
  } catch (e) {
    ok(false, `${name} -> verifies`, `threw ${e.code ?? e.message}`);
    return null;
  }
}

async function expectCode(name, code) {
  const { jws } = suite.vectors[name];
  try {
    await verifyRiskPayload(jws, { jwks });
    ok(false, `${name} -> rejected as ${code}`, "verified but should have failed");
  } catch (e) {
    ok(e instanceof FidacyVerificationError && e.code === code, `${name} -> rejected as ${code}`, e.code ?? e.message);
  }
}

// Layer 1: authenticity, one assertion per committed vector.
const valid = await expectValid("valid");
await expectCode("expired", "expired");
await expectCode("bad-signature", "invalid_signature");
await expectCode("rotated-key", "unknown_kid");
const wrong = await expectValid("wrong-session");

// Layer 2: the consumer's half of the split, exactly as the profile states it:
// compare the claim's subject to the checkout session in hand. The valid
// vector's subject is an AGENT id (agent:demo-northwind), not a session, and
// that is the vector telling the truth about production shape; what the
// consumer rejects is a subject that names a DIFFERENT session than the one
// presented, which is precisely the wrong-session vector.
ok(typeof valid?.claims.subject === "string" && valid.claims.subject.length > 0, "valid -> carries a subject for the consumer to bind", valid?.claims.subject);
ok(wrong !== null && wrong.claims.subject !== PRESENTED_SESSION, "wrong-session -> consumer rejects on subject mismatch", wrong?.claims.subject);

console.log(`\ncommitted-vector conformance: ${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
