#!/usr/bin/env node
/**
 * Runnable verifier for the COMMITTED decision-provenance vectors (the
 * com.fidacy.decision_provenance, record-scoped half), closing the same gap #8
 * named for fidacy-risk: a profile that ships vectors without a verifier makes
 * the reader write the proof themselves.
 *
 * Deliberately plain jose, no Fidacy library: this profile's claim is that any
 * JOSE implementation reproduces the verdict, so the verifier must not smuggle
 * in a vendor dependency. The rejection codes asserted are jose's own
 * (ERR_JWS_SIGNATURE_VERIFICATION_FAILED, ERR_JWKS_NO_MATCHING_KEY), which
 * keeps the vectors honest about which library produced them; a reader on a
 * different library gets the same two rejections under that library's names.
 *
 * Two layers, same split as every profile in this repo:
 *   authenticity  signature over the committed test JWKS, typ pinned
 *   consumer      sha256(record bytes) equals the receipt's sha256; the
 *                 content-mismatch vector verifying while its presented record
 *                 hashes differently is the point, not a bug
 *
 *   npm i && node verify.mjs        exit 0 iff every assertion holds
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { compactVerify, createLocalJWKSet } from "jose";

const HERE = dirname(fileURLToPath(import.meta.url));
const readJson = (p) => JSON.parse(readFileSync(join(HERE, p), "utf8"));

const suite = readJson("vectors/vectors.json");
const JWKS = createLocalJWKSet(readJson("vectors/test-jwks.json"));
// The committed record is pretty-printed for the reader, but the receipt's
// sha256 is over the record's JCS-canonical bytes: formatting must never break
// verification. Same minimal JCS as the generator (sorted keys, no whitespace),
// exact for this flat claim set.
const jcs = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(jcs).join(",")}]`
      : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
const RECORD_BYTES = Buffer.from(jcs(readJson(join("vectors", suite.record))), "utf8");
const TYP = "fidacy-artifact-receipt+jws";

const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`);
};

// The conformant verifier for this profile, verbatim from the spec: signature
// over the pinned JWKS, typ pinned, everything else is the consumer's.
async function verify(jws) {
  const { payload, protectedHeader } = await compactVerify(jws, JWKS);
  if (protectedHeader.typ !== TYP) { const e = new Error("typ"); e.code = "typ"; throw e; }
  return { claims: JSON.parse(new TextDecoder().decode(payload)), protectedHeader };
}

async function expectValid(name) {
  try {
    const r = await verify(suite.vectors[name].jws);
    ok(true, `${name} -> verifies`);
    return r;
  } catch (e) {
    ok(false, `${name} -> verifies`, `threw ${e.code ?? e.message}`);
    return null;
  }
}

async function expectReject(name, code) {
  try {
    await verify(suite.vectors[name].jws);
    ok(false, `${name} -> rejected as ${code}`, "verified but should have failed");
  } catch (e) {
    ok(e.code === code, `${name} -> rejected as ${code}`, e.code ?? e.message);
  }
}

// Layer 1: authenticity of every committed vector.
const valid = await expectValid("valid");
await expectReject("bad-signature", "ERR_JWS_SIGNATURE_VERIFICATION_FAILED");
await expectReject("rotated-key", "ERR_JWKS_NO_MATCHING_KEY");
await expectReject("wrong-typ", "typ");
const mism = await expectValid("content-mismatch");

// Layer 2: the record binding. The receipt's sha256 must match the committed
// record's bytes, and the mismatch vector's presented record must NOT.
ok(suite.record_sha256 === sha256hex(RECORD_BYTES), "suite record_sha256 IS sha256(committed record bytes)");
ok(valid !== null && valid.claims.sha256 === sha256hex(RECORD_BYTES), "valid -> receipt sha256 matches the record", valid?.claims.sha256?.slice(0, 16));
const presented = suite.vectors["content-mismatch"].presented_record;
const presentedBytes = typeof presented === "string" ? Buffer.from(presented, "utf8") : Buffer.from(jcs(presented), "utf8");
ok(
  mism !== null && sha256hex(presentedBytes) !== mism.claims.sha256,
  "content-mismatch -> consumer rejects: presented record hashes differently",
);

console.log(`\ncommitted-vector conformance: ${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
