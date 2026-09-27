import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { keypairFromSeed, signBody, verifyBody, SIG_ALG } from "./signature.ts";
import { bytesToHex, hexToBytes } from "./bytes.ts";

const vector = JSON.parse(
  readFileSync(
    new URL("../../../conformance/signatures/traveler-sig.json", import.meta.url),
    "utf8",
  ),
) as {
  alg: string;
  domain: string;
  seed_hex: string;
  public_key_hex: string;
  canonical_body: string;
  signature_hex: string;
};

describe("ML-DSA-87 authorship signatures", () => {
  it("re-derives the vector public key from the seed", () => {
    assert.equal(vector.alg, SIG_ALG);
    const kp = keypairFromSeed(hexToBytes(vector.seed_hex));
    assert.equal(bytesToHex(kp.publicKey), vector.public_key_hex);
  });

  it("signs the canonical body deterministically to the vector signature", () => {
    const kp = keypairFromSeed(hexToBytes(vector.seed_hex));
    assert.equal(signBody(vector.domain, vector.canonical_body, kp.secretKey), vector.signature_hex);
  });

  it("verifies the vector signature and rejects tampering", () => {
    const pk = hexToBytes(vector.public_key_hex);
    assert.equal(verifyBody(vector.domain, vector.canonical_body, vector.signature_hex, pk), true);
    // a changed body no longer verifies
    assert.equal(
      verifyBody(vector.domain, vector.canonical_body + " ", vector.signature_hex, pk),
      false,
    );
    // a signature under one domain cannot be replayed under another
    assert.equal(
      verifyBody("sje-sig/quote/0.1.0", vector.canonical_body, vector.signature_hex, pk),
      false,
    );
    // a flipped signature byte fails
    const flipped =
      vector.signature_hex.slice(0, -2) + (vector.signature_hex.endsWith("00") ? "01" : "00");
    assert.equal(verifyBody(vector.domain, vector.canonical_body, flipped, pk), false);
  });
});
