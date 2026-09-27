import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { kemKeypairFromSeed, sealEnvelope, openEnvelope, type Envelope } from "./envelope.ts";
import { bytesToHex, hexToBytes } from "./signature.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/envelope.json", import.meta.url), "utf8"),
) as {
  recipient: { kid: string; seed_hex: string; public_key_hex: string };
  determinism: { cek_hex: string; payload_nonce_hex: string; coins_hex: string; wrap_nonce_hex: string };
  plaintext_utf8: string;
  envelope: Envelope;
};

const kid = vec.recipient.kid;

function det() {
  return {
    cek: hexToBytes(vec.determinism.cek_hex),
    payload_nonce: hexToBytes(vec.determinism.payload_nonce_hex),
    coins: [hexToBytes(vec.determinism.coins_hex)],
    wrap_nonces: [hexToBytes(vec.determinism.wrap_nonce_hex)],
  };
}

describe("encrypted envelope (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM)", () => {
  it("re-derives the recipient key and re-seals deterministically to the vector", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    assert.equal(bytesToHex(kp.publicKey), vec.recipient.public_key_hex);
    const env = sealEnvelope(
      new TextEncoder().encode(vec.plaintext_utf8),
      [{ kid, public_key: vec.recipient.public_key_hex }],
      det(),
    );
    assert.deepEqual(env, vec.envelope);
  });

  it("opens the vector envelope back to the plaintext", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    const opened = new TextDecoder().decode(openEnvelope(vec.envelope, kid, kp.secretKey));
    assert.equal(opened, vec.plaintext_utf8);
  });

  it("rejects a tampered payload and an unknown recipient", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    const bad: Envelope = {
      ...vec.envelope,
      payload: vec.envelope.payload.slice(0, -2) + (vec.envelope.payload.endsWith("00") ? "01" : "00"),
    };
    assert.throws(() => openEnvelope(bad, kid, kp.secretKey));
    assert.throws(() => openEnvelope(vec.envelope, "no-such-kid", kp.secretKey));
  });
});
