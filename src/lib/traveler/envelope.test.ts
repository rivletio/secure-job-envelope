import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  kemKeypairFromSeed,
  sealEnvelope,
  sealEnvelopeDeterministic,
  openEnvelope,
  recipientByOrg,
  encKid,
  type Envelope,
} from "./envelope.ts";
import { bytesToHex, hexToBytes } from "./bytes.ts";
import type { Directory } from "./directory.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/envelope.json", import.meta.url), "utf8"),
) as {
  recipient: { kid: string; org_id: string; seed_hex: string; public_key_hex: string };
  determinism: { cek_hex: string; payload_nonce_hex: string; coins_hex: string; wrap_nonce_hex: string };
  plaintext_utf8: string;
  envelope: Envelope;
};

const dirVec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/directory.json", import.meta.url), "utf8"),
) as { directory: Directory };

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
    const env = sealEnvelopeDeterministic(
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

  it("resolves a recipient from the signed directory and derives its kid from the key (M3)", () => {
    const r = recipientByOrg(dirVec.directory, "org_northline");
    assert.ok(r);
    // the kid is bound to the key, so the two cannot be pointed at each other's mismatch
    assert.equal(r!.kid, encKid(r!.public_key));
    // an org with no attested encryption key resolves to nothing
    assert.equal(recipientByOrg(dirVec.directory, "org_unknown"), undefined);
  });

  it("authenticates the recipient set: reordering or dropping a recipient fails open (L2)", () => {
    const a = recipientByOrg(dirVec.directory, "org_huron")!;
    const b = recipientByOrg(dirVec.directory, "org_northline")!;
    const env = sealEnvelope(new TextEncoder().encode("secret payload"), [a, b]);
    const northlineSk = kemKeypairFromSeed(new Uint8Array(64).fill(0x53)).secretKey;
    // intact -> opens for the second recipient
    assert.equal(
      new TextDecoder().decode(openEnvelope(env, b.kid, northlineSk)),
      "secret payload",
    );
    // reordered recipient list -> payload AAD no longer matches -> fails closed
    const reordered: Envelope = { ...env, recipients: [env.recipients[1]!, env.recipients[0]!] };
    assert.throws(() => openEnvelope(reordered, b.kid, northlineSk));
    // dropped co-recipient -> also fails
    const dropped: Envelope = { ...env, recipients: [env.recipients[1]!] };
    assert.throws(() => openEnvelope(dropped, b.kid, northlineSk));
  });
});
