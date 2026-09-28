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
  sealFsEnvelope,
  sealFsEnvelopeDeterministic,
  openFsEnvelope,
  fsRecipientFromBundle,
  type Envelope,
  type FsEnvelope,
} from "./envelope.ts";
import { bytesToHex, hexToBytes } from "./bytes.ts";
import type { Directory } from "./directory.ts";
import type { PrekeyBundle } from "./prekeys.ts";

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

describe("forward-secret envelope (sje-envelope/0.2.0)", () => {
  const fsVec = JSON.parse(
    readFileSync(new URL("../../../conformance/signatures/fs-envelope.json", import.meta.url), "utf8"),
  ) as {
    recipient: {
      kid: string;
      org_id: string;
      prekey_id: string;
      static_seed_hex: string;
      onetime_seed_hex: string;
      static_public_key_hex: string;
      onetime_public_key_hex: string;
    };
    determinism: {
      cek_hex: string;
      payload_nonce_hex: string;
      coins_onetime_hex: string;
      coins_static_hex: string;
      wrap_nonce_hex: string;
    };
    plaintext_utf8: string;
    envelope: FsEnvelope;
  };
  const bundleVec = JSON.parse(
    readFileSync(new URL("../../../conformance/signatures/prekey-bundle.json", import.meta.url), "utf8"),
  ) as { root_public_key_hex: string; at_ms: number; directory: Directory; bundle: PrekeyBundle };

  const kid = fsVec.recipient.kid;
  const at = new Date(bundleVec.at_ms);
  const staticSk = kemKeypairFromSeed(hexToBytes(fsVec.recipient.static_seed_hex)).secretKey;
  const onetimeSk = kemKeypairFromSeed(hexToBytes(fsVec.recipient.onetime_seed_hex)).secretKey;

  function fsDet() {
    return {
      cek: hexToBytes(fsVec.determinism.cek_hex),
      payload_nonce: hexToBytes(fsVec.determinism.payload_nonce_hex),
      coins_onetime: [hexToBytes(fsVec.determinism.coins_onetime_hex)],
      coins_static: [hexToBytes(fsVec.determinism.coins_static_hex)],
      wrap_nonces: [hexToBytes(fsVec.determinism.wrap_nonce_hex)],
    };
  }

  it("re-seals deterministically to the vector", () => {
    const env = sealFsEnvelopeDeterministic(
      new TextEncoder().encode(fsVec.plaintext_utf8),
      [
        {
          kid,
          static_public_key: fsVec.recipient.static_public_key_hex,
          prekey_id: fsVec.recipient.prekey_id,
          onetime_public_key: fsVec.recipient.onetime_public_key_hex,
        },
      ],
      fsDet(),
    );
    assert.deepEqual(env, fsVec.envelope);
  });

  it("opens with both the static and one-time secret keys", () => {
    const opened = new TextDecoder().decode(openFsEnvelope(fsVec.envelope, kid, staticSk, onetimeSk));
    assert.equal(opened, fsVec.plaintext_utf8);
  });

  it("cannot be opened without the correct one-time secret (forward secrecy)", () => {
    // Deleting/losing the one-time secret means the two-KEM KEK can't be rebuilt,
    // so a later static-key compromise alone cannot recover the message.
    const wrongOt = kemKeypairFromSeed(new Uint8Array(64).fill(0x99)).secretKey;
    assert.throws(() => openFsEnvelope(fsVec.envelope, kid, staticSk, wrongOt));
    // and a wrong static secret likewise fails (both halves are required)
    const wrongStatic = kemKeypairFromSeed(new Uint8Array(64).fill(0x98)).secretKey;
    assert.throws(() => openFsEnvelope(fsVec.envelope, kid, wrongStatic, onetimeSk));
  });

  it("resolves an FS recipient from the directory + signed bundle", () => {
    const r = fsRecipientFromBundle(
      bundleVec.directory,
      bundleVec.bundle,
      "org_northline",
      "northline-ot-1",
      bundleVec.root_public_key_hex,
      at,
    );
    assert.ok(r);
    assert.equal(r!.kid, kid);
    assert.equal(r!.onetime_public_key, fsVec.recipient.onetime_public_key_hex);
    // an unverifiable bundle (wrong root) yields nothing — no sealing to unvetted prekeys
    assert.equal(
      fsRecipientFromBundle(
        bundleVec.directory,
        bundleVec.bundle,
        "org_northline",
        "northline-ot-1",
        "00".repeat(2592),
        at,
      ),
      undefined,
    );
  });

  it("authenticates the recipient set incl prekey_id (reorder/drop fails open, L2)", () => {
    // Two distinct static recipients (northline via ot-1, huron via ot-2).
    const a = fsRecipientFromBundle(
      bundleVec.directory,
      bundleVec.bundle,
      "org_northline",
      "northline-ot-1",
      bundleVec.root_public_key_hex,
      at,
    )!;
    const huronStatic = recipientByOrg(bundleVec.directory, "org_huron", at)!;
    const ot2 = bundleVec.bundle.prekeys.find((p) => p.prekey_id === "northline-ot-2")!;
    const b = {
      kid: huronStatic.kid,
      static_public_key: huronStatic.public_key,
      prekey_id: "northline-ot-2",
      onetime_public_key: ot2.public_key,
    };
    const env = sealFsEnvelope(new TextEncoder().encode("fs secret"), [a, b]);
    const huronStaticSk = kemKeypairFromSeed(new Uint8Array(64).fill(0x51)).secretKey; // org_huron static enc seed
    const ot2Sk = kemKeypairFromSeed(new Uint8Array(64).fill(0x62)).secretKey; // northline-ot-2 seed
    // intact -> b opens
    assert.equal(
      new TextDecoder().decode(openFsEnvelope(env, b.kid, huronStaticSk, ot2Sk)),
      "fs secret",
    );
    // reordered recipient list -> payload AAD (which binds kid+prekey_id) mismatches
    const reordered: FsEnvelope = { ...env, recipients: [env.recipients[1]!, env.recipients[0]!] };
    assert.throws(() => openFsEnvelope(reordered, b.kid, huronStaticSk, ot2Sk));
    // dropped co-recipient -> also fails
    const dropped: FsEnvelope = { ...env, recipients: [env.recipients[1]!] };
    assert.throws(() => openFsEnvelope(dropped, b.kid, huronStaticSk, ot2Sk));
  });
});
