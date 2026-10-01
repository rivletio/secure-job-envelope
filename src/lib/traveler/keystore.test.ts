import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";
import { createIdentity, unlock, KEYSTORE_SPEC, type Keystore } from "./keystore.ts";
import { sealEnvelope, openEnvelope, kemKeypairFromSeed, encKid, KEM_ALG } from "./envelope.ts";
import { canonicalJson } from "./canonical.ts";
import { bytesToHex, utf8ToBytes } from "./bytes.ts";

const PASS = "correct horse battery staple";

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Mint a keystore blob at an arbitrary scrypt N — including BELOW the floor — the
 *  way an older MCP/CLI minter would (importIdentity accepts such blobs). Replicates
 *  the documented at-rest format so the upgrade-on-unlock path can be exercised. */
async function forgeKeystore(passphrase: string, N: number): Promise<Keystore> {
  const seed = randomBytes(64);
  const enc_public_key = bytesToHex(kemKeypairFromSeed(seed).publicKey);
  const kid = encKid(enc_public_key);
  const kdf = { name: "scrypt" as const, N, r: 8, p: 1, salt: bytesToHex(randomBytes(16)) };
  const aad = utf8ToBytes(canonicalJson({ spec: KEYSTORE_SPEC, kid, enc_alg: KEM_ALG, enc_public_key, kdf }));
  const key = await scryptAsync(utf8ToBytes(passphrase), new Uint8Array(Buffer.from(kdf.salt, "hex")), {
    N,
    r: 8,
    p: 1,
    dkLen: 32,
  });
  const nonce = randomBytes(12);
  const vault = { static_seed: bytesToHex(seed), prekeys: {} };
  const ct = gcm(key, nonce, aad).encrypt(utf8ToBytes(JSON.stringify(vault)));
  return {
    spec: KEYSTORE_SPEC,
    kid,
    enc_alg: KEM_ALG,
    enc_public_key,
    kdf,
    cipher: "AES-256-GCM",
    nonce: bytesToHex(nonce),
    ct: bytesToHex(ct),
  };
}

describe("passphrase-encrypted keystore", () => {
  it("creates an identity, unlocks it, and the stored key decrypts a real envelope", async () => {
    const { keystore, directoryEntry } = await createIdentity({ passphrase: PASS, orgId: "org_huron" });
    assert.equal(keystore.spec, "sje-keystore/0.1.0");
    assert.equal(keystore.enc_alg, "ML-KEM-1024");
    assert.equal(directoryEntry.kid, keystore.kid);
    // The secret is NOT in the clear blob.
    assert.ok(!JSON.stringify(keystore).includes(directoryEntry.enc_public_key.slice(0, 0) + "static_seed"));

    const unlocked = await unlock(keystore, PASS);
    assert.equal(unlocked.kid, keystore.kid);
    assert.equal(unlocked.orgId, "org_huron");

    // End to end: seal an envelope to the published public key, open with the
    // keystore's secret. Proves the custody actually matches the envelope layer.
    const pt = utf8ToBytes("secret payload");
    const env = sealEnvelope(pt, [{ kid: directoryEntry.kid, public_key: directoryEntry.enc_public_key }]);
    const opened = openEnvelope(env, directoryEntry.kid, unlocked.staticSecretKey());
    assert.deepEqual(opened, pt);
  });

  it("rejects the wrong passphrase with a uniform error (no oracle)", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    await assert.rejects(() => unlock(keystore, "a different passphrase"), /unlock failed/);
  });

  it("rejects a tampered ciphertext, nonce, or substituted public key", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    const flip = (hex: string) => (hex[0] === "a" ? "b" : "a") + hex.slice(1);

    const badCt: Keystore = { ...keystore, ct: flip(keystore.ct) };
    await assert.rejects(() => unlock(badCt, PASS), /unlock failed/);

    const badNonce: Keystore = { ...keystore, nonce: flip(keystore.nonce) };
    await assert.rejects(() => unlock(badNonce, PASS), /unlock failed/);

    // Substitution: a tampered clear public key must not unlock (AAD + derive check).
    const badPub: Keystore = { ...keystore, enc_public_key: flip(keystore.enc_public_key) };
    await assert.rejects(() => unlock(badPub, PASS), /unlock failed/);
  });

  it("enforces a minimum passphrase length", async () => {
    await assert.rejects(() => createIdentity({ passphrase: "short" }), /at least/);
  });

  it("adds one-time prekeys and consumes them exactly once (forward secrecy)", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    const unlocked = await unlock(keystore, PASS);

    const { keystore: ks2, prekeys } = unlocked.addPrekeys(2);
    assert.equal(prekeys.length, 2);
    assert.notEqual(prekeys[0]!.prekey_id, prekeys[1]!.prekey_id);

    // In-memory: first consume returns the secret; second returns undefined (deleted).
    assert.ok(unlocked.consumePrekey(prekeys[0]!.prekey_id).secretKey instanceof Uint8Array);
    assert.equal(unlocked.consumePrekey(prekeys[0]!.prekey_id).secretKey, undefined);

    // Persistence: consumePrekey returns a new blob with the prekey deleted.
    // ks2 (from addPrekeys) still has BOTH; the blob from consuming has it removed.
    const u2 = await unlock(ks2, PASS);
    const { keystore: ks3, secretKey } = u2.consumePrekey(prekeys[0]!.prekey_id);
    assert.ok(secretKey instanceof Uint8Array);
    const u3 = await unlock(ks3, PASS);
    assert.equal(u3.consumePrekey(prekeys[0]!.prekey_id).secretKey, undefined, "deletion persisted");
    assert.ok(u3.consumePrekey(prekeys[1]!.prekey_id).secretKey instanceof Uint8Array, "other prekey intact");
  });

  it("lock() blocks further use", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    const unlocked = await unlock(keystore, PASS);
    unlocked.lock();
    assert.throws(() => unlocked.staticSecretKey(), /locked/);
  });

  it("re-keys a below-floor keystore on unlock so the resealed blob still unlocks (no brick)", async () => {
    const belowFloor = await forgeKeystore(PASS, 16384); // < MIN_SCRYPT_N (32768)
    const u = await unlock(belowFloor, PASS); // unlocks with the stored (low) N
    assert.equal(u.kid, belowFloor.kid);

    const { keystore: resealed } = u.addPrekeys(1); // reseal → must upgrade the KDF
    assert.equal(resealed.kdf.N, 65536, "KDF upgraded to the floor");
    assert.notEqual(resealed.kdf.salt, belowFloor.kdf.salt, "fresh salt on re-key");

    // The regression: before the fix the resealed blob advertised the new N but was
    // encrypted with the old-N key, so the next unlock derived a different key and the
    // keystore was bricked. It must now unlock.
    const u2 = await unlock(resealed, PASS);
    assert.equal(u2.kid, belowFloor.kid);
    assert.ok(u2.staticSecretKey() instanceof Uint8Array);
  });

  it("ignores prototype-chain prekey ids (no inherited-member confusion)", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    const u = await unlock(keystore, PASS);
    for (const id of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
      assert.equal(u.peekPrekey(id), undefined, `peekPrekey(${id}) must be undefined`);
      assert.equal(u.consumePrekey(id).secretKey, undefined, `consumePrekey(${id}) must be undefined`);
    }
  });

  it("peekPrekey returns the secret WITHOUT consuming it", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    const u = await unlock(keystore, PASS);
    const { prekeys } = u.addPrekeys(1);
    const id = prekeys[0]!.prekey_id;
    assert.ok(u.peekPrekey(id) instanceof Uint8Array);
    assert.ok(u.peekPrekey(id) instanceof Uint8Array, "still present after peek (not consumed)");
    assert.ok(u.consumePrekey(id).secretKey instanceof Uint8Array, "consume after peek works");
    assert.equal(u.peekPrekey(id), undefined, "gone only after an explicit consume");
  });
});
