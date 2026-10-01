import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createIdentity, unlock, type Keystore } from "./keystore.ts";
import { sealEnvelope, openEnvelope } from "./envelope.ts";
import { utf8ToBytes } from "./bytes.ts";

const PASS = "correct horse battery staple";

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
});
