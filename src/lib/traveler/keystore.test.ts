import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";
import {
  createIdentity,
  keystoreShapeError,
  unlock,
  KEYSTORE_SPEC,
  KEYSTORE_SPEC_LEGACY,
  MAX_SCRYPT_N,
  MIN_SCRYPT_N,
  type Keystore,
} from "./keystore.ts";
import { sealEnvelope, openEnvelope, kemKeypairFromSeed, encKid, KEM_ALG } from "./envelope.ts";
import { canonicalJson } from "./canonical.ts";
import { bytesToHex, utf8ToBytes } from "./bytes.ts";

const PASS = "correct horse battery staple";
const UNIFORM = "keystore unlock failed (wrong passphrase or corrupt keystore)";

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Mint a LEGACY (`sje-keystore/0.1.0`) blob exactly as the first version of this
 *  module did, at arbitrary scrypt parameters and with an arbitrary vault. The 0.1.0
 *  layout is written out here by hand — the associated data is the canonical JSON of
 *  { spec, kid, enc_alg, enc_public_key, kdf }, WITHOUT org_id — so these tests pin the
 *  legacy format independently of the code that now has to keep reading it. */
async function forgeLegacy(
  passphrase: string,
  opts: {
    N?: number;
    r?: number;
    p?: number;
    saltBytes?: number;
    nonceBytes?: number;
    orgId?: string;
    vault?: (seedHex: string) => unknown;
  } = {},
): Promise<Keystore> {
  const seed = randomBytes(64);
  const enc_public_key = bytesToHex(kemKeypairFromSeed(seed).publicKey);
  const kid = encKid(enc_public_key);
  const N = opts.N ?? 32768;
  const r = opts.r ?? 8;
  const p = opts.p ?? 1;
  const kdf = { name: "scrypt" as const, N, r, p, salt: bytesToHex(randomBytes(opts.saltBytes ?? 16)) };
  const aad = utf8ToBytes(
    canonicalJson({ spec: "sje-keystore/0.1.0", kid, enc_alg: KEM_ALG, enc_public_key, kdf }),
  );
  const key = await scryptAsync(utf8ToBytes(passphrase), new Uint8Array(Buffer.from(kdf.salt, "hex")), {
    N,
    r,
    p,
    dkLen: 32,
  });
  const nonce = randomBytes(opts.nonceBytes ?? 12);
  const vault = opts.vault
    ? opts.vault(bytesToHex(seed))
    : { static_seed: bytesToHex(seed), prekeys: {} };
  const ct = gcm(key, nonce, aad).encrypt(utf8ToBytes(JSON.stringify(vault)));
  return {
    spec: "sje-keystore/0.1.0",
    kid,
    enc_alg: KEM_ALG,
    enc_public_key,
    ...(opts.orgId ? { org_id: opts.orgId } : {}),
    kdf,
    cipher: "AES-256-GCM",
    nonce: bytesToHex(nonce),
    ct: bytesToHex(ct),
  };
}

const flip = (hex: string) => (hex[0] === "a" ? "b" : "a") + hex.slice(1);

/** The error `unlock` rejects with, or "UNLOCKED". (A rest parameter, not a default:
 *  an explicit `undefined` passphrase must reach `unlock` as `undefined`.) */
async function outcome(blob: unknown, ...passphrase: unknown[]): Promise<string> {
  const pass = passphrase.length > 0 ? passphrase[0] : PASS;
  try {
    await unlock(blob as Keystore, pass as string);
    return "UNLOCKED";
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

describe("passphrase-encrypted keystore", () => {
  it("creates an identity, unlocks it, and the stored key decrypts a real envelope", async () => {
    const { keystore, directoryEntry } = await createIdentity({ passphrase: PASS, orgId: "org_huron" });
    assert.equal(keystore.spec, "sje-keystore/0.2.0");
    assert.equal(keystore.spec, KEYSTORE_SPEC);
    assert.equal(keystore.enc_alg, "ML-KEM-1024");
    assert.equal(directoryEntry.kid, keystore.kid);
    assert.equal(keystoreShapeError(keystore), null);
    // The secret is NOT in the clear blob.
    assert.ok(!JSON.stringify(keystore).includes("static_seed"));

    const unlocked = await unlock(keystore, PASS);
    assert.equal(unlocked.kid, keystore.kid);
    assert.equal(unlocked.orgId, "org_huron");
    assert.equal(unlocked.needsUpgrade, false);

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
    assert.throws(() => unlocked.reseal(), /locked/);
  });

  it("re-keys a keystore below this version's cost on unlock so the resealed blob still unlocks (no brick)", async () => {
    // The lowest cost a blob may declare (2^15) is below what this version writes (2^16).
    const belowCurrent = await forgeLegacy(PASS, { N: 32768 });
    const u = await unlock(belowCurrent, PASS); // unlocks with the stored (lower) N
    assert.equal(u.kid, belowCurrent.kid);
    assert.equal(u.needsUpgrade, true);

    const { keystore: resealed } = u.addPrekeys(1); // reseal → must upgrade the KDF
    assert.equal(resealed.kdf.N, 65536, "KDF upgraded to this version's cost");
    assert.notEqual(resealed.kdf.salt, belowCurrent.kdf.salt, "fresh salt on re-key");

    // The regression: before the fix the resealed blob advertised the new N but was
    // encrypted with the old-N key, so the next unlock derived a different key and the
    // keystore was bricked. It must now unlock.
    const u2 = await unlock(resealed, PASS);
    assert.equal(u2.kid, belowCurrent.kid);
    assert.ok(u2.staticSecretKey() instanceof Uint8Array);
    assert.equal(u2.needsUpgrade, false);
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

describe("the blob is untrusted: its cost parameters and shape are checked before the KDF runs", () => {
  it("accepts exactly the cost range [2^15, 2^20], powers of two, r = 8, p = 1 (shape only)", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    assert.equal(keystore.kdf.N, 65536, "what this version writes");
    assert.equal(MIN_SCRYPT_N, 2 ** 15);
    assert.equal(MAX_SCRYPT_N, 2 ** 20);
    const withKdf = (kdf: Record<string, unknown>) => ({ ...keystore, kdf: { ...keystore.kdf, ...kdf } });
    for (const N of [2 ** 15, 2 ** 16, 2 ** 17, 2 ** 18, 2 ** 19, 2 ** 20]) {
      assert.equal(keystoreShapeError(withKdf({ N })), null, `N=${N} is within bounds`);
    }
    for (const N of [0, 1, 2, 1024, 2 ** 14, 2 ** 15 - 1, 2 ** 15 + 1, 65537, 3 * 2 ** 15, 2 ** 21, 2 ** 32, -65536, 65536.5, NaN, Infinity, "65536", null]) {
      assert.equal(keystoreShapeError(withKdf({ N })), "kdf.N", `N=${String(N)} must be refused`);
    }
    for (const r of [0, 1, 7, 9, 16, 1024, "8", null]) {
      assert.equal(keystoreShapeError(withKdf({ r })), "kdf.r", `r=${String(r)} must be refused`);
    }
    for (const p of [0, 2, 16, 4096, "1", null]) {
      assert.equal(keystoreShapeError(withKdf({ p })), "kdf.p", `p=${String(p)} must be refused`);
    }
  });

  it("refuses hostile parameters with the SAME error as a wrong passphrase — and without deriving anything", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS, orgId: "org_victim" });
    const wrongPass = await outcome(keystore, "wrong horse battery staple");
    assert.equal(wrongPass, UNIFORM);

    const kdf = (o: Record<string, unknown>) => ({ ...keystore, kdf: { ...keystore.kdf, ...o } });
    const hostile: Record<string, unknown> = {
      // Each of these used to reach scrypt. (p = 4096 — hours of work — is refused the
      // same way; it is checked at the shape level above and timed, at p = 64, below.)
      "r = 2^20 (unbounded allocation)": kdf({ r: 2 ** 20 }),
      "N = 2^21 (2 GiB)": kdf({ N: 2 ** 21 }),
      "N = 2^30": kdf({ N: 2 ** 30 }),
      "N = 2 (no work at all)": kdf({ N: 2 }),
      "N = 2^14 (below the floor)": kdf({ N: 2 ** 14 }),
      "N = 65537 (not a power of two)": kdf({ N: 65537 }),
      "N as a string": kdf({ N: "65536" }),
      "r = 0": kdf({ r: 0 }),
      "p = 0": kdf({ p: 0 }),
      "salt not hex": kdf({ salt: "zz".repeat(16) }),
      "salt too short": kdf({ salt: "00" }),
      "salt too long": kdf({ salt: "00".repeat(1024) }),
      "salt upper-case": kdf({ salt: "AB".repeat(16) }),
      "kdf name": kdf({ name: "pbkdf2" }),
      "kdf extra member": kdf({ maxmem: 2 ** 40 }),
      "kdf missing": { ...keystore, kdf: undefined },
      "kdf null": { ...keystore, kdf: null },
      "nonce too short": { ...keystore, nonce: "00" },
      "nonce too long": { ...keystore, nonce: "00".repeat(16) },
      "nonce not hex": { ...keystore, nonce: "zz".repeat(12) },
      "ct not hex": { ...keystore, ct: "zz".repeat(64) },
      "ct odd length": { ...keystore, ct: keystore.ct.slice(1) },
      "ct only a tag": { ...keystore, ct: "00".repeat(16) },
      "ct a number": { ...keystore, ct: 7 },
      "unknown spec": { ...keystore, spec: "sje-keystore/9.9.9" },
      "unknown cipher": { ...keystore, cipher: "AES-128-GCM" },
      "unknown enc_alg": { ...keystore, enc_alg: "ML-KEM-512" },
      "kid not the key's": { ...keystore, kid: flip(keystore.kid) },
      "public key wrong length": { ...keystore, enc_public_key: keystore.enc_public_key.slice(2) },
      "org_id empty": { ...keystore, org_id: "" },
      "org_id not a string": { ...keystore, org_id: 5 },
      "org_id oversized": { ...keystore, org_id: "x".repeat(257) },
      "extra member": { ...keystore, hint: "the passphrase is…" },
      "missing member": (({ cipher: _c, ...rest }) => rest)(keystore),
      "an array": [keystore],
      "a string": JSON.stringify(keystore),
      "null": null,
      "undefined": undefined,
      "a number": 42,
    };
    for (const [label, blob] of Object.entries(hostile)) {
      assert.notEqual(keystoreShapeError(blob), null, `${label}: shape must be refused`);
      assert.equal(await outcome(blob), wrongPass, `${label}: must fail exactly like a wrong passphrase`);
    }
    // A passphrase that is not a string is the same failure, not a TypeError.
    for (const pass of [undefined, null, 12345678901234, {}, ["correct horse battery staple"]]) {
      assert.equal(await outcome(keystore, pass), wrongPass);
    }
    // …and the genuine blob still opens.
    assert.equal(await outcome(keystore), "UNLOCKED");
  });

  it("a blob validly encrypted under out-of-bounds parameters (N = 2, say) is refused even with the right passphrase", async () => {
    // Each blob here is VALIDLY encrypted under the parameters it declares, and the
    // passphrase is right: if `unlock` ran the KDF with what the blob asks for, it would
    // open. It unlocked silently before — at N = 2, as if it had been protected by scrypt.
    const weak = await forgeLegacy(PASS, { N: 2, r: 1, p: 1 });
    assert.equal(await outcome(weak), UNIFORM);
    const lowN = await forgeLegacy(PASS, { N: 16384 });
    assert.equal(await outcome(lowN), UNIFORM, "2^14 is below the floor");
    const oddR = await forgeLegacy(PASS, { N: 32768, r: 4 });
    assert.equal(await outcome(oddR), UNIFORM, "r must be the value this code writes");
    const bigR = await forgeLegacy(PASS, { N: 32768, r: 16 });
    assert.equal(await outcome(bigR), UNIFORM, "…not a larger one either");
    const twoP = await forgeLegacy(PASS, { N: 32768, p: 2 });
    assert.equal(await outcome(twoP), UNIFORM, "p must be 1");
    const shortSalt = await forgeLegacy(PASS, { saltBytes: 8 });
    assert.equal(await outcome(shortSalt), UNIFORM, "the salt is exactly 16 bytes");
    const longNonce = await forgeLegacy(PASS, { nonceBytes: 16 });
    assert.equal(await outcome(longNonce), UNIFORM, "the nonce is exactly 12 bytes");
    // The control: the same forger at accepted parameters does open.
    assert.equal(await outcome(await forgeLegacy(PASS)), "UNLOCKED");
  });

  it("a blob asking for far more work is refused at once, not after doing the work", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS });
    // p = 64 at the lowest accepted N is ~64× a normal unlock: several seconds of scrypt
    // (p = 4096, refused by the same check, would be minutes). A refusal takes
    // microseconds, so a generous bound separates the two with no risk of flaking.
    const costly = { ...keystore, kdf: { ...keystore.kdf, N: 2 ** 15, p: 64 } };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tooLong = new Promise<string>((resolve) => {
      timer = setTimeout(() => resolve("STILL DERIVING after 2 s"), 2000);
    });
    try {
      assert.equal(await Promise.race([outcome(costly), tooLong]), UNIFORM);
    } finally {
      clearTimeout(timer);
    }
  });

  it("a vault that is not a vault fails with the same error (never a stray exception)", async () => {
    const vaults: Array<(seed: string) => unknown> = [
      () => [],
      () => "vault",
      () => ({}),
      (seed) => ({ static_seed: seed }), // no prekeys
      (seed) => ({ static_seed: seed, prekeys: null }),
      (seed) => ({ static_seed: seed, prekeys: [] }),
      (seed) => ({ static_seed: seed.slice(2), prekeys: {} }), // wrong seed length
      (seed) => ({ static_seed: seed, prekeys: {}, sign_seed: "not hex" }),
      (seed) => ({ static_seed: seed, prekeys: {}, extra: true }),
      (seed) => ({ static_seed: flip(seed), prekeys: {} }), // a seed for some OTHER key
    ];
    for (const [i, vault] of vaults.entries()) {
      assert.equal(await outcome(await forgeLegacy(PASS, { vault })), UNIFORM, `vault #${i}`);
    }
  });
});

describe("keystore format versions: the header is authenticated in 0.2.0, and 0.1.0 still opens", () => {
  it("a legacy 0.1.0 blob still unlocks, and is upgraded to 0.2.0 the next time it is re-sealed", async () => {
    const legacy = await forgeLegacy(PASS, { N: 65536, orgId: "org_legacy" });
    assert.equal(legacy.spec, KEYSTORE_SPEC_LEGACY);
    assert.equal(keystoreShapeError(legacy), null);

    const u = await unlock(legacy, PASS);
    assert.equal(u.kid, legacy.kid);
    assert.equal(u.orgId, "org_legacy");
    assert.equal(u.needsUpgrade, true, "a legacy blob is flagged for upgrade");

    // Any re-seal writes the current format — with the SAME identity and KDF salt/cost
    // (N was already this version's), so nothing about the key changes.
    const { keystore: upgraded, prekeys } = u.addPrekeys(1);
    assert.equal(upgraded.spec, "sje-keystore/0.2.0");
    assert.equal(upgraded.kid, legacy.kid);
    assert.equal(upgraded.enc_public_key, legacy.enc_public_key);
    assert.equal(upgraded.org_id, "org_legacy");
    assert.deepEqual(upgraded.kdf, legacy.kdf);
    assert.equal(keystoreShapeError(upgraded), null);
    assert.equal(u.reseal().spec, "sje-keystore/0.2.0", "reseal() alone upgrades too");

    const u2 = await unlock(upgraded, PASS);
    assert.equal(u2.needsUpgrade, false);
    assert.equal(u2.orgId, "org_legacy");
    assert.deepEqual(u2.staticSecretKey(), u.staticSecretKey(), "same identity after the upgrade");
    assert.ok(u2.peekPrekey(prekeys[0]!.prekey_id) instanceof Uint8Array, "vault contents carried over");

    // The legacy blob itself is untouched and still opens (nobody is locked out by
    // holding an old copy).
    assert.equal(await outcome(legacy), "UNLOCKED");
  });

  it("a blob cannot be relabelled from one version to the other", async () => {
    const legacy = await forgeLegacy(PASS, { orgId: "org_a" });
    assert.equal(await outcome({ ...legacy, spec: KEYSTORE_SPEC }), UNIFORM, "0.1.0 relabelled as 0.2.0");
    const { keystore: current } = await createIdentity({ passphrase: PASS, orgId: "org_a" });
    assert.equal(
      await outcome({ ...current, spec: KEYSTORE_SPEC_LEGACY }),
      UNIFORM,
      "0.2.0 relabelled as 0.1.0 (which would drop org_id from the authenticated data)",
    );
  });

  it("0.2.0: editing ANY clear member of the blob makes it fail to unlock", async () => {
    const { keystore } = await createIdentity({ passphrase: PASS, orgId: "org_mine" });
    const other = await createIdentity({ passphrase: PASS, orgId: "org_mine" });
    const edits: Record<string, unknown> = {
      "org_id rewritten": { ...keystore, org_id: "org_someone_else" },
      "org_id removed": (({ org_id: _o, ...rest }) => rest)(keystore),
      "org_id re-cased": { ...keystore, org_id: "ORG_MINE" },
      "kid + public key swapped for another identity's": {
        ...keystore,
        kid: other.keystore.kid,
        enc_public_key: other.keystore.enc_public_key,
      },
      "kdf.N raised": { ...keystore, kdf: { ...keystore.kdf, N: 2 ** 17 } },
      "kdf.N lowered": { ...keystore, kdf: { ...keystore.kdf, N: 2 ** 15 } },
      "kdf.salt changed": { ...keystore, kdf: { ...keystore.kdf, salt: flip(keystore.kdf.salt) } },
      "nonce changed": { ...keystore, nonce: flip(keystore.nonce) },
      "ct changed": { ...keystore, ct: flip(keystore.ct) },
      "spec downgraded": { ...keystore, spec: KEYSTORE_SPEC_LEGACY },
    };
    for (const [label, blob] of Object.entries(edits)) {
      assert.equal(await outcome(blob), UNIFORM, label);
    }
    // Every clear member is covered by one of the edits above — a member added to the
    // format later must be added here (and to the associated data) too.
    assert.deepEqual(
      Object.keys(keystore).sort(),
      ["cipher", "ct", "enc_alg", "enc_public_key", "kdf", "kid", "nonce", "org_id", "spec"],
    );
    // A blob with no org label: adding one must fail as well (absent is authenticated).
    const { keystore: unlabelled } = await createIdentity({ passphrase: PASS });
    assert.equal(await outcome({ ...unlabelled, org_id: "org_injected" }), UNIFORM, "org_id added");
    assert.equal(await outcome(keystore), "UNLOCKED");
  });

  it("0.1.0 did NOT authenticate org_id — which is why a legacy blob is upgraded", async () => {
    // Characterizes the legacy format: the label of a 0.1.0 blob can be rewritten by
    // anyone who can write the blob, and it still unlocks. This cannot be fixed for a
    // blob that already exists; it stops being true the moment the blob is re-sealed.
    const legacy = await forgeLegacy(PASS, { N: 65536, orgId: "org_victim" });
    const relabelled = { ...legacy, org_id: "org_someone_else" };
    const u = await unlock(relabelled, PASS);
    assert.equal(u.orgId, "org_someone_else");

    const upgraded = (await unlock(legacy, PASS)).reseal();
    assert.equal(upgraded.org_id, "org_victim");
    assert.equal(await outcome({ ...upgraded, org_id: "org_someone_else" }), UNIFORM);
    assert.equal(await outcome(upgraded), "UNLOCKED");
  });
});
