import assert from "node:assert/strict";
import { describe, it, before, beforeEach } from "node:test";
import { readFileSync } from "node:fs";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";

// The desk's storage, as a browser provides it — installed BEFORE the store is used.
// One `disk` shared by every "tab" below, with the ways a real browser fails:
//   quota   setItem throws (storage full)
//   drop    setItem returns without storing anything
//   blocked every access throws (storage disabled for the site)
const disk = new Map<string, string>();
let fault: "none" | "quota" | "drop" | "blocked" = "none";
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => {
    if (fault === "blocked") throw new DOMException("storage is blocked", "SecurityError");
    return disk.get(k) ?? null;
  },
  setItem: (k: string, v: string) => {
    if (fault === "blocked") throw new DOMException("storage is blocked", "SecurityError");
    if (fault === "quota") throw new DOMException("quota exceeded", "QuotaExceededError");
    if (fault === "drop") return;
    disk.set(k, v);
  },
  removeItem: (k: string) => void disk.delete(k),
  clear: () => disk.clear(),
  key: (i: number) => [...disk.keys()][i] ?? null,
  get length() {
    return disk.size;
  },
};

import { sanitizeTrust, sanitizeTrustMarks, KEYS_STORAGE_KEY } from "./keys-store.ts";
import { sealTraveler, openTraveler } from "./transport.ts";
import { keypairFromSeed, type Keypair } from "./signature.ts";
import { encKid, kemKeypairFromSeed, KEM_ALG } from "./envelope.ts";
import { entryByKid, signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "./prekeys.ts";
import { createIdentity, unlock, type Keystore, type PublicPrekey } from "./keystore.ts";
import { buildDemoTrust } from "./demo-trust.ts";
import { rootDigest, rootFingerprint } from "./fingerprint.ts";
import { usedPrekeyIds } from "./prekey-ledger.ts";
import { canonicalJson } from "./canonical.ts";
import { parseTraveler } from "./conformance.ts";
import { bytesToHex, utf8ToBytes } from "./bytes.ts";
import type { Traveler } from "./types.ts";

type Tab = typeof import("./keys-store.ts");

const PASS = "correct horse battery staple";
const AT = new Date("2027-01-01T00:00:00.000Z");
const confRoot = new URL("../../../conformance/", import.meta.url).pathname;

function sampleTraveler(): Traveler {
  return parseTraveler(JSON.parse(readFileSync(`${confRoot}travelers/l0-bracket.json`, "utf8")));
}

/* ------------------------------------------------------------------ tabs ---- */

let tabSeq = 0;
/** Open a new tab on the same browser storage: a fresh copy of the store module (its
 *  own in-memory state), hydrated from `disk` the way the app's provider does it.
 *  `storageEvent` delivers a `storage` event to that tab, as the browser would when
 *  ANOTHER tab writes. */
async function openTab(): Promise<Tab & { storageEvent: (key: string | null) => void }> {
  const specifier = `./keys-store.ts?tab=${++tabSeq}`;
  const tab = (await import(specifier)) as Tab;
  void tab.useKeysStore.persist.rehydrate();
  tab.useKeysStore.getState().setHydrated(true);
  const bus = new EventTarget();
  tab.watchKeysStorage(bus);
  return {
    ...tab,
    storageEvent: (key) => void bus.dispatchEvent(Object.assign(new Event("storage"), { key })),
  };
}

/** What is stored right now, parsed. */
function stored(): { identity?: Keystore; trust?: unknown; trustMarks?: unknown; prekeyLedger?: unknown } {
  const raw = disk.get(KEYS_STORAGE_KEY);
  return raw === undefined ? {} : (JSON.parse(raw) as { state: Record<string, never> }).state;
}
/** Put a state on disk as an earlier session would have left it. */
function store(state: Record<string, unknown>): void {
  disk.set(KEYS_STORAGE_KEY, JSON.stringify({ state, version: 0 }));
}

/* -------------------------------------------------------------- fixtures ---- */

const R1 = keypairFromSeed(new Uint8Array(32).fill(3));
const R2 = keypairFromSeed(new Uint8Array(32).fill(13));
const signer = keypairFromSeed(new Uint8Array(32).fill(4));
const retiredSigner = keypairFromSeed(new Uint8Array(32).fill(14));
const root1 = bytesToHex(R1.publicKey);
const root2 = bytesToHex(R2.publicKey);

/** A directory for org_recipient signed by `root`. Its second entry is an older key:
 *  active in the directory issued first, REVOKED in the later one. */
function directoryOf(
  root: Keypair,
  issued_at: string,
  opts: { retired: "active" | "revoked"; encPublicKey?: string },
): Directory {
  const window = { valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2030-01-01T00:00:00.000Z" };
  const body: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at,
    valid_until: "2030-01-01T00:00:00.000Z",
    root_kid: "root-2026",
    entries: [
      {
        org_id: "org_recipient",
        kid: "recip-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(signer.publicKey),
        ...window,
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key:
          opts.encPublicKey ?? bytesToHex(kemKeypairFromSeed(new Uint8Array(64).fill(1)).publicKey),
      },
      {
        org_id: "org_recipient",
        kid: "recip-2025",
        alg: "ML-DSA-87",
        public_key: bytesToHex(retiredSigner.publicKey),
        ...window,
        status: opts.retired,
      },
    ],
  };
  return { ...body, sig: signDirectory(body, root.secretKey) };
}
const V1 = "2026-01-01T00:00:00.000Z";
const V2 = "2026-06-01T00:00:00.000Z";
const dirV1 = directoryOf(R1, V1, { retired: "active" });
const dirV2 = directoryOf(R1, V2, { retired: "revoked" });
const dirOther = directoryOf(R2, V1, { retired: "active" });

function bundleOf(prekeys: PublicPrekey[]): PrekeyBundle {
  const b: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: "org_recipient",
    kid: "recip-2026",
    enc_alg: "ML-KEM-1024",
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    prekeys,
  };
  b.sig = signPrekeyBundle(b, signer.secretKey);
  return b;
}
const fixedPrekey = (n: number): PublicPrekey => {
  const pub = bytesToHex(kemKeypairFromSeed(new Uint8Array(64).fill(n)).publicKey);
  return { prekey_id: `pk${n}`, public_key: pub };
};

/** One desk identity for the whole file (scrypt is deliberately slow): an encrypted
 *  keystore holding three one-time prekeys, the directory that publishes its key, and
 *  the bundle that publishes its prekeys. */
let deskBlob: Keystore;
let deskPrekeys: PublicPrekey[];
let deskDir: Directory;
let deskBundle: PrekeyBundle;
before(async () => {
  const id = await createIdentity({ passphrase: PASS, orgId: "org_recipient" });
  const minted = (await unlock(id.keystore, PASS)).addPrekeys(3);
  deskBlob = minted.keystore;
  deskPrekeys = minted.prekeys;
  deskDir = directoryOf(R1, V1, { retired: "active", encPublicKey: id.directoryEntry.enc_public_key });
  deskBundle = bundleOf(deskPrekeys);
});

beforeEach(() => {
  disk.clear();
  fault = "none";
});

/** Which of the desk's one-time prekeys a keystore blob still holds. */
async function prekeysHeld(blob: Keystore): Promise<string[]> {
  const u = await unlock(blob, PASS);
  return deskPrekeys.map((p) => p.prekey_id).filter((id) => u.peekPrekey(id) !== undefined);
}

/* ----------------------------------------------------------------- tests ---- */

describe("keys store (desk custody)", () => {
  it("creates an identity encrypted at rest, unlocked, and returns the public entry", async () => {
    const tab = await openTab();
    const entry = await tab.useKeysStore.getState().createIdentity(PASS, "org_me");
    const s = tab.useKeysStore.getState();
    assert.ok(s.identity, "identity stored");
    assert.equal(s.identity!.spec, "sje-keystore/0.2.0");
    assert.equal(entry.kid, s.identity!.kid);
    assert.equal(s.identity!.org_id, "org_me");
    assert.ok(s.isUnlocked(), "left unlocked after create");
    // The secret seed is encrypted into ct, never a clear field.
    assert.ok(!JSON.stringify(s.identity).includes("static_seed"));
    assert.deepEqual(stored().identity, s.identity, "and it is what the browser stored");
  });

  it("locks (clearing the in-memory secret) while keeping the encrypted blob", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await tab.useKeysStore.getState().unlock(PASS);
    const session = tab.useKeysStore.getState().unlocked!;
    tab.useKeysStore.getState().lock();
    const s = tab.useKeysStore.getState();
    assert.ok(!s.isUnlocked(), "locked");
    assert.throws(() => session.staticSecretKey(), /locked/);
    assert.ok(s.identity, "encrypted blob remains after lock");
  });

  it("rejects a wrong passphrase with the uniform error and unlocks with the right one", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await assert.rejects(() => tab.useKeysStore.getState().unlock("a different passphrase"), /unlock failed/);
    assert.ok(!tab.useKeysStore.getState().isUnlocked());
    await tab.useKeysStore.getState().unlock(PASS);
    assert.ok(tab.useKeysStore.getState().isUnlocked());
  });

  it("mints prekeys only when unlocked and persists them into the blob", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    assert.throws(() => tab.useKeysStore.getState().addPrekeys(1), /Unlock/);
    await tab.useKeysStore.getState().unlock(PASS);
    const before = tab.useKeysStore.getState().identity!.ct;
    const pks = tab.useKeysStore.getState().addPrekeys(3);
    assert.equal(pks.length, 3);
    assert.notEqual(tab.useKeysStore.getState().identity!.ct, before, "blob re-sealed with prekeys");
    assert.deepEqual(stored().identity, tab.useKeysStore.getState().identity, "and stored");
  });

  it("a desk identity opens an envelope sealed to its published key (end-to-end)", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await tab.useKeysStore.getState().unlock(PASS);
    const traveler = sampleTraveler();
    const { envelope } = await sealTraveler(traveler, {
      directory: deskDir,
      rootPublicKeyHex: root1,
      recipientOrg: "org_recipient",
      at: AT,
    });
    const opened = await openTraveler(envelope, tab.useKeysStore.getState().unlocked!);
    assert.deepEqual(opened, traveler);
  });

  it("upgrades a legacy (0.1.0) keystore to the current format the first time it is unlocked", async () => {
    // A blob exactly as the first keystore format wrote it (see keystore.test.ts).
    const seed = crypto.getRandomValues(new Uint8Array(64));
    const enc_public_key = bytesToHex(kemKeypairFromSeed(seed).publicKey);
    const kid = encKid(enc_public_key);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kdf = { name: "scrypt" as const, N: 65536, r: 8, p: 1, salt: bytesToHex(salt) };
    const key = await scryptAsync(utf8ToBytes(PASS), salt, { N: 65536, r: 8, p: 1, dkLen: 32 });
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = utf8ToBytes(canonicalJson({ spec: "sje-keystore/0.1.0", kid, enc_alg: KEM_ALG, enc_public_key, kdf }));
    const ct = gcm(key, nonce, aad).encrypt(utf8ToBytes(JSON.stringify({ static_seed: bytesToHex(seed), prekeys: {} })));
    const legacy = {
      spec: "sje-keystore/0.1.0",
      kid,
      enc_alg: KEM_ALG,
      enc_public_key,
      org_id: "org_old",
      kdf,
      cipher: "AES-256-GCM",
      nonce: bytesToHex(nonce),
      ct: bytesToHex(ct),
    };
    store({ identity: legacy });

    const tab = await openTab();
    assert.equal(tab.useKeysStore.getState().identity!.spec, "sje-keystore/0.1.0", "loaded as stored");
    await tab.useKeysStore.getState().unlock(PASS);
    assert.equal(tab.useKeysStore.getState().identity!.spec, "sje-keystore/0.2.0", "re-sealed on unlock");
    assert.equal(stored().identity!.spec, "sje-keystore/0.2.0", "and the upgraded blob is what is stored");
    assert.equal(stored().identity!.kid, kid, "same identity");
    // A later session opens the upgraded blob.
    const later = await openTab();
    await later.useKeysStore.getState().unlock(PASS);
    assert.equal(later.useKeysStore.getState().unlocked!.orgId, "org_old");
  });
});

describe("trust anchor: confirmed by fingerprint, never replaced silently, never rolled back", () => {
  it("loads a trust anchor only if the directory verifies, dropping unverifiable bundles", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    const bundle = bundleOf([fixedPrekey(9)]);
    // Wrong root → refuse.
    assert.throws(
      () => s().setTrust({ rootPublicKeyHex: "00".repeat(2592), directory: dirV1, bundles: {} }, { at: AT }),
      /does not verify/,
    );
    assert.equal(s().trust, undefined);

    // Correct root → accept, keeping the verifying bundle.
    const confirmedRoot = rootDigest(root1)!;
    s().setTrust(
      { rootPublicKeyHex: root1, directory: dirV1, bundles: { org_recipient: bundle } },
      { at: AT, confirmedRoot },
    );
    const t1 = s().trust!;
    assert.ok(t1, "trust loaded");
    assert.equal(t1.rootPublicKeyHex, root1);
    assert.ok(t1.bundles.org_recipient, "verifying bundle kept");

    // A tampered bundle signature is filtered out (fail closed) — and reported.
    const badBundle: PrekeyBundle = { ...bundle, sig: (bundle.sig![0] === "a" ? "b" : "a") + bundle.sig!.slice(1) };
    const review = s().setTrust(
      { rootPublicKeyHex: root1, directory: dirV1, bundles: { org_recipient: badBundle } },
      { at: AT },
    );
    assert.ok(!s().trust!.bundles.org_recipient, "unverifiable bundle dropped");
    assert.deepEqual(review.bundles, { kept: [], dropped: ["org_recipient"] });
    // A bundle filed under an org it was not issued for is not that org's bundle.
    const misfiled = s().setTrust(
      { rootPublicKeyHex: root1, directory: dirV1, bundles: { org_someone_else: bundle } },
      { at: AT },
    );
    assert.deepEqual(misfiled.bundles, { kept: [], dropped: ["org_someone_else"] });
  });

  it("says why an anchor does not verify: not a directory, outside its window, or not this root's", async () => {
    const tab = await openTab();
    const why = (anchor: Parameters<Tab["reviewTrustChange"]>[1], at = AT) => {
      try {
        tab.reviewTrustChange(tab.useKeysStore.getState(), anchor, at);
        return "accepted";
      } catch (e) {
        return (e as Error).message;
      }
    };
    assert.match(why({ rootPublicKeyHex: root2, directory: dirV1 }), /^Directory does not verify against this root/);
    assert.match(why({ rootPublicKeyHex: "not hex", directory: dirV1 }), /root public key is not hex/);
    assert.match(
      why({ rootPublicKeyHex: root1, directory: { ...dirV1, extra: 1 } as never }),
      /not a well-formed directory \(unexpected or missing members\)/,
    );
    assert.match(why({ rootPublicKeyHex: root1, directory: "a directory" as never }), /not a well-formed directory/);
    assert.match(
      why({ rootPublicKeyHex: root1, directory: dirV1 }, new Date("2031-01-01T00:00:00.000Z")),
      /valid from 2026-01-01T00:00:00.000Z until 2030-01-01T00:00:00.000Z, which does not include now/,
    );
    // Every one of them is the same refusal as far as loading goes.
    for (const anchor of [{ rootPublicKeyHex: root2, directory: dirV1 }, { rootPublicKeyHex: "zz", directory: dirV1 }]) {
      assert.throws(() => tab.useKeysStore.getState().setTrust(anchor, { at: AT, confirmedRoot: "x" }), /does not verify/);
    }
    assert.equal(tab.useKeysStore.getState().trust, undefined);
  });

  it("the first root a desk loads must be confirmed — by the fingerprint the review shows", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    const anchor = { rootPublicKeyHex: root1, directory: dirV1 };

    const review = tab.reviewTrustChange(s(), anchor, AT);
    assert.equal(review.kind, "first-load");
    assert.equal(review.needsConfirmation, true);
    assert.equal(review.root.fingerprint, rootFingerprint(root1));
    assert.equal(review.root.fingerprint, "0aa0 96d5 8b4f b69f 7b61 d42e bb3f 8844");
    assert.equal(review.root.demo, false);
    assert.equal(review.held, undefined);
    assert.equal(review.knownIssuedAt, undefined, "a desk with no record of this root says so");

    // Unconfirmed: refused, and the refusal carries what to show.
    assert.throws(
      () => s().setTrust(anchor, { at: AT }),
      (e: unknown) => e instanceof tab.TrustConfirmationRequired && e.review.root.digest === review.root.digest,
    );
    assert.equal(s().trust, undefined, "nothing was loaded");
    // Confirming some OTHER root is not confirming this one.
    assert.throws(() => s().setTrust(anchor, { at: AT, confirmedRoot: rootDigest(root2)! }), tab.TrustConfirmationRequired);
    assert.throws(() => s().setTrust(anchor, { at: AT, confirmedRoot: "yes" }), tab.TrustConfirmationRequired);
    assert.equal(s().trust, undefined);

    s().setTrust(anchor, { at: AT, confirmedRoot: review.root.digest });
    assert.equal(s().trust!.rootPublicKeyHex, root1);
    assert.deepEqual(s().trustMarks, { [review.root.digest]: V1 });
  });

  it("refuses a directory OLDER than one already accepted under the same root (a revoked key must not come back)", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    const confirmedRoot = rootDigest(root1)!;
    // Why it matters: recip-2025 authenticates under v1 and is revoked in v2.
    assert.ok(entryByKid(dirV1, "recip-2025", AT), "v1: the old key is usable");
    assert.equal(entryByKid(dirV2, "recip-2025", AT), undefined, "v2: it is revoked");

    s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot });
    // A NEWER directory under the same root needs no confirmation.
    const up = s().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT });
    assert.equal(up.kind, "same-root");
    assert.equal(up.needsConfirmation, false);
    assert.equal(up.knownIssuedAt, V1);
    assert.equal(s().trust!.directory.issued_at, V2);
    // The SAME directory again is fine (equal issued_at).
    s().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT });

    // Going back is refused — with or without a confirmation.
    for (const opts of [{ at: AT }, { at: AT, confirmedRoot }]) {
      assert.throws(
        () => s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, opts),
        (e: unknown) => e instanceof tab.TrustRollbackError && /older directory/.test(e.message),
      );
    }
    assert.throws(() => tab.reviewTrustChange(s(), { rootPublicKeyHex: root1, directory: dirV1 }, AT), tab.TrustRollbackError);
    assert.equal(s().trust!.directory.issued_at, V2, "the newer directory is still the one held");
    assert.equal(entryByKid(s().trust!.directory, "recip-2025", AT), undefined, "…and the key stays revoked");
  });

  it("the rollback mark is persisted: it survives a reload, and clearing the anchor", async () => {
    const first = await openTab();
    const confirmedRoot = rootDigest(root1)!;
    first.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT, confirmedRoot });
    assert.deepEqual(stored().trustMarks, { [confirmedRoot]: V2 }, "the mark is on disk");

    // Reload: a new tab knows nothing but what is stored.
    const reloaded = await openTab();
    const s = () => reloaded.useKeysStore.getState();
    assert.equal(s().trust!.directory.issued_at, V2);
    assert.throws(() => s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT }), reloaded.TrustRollbackError);

    // "Clear trust anchor" forgets the anchor, not what this desk has seen: the older
    // directory is still refused, even freshly confirmed.
    s().clearTrust();
    assert.equal(s().trust, undefined);
    assert.deepEqual(s().trustMarks, { [confirmedRoot]: V2 });
    const again = await openTab();
    assert.throws(
      () => again.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot }),
      again.TrustRollbackError,
    );
    // The newer one loads (as a first load — it must be confirmed — and the review says
    // this root has been seen before).
    const review = again.reviewTrustChange(again.useKeysStore.getState(), { rootPublicKeyHex: root1, directory: dirV2 }, AT);
    assert.equal(review.kind, "first-load");
    assert.equal(review.knownIssuedAt, V2);
  });

  it("a desk whose storage was cleared has nothing to compare with — and the review says so", async () => {
    const first = await openTab();
    const confirmedRoot = rootDigest(root1)!;
    first.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT, confirmedRoot });

    disk.clear(); // "Clear site data"
    const wiped = await openTab();
    const s = () => wiped.useKeysStore.getState();
    assert.equal(s().trust, undefined);
    assert.deepEqual(s().trustMarks, {});
    const review = wiped.reviewTrustChange(s(), { rootPublicKeyHex: root1, directory: dirV1 }, AT);
    assert.equal(review.kind, "first-load");
    assert.equal(review.knownIssuedAt, undefined, "no record of this root: rollback cannot be detected");
    // The limit, stated: the older directory IS accepted by a desk with no memory.
    s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot });
    assert.equal(s().trust!.directory.issued_at, V1);
  });

  it("a DIFFERENT root replaces the held one only when its fingerprint is confirmed (both are shown)", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    s().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT, confirmedRoot: rootDigest(root1)! });
    const other = { rootPublicKeyHex: root2, directory: dirOther };

    const review = tab.reviewTrustChange(s(), other, AT);
    assert.equal(review.kind, "root-change");
    assert.equal(review.needsConfirmation, true);
    assert.equal(review.held!.fingerprint, rootFingerprint(root1), "old root");
    assert.equal(review.root.fingerprint, rootFingerprint(root2), "new root");
    assert.notEqual(review.held!.fingerprint, review.root.fingerprint);
    assert.equal(review.held!.issuedAt, V2);

    // Silently: no. Confirming the OLD root's fingerprint: no.
    assert.throws(() => s().setTrust(other, { at: AT }), tab.TrustConfirmationRequired);
    assert.throws(() => s().setTrust(other, { at: AT, confirmedRoot: rootDigest(root1)! }), tab.TrustConfirmationRequired);
    assert.equal(s().trust!.rootPublicKeyHex, root1, "the held root is untouched");

    s().setTrust(other, { at: AT, confirmedRoot: review.root.digest });
    assert.equal(s().trust!.rootPublicKeyHex, root2);

    // Switching roots does not launder a rollback: going back to the first root with
    // its OLDER directory is still refused.
    assert.throws(
      () => s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot: rootDigest(root1)! }),
      tab.TrustRollbackError,
    );
    assert.equal(Object.keys(s().trustMarks).length, 2, "one mark per root");
  });

  it("identifies a root by its key, not its spelling, and names the demo root", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    s().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot: rootDigest(root1)! });
    // The same key in upper-case hex is the same root: no "root change", no second mark.
    const recased = s().setTrust({ rootPublicKeyHex: root1.toUpperCase(), directory: dirV2 }, { at: AT });
    assert.equal(recased.kind, "same-root");
    assert.equal(s().trust!.rootPublicKeyHex, root1, "stored in one spelling");
    assert.equal(Object.keys(s().trustMarks).length, 1);
    // …and cannot be used to slip an older directory past the mark.
    assert.throws(() => s().setTrust({ rootPublicKeyHex: root1.toUpperCase(), directory: dirV1 }, { at: AT }), tab.TrustRollbackError);

    const demo = buildDemoTrust();
    const review = tab.reviewTrustChange(s(), demo, AT);
    assert.equal(review.kind, "root-change");
    assert.equal(review.root.demo, true, "the review says the incoming root is the demo root");
    assert.equal(review.held!.demo, false);
    s().setTrust(demo, { at: AT, confirmedRoot: review.root.digest });
    assert.equal(tab.reviewTrustChange(s(), { rootPublicKeyHex: root1, directory: dirV2 }, AT).held!.demo, true);
  });

  it("on load: a stored anchor older than this desk's own mark is not loaded; one stored before marks existed gets a mark", async () => {
    const digest = rootDigest(root1)!;
    // Someone put the older directory back in storage, under a mark that says newer.
    store({ trust: { rootPublicKeyHex: root1, directory: dirV1, bundles: {} }, trustMarks: { [digest]: V2 } });
    const rolledBack = await openTab();
    assert.equal(rolledBack.useKeysStore.getState().trust, undefined, "not loaded");
    assert.deepEqual(rolledBack.useKeysStore.getState().trustMarks, { [digest]: V2 }, "the mark stands");

    // State written by a version that had no marks: the anchor is kept, the mark starts here.
    store({ trust: { rootPublicKeyHex: root1, directory: dirV2, bundles: {} } });
    const migrated = await openTab();
    assert.equal(migrated.useKeysStore.getState().trust!.directory.issued_at, V2);
    assert.deepEqual(migrated.useKeysStore.getState().trustMarks, { [digest]: V2 });
    assert.deepEqual(stored().trustMarks, { [digest]: V2 }, "and it is written back on load");
    assert.throws(
      () => migrated.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT }),
      migrated.TrustRollbackError,
    );
  });
});

describe("storage is not assumed to work: a write is read back", () => {
  for (const mode of ["quota", "drop"] as const) {
    it(`a consumed prekey whose deletion was not stored is an ERROR, not a success (${mode})`, async () => {
      store({ identity: deskBlob });
      const tab = await openTab();
      await tab.useKeysStore.getState().unlock(PASS);
      const session = tab.useKeysStore.getState().unlocked!;
      const spent = deskPrekeys[0]!.prekey_id;
      const { keystore: updated } = session.consumePrekey(spent);

      fault = mode; // the browser stops storing
      assert.throws(
        () => tab.useKeysStore.getState().persistKeystore(updated),
        (e: unknown) => e instanceof tab.KeystoreNotSavedError && /still stored/.test(e.message),
      );
      assert.match(tab.useCustodyStatus.getState().storageError ?? "", /did not save/);
      fault = "none";
      // The truth on disk: the old blob, with the spent prekey's secret still in it.
      assert.deepEqual(stored().identity, deskBlob);
      assert.ok((await prekeysHeld(stored().identity!)).includes(spent), "the prekey is still on disk");

      // Once storage works again, a retry stores what this tab holds and clears the error.
      assert.equal(tab.useKeysStore.getState().retrySave(), true);
      assert.equal(tab.useCustodyStatus.getState().storageError, undefined);
      assert.deepEqual(stored().identity, updated);
      assert.ok(!(await prekeysHeld(stored().identity!)).includes(spent), "now it is gone from disk");
    });
  }

  it("opening a forward-secret envelope FAILS when the keystore cannot be stored afterwards", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await tab.useKeysStore.getState().unlock(PASS);
    const { envelope, forwardSecret } = await sealTraveler(sampleTraveler(), {
      directory: deskDir,
      rootPublicKeyHex: root1,
      recipientOrg: "org_recipient",
      prekeyBundle: deskBundle,
      at: AT,
    });
    assert.equal(forwardSecret, true);
    fault = "quota";
    // Exactly the desk's wiring (routes/index.tsx).
    await assert.rejects(
      () =>
        openTraveler(envelope, tab.useKeysStore.getState().unlocked!, {
          persistKeystore: (ks) => tab.useKeysStore.getState().persistKeystore(ks),
        }),
      tab.KeystoreNotSavedError,
    );
    assert.deepEqual(stored().identity, deskBlob, "disk is unchanged — and the desk did not say otherwise");
  });

  it("does not hand out prekeys whose secrets were not stored", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await tab.useKeysStore.getState().unlock(PASS);
    fault = "quota";
    assert.throws(() => tab.useKeysStore.getState().addPrekeys(2), tab.KeystoreNotSavedError);
    assert.deepEqual(stored().identity, deskBlob);
  });

  it("creates no identity when the browser will not store it", async () => {
    const tab = await openTab();
    fault = "blocked";
    await assert.rejects(() => tab.useKeysStore.getState().createIdentity(PASS, "org_me"), tab.KeystoreNotSavedError);
    assert.equal(tab.useKeysStore.getState().identity, undefined, "nothing is left in the tab");
    assert.ok(!tab.useKeysStore.getState().isUnlocked());
    fault = "none";
    assert.equal(stored().identity, undefined);
  });

  it("storage that becomes UNREADABLE is not mistaken for 'removed in another tab'", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    await tab.useKeysStore.getState().unlock(PASS);
    const session = tab.useKeysStore.getState().unlocked!;

    fault = "blocked"; // every access to storage now throws
    // Neither a storage event nor an action may conclude "nothing is stored" from that.
    tab.storageEvent(KEYS_STORAGE_KEY);
    tab.storageEvent(null);
    assert.throws(() => tab.useKeysStore.getState().addPrekeys(1), tab.KeystoreNotSavedError);
    const s = tab.useKeysStore.getState();
    assert.ok(s.identity, "the tab keeps the identity it holds");
    assert.ok(s.isUnlocked(), "and stays unlocked");
    assert.ok(session.staticSecretKey() instanceof Uint8Array);
    assert.deepEqual(tab.useCustodyStatus.getState().notices, [], "no 'removed elsewhere' notice");
    assert.match(tab.useCustodyStatus.getState().storageError ?? "", /did not save/);

    fault = "none";
    assert.deepEqual(stored().identity, deskBlob, "nothing was written while storage was blocked");
    assert.equal(tab.useKeysStore.getState().retrySave(), true);
    assert.deepEqual(stored().identity, tab.useKeysStore.getState().identity, "…and now it is");
  });

  it("removing an identity that stays on disk is reported", async () => {
    store({ identity: deskBlob });
    const tab = await openTab();
    fault = "drop";
    assert.throws(() => tab.useKeysStore.getState().clearIdentity(), tab.KeystoreNotSavedError);
    fault = "none";
    assert.deepEqual(stored().identity, deskBlob);
    assert.match(tab.useCustodyStatus.getState().storageError ?? "", /did not save/);
  });
});

describe("two tabs on one keystore", () => {
  it("when another tab re-seals the keystore, this tab locks, reloads the stored blob, and says why", async () => {
    store({ identity: deskBlob });
    const a = await openTab();
    const b = await openTab();
    await a.useKeysStore.getState().unlock(PASS);
    await b.useKeysStore.getState().unlock(PASS);
    const staleSession = b.useKeysStore.getState().unlocked!;

    // Tab A opens a forward-secret envelope: a one-time prekey is consumed and the
    // keystore re-sealed and stored.
    const spent = deskPrekeys[0]!.prekey_id;
    a.useKeysStore.getState().persistKeystore(a.useKeysStore.getState().unlocked!.consumePrekey(spent).keystore);
    assert.ok(b.useKeysStore.getState().isUnlocked(), "B has not heard yet");

    b.storageEvent(KEYS_STORAGE_KEY); // the browser tells tab B
    const sb = b.useKeysStore.getState();
    assert.ok(!sb.isUnlocked(), "B is locked");
    assert.throws(() => staleSession.staticSecretKey(), /locked/, "its out-of-date session is wiped");
    assert.deepEqual(sb.identity, a.useKeysStore.getState().identity, "B holds the blob A stored");
    const notices = b.useCustodyStatus.getState().notices;
    assert.equal(notices.length, 1);
    assert.equal(notices[0]!.kind, "keystore-changed-elsewhere");
    assert.match(notices[0]!.message, /locked because another tab or window changed this desk's keystore/);
    b.useCustodyStatus.getState().dismissNotice(notices[0]!.id);
    assert.equal(b.useCustodyStatus.getState().notices.length, 0);

    // Unlocking again gives B the CURRENT vault: the spent prekey is not there.
    await b.useKeysStore.getState().unlock(PASS);
    assert.equal(b.useKeysStore.getState().unlocked!.peekPrekey(spent), undefined);
    // Tab A was the writer: it is not disturbed.
    assert.ok(a.useKeysStore.getState().isUnlocked());
    assert.equal(a.useCustodyStatus.getState().notices.length, 0);
  });

  it("a tab that has NOT heard yet still cannot write its out-of-date keystore over the other's", async () => {
    store({ identity: deskBlob });
    const a = await openTab();
    const b = await openTab();
    await a.useKeysStore.getState().unlock(PASS);
    await b.useKeysStore.getState().unlock(PASS);
    const [p1, p2, p3] = deskPrekeys.map((p) => p.prekey_id) as [string, string, string];

    // A consumes P1 and mints one more prekey; both are stored.
    a.useKeysStore.getState().persistKeystore(a.useKeysStore.getState().unlocked!.consumePrekey(p1).keystore);
    const minted = a.useKeysStore.getState().addPrekeys(1)[0]!.prekey_id;
    const afterA = stored().identity!;

    // B — no storage event delivered — consumes P2 from ITS copy of the vault, which
    // still holds P1 and has never heard of the new prekey. Writing that blob would
    // resurrect P1 and drop the minted one.
    const staleBlob = b.useKeysStore.getState().unlocked!.consumePrekey(p2).keystore;
    assert.deepEqual((await prekeysHeld(staleBlob)).sort(), [p1, p3].sort(), "the stale blob would bring P1 back");
    assert.throws(() => b.useKeysStore.getState().persistKeystore(staleBlob), b.KeystoreChangedElsewhereError);

    assert.deepEqual(stored().identity, afterA, "what A stored is intact");
    assert.deepEqual((await prekeysHeld(afterA)).sort(), [p2, p3].sort(), "P1 stays consumed");
    const reloaded = await unlock(stored().identity!, PASS);
    assert.ok(reloaded.peekPrekey(minted) !== undefined, "the prekey A minted is still there");
    assert.ok(!b.useKeysStore.getState().isUnlocked(), "B locked itself and adopted the stored blob");
    assert.deepEqual(b.useKeysStore.getState().identity, afterA);
    assert.equal(b.useCustodyStatus.getState().notices.at(-1)!.kind, "keystore-changed-elsewhere");

    // Minting from the stale tab is refused the same way (it would drop nothing now —
    // B has adopted the stored blob — but it must be unlocked again first).
    assert.throws(() => b.useKeysStore.getState().addPrekeys(1), /Unlock/);
  });

  it("an out-of-date tab's unrelated writes do not put old data back either", async () => {
    store({ identity: deskBlob });
    const a = await openTab();
    const b = await openTab();
    await a.useKeysStore.getState().unlock(PASS);
    await b.useKeysStore.getState().unlock(PASS);
    a.useKeysStore.getState().persistKeystore(
      a.useKeysStore.getState().unlocked!.consumePrekey(deskPrekeys[0]!.prekey_id).keystore,
    );
    const afterA = disk.get(KEYS_STORAGE_KEY);
    // Every `set` re-writes the whole stored item. B locking itself must not re-write
    // B's old copy of the keystore over A's.
    b.useKeysStore.getState().lock();
    b.useKeysStore.getState().setHydrated(true);
    assert.equal(disk.get(KEYS_STORAGE_KEY), afterA);
  });

  it("unlocking in a tab that has not heard yet unlocks the STORED keystore, not the tab's old copy", async () => {
    store({ identity: deskBlob });
    const a = await openTab();
    const b = await openTab();
    await a.useKeysStore.getState().unlock(PASS);
    const spent = deskPrekeys[1]!.prekey_id;
    a.useKeysStore.getState().persistKeystore(a.useKeysStore.getState().unlocked!.consumePrekey(spent).keystore);
    await b.useKeysStore.getState().unlock(PASS); // B was locked; no event delivered
    assert.equal(b.useKeysStore.getState().unlocked!.peekPrekey(spent), undefined);
    assert.deepEqual(b.useKeysStore.getState().identity, stored().identity);
    assert.equal(b.useCustodyStatus.getState().notices.length, 0, "a locked tab adopting a newer blob is not news");
  });

  it("follows the trust anchor and the rollback mark across tabs, and reports a root change", async () => {
    const a = await openTab();
    const b = await openTab();
    a.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV2 }, { at: AT, confirmedRoot: rootDigest(root1)! });
    // B has not heard. It must not accept the older directory on the strength of its
    // own (empty) memory: it looks at storage first.
    assert.throws(
      () => b.useKeysStore.getState().setTrust({ rootPublicKeyHex: root1, directory: dirV1 }, { at: AT, confirmedRoot: rootDigest(root1)! }),
      b.TrustRollbackError,
    );
    assert.equal(b.useKeysStore.getState().trust!.directory.issued_at, V2, "B adopted what A loaded");
    assert.match(b.useCustodyStatus.getState().notices.at(-1)!.message, /trust anchor was changed in another tab/);
    assert.match(b.useCustodyStatus.getState().notices.at(-1)!.message, new RegExp(rootFingerprint(root1)));

    // Events for other keys are ignored; a whole-storage clear is not.
    store({});
    b.storageEvent("some-other-key");
    assert.ok(b.useKeysStore.getState().trust, "unrelated key: nothing happens");
    b.storageEvent(null);
    assert.equal(b.useKeysStore.getState().trust, undefined, "storage cleared elsewhere: adopted");
  });

  it("a keystore removed in another tab is removed here too, with a notice", async () => {
    store({ identity: deskBlob });
    const a = await openTab();
    const b = await openTab();
    await b.useKeysStore.getState().unlock(PASS);
    const session = b.useKeysStore.getState().unlocked!;
    a.useKeysStore.getState().clearIdentity();
    b.storageEvent(KEYS_STORAGE_KEY);
    assert.equal(b.useKeysStore.getState().identity, undefined);
    assert.ok(!b.useKeysStore.getState().isUnlocked());
    assert.throws(() => session.staticSecretKey(), /locked/);
    assert.equal(b.useCustodyStatus.getState().notices.at(-1)!.kind, "keystore-removed-elsewhere");
  });
});

describe("the desk remembers which one-time prekeys it has sealed to", () => {
  it("records each use, persists it, and refuses to record one twice", async () => {
    const tab = await openTab();
    const s = () => tab.useKeysStore.getState();
    s().setTrust(
      { rootPublicKeyHex: root1, directory: deskDir, bundles: { org_recipient: deskBundle } },
      { at: AT, confirmedRoot: rootDigest(root1)! },
    );
    const bundle = s().trust!.bundles.org_recipient!;
    const [p1, p2] = deskPrekeys.map((p) => p.prekey_id) as [string, string];
    assert.deepEqual(usedPrekeyIds(s().prekeyLedger, bundle), []);
    s().recordPrekeyUse(bundle, p1);
    assert.deepEqual(usedPrekeyIds(s().prekeyLedger, bundle), [p1]);
    assert.deepEqual(stored().prekeyLedger, s().prekeyLedger, "stored");

    // After a reload the desk still knows.
    const reloaded = await openTab();
    assert.deepEqual(usedPrekeyIds(reloaded.useKeysStore.getState().prekeyLedger, bundle), [p1]);
    // A second tab that sealed to the same prekey in the meantime is told so.
    assert.throws(() => reloaded.useKeysStore.getState().recordPrekeyUse(bundle, p1), /used from another tab/);
    // …even if it has not heard of the first tab's use yet.
    s().recordPrekeyUse(bundle, p2);
    assert.throws(() => reloaded.useKeysStore.getState().recordPrekeyUse(bundle, p2), /used from another tab/);

    // A use that cannot be stored is not a use the desk may act on.
    fault = "quota";
    assert.throws(() => s().recordPrekeyUse(bundle, deskPrekeys[2]!.prekey_id), tab.KeystoreNotSavedError);
  });
});

describe("sanitizeTrust / sanitizeTrustMarks (defensive hydration)", () => {
  it("drops a malformed persisted trust anchor and keeps a well-shaped one", () => {
    // Malformed blobs (schema drift / corrupted localStorage) must not load — they
    // would crash the routes that read directory.entries / bundles on render.
    assert.equal(sanitizeTrust(undefined), undefined);
    assert.equal(sanitizeTrust(null), undefined);
    assert.equal(sanitizeTrust("nope"), undefined);
    assert.equal(sanitizeTrust({}), undefined);
    assert.equal(sanitizeTrust({ rootPublicKeyHex: "x" }), undefined, "no directory");
    assert.equal(sanitizeTrust({ rootPublicKeyHex: "x", directory: null }), undefined);
    assert.equal(sanitizeTrust({ rootPublicKeyHex: "x", directory: {} }), undefined, "entries not an array");
    assert.equal(sanitizeTrust({ rootPublicKeyHex: 5, directory: { entries: [] } }), undefined, "root not a string");

    // "Has an entries array" is not a directory: everything that renders or resolves
    // entries relies on the exact shape, so a persisted anchor must have it.
    assert.equal(
      sanitizeTrust({ rootPublicKeyHex: "abcd", directory: { entries: [] }, bundles: {} }),
      undefined,
      "an entries array alone is not a directory",
    );
    const directory = (
      JSON.parse(
        readFileSync(new URL("../../../conformance/signatures/directory.json", import.meta.url), "utf8"),
      ) as { directory: Directory }
    ).directory;
    const withNull = { ...directory, entries: [null, ...directory.entries] };
    assert.equal(sanitizeTrust({ rootPublicKeyHex: "abcd", directory: withNull }), undefined, "entries: [null]");

    const out = sanitizeTrust({ rootPublicKeyHex: "abcd", directory, bundles: {} });
    assert.ok(out && out.rootPublicKeyHex === "abcd" && out.directory.entries.length === 3);
    // A well-shaped anchor missing `bundles` defaults it to an empty map.
    const out2 = sanitizeTrust({ rootPublicKeyHex: "abcd", directory });
    assert.deepEqual(out2?.bundles, {});
    // A root that is not hex-encoded bytes has no fingerprint and verifies nothing.
    assert.equal(sanitizeTrust({ rootPublicKeyHex: "not hex", directory }), undefined);
    // Bundles are held to their shape too: what is not a bundle is dropped, not kept
    // for a route to trip over.
    const bundle = bundleOf([fixedPrekey(9)]);
    const kept = sanitizeTrust({
      rootPublicKeyHex: "abcd",
      directory,
      bundles: { org_recipient: bundle, org_junk: { prekeys: 3 }, org_null: null, org_misfiled: bundle },
    });
    assert.deepEqual(Object.keys(kept!.bundles), ["org_recipient"]);
  });

  it("keeps only root-digest -> datetime marks", () => {
    const d = "ab".repeat(48);
    assert.deepEqual(sanitizeTrustMarks(undefined), {});
    assert.deepEqual(sanitizeTrustMarks([]), {});
    assert.deepEqual(
      sanitizeTrustMarks({
        [d]: V2,
        short: V2,
        ["cd".repeat(48)]: "yesterday",
        ["ef".repeat(48)]: 5,
        ["AB".repeat(48)]: V1,
      }),
      { [d]: V2 },
    );
  });
});
