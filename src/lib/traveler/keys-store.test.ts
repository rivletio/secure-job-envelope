import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { readFileSync } from "node:fs";
import { useKeysStore, sanitizeTrust } from "./keys-store.ts";
import { sealTraveler, openTraveler } from "./transport.ts";
import { keypairFromSeed } from "./signature.ts";
import { kemKeypairFromSeed } from "./envelope.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "./prekeys.ts";
import { parseTraveler } from "./conformance.ts";
import { bytesToHex } from "./bytes.ts";
import type { Traveler } from "./types.ts";

const PASS = "correct horse battery staple";
const AT = new Date("2027-01-01T00:00:00.000Z");
const confRoot = new URL("../../../conformance/", import.meta.url).pathname;

function sampleTraveler(): Traveler {
  return parseTraveler(JSON.parse(readFileSync(`${confRoot}travelers/l0-bracket.json`, "utf8")));
}

/** A signed directory + a bundle signed by the org's key, both verifying at AT. */
function trustFixture() {
  const root = keypairFromSeed(new Uint8Array(32).fill(3));
  const signer = keypairFromSeed(new Uint8Array(32).fill(4));
  const rootPublicKeyHex = bytesToHex(root.publicKey);
  const prekeyPub = bytesToHex(kemKeypairFromSeed(new Uint8Array(64).fill(9)).publicKey);
  const body: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    root_kid: "root-2026",
    entries: [
      {
        org_id: "org_recipient",
        kid: "recip-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(signer.publicKey),
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_until: "2030-01-01T00:00:00.000Z",
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: bytesToHex(kemKeypairFromSeed(new Uint8Array(64).fill(1)).publicKey),
      },
    ],
  };
  const directory: Directory = { ...body, sig: signDirectory(body, root.secretKey) };
  const bundleBody: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: "org_recipient",
    kid: "recip-2026",
    enc_alg: "ML-KEM-1024",
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    prekeys: [{ prekey_id: "pk1", public_key: prekeyPub }],
  };
  bundleBody.sig = signPrekeyBundle(bundleBody, signer.secretKey);
  return { rootPublicKeyHex, directory, bundle: bundleBody };
}

describe("keys store (desk custody)", () => {
  beforeEach(() => {
    const s = useKeysStore.getState();
    s.clearIdentity();
    s.clearTrust();
  });

  it("creates an identity encrypted at rest, unlocked, and returns the public entry", async () => {
    const entry = await useKeysStore.getState().createIdentity(PASS, "org_me");
    const s = useKeysStore.getState();
    assert.ok(s.identity, "identity stored");
    assert.equal(s.identity!.spec, "sje-keystore/0.1.0");
    assert.equal(entry.kid, s.identity!.kid);
    assert.equal(s.identity!.org_id, "org_me");
    assert.ok(s.isUnlocked(), "left unlocked after create");
    // The secret seed is encrypted into ct, never a clear field.
    assert.ok(!JSON.stringify(s.identity).includes("static_seed"));
  });

  it("locks (clearing the in-memory secret) while keeping the encrypted blob", async () => {
    await useKeysStore.getState().createIdentity(PASS);
    useKeysStore.getState().lock();
    const s = useKeysStore.getState();
    assert.ok(!s.isUnlocked(), "locked");
    assert.ok(s.identity, "encrypted blob remains after lock");
  });

  it("rejects a wrong passphrase with the uniform error and unlocks with the right one", async () => {
    await useKeysStore.getState().createIdentity(PASS);
    useKeysStore.getState().lock();
    await assert.rejects(() => useKeysStore.getState().unlock("a different passphrase"), /unlock failed/);
    assert.ok(!useKeysStore.getState().isUnlocked());
    await useKeysStore.getState().unlock(PASS);
    assert.ok(useKeysStore.getState().isUnlocked());
  });

  it("mints prekeys only when unlocked and persists them into the blob", async () => {
    await useKeysStore.getState().createIdentity(PASS);
    const before = useKeysStore.getState().identity!.ct;
    const pks = useKeysStore.getState().addPrekeys(3);
    assert.equal(pks.length, 3);
    assert.notEqual(useKeysStore.getState().identity!.ct, before, "blob re-sealed with prekeys");
    useKeysStore.getState().lock();
    assert.throws(() => useKeysStore.getState().addPrekeys(1), /Unlock/);
  });

  it("loads a trust anchor only if the directory verifies, dropping unverifiable bundles", () => {
    const { rootPublicKeyHex, directory, bundle } = trustFixture();
    // Wrong root → refuse.
    assert.throws(
      () => useKeysStore.getState().setTrust({ rootPublicKeyHex: "00".repeat(2592), directory, bundles: {} }, AT),
      /does not verify/,
    );
    assert.equal(useKeysStore.getState().trust, undefined);

    // Correct root → accept, keeping the verifying bundle.
    useKeysStore.getState().setTrust({ rootPublicKeyHex, directory, bundles: { org_recipient: bundle } }, AT);
    const t1 = useKeysStore.getState().trust!;
    assert.ok(t1, "trust loaded");
    assert.equal(t1.rootPublicKeyHex, rootPublicKeyHex);
    assert.ok(t1.bundles.org_recipient, "verifying bundle kept");

    // A tampered bundle signature is filtered out (fail closed).
    const badBundle: PrekeyBundle = { ...bundle, sig: (bundle.sig![0] === "a" ? "b" : "a") + bundle.sig!.slice(1) };
    useKeysStore.getState().setTrust({ rootPublicKeyHex, directory, bundles: { org_recipient: badBundle } }, AT);
    assert.ok(!useKeysStore.getState().trust!.bundles.org_recipient, "unverifiable bundle dropped");
  });

  it("a desk identity opens an envelope sealed to its published key (end-to-end)", async () => {
    const entry = await useKeysStore.getState().createIdentity(PASS, "org_recipient");
    const root = keypairFromSeed(new Uint8Array(32).fill(5));
    const signer = keypairFromSeed(new Uint8Array(32).fill(6));
    const body: Directory = {
      spec: DIRECTORY_SPEC,
      issued_at: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      root_kid: "root-2026",
      entries: [
        {
          org_id: "org_recipient",
          kid: "recip-2026",
          alg: "ML-DSA-87",
          public_key: bytesToHex(signer.publicKey),
          valid_from: "2026-01-01T00:00:00.000Z",
          valid_until: "2030-01-01T00:00:00.000Z",
          status: "active",
          enc_alg: "ML-KEM-1024",
          enc_public_key: entry.enc_public_key, // the desk's published key
        },
      ],
    };
    const directory: Directory = { ...body, sig: signDirectory(body, root.secretKey) };
    const traveler = sampleTraveler();
    const { envelope } = await sealTraveler(traveler, {
      directory,
      rootPublicKeyHex: bytesToHex(root.publicKey),
      recipientOrg: "org_recipient",
      at: AT,
    });
    const opened = await openTraveler(envelope, useKeysStore.getState().unlocked!);
    assert.deepEqual(opened, traveler);
  });
});

describe("sanitizeTrust (defensive hydration)", () => {
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

    const out = sanitizeTrust({ rootPublicKeyHex: "abcd", directory: { entries: [] }, bundles: {} });
    assert.ok(out && out.rootPublicKeyHex === "abcd" && Array.isArray(out.directory.entries));
    // A well-shaped anchor missing `bundles` defaults it to an empty map.
    const out2 = sanitizeTrust({ rootPublicKeyHex: "abcd", directory: { entries: [] } });
    assert.deepEqual(out2?.bundles, {});
  });
});
