import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { sealTraveler, openTraveler, parseSjeEnvelope } from "./transport.ts";
import { createIdentity, unlock, type Keystore, type Unlocked } from "./keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "./prekeys.ts";
import type { FsEnvelope } from "./envelope.ts";
import { keypairFromSeed, type Keypair } from "./signature.ts";
import { bytesToHex } from "./bytes.ts";
import { parseTraveler } from "./conformance.ts";
import { importTravelerFile } from "./zip.ts";
import type { Traveler } from "./types.ts";

const PASS = "correct horse battery staple";
const root = new URL("../../../conformance/", import.meta.url).pathname;

function sampleTraveler(): Traveler {
  return parseTraveler(JSON.parse(readFileSync(`${root}travelers/l0-bracket.json`, "utf8")));
}

/** A signed directory whose org_recipient entry carries the keystore's ML-KEM key. */
async function setup() {
  const trustRoot = keypairFromSeed(new Uint8Array(32).fill(7));
  const rootPublicKeyHex = bytesToHex(trustRoot.publicKey);
  const signer = keypairFromSeed(new Uint8Array(32).fill(8)); // the org's (placeholder) signing key
  const { keystore, directoryEntry } = await createIdentity({ passphrase: PASS, orgId: "org_recipient" });
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
        enc_public_key: directoryEntry.enc_public_key,
      },
    ],
  };
  const directory: Directory = { ...body, sig: signDirectory(body, trustRoot.secretKey) };
  return { directory, rootPublicKeyHex, keystore, signer, unlocked: await unlock(keystore, PASS) };
}

/** Mint `n` one-time prekeys into `unlocked` (mutating its in-memory vault) and
 *  return a prekey bundle signed by the org's directory key. */
function signedBundle(unlocked: Unlocked, signer: Keypair, n: number) {
  const { prekeys } = unlocked.addPrekeys(n);
  const body: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: "org_recipient",
    kid: "recip-2026", // resolves in the directory to org_recipient
    enc_alg: "ML-KEM-1024",
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    prekeys,
  };
  body.sig = signPrekeyBundle(body, signer.secretKey);
  return { bundle: body, prekeyIds: prekeys.map((p) => p.prekey_id) };
}

describe("encrypted transport (static path)", () => {
  it("seals a traveler to a directory recipient and opens it back", async () => {
    const { directory, rootPublicKeyHex, unlocked } = await setup();
    const traveler = sampleTraveler();
    const { envelope, forwardSecret } = await sealTraveler(traveler, {
      directory,
      rootPublicKeyHex,
      recipientOrg: "org_recipient",
    });
    assert.equal(forwardSecret, false);
    assert.equal(envelope.spec, "sje-envelope/0.1.0");
    const opened = await openTraveler(envelope, unlocked);
    assert.deepEqual(opened, traveler);
  });

  it("the sealed artifact is ciphertext — not a zip, no plaintext field values", async () => {
    const { directory, rootPublicKeyHex } = await setup();
    const traveler = sampleTraveler();
    const { envelope } = await sealTraveler(traveler, { directory, rootPublicKeyHex, recipientOrg: "org_recipient" });
    const wire = JSON.stringify(envelope);
    // No plaintext markers from the traveler leak into the envelope.
    assert.ok(!wire.includes(traveler.traveler_id), "traveler_id must not appear in the clear");
    assert.ok(!wire.includes(traveler.buyer.name), "buyer name must not appear in the clear");
    assert.ok(!wire.includes(traveler.part.part_number), "part number must not appear in the clear");
    // The payload hex decodes to bytes that are NOT a parseable traveler zip.
    const payloadBytes = Buffer.from(envelope.payload, "hex");
    assert.ok(!payloadBytes.includes(Buffer.from("PK\x03\x04")), "no ZIP local-file-header in the ciphertext");
    await assert.rejects(
      importTravelerFile(new File([payloadBytes], "x.zip", { type: "application/zip" })),
      "ciphertext must not import as a traveler",
    );
  });

  it("refuses a tampered envelope and the wrong keystore", async () => {
    const { directory, rootPublicKeyHex, unlocked } = await setup();
    const { envelope } = await sealTraveler(sampleTraveler(), {
      directory,
      rootPublicKeyHex,
      recipientOrg: "org_recipient",
    });

    const tampered = { ...envelope, payload: (envelope.payload[0] === "a" ? "b" : "a") + envelope.payload.slice(1) };
    await assert.rejects(() => openTraveler(tampered, unlocked));

    // A different identity's keystore cannot open it (not a recipient).
    const other = await createIdentity({ passphrase: PASS, orgId: "org_other" });
    const otherUnlocked = await unlock(other.keystore, PASS);
    await assert.rejects(() => openTraveler(envelope, otherUnlocked), /no recipient entry/);
  });

  it("refuses to seal against a directory that does not verify", async () => {
    const { directory } = await setup();
    await assert.rejects(
      () => sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex: "00".repeat(2592), recipientOrg: "org_recipient" }),
      /does not verify/,
    );
  });

  it("parseSjeEnvelope accepts a round-tripped envelope and rejects junk", async () => {
    const { directory, rootPublicKeyHex } = await setup();
    const { envelope } = await sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient" });
    assert.equal(parseSjeEnvelope(JSON.stringify(envelope)).spec, "sje-envelope/0.1.0");
    assert.throws(() => parseSjeEnvelope('{"spec":"not-an-envelope"}'), /not a recognized/);
  });
});

describe("encrypted transport (forward-secret path)", () => {
  it("seals forward-secret when a verifying prekey bundle is supplied, and opens it", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 2);
    const traveler = sampleTraveler();
    const { envelope, forwardSecret } = await sealTraveler(traveler, {
      directory,
      rootPublicKeyHex,
      recipientOrg: "org_recipient",
      prekeyBundle: bundle,
      prekeyId: prekeyIds[0],
    });
    assert.equal(forwardSecret, true);
    assert.equal(envelope.spec, "sje-envelope/0.2.0");
    assert.deepEqual(await openTraveler(envelope, unlocked), traveler);
  });

  it("consumes the one-time prekey: a second envelope to the same prekey cannot be opened", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 2);
    const seal = (prekeyId: string) =>
      sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle, prekeyId });
    const first = (await seal(prekeyIds[0]!)).envelope;
    const second = (await seal(prekeyIds[0]!)).envelope;
    assert.deepEqual(await openTraveler(first, unlocked), sampleTraveler()); // consumes prekeyIds[0]
    await assert.rejects(() => openTraveler(second, unlocked), /already consumed/);
    // A different, unspent prekey still opens.
    const other = (await seal(prekeyIds[1]!)).envelope;
    assert.deepEqual(await openTraveler(other, unlocked), sampleTraveler());
  });

  it("a tampered FS envelope naming a real prekey fails WITHOUT burning it (verify before consume)", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 1);
    const pid = prekeyIds[0]!;
    const seal = () =>
      sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle, prekeyId: pid });

    const good = (await seal()).envelope as FsEnvelope;
    const tampered: FsEnvelope = { ...good, payload: (good.payload[0] === "a" ? "b" : "a") + good.payload.slice(1) };
    await assert.rejects(() => openTraveler(tampered, unlocked), "a tampered FS envelope must be refused");

    // The prekey must survive the failed open — a fresh, legitimate envelope to the
    // SAME prekey still opens. (Before the fix, the failed open consumed the prekey,
    // so this second open failed with "already consumed" — a remote prekey-burn DoS.)
    assert.deepEqual(await openTraveler((await seal()).envelope, unlocked), sampleTraveler());
  });

  it("persists the consumed prekey so a reload cannot reuse it", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 1);
    const seal = () =>
      sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle, prekeyId: prekeyIds[0] });
    let persisted: Keystore | undefined;
    await openTraveler((await seal()).envelope, unlocked, { persistKeystore: (ks) => { persisted = ks; } });
    assert.ok(persisted, "a new keystore blob is produced to persist");
    // Reload the persisted blob: the consumed prekey is gone, so a re-sent envelope
    // to it cannot be opened even by a fresh unlock (crash/restart safety).
    const reloaded = await unlock(persisted!, PASS);
    const resent = (await seal()).envelope;
    await assert.rejects(() => openTraveler(resent, reloaded), /already consumed/);
  });

  it("requireForwardSecret throws instead of silently downgrading to static", async () => {
    const { directory, rootPublicKeyHex } = await setup();
    await assert.rejects(
      () => sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", requireForwardSecret: true }),
      /forward secrecy required/,
    );
  });

  it("falls back to static (reported) when the bundle does not verify", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle } = signedBundle(unlocked, signer, 1);
    const broken: PrekeyBundle = { ...bundle, sig: (bundle.sig![0] === "a" ? "b" : "a") + bundle.sig!.slice(1) };
    const { forwardSecret, envelope } = await sealTraveler(sampleTraveler(), {
      directory,
      rootPublicKeyHex,
      recipientOrg: "org_recipient",
      prekeyBundle: broken,
    });
    assert.equal(forwardSecret, false);
    assert.equal(envelope.spec, "sje-envelope/0.1.0");
    // With requireForwardSecret it must throw rather than downgrade.
    await assert.rejects(
      () => sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: broken, requireForwardSecret: true }),
      /forward secrecy required/,
    );
  });
});
