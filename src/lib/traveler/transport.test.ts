import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  sealTraveler,
  openTraveler,
  openTravelerDeferred,
  parseSjeEnvelope,
  type SjeEnvelope,
} from "./transport.ts";
import { createIdentity, unlock, type Keystore, type Unlocked } from "./keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "./prekeys.ts";
import { fsRecipientFromBundle, sealFsEnvelope, type FsEnvelope } from "./envelope.ts";
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
    assert.throws(() => parseSjeEnvelope('{"spec":"not-an-envelope"}'), /malformed envelope/);
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

  it("persists the consumed prekey to disk: a reload from the written file cannot reuse it", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 1);
    const seal = () =>
      sealTraveler(sampleTraveler(), { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle, prekeyId: prekeyIds[0] });
    const dir = mkdtempSync(join(tmpdir(), "sje-ks-"));
    const ksPath = join(dir, "desk.keystore.json");
    try {
      // Open with a persistKeystore that writes the updated blob to a real file.
      await openTraveler((await seal()).envelope, unlocked, {
        persistKeystore: (ks) => writeFileSync(ksPath, JSON.stringify(ks)),
      });
      // Reload the keystore straight from disk; the consumed prekey must be gone, so a
      // re-sent envelope to it cannot be opened even by this fresh, file-backed unlock.
      const reloaded = await unlock(JSON.parse(readFileSync(ksPath, "utf8")) as Keystore, PASS);
      const resent = (await seal()).envelope;
      await assert.rejects(() => openTraveler(resent, reloaded), /already consumed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a sender that tracks its prekeys never reuses one: N seals use N distinct prekeys, the (N+1)th reports the fallback", async () => {
    const N = 8; // the desk's default bundle size
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, N);
    const common = { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle };

    // What a sender does: remember every prekeyId a seal returns, pass them all back.
    const used: string[] = [];
    const envelopes: SjeEnvelope[] = [];
    for (let i = 0; i < N; i++) {
      const r = await sealTraveler(sampleTraveler(), {
        ...common,
        excludePrekeyIds: used,
        requireForwardSecret: true,
      });
      assert.equal(r.forwardSecret, true, `seal #${i + 1} is forward-secret`);
      assert.equal(r.staticReason, undefined);
      assert.ok(r.prekeyId !== undefined && prekeyIds.includes(r.prekeyId), "reports the prekey it spent");
      assert.equal((r.envelope as FsEnvelope).recipients[0]!.prekey_id, r.prekeyId, "…the one in the envelope");
      assert.ok(!used.includes(r.prekeyId), `seal #${i + 1} must not reuse a prekey`);
      used.push(r.prekeyId);
      envelopes.push(r.envelope);
    }
    assert.equal(new Set(used).size, N, "N seals spent N distinct prekeys");
    assert.deepEqual([...used].sort(), [...prekeyIds].sort(), "…exactly the bundle's");

    // The (N+1)th: every prekey is spent, so there is no usable prekey — exactly the
    // reported static fallback, never a reused prekey reported as forward-secret.
    const next = await sealTraveler(sampleTraveler(), { ...common, excludePrekeyIds: used });
    assert.equal(next.forwardSecret, false);
    assert.equal(next.prekeyId, undefined);
    assert.equal(next.staticReason, "prekeys-exhausted");
    assert.equal(next.envelope.spec, "sje-envelope/0.1.0");
    // …and under requireForwardSecret, a refusal that says why.
    await assert.rejects(
      () => sealTraveler(sampleTraveler(), { ...common, excludePrekeyIds: used, requireForwardSecret: true }),
      /forward secrecy required.*prekeys-exhausted/,
    );

    // Nothing was lost: the recipient opens all N forward-secret envelopes and the
    // static one. (Untracked, the same seals collide and most are unopenable.)
    for (const e of [...envelopes, next.envelope]) {
      assert.deepEqual(await openTraveler(e, unlocked), sampleTraveler());
    }
  });

  it("an explicitly requested prekey that is excluded, or not in the bundle, is not used", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 2);
    const common = { directory, rootPublicKeyHex, recipientOrg: "org_recipient", prekeyBundle: bundle };
    const spent = await sealTraveler(sampleTraveler(), {
      ...common,
      prekeyId: prekeyIds[0],
      excludePrekeyIds: [prekeyIds[0]!],
    });
    assert.equal(spent.forwardSecret, false);
    assert.equal(spent.staticReason, "prekey-unavailable");
    const absent = await sealTraveler(sampleTraveler(), { ...common, prekeyId: "no-such-prekey" });
    assert.equal(absent.forwardSecret, false);
    assert.equal(absent.staticReason, "prekey-unavailable");
    // The other prekey is still usable when asked for by id.
    const ok = await sealTraveler(sampleTraveler(), {
      ...common,
      prekeyId: prekeyIds[1],
      excludePrekeyIds: [prekeyIds[0]!],
    });
    assert.equal(ok.forwardSecret, true);
    assert.equal(ok.prekeyId, prekeyIds[1]);
  });

  it("a static seal always says why it was not forward-secret", async () => {
    const { directory, rootPublicKeyHex, unlocked, signer } = await setup();
    const { bundle, prekeyIds } = signedBundle(unlocked, signer, 1);
    const common = { directory, rootPublicKeyHex, recipientOrg: "org_recipient" };
    const reason = async (o: Partial<Parameters<typeof sealTraveler>[1]>) => {
      const r = await sealTraveler(sampleTraveler(), { ...common, ...o });
      assert.equal(r.forwardSecret, false);
      assert.equal(r.prekeyId, undefined);
      return r.staticReason;
    };
    assert.equal(await reason({}), "no-bundle");
    const badSig: PrekeyBundle = { ...bundle, sig: (bundle.sig![0] === "a" ? "b" : "a") + bundle.sig!.slice(1) };
    assert.equal(await reason({ prekeyBundle: badSig }), "bundle-not-verified");
    // "Exhausted" is only said of a bundle that verifies.
    assert.equal(await reason({ prekeyBundle: badSig, excludePrekeyIds: prekeyIds }), "bundle-not-verified");
    assert.equal(await reason({ prekeyBundle: bundle, excludePrekeyIds: prekeyIds }), "prekeys-exhausted");
    // Expired: outside the bundle's own validity window (the directory's too — so use a
    // bundle that expires earlier than the directory does).
    const shortLived: PrekeyBundle = { ...bundle, valid_until: "2026-06-01T00:00:00.000Z" };
    shortLived.sig = signPrekeyBundle(shortLived, signer.secretKey);
    assert.equal(
      await reason({ prekeyBundle: shortLived, at: new Date("2027-01-01T00:00:00.000Z") }),
      "bundle-not-verified",
    );
    // A value that is not a bundle at all falls back the same way — never a TypeError
    // out of reading its `prekeys`.
    for (const junk of [{}, { prekeys: "all of them" }, { ...bundle, prekeys: null }, { ...bundle, prekeys: [null] }]) {
      assert.equal(await reason({ prekeyBundle: junk as unknown as PrekeyBundle }), "bundle-not-verified");
    }
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

describe("two-phase open: decrypting is not accepting", () => {
  const fsSeal = async (ctx: Awaited<ReturnType<typeof setup>>, bundle: PrekeyBundle, prekeyId: string) =>
    (
      await sealTraveler(sampleTraveler(), {
        directory: ctx.directory,
        rootPublicKeyHex: ctx.rootPublicKeyHex,
        recipientOrg: "org_recipient",
        prekeyBundle: bundle,
        prekeyId,
      })
    ).envelope;

  it("does not spend the one-time prekey until commit(), and persists exactly then", async () => {
    const ctx = await setup();
    const { bundle, prekeyIds } = signedBundle(ctx.unlocked, ctx.signer, 2);
    const envelope = await fsSeal(ctx, bundle, prekeyIds[0]!);
    const persisted: Keystore[] = [];
    const opts = { persistKeystore: (ks: Keystore) => void persisted.push(ks) };

    const first = await openTravelerDeferred(envelope, ctx.unlocked, opts);
    assert.equal(first.forwardSecret, true);
    assert.deepEqual(first.traveler, sampleTraveler());
    assert.equal(persisted.length, 0, "nothing is persisted by decrypting");
    assert.ok(ctx.unlocked.peekPrekey(prekeyIds[0]!), "the prekey is still held");

    // The import was refused, or the tab closed: the same envelope opens again.
    const again = await openTravelerDeferred(envelope, ctx.unlocked, opts);
    assert.deepEqual(again.traveler, sampleTraveler());

    await again.commit();
    assert.equal(persisted.length, 1, "the deletion is persisted at commit");
    assert.equal(ctx.unlocked.peekPrekey(prekeyIds[0]!), undefined);
    await again.commit(); // idempotent
    await first.commit(); // the other handle finds it already spent: a no-op, not an error
    assert.equal(persisted.length, 1);
    await assert.rejects(openTravelerDeferred(envelope, ctx.unlocked, opts), /already consumed/);
    assert.ok(ctx.unlocked.peekPrekey(prekeyIds[1]!), "other prekeys are untouched");
  });

  it("a validly encrypted envelope carrying junk does not burn the prekey", async () => {
    // Anyone holding the public bundle can encrypt to a prekey. If decrypting spent it,
    // a junk payload under a valid tag would destroy the genuine sender's envelope.
    const ctx = await setup();
    const { bundle, prekeyIds } = signedBundle(ctx.unlocked, ctx.signer, 1);
    const recipient = fsRecipientFromBundle(
      ctx.directory,
      bundle,
      "org_recipient",
      prekeyIds[0]!,
      ctx.rootPublicKeyHex,
    )!;
    const junk = sealFsEnvelope(new TextEncoder().encode("not an archive"), [recipient]);
    await assert.rejects(openTravelerDeferred(junk, ctx.unlocked), /Not a valid zip archive/);
    await assert.rejects(openTraveler(junk, ctx.unlocked), /Not a valid zip archive/);
    assert.ok(ctx.unlocked.peekPrekey(prekeyIds[0]!), "still held after the junk envelope");
    // …so the genuine envelope sealed to the same prekey still opens.
    const genuine = await fsSeal(ctx, bundle, prekeyIds[0]!);
    assert.deepEqual(await openTraveler(genuine, ctx.unlocked), sampleTraveler());
  });

  it("a failed persist fails the commit — the caller must not report the prekey deleted", async () => {
    const ctx = await setup();
    const { bundle, prekeyIds } = signedBundle(ctx.unlocked, ctx.signer, 1);
    const envelope = await fsSeal(ctx, bundle, prekeyIds[0]!);
    const opened = await openTravelerDeferred(envelope, ctx.unlocked, {
      persistKeystore: () => {
        throw new Error("storage is full");
      },
    });
    await assert.rejects(opened.commit(), /storage is full/);
  });

  it("stores the deletion before forgetting the prekey: a failed store changes nothing, and can be retried", async () => {
    // It used to delete in memory first. After a failed write the session had lost a
    // prekey the stored blob still had, and a second commit() returned at once having
    // done nothing: the deletion was never stored, and nothing said so again.
    const ctx = await setup();
    const { bundle, prekeyIds } = signedBundle(ctx.unlocked, ctx.signer, 2);
    const envelope = await fsSeal(ctx, bundle, prekeyIds[0]!);
    let fail = true;
    const stored: Keystore[] = [];
    const opened = await openTravelerDeferred(envelope, ctx.unlocked, {
      persistKeystore: (ks) => {
        if (fail) throw new Error("storage is full");
        stored.push(ks);
      },
    });

    await assert.rejects(opened.commit(), /storage is full/);
    assert.ok(ctx.unlocked.peekPrekey(prekeyIds[0]!), "the session still holds the prekey");
    // …so the same envelope still opens in this session, as it would after a reload.
    assert.deepEqual((await openTravelerDeferred(envelope, ctx.unlocked)).traveler, sampleTraveler());

    fail = false;
    await opened.commit(); // the retry does the work the first call could not
    assert.equal(stored.length, 1);
    assert.equal(ctx.unlocked.peekPrekey(prekeyIds[0]!), undefined, "forgotten once stored");
    // What was stored is the keystore without that prekey, and with the other one.
    const reopened = await unlock(stored[0]!, PASS);
    assert.equal(reopened.peekPrekey(prekeyIds[0]!), undefined);
    assert.ok(reopened.peekPrekey(prekeyIds[1]!));
  });

  it("two commits at once store the deletion once", async () => {
    const ctx = await setup();
    const { bundle, prekeyIds } = signedBundle(ctx.unlocked, ctx.signer, 1);
    const envelope = await fsSeal(ctx, bundle, prekeyIds[0]!);
    let writes = 0;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    const opened = await openTravelerDeferred(envelope, ctx.unlocked, {
      persistKeystore: async () => {
        writes++;
        await held;
      },
    });
    const both = Promise.all([opened.commit(), opened.commit()]);
    release();
    await both;
    await opened.commit();
    assert.equal(writes, 1);
    assert.equal(ctx.unlocked.peekPrekey(prekeyIds[0]!), undefined);
  });

  it("a static envelope has nothing to spend", async () => {
    const ctx = await setup();
    const { envelope } = await sealTraveler(sampleTraveler(), {
      directory: ctx.directory,
      rootPublicKeyHex: ctx.rootPublicKeyHex,
      recipientOrg: "org_recipient",
    });
    const opened = await openTravelerDeferred(envelope, ctx.unlocked);
    assert.equal(opened.forwardSecret, false);
    await opened.commit();
    assert.deepEqual((await openTravelerDeferred(envelope, ctx.unlocked)).traveler, sampleTraveler());
  });
});

