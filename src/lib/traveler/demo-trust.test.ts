import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildDemoTrust,
  isDemoTrustRoot,
  DEMO_ROOT_DIGEST,
  DEMO_TRUST_WARNING,
} from "./demo-trust.ts";
import { verifyDirectory } from "./directory.ts";
import { sealTraveler } from "./transport.ts";
import { seedTravelers } from "./fixtures.ts";
import { keypairFromSeed } from "./signature.ts";
import { encKid, kemKeypairFromSeed, openEnvelope, type Envelope } from "./envelope.ts";
import { signTraveler, verificationReport } from "./authenticity.ts";
import { parseTraveler } from "./conformance.ts";
import { importTravelerFile } from "./zip.ts";
import { rootDigest } from "./fingerprint.ts";
import { bytesToHex } from "./bytes.ts";

describe("demo trust anchor", () => {
  const now = new Date("2026-10-21T00:00:00.000Z");

  it("builds a directory that verifies against its own root, within the window", () => {
    const t = buildDemoTrust();
    assert.equal(verifyDirectory(t.directory, t.rootPublicKeyHex, now), true);
    assert.ok(t.directory.entries.length >= 1);
    for (const e of t.directory.entries) {
      assert.equal(e.enc_alg, "ML-KEM-1024");
      assert.equal(e.status, "active");
      assert.ok(e.enc_public_key && e.enc_public_key.length > 0);
    }
  });

  it("is deterministic (same root + directory every call)", () => {
    assert.equal(buildDemoTrust().rootPublicKeyHex, buildDemoTrust().rootPublicKeyHex);
  });

  it("seals a traveler to a demo recipient as ciphertext with no plaintext leak", async () => {
    const t = buildDemoTrust();
    const traveler = seedTravelers()[0]!;
    const { envelope, forwardSecret } = await sealTraveler(traveler, {
      directory: t.directory,
      rootPublicKeyHex: t.rootPublicKeyHex,
      recipientOrg: "org_summitfab",
    });
    assert.equal(forwardSecret, false); // no bundles -> static envelope
    const wire = JSON.stringify(envelope);
    assert.ok(
      !wire.includes(traveler.part.part_number),
      "part number must not appear in the clear",
    );
    assert.ok(!wire.includes(traveler.buyer.name), "buyer name must not appear in the clear");
  });
});

describe("the demo anchor is recognized by its root key", () => {
  const now = new Date("2026-10-21T00:00:00.000Z");

  it("isDemoTrustRoot is true for the demo root, however its hex is spelled", () => {
    const { rootPublicKeyHex } = buildDemoTrust();
    assert.equal(isDemoTrustRoot(rootPublicKeyHex), true);
    // Upper-case hex is the same key and verifies the same directory, so it must be
    // recognized too — comparing hex TEXT would let a re-cased demo root pass as real.
    const upper = rootPublicKeyHex.toUpperCase();
    assert.equal(verifyDirectory(buildDemoTrust().directory, upper, now), true);
    assert.equal(isDemoTrustRoot(upper), true);
  });

  it("the recognized digest is the digest of the key the public seed derives", () => {
    // If the demo seed ever changes, this fails until DEMO_ROOT_DIGEST follows it.
    const derived = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(1)).publicKey);
    assert.equal(derived, buildDemoTrust().rootPublicKeyHex);
    assert.equal(rootDigest(derived), DEMO_ROOT_DIGEST);
  });

  it("isDemoTrustRoot is false for any other root, and for things that are not keys", () => {
    const other = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(2)).publicKey);
    assert.equal(isDemoTrustRoot(other), false);
    const demo = buildDemoTrust().rootPublicKeyHex;
    const oneNibbleOff = (demo[0] === "a" ? "b" : "a") + demo.slice(1);
    assert.equal(isDemoTrustRoot(oneNibbleOff), false);
    for (const bad of ["", "demo", "root-demo", demo.slice(1), null, undefined, 0, {}]) {
      assert.equal(isDemoTrustRoot(bad), false);
    }
  });

  it("verifyDirectory itself knows nothing about demos (the predicate is the caller's to ask)", () => {
    const t = buildDemoTrust();
    assert.equal(verifyDirectory(t.directory, t.rootPublicKeyHex, now), true);
  });

  it("what the warning says is true: an outsider can forge a verified document and read a sealed one", async () => {
    assert.match(DEMO_TRUST_WARNING, /proves nothing/);
    assert.match(DEMO_TRUST_WARNING, /read by anyone/);
    const anchor = buildDemoTrust();
    const entry = anchor.directory.entries.find((e) => e.org_id === "org_summitfab")!;

    // An outsider re-derives org_summitfab's SIGNING key from the constant in the
    // public source (seed byte 10) — not from any object the desk holds.
    const forgedKey = keypairFromSeed(new Uint8Array(32).fill(10));
    assert.equal(bytesToHex(forgedKey.publicKey), entry.public_key);
    const unsigned = parseTraveler({
      ...seedTravelers()[0]!,
      buyer: { org_id: "org_summitfab", name: "Summit Fabrication" },
      quotes: [],
      award: null,
      signatures: [],
    });
    const forged = parseTraveler({
      ...unsigned,
      signatures: [signTraveler(unsigned, entry.kid, forgedKey.secretKey)],
    });
    const report = verificationReport(forged, anchor.directory, anchor.rootPublicKeyHex, now);
    assert.equal(report.verified, true, "the library reports it verified — under this anchor");
    // …which is exactly why every caller must ask this before showing that verdict:
    assert.equal(isDemoTrustRoot(anchor.rootPublicKeyHex), true);

    // And the outsider re-derives org_summitfab's DECRYPTION key (seed byte 11) and
    // reads an envelope sealed to it.
    const { envelope } = await sealTraveler(unsigned, {
      directory: anchor.directory,
      rootPublicKeyHex: anchor.rootPublicKeyHex,
      recipientOrg: "org_summitfab",
      at: now,
    });
    const stolen = kemKeypairFromSeed(new Uint8Array(64).fill(11));
    const zipBytes = openEnvelope(
      envelope as Envelope,
      encKid(bytesToHex(stolen.publicKey)),
      stolen.secretKey,
    );
    const read = await importTravelerFile(
      new File([new Uint8Array(zipBytes)], "stolen.zip", { type: "application/zip" }),
    );
    assert.deepEqual(read, unsigned);
  });
});
