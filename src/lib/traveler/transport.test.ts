import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { sealTraveler, openTraveler, parseSjeEnvelope } from "./transport.ts";
import { createIdentity, unlock } from "./keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { keypairFromSeed } from "./signature.ts";
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
  return { directory, rootPublicKeyHex, keystore, unlocked: await unlock(keystore, PASS) };
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
