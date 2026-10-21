import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildDemoTrust } from "./demo-trust.ts";
import { verifyDirectory } from "./directory.ts";
import { sealTraveler } from "./transport.ts";
import { seedTravelers } from "./fixtures.ts";

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
