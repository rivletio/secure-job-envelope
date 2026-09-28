import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { verifyPrekeyBundle, prekeyById, type PrekeyBundle } from "./prekeys.ts";
import type { Directory } from "./directory.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/prekey-bundle.json", import.meta.url), "utf8"),
) as { root_public_key_hex: string; at_ms: number; directory: Directory; bundle: PrekeyBundle };

const when = new Date(vec.at_ms);

describe("signed one-time prekey bundle", () => {
  it("verifies against the directory and returns the vetted bundle", () => {
    const ok = verifyPrekeyBundle(vec.bundle, vec.directory, vec.root_public_key_hex, when);
    assert.ok(ok);
    assert.equal(ok!.org_id, "org_northline");
    assert.ok(prekeyById(ok!, "northline-ot-1"));
    assert.equal(prekeyById(ok!, "no-such-prekey"), undefined);
  });

  it("rejects a tampered prekey, a wrong root, and an out-of-window bundle", () => {
    // tampering a prekey public_key breaks the org's signature over the bundle
    const tampered: PrekeyBundle = structuredClone(vec.bundle);
    tampered.prekeys[0]!.public_key = "00".repeat(tampered.prekeys[0]!.public_key.length / 2);
    assert.equal(verifyPrekeyBundle(tampered, vec.directory, vec.root_public_key_hex, when), undefined);
    // wrong root key
    assert.equal(verifyPrekeyBundle(vec.bundle, vec.directory, "00".repeat(2592), when), undefined);
    // evaluated after the bundle's validity window
    assert.equal(
      verifyPrekeyBundle(
        vec.bundle,
        vec.directory,
        vec.root_public_key_hex,
        new Date("2028-01-01T00:00:00.000Z"),
      ),
      undefined,
    );
  });

  it("rejects a bundle whose claimed org_id does not match its signing kid", () => {
    const spoof: PrekeyBundle = { ...structuredClone(vec.bundle), org_id: "org_summitfab" };
    assert.equal(verifyPrekeyBundle(spoof, vec.directory, vec.root_public_key_hex, when), undefined);
  });
});
