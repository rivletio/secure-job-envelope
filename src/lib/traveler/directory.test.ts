import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  verifyDirectory,
  encryptionEntryByOrg,
  entryByKid,
  orgHasCapability,
  signDirectory,
  DIRECTORY_SPEC,
  type Directory,
  type DirectoryEntry,
} from "./directory.ts";
import { keypairFromSeed } from "./signature.ts";
import { bytesToHex } from "./bytes.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/directory.json", import.meta.url), "utf8"),
) as { root_public_key_hex: string; directory: Directory };

const dir = vec.directory;
const rootPk = vec.root_public_key_hex;
const at = new Date("2027-01-01T00:00:00.000Z");

describe("signed key directory", () => {
  it("verifies against the trust root and rejects tampering", () => {
    assert.equal(verifyDirectory(dir, rootPk), true);
    // flipping an attested capability breaks the root signature
    const tampered: Directory = structuredClone(dir);
    tampered.entries[1]!.capabilities = { itar: true };
    assert.equal(verifyDirectory(tampered, rootPk), false);
    // wrong root key, and a missing signature, both fail
    assert.equal(verifyDirectory(dir, "00".repeat(2592)), false);
    assert.equal(verifyDirectory({ ...structuredClone(dir), sig: undefined }, rootPk), false);
  });

  it("refuses a directory evaluated outside its own validity window (H3)", () => {
    // The vector directory runs 2026-01-01 .. 2030-01-01.
    assert.equal(verifyDirectory(dir, rootPk, new Date("2027-01-01T00:00:00.000Z")), true);
    assert.equal(verifyDirectory(dir, rootPk, new Date("2025-06-01T00:00:00.000Z")), false); // before issued_at
    assert.equal(verifyDirectory(dir, rootPk, new Date("2031-01-01T00:00:00.000Z")), false); // after valid_until
  });

  it("resolves org and kid entries and attested capabilities", () => {
    assert.equal(encryptionEntryByOrg(dir, "org_huron", at)?.kid, "huron-2026");
    assert.equal(entryByKid(dir, "summit-2026", at)?.org_id, "org_summitfab");
    // ITAR is attested by the directory, not self-declared by the seller (caveat 3)
    assert.equal(orgHasCapability(dir, "org_huron", "itar", at), true);
    assert.equal(orgHasCapability(dir, "org_summitfab", "itar", at), false);
    assert.equal(orgHasCapability(dir, "org_unknown", "itar", at), false);
  });

  it("ignores revoked and out-of-window entries", () => {
    const revoked: Directory = structuredClone(dir);
    revoked.entries[0]!.status = "revoked";
    assert.equal(encryptionEntryByOrg(revoked, "org_huron", at), undefined);
    assert.equal(encryptionEntryByOrg(dir, "org_huron", new Date("2025-01-01T00:00:00.000Z")), undefined);
  });
});

describe("directory cross-implementation parity hardening", () => {
  it("rejects a non-strict datetime in the window even with a valid signature (F1)", () => {
    // The window is checked with the strict shared parser (isoDateTimeMs ==
    // Rust rfc3339_millis), NOT a lenient Date.parse. A directory can be validly
    // root-signed over a non-strict timestamp; it must still be refused, or TS
    // and Rust reach opposite verify verdicts.
    const root = keypairFromSeed(new Uint8Array(32).fill(7));
    const rpk = bytesToHex(root.publicKey);
    const signed = (validUntil: string): Directory => {
      const body: Directory = {
        spec: DIRECTORY_SPEC,
        issued_at: "2026-01-01T00:00:00.000Z",
        valid_until: validUntil,
        root_kid: "root-2026",
        entries: [],
      };
      return { ...body, sig: signDirectory(body, root.secretKey) };
    };
    const when = new Date("2027-01-01T00:00:00.000Z");
    assert.equal(verifyDirectory(signed("2030-01-01T00:00:00.000Z"), rpk, when), true);
    assert.equal(verifyDirectory(signed("2030-01-01T00:00:00.000+00:00"), rpk, when), false); // trailing offset
    assert.equal(verifyDirectory(signed("2030-01-01"), rpk, when), false); // date-only
    assert.equal(verifyDirectory(signed("2030-1-1T0:0:0Z"), rpk, when), false); // single-digit fields
  });

  it("attests a capability from ANY in-window entry, order-independently (F2)", () => {
    // An org may have several entries (overlapping key rotation). The capability
    // holds if ANY active, in-window entry carries it — matching Rust's `.any()`
    // (sign.rs org_has_itar). Checking only the first entry made the two
    // implementations reach opposite ITAR decisions on entry ordering.
    const entry = (kid: string, itar: boolean): DirectoryEntry => ({
      org_id: "org_acme",
      kid,
      alg: "ML-DSA-87",
      public_key: "00",
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: itar ? { itar: true } : {},
    });
    const mk = (entries: DirectoryEntry[]): Directory => ({
      spec: DIRECTORY_SPEC,
      issued_at: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      root_kid: "root-2026",
      entries,
    });
    const when = new Date("2027-01-01T00:00:00.000Z");
    assert.equal(orgHasCapability(mk([entry("a", false), entry("b", true)]), "org_acme", "itar", when), true);
    assert.equal(orgHasCapability(mk([entry("b", true), entry("a", false)]), "org_acme", "itar", when), true);
    assert.equal(orgHasCapability(mk([entry("a", false), entry("c", false)]), "org_acme", "itar", when), false);
    // a revoked or out-of-window itar entry does not count
    const revoked = mk([{ ...entry("b", true), status: "revoked" }]);
    assert.equal(orgHasCapability(revoked, "org_acme", "itar", when), false);
  });
});

describe("trust-root governance — vendor neutrality (GOVERNANCE.md)", () => {
  // The verifier is handed the root public key as a parameter (verifyDirectory's
  // rootPublicKeyHex). No root is baked into the format or the code, so the trust
  // model is root-agnostic: anyone can operate a directory, a verifier trusts
  // whichever root(s) it was configured with out-of-band, and independent roots
  // coexist (federation). This test pins that property so no later change can
  // silently privilege one root.
  const when = new Date("2027-01-01T00:00:00.000Z");
  const dirFor = (root: ReturnType<typeof keypairFromSeed>, orgKeyHex: string): Directory => {
    const body: Directory = {
      spec: DIRECTORY_SPEC,
      issued_at: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      root_kid: "root",
      entries: [
        {
          org_id: "org_acme",
          kid: "acme-2026",
          alg: "ML-DSA-87",
          public_key: orgKeyHex,
          valid_from: "2026-01-01T00:00:00.000Z",
          valid_until: "2030-01-01T00:00:00.000Z",
          status: "active",
        },
      ],
    };
    return { ...body, sig: signDirectory(body, root.secretKey) };
  };

  it("lets two independent roots each operate a directory, trusted only under their own key", () => {
    const rootA = keypairFromSeed(new Uint8Array(32).fill(0xa1));
    const rootB = keypairFromSeed(new Uint8Array(32).fill(0xb2));
    const pkA = bytesToHex(rootA.publicKey);
    const pkB = bytesToHex(rootB.publicKey);
    assert.notEqual(pkA, pkB);

    // Each root publishes its own directory (here, even binding the same org to a
    // different key — the two roots are independent naming authorities).
    const dirA = dirFor(rootA, "aa".repeat(2592));
    const dirB = dirFor(rootB, "bb".repeat(2592));

    // Each directory verifies under its own root…
    assert.equal(verifyDirectory(dirA, pkA, when), true);
    assert.equal(verifyDirectory(dirB, pkB, when), true);
    // …and NOT under the other root. No root is globally privileged; trust is
    // exactly the configured root key, nothing more.
    assert.equal(verifyDirectory(dirA, pkB, when), false);
    assert.equal(verifyDirectory(dirB, pkA, when), false);
  });

  it("makes the configured root the sole arbiter — swapping it changes which directory is authoritative", () => {
    const incumbent = keypairFromSeed(new Uint8Array(32).fill(0xc3));
    const challenger = keypairFromSeed(new Uint8Array(32).fill(0xd4));
    const dir = dirFor(incumbent, "cc".repeat(2592));
    // A verifier that trusts the incumbent accepts it; one that trusts a different
    // root rejects the very same bytes. There is no appeal to a built-in authority.
    assert.equal(verifyDirectory(dir, bytesToHex(incumbent.publicKey), when), true);
    assert.equal(verifyDirectory(dir, bytesToHex(challenger.publicKey), when), false);
  });
});
