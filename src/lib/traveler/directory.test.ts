import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  verifyDirectory,
  entryByOrg,
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
    assert.equal(entryByOrg(dir, "org_huron", at)?.kid, "huron-2026");
    assert.equal(entryByKid(dir, "summit-2026", at)?.org_id, "org_summitfab");
    // ITAR is attested by the directory, not self-declared by the seller (caveat 3)
    assert.equal(orgHasCapability(dir, "org_huron", "itar", at), true);
    assert.equal(orgHasCapability(dir, "org_summitfab", "itar", at), false);
    assert.equal(orgHasCapability(dir, "org_unknown", "itar", at), false);
  });

  it("ignores revoked and out-of-window entries", () => {
    const revoked: Directory = structuredClone(dir);
    revoked.entries[0]!.status = "revoked";
    assert.equal(entryByOrg(revoked, "org_huron", at), undefined);
    assert.equal(entryByOrg(dir, "org_huron", new Date("2025-01-01T00:00:00.000Z")), undefined);
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
