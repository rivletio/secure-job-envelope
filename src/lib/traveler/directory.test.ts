import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  verifyDirectory,
  entryByOrg,
  entryByKid,
  orgHasCapability,
  type Directory,
} from "./directory.ts";

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
