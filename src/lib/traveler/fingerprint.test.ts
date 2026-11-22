import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  NO_FINGERPRINT,
  formatFingerprint,
  rootDigest,
  rootFingerprint,
  sameRoot,
} from "./fingerprint.ts";
import { keypairFromSeed } from "./signature.ts";
import { bytesToHex } from "./bytes.ts";

describe("trust-root fingerprint", () => {
  it("is SHA-384 of the key bytes: first 32 hex characters, grouped in fours (fixed vector)", () => {
    // The NIST SHA-384 test vector for the three bytes "abc" (hex 616263):
    //   cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed
    //   8086072ba1e7cc23 58baeca134c825a7
    // so anyone can re-derive the expected value with `printf abc | sha384sum`.
    assert.equal(
      rootDigest("616263"),
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    );
    assert.equal(rootFingerprint("616263"), "cb00 753f 45a3 5e8b b5a0 3d69 9ac6 5007");
  });

  it("has a fixed value for a real ML-DSA-87 root key (2,592 bytes)", () => {
    const rootHex = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(3)).publicKey);
    assert.equal(rootHex.length, 5184);
    const fp = rootFingerprint(rootHex);
    assert.match(fp, /^[0-9a-f]{4}( [0-9a-f]{4}){7}$/);
    // Checked against coreutils: `sha384sum` over the 2,592 raw key bytes begins
    // 0aa096d58b4fb69f7b61d42ebb3f8844….
    assert.equal(fp, "0aa0 96d5 8b4f b69f 7b61 d42e bb3f 8844");
    assert.equal(fp, formatFingerprint(rootDigest(rootHex)!));
  });

  it("identifies the key, not its spelling: re-cased hex is the same root", () => {
    const rootHex = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(3)).publicKey);
    assert.equal(rootFingerprint(rootHex.toUpperCase()), rootFingerprint(rootHex));
    assert.ok(sameRoot(rootHex, rootHex.toUpperCase()));
    const other = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(4)).publicKey);
    assert.ok(!sameRoot(rootHex, other));
    assert.notEqual(rootFingerprint(rootHex), rootFingerprint(other));
  });

  it("never throws: a value that is not a key has no fingerprint", () => {
    for (const bad of ["", "abc", "zz", "0x00", " 00", 5, null, undefined, {}, ["00"]]) {
      assert.equal(rootDigest(bad), null, `rootDigest(${JSON.stringify(bad)})`);
      assert.equal(rootFingerprint(bad), NO_FINGERPRINT);
      assert.ok(!sameRoot(bad, bad), "two non-keys are never 'the same root'");
    }
  });
});
