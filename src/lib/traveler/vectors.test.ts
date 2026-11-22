/** Conformance vector runner (TypeScript side).
 *  The same files are independently verified by the Rust implementation
 *  (crates/secure-job-envelope/tests/vectors.rs); agreement across both is the
 *  cross-implementation proof. See conformance/README.md.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { canonicalJson } from "./canonical.ts";
import { travelerHash } from "./hash.ts";
import { levelOf, parseTraveler, parseTravelerJson } from "./conformance.ts";
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "./bytes.ts";

const root = new URL("../../../conformance/", import.meta.url).pathname;

type CanonicalVectors = {
  valid: Array<{ name: string; value: unknown; canonical: string; sha384: string }>;
  invalid: Array<{ name: string; value: unknown; reason: string }>;
};

describe("conformance vectors", () => {
  const vec = JSON.parse(readFileSync(`${root}canonical.json`, "utf8")) as CanonicalVectors;

  it("canonicalizes every valid vector to the exact bytes and hash", () => {
    for (const v of vec.valid) {
      const c = canonicalJson(v.value);
      assert.equal(c, v.canonical, `canonical bytes: ${v.name}`);
      assert.equal(`sha384:${bytesToHex(sha384(utf8ToBytes(c)))}`, v.sha384, `hash: ${v.name}`);
    }
  });

  it("refuses every invalid canonicalization vector", () => {
    for (const v of vec.invalid) {
      assert.throws(() => canonicalJson(v.value), `must refuse: ${v.name} (${v.reason})`);
    }
  });

  it("refuses strings and keys with a lone surrogate (cross-impl safety)", () => {
    // Rust's serde_json cannot parse a lone surrogate, so TS must refuse to hash
    // one too — otherwise the same document hashes on one side and not the other.
    assert.throws(() => canonicalJson({ s: "A\uD800B" }), /lone surrogate/);
    assert.throws(() => canonicalJson({ ["k\uDC00"]: 1 }), /lone surrogate/);
    // a valid surrogate pair (astral character) is fine and hashes on both sides
    assert.doesNotThrow(() => canonicalJson({ s: "ok \u{1F600}" }));
  });

  it("parseTraveler refuses a lone surrogate in any string field (matches serde)", () => {
    // serde rejects the whole document at parse; TS must reject it too, or the two
    // implementations disagree on whether the document is even acceptable.
    const base = JSON.parse(
      readFileSync(`${root}travelers/l0-bracket.json`, "utf8"),
    ) as Record<string, any>;
    assert.doesNotThrow(() => parseTraveler(structuredClone(base)));
    const withSurrogate = structuredClone(base);
    withSurrogate.part.notes = "note\uD800end";
    assert.throws(() => parseTraveler(withSurrogate), /lone surrogate/);
  });

  it("computes the expected hash and level for every traveler vector", () => {
    const expected = JSON.parse(readFileSync(`${root}travelers/expected.json`, "utf8")) as Record<
      string,
      { traveler_hash: string; level: string }
    >;
    for (const [file, exp] of Object.entries(expected)) {
      // Parsed from the file's BYTES through the strict text entry point — the same
      // bytes the Rust runner hands to parse_traveler.
      const traveler = parseTravelerJson(readFileSync(`${root}travelers/${file}`));
      assert.equal(travelerHash(traveler), exp.traveler_hash, `hash: ${file}`);
      assert.equal(levelOf(traveler).code, exp.level, `level: ${file}`);
    }
  });

  it("refuses every reject vector at parse time — for the reason it is named for", () => {
    // A reject vector that is refused for some OTHER reason proves nothing about the
    // rule it is named for (itar-mismatch.json once carried a fractional price, so it
    // kept "passing" with the ITAR check deleted). reject-reasons.json pins, per
    // vector and per implementation, a fragment the refusal must mention; the Rust
    // runner checks its own column of the same file.
    const reasons = JSON.parse(
      readFileSync(`${root}travelers/reject-reasons.json`, "utf8"),
    ) as Record<string, { ts: string; rs: string }>;
    const files = readdirSync(`${root}travelers/reject`);
    assert.deepEqual(
      files.filter((f) => !reasons[f]),
      [],
      "every reject vector must declare why it is refused (reject-reasons.json)",
    );
    assert.deepEqual(
      Object.keys(reasons).filter((f) => !files.includes(f)),
      [],
      "reject-reasons.json names a vector that does not exist",
    );
    for (const file of files) {
      // The vector's BYTES, not a pre-parsed object: a byte-order mark or a repeated
      // member name exists only in the text, and JSON.parse would erase both.
      const bytes = readFileSync(`${root}travelers/reject/${file}`);
      let message: string | undefined;
      try {
        parseTravelerJson(bytes);
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
      assert.notEqual(message, undefined, `must refuse: ${file}`);
      assert.ok(
        message!.includes(reasons[file]!.ts),
        `${file}: refused for the wrong reason — "${message}" does not mention "${reasons[file]!.ts}"`,
      );
    }
  });

  it("keeps the worked example's documented hash and level in sync", () => {
    const example = parseTraveler(
      JSON.parse(readFileSync(`${root}../examples/bracket.traveler.json`, "utf8")),
    );
    const hash = travelerHash(example);
    assert.equal(levelOf(example).code, "L0");
    const readme = readFileSync(`${root}../examples/README.md`, "utf8");
    assert.ok(
      readme.includes(hash),
      `examples/README.md must document the current example hash ${hash}`,
    );
  });
});
