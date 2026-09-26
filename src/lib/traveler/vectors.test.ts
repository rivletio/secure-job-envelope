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
import { levelOf, parseTraveler } from "./conformance.ts";
import { sha384 } from "js-sha512";

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
      assert.equal(`sha384:${sha384(c)}`, v.sha384, `hash: ${v.name}`);
    }
  });

  it("refuses every invalid canonicalization vector", () => {
    for (const v of vec.invalid) {
      assert.throws(() => canonicalJson(v.value), `must refuse: ${v.name} (${v.reason})`);
    }
  });

  it("computes the expected hash and level for every traveler vector", () => {
    const expected = JSON.parse(readFileSync(`${root}travelers/expected.json`, "utf8")) as Record<
      string,
      { traveler_hash: string; level: string }
    >;
    for (const [file, exp] of Object.entries(expected)) {
      const traveler = parseTraveler(JSON.parse(readFileSync(`${root}travelers/${file}`, "utf8")));
      assert.equal(travelerHash(traveler), exp.traveler_hash, `hash: ${file}`);
      assert.equal(levelOf(traveler).code, exp.level, `level: ${file}`);
    }
  });

  it("refuses every reject vector at parse time", () => {
    for (const file of readdirSync(`${root}travelers/reject`)) {
      const doc = JSON.parse(readFileSync(`${root}travelers/reject/${file}`, "utf8"));
      assert.throws(() => parseTraveler(doc), `must refuse: ${file}`);
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
