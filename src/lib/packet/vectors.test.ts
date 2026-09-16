/** Conformance vector runner (TypeScript side).
 *  The same files are independently verified by the Rust implementation
 *  (crates/rivlet-packet/tests/vectors.rs); agreement across both is the
 *  cross-implementation proof. See conformance/README.md.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { canonicalJson } from "./canonical.ts";
import { packetHash } from "./hash.ts";
import { levelOf, parsePacket } from "./conformance.ts";
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

  it("computes the expected hash and level for every packet vector", () => {
    const expected = JSON.parse(readFileSync(`${root}packets/expected.json`, "utf8")) as Record<
      string,
      { packet_hash: string; level: string }
    >;
    for (const [file, exp] of Object.entries(expected)) {
      const packet = parsePacket(JSON.parse(readFileSync(`${root}packets/${file}`, "utf8")));
      assert.equal(packetHash(packet), exp.packet_hash, `hash: ${file}`);
      assert.equal(levelOf(packet).code, exp.level, `level: ${file}`);
    }
  });

  it("refuses every reject vector at parse time", () => {
    for (const file of readdirSync(`${root}packets/reject`)) {
      const doc = JSON.parse(readFileSync(`${root}packets/reject/${file}`, "utf8"));
      assert.throws(() => parsePacket(doc), `must refuse: ${file}`);
    }
  });
});
