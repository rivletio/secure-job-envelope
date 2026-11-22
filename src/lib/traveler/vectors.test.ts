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

/** A canonical case gives its input as `value` (a JSON value; how the vector file spells
 *  it is not part of the test) or as `text` (the exact JSON text — its spelling IS the
 *  test: `10.0`, `-0`, `1e2`, an escaped letter). Exactly one of the two. */
type CanonicalCase = { name: string; value?: unknown; text?: string };
type CanonicalVectors = {
  valid: Array<CanonicalCase & { canonical: string; sha384: string }>;
  invalid: Array<CanonicalCase & { reason: string; refusal: { ts: string; rs: string } }>;
};

/** What this implementation does with a canonical case: the canonical bytes, or why it
 *  refuses. A `text` is parsed here, by this implementation's own JSON parser, before it
 *  is canonicalized; "not JSON" means that parser rejected the text. */
function canonicalOutcome(c: CanonicalCase): { canonical: string } | { refusal: string } {
  assert.ok(
    (c.value === undefined) !== (c.text === undefined),
    `${c.name}: a case gives exactly one of value and text`,
  );
  let value: unknown;
  if (c.text !== undefined) {
    try {
      value = JSON.parse(c.text);
    } catch (e) {
      if (!(e instanceof SyntaxError)) throw e;
      return { refusal: "not JSON" };
    }
  } else {
    value = c.value;
  }
  try {
    return { canonical: canonicalJson(value) };
  } catch (e) {
    return { refusal: e instanceof Error ? e.message : String(e) };
  }
}

describe("conformance vectors", () => {
  const canonicalFile = readFileSync(`${root}canonical.json`, "utf8");
  const vec = JSON.parse(canonicalFile) as CanonicalVectors;

  it("canonicalizes every valid vector to the exact bytes and hash", () => {
    for (const v of vec.valid) {
      const outcome = canonicalOutcome(v);
      assert.ok("canonical" in outcome, `${v.name}: refused (${"refusal" in outcome ? outcome.refusal : ""})`);
      assert.equal(outcome.canonical, v.canonical, `canonical bytes: ${v.name}`);
      assert.equal(`sha384:${bytesToHex(sha384(utf8ToBytes(outcome.canonical)))}`, v.sha384, `hash: ${v.name}`);
    }
  });

  it("refuses every invalid canonicalization vector — for the reason it is named for", () => {
    // Refused for some OTHER reason proves nothing about the rule (a text that is simply
    // malformed would "pass"), so each case pins a fragment of the refusal, as the
    // traveler reject vectors do. The Rust runner checks its own column.
    for (const v of vec.invalid) {
      const outcome = canonicalOutcome(v);
      assert.ok("refusal" in outcome, `must refuse: ${v.name} (${v.reason})`);
      assert.ok(
        outcome.refusal.includes(v.refusal.ts),
        `${v.name}: refused for the wrong reason — "${outcome.refusal}" does not mention "${v.refusal.ts}"`,
      );
    }
  });

  it("carries the spellings its cases are named for (a parsed value cannot)", () => {
    // `negative-zero` was once stored as the value -0, which the file spelled 0, and
    // nothing in it ever spelled 10.0: neither runner was shown what the names promised.
    const text = (name: string) => vec.valid.find((v) => v.name === name)?.text;
    assert.equal(text("negative-zero"), '{"t":-0}');
    assert.equal(text("integer-valued-float"), '{"t":10.0}');
    assert.equal(text("exponent"), '{"t":1e2}');
    assert.equal(text("escape-u0041-is-A"), '{"s":"\\u0041"}');
    // ...and the file itself holds them character for character.
    for (const spelled of ['"{\\"t\\":-0}"', '"{\\"t\\":10.0}"', '"{\\"t\\":1e+2}"', '"{\\"s\\":\\"\\\\u0041\\"}"']) {
      assert.ok(canonicalFile.includes(spelled), `canonical.json should contain ${spelled}`);
    }
    assert.ok(vec.valid.filter((v) => v.text !== undefined).length >= 60, "the text cases are present");
    assert.ok(vec.invalid.filter((v) => v.text !== undefined).length >= 30, "the refused text cases are present");
    // The file is ASCII: an invisible character in a vector is an escape a reviewer can see.
    assert.match(canonicalFile, /^[\n -~]*$/);
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
