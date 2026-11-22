/** The committed fuzz corpus (conformance/fuzz), replayed by the TypeScript reference
 *  from each case's BYTES — the other half of crates/…/tests/fuzz_corpus.rs, which
 *  replays the same files through the Rust core. Agreement of both with the one
 *  manifest is agreement between two independent codebases.
 *
 *  Also pins the fuzzer's own invariants: a seed fully determines a case, an
 *  unmutated document is spelled as JSON.stringify spells it, and the boundary
 *  mutations land exactly on the boundaries they claim.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { sha384Hex } from "../src/lib/traveler/hash.ts";
import { MAX_TRAVELER_JSON_BYTES } from "../src/lib/traveler/types.ts";
import { buildCase, CATALOG, showApplied } from "./case.ts";
import type { ManifestEntry } from "./corpus.ts"; // type only: corpus.ts is a script, importing it would run it
import { genPlan, genTraveler } from "./generate.ts";
import { rawNumber, serializeDoc } from "./mutations.ts";
import { BLOB_FILLERS, BLOB_MEASURES, blobOfSize } from "./mutations-wire.ts";
import { Rng } from "./rng.ts";
import { loadTsImpl, tsOutcome } from "./verdict.ts";
import { encodeWire, printWire, raw, splice, toWire, type Wire } from "./wire.ts";

const dir = new URL("../conformance/fuzz/", import.meta.url).pathname;
const manifest = readFileSync(`${dir}manifest.jsonl`, "utf8")
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line) as ManifestEntry);
const nameOf = (shown: string): string => shown.replace(/\[[\s\S]*$/, "");
/** Corpus cases in which `name` is the only mutation. */
const alone = (name: string) => manifest.filter((e) => e.mutations.length === 1 && nameOf(e.mutations[0]!) === name);

describe("fuzz corpus (TypeScript replay)", () => {
  it("is, byte for byte, what the manifest describes", () => {
    assert.ok(manifest.length >= 200, `corpus is unexpectedly small: ${manifest.length}`);
    let total = 0;
    for (const e of manifest) {
      const bytes = readFileSync(`${dir}${e.file}`);
      assert.equal(bytes.length, e.bytes, `${e.file}: size`);
      // A checkout that normalized line endings or re-encoded a case would still
      // "pass" a verdict replay on most cases; the digest catches it on all of them.
      assert.equal(sha384Hex(bytes), e.sha384, `${e.file}: bytes differ from the manifest`);
      total += bytes.length;
    }
    assert.deepEqual(readdirSync(`${dir}cases`).sort(), manifest.map((e) => e.file.replace("cases/", "")).sort());
    assert.ok(total < 1_500_000, `corpus has grown to ${total} bytes`);
  });

  it("reaches the committed verdict for every case, from its bytes", async () => {
    const impl = await loadTsImpl();
    for (const e of manifest) {
      const got = tsOutcome(impl, readFileSync(`${dir}${e.file}`));
      assert.equal(got.crash, undefined, `${e.file} (${e.mutations.join(" + ")}): TypeScript crashed`);
      assert.deepEqual(got.verdict, e.expected, `${e.file} (${e.mutations.join(" + ")})`);
    }
  });

  it("is what the generator produces for each seed (else: npm run corpus)", () => {
    for (const e of manifest) {
      const c = buildCase(e.seed);
      assert.deepEqual(c.applied.map(showApplied), e.mutations, `seed ${e.seed}: mutations`);
      assert.ok(Buffer.compare(c.bytes, readFileSync(`${dir}${e.file}`)) === 0, `seed ${e.seed}: bytes`);
    }
  });

  it("carries every mutation small enough to commit, on its own", () => {
    const missing = CATALOG.filter((m) => !m.liveOnly && alone(m.name).length === 0).map((m) => m.name);
    assert.deepEqual(missing, []);
  });

  it("pins the audit's wire-level splits as refusals on both sides", () => {
    // Each of these was once accepted by one implementation (or, for the identifier
    // duplicates, by both). The corpus must hold every one of them as a refusal.
    const mustRefuse = [
      "positional-struct", // K1  a struct written as a positional array
      "proto-only-blob", //   K2  a blob member named __proto__
      "dup-quote-id", //      K5  identifier duplicates
      "dup-line-qty",
      "dup-op-seq",
      "dup-member-typed", //  K6  a member name written twice
      "dup-member-blob",
      "dup-member-escaped",
      "dup-shadow-range",
      "dup-shadow-surrogate",
      "dup-shadow-deep",
      "dup-member-whole",
      "bom-prefix", //        K7  a byte-order mark; bytes that are not UTF-8
      "utf8-invalid",
    ];
    for (const name of mustRefuse) {
      const cases = alone(name);
      assert.ok(cases.length > 0, `${name}: not in the corpus`);
      for (const e of cases) assert.equal(e.expected.accept, false, `${e.file} (${e.mutations[0]}) must be refused`);
    }
    // K3 and K4 have both outcomes by design: a well-formed signature and a name of
    // U+0085 (not ECMAScript whitespace) are accepted, the malformed ones are not.
    for (const name of ["sig-shape", "ws-whole-name"]) {
      assert.ok(alone(name).some((e) => !e.expected.accept), `${name}: no refused case in the corpus`);
    }
  });
});

describe("fuzz harness", () => {
  it("builds the same case from the same seed, every time", () => {
    for (let seed = 1; seed <= 400; seed++) {
      const a = buildCase(seed);
      const b = buildCase(seed);
      assert.equal(a.label, b.label, `seed ${seed}`);
      assert.ok(Buffer.compare(a.bytes, b.bytes) === 0, `seed ${seed}: bytes differ between builds`);
    }
  });

  it("spells an unmutated document exactly as JSON.stringify does", () => {
    for (let seed = 1; seed <= 200; seed++) {
      const rng = new Rng(seed);
      const doc = genTraveler(rng, { ...genPlan(rng), rich: seed % 2 === 0 });
      assert.equal(printWire(toWire(doc)), JSON.stringify(doc), `seed ${seed}`);
    }
    // …except for a raw literal, which is the point of having one.
    assert.equal(serializeDoc({ a: rawNumber("250.0"), b: [rawNumber("-0")] }), '{"a":250.0,"b":[-0]}');
    assert.equal(JSON.stringify(JSON.parse('{"a":250.0}')), '{"a":250}', "what JSON.stringify alone would have sent");
  });

  it("encodes text to exact bytes: UTF-8, lone surrogates and spliced bytes verbatim", () => {
    const widths = String.fromCodePoint(0x61, 0xe9, 0x6f22, 0x1f600); // 1-, 2-, 3- and 4-byte characters
    assert.deepEqual([...encodeWire(widths)], [0x61, 0xc3, 0xa9, 0xe6, 0xbc, 0xa2, 0xf0, 0x9f, 0x98, 0x80]);
    // TextEncoder would hide a lone surrogate as U+FFFD (EF BF BD).
    assert.deepEqual([...encodeWire(`"${String.fromCharCode(0xd800)}"`)], [0x22, 0xed, 0xa0, 0x80, 0x22]);
    const w: Wire = { root: raw(""), splices: [] };
    const spliced = `[${splice(w, Uint8Array.of(0xff, 0x00))},1]`;
    assert.deepEqual([...encodeWire(spliced, w.splices)], [0x5b, 0xff, 0x00, 0x2c, 0x31, 0x5d]);
  });

  it("gives every mutation a unique name and a reason", () => {
    assert.equal(new Set(CATALOG.map((m) => m.name)).size, CATALOG.length);
    for (const m of CATALOG) {
      assert.match(m.name, /^[a-z0-9][a-z0-9.-]*$/, m.name);
      assert.ok(m.why.length > 20, `${m.name}: why`);
    }
  });

  it("lands the size-cap mutations exactly on the 512 KiB cap", () => {
    const cap = MAX_TRAVELER_JSON_BYTES;
    const want: Record<string, number> = { "cap-1": cap - 1, cap, "cap+1": cap + 1 };
    for (const name of ["pad-to-cap", "inflate-to-cap"]) {
      const seen = new Set<string>();
      for (let seed = 1; seed <= 60 && seen.size < 3; seed++) {
        const c = buildCase(seed, { only: [name] });
        const target = c.applied[0]?.detail?.split(" ").find((word) => Object.hasOwn(want, word));
        if (!target || seen.has(target)) continue;
        seen.add(target);
        assert.equal(c.bytes.length, want[target], `${name} seed ${seed}: ${c.label}`);
      }
      assert.deepEqual([...seen].sort(), ["cap", "cap+1", "cap-1"], `${name}: every boundary reached`);
    }
  });

  it("fills a blob to exactly the size it names, whatever the filler and whatever the unit", () => {
    for (const filler of BLOB_FILLERS) {
      for (const measure of BLOB_MEASURES) {
        for (const target of [8191, 8192, 8193]) {
          assert.equal(
            measure.of(blobOfSize(filler, target, measure)),
            target,
            `${filler.name} at ${target} ${measure.name}`,
          );
        }
      }
    }
  });
});
