/** The published JSON Schemas (public/schemas/*.json) are what a third party validates
 *  against. This file holds them to one statement, checked in both directions:
 *
 *      a document passes the schema  <=>  the implementation accepts it,
 *      except for the rules listed in public/schemas/not-expressible-0.1.0.json.
 *
 *  It used to read "the schema accepts four of our vectors". That let the schema fall
 *  behind the format unnoticed: it had no `award.quote_hash` and no `award.sig`, so it
 *  refused every award the desk produces (and a "remove additional properties" pass driven
 *  by it would have stripped the signature), while accepting documents both
 *  implementations refuse.
 *
 *  Four independent checks, because each catches what the others cannot. Three are here;
 *  the fourth has its own file:
 *
 *   1. STRUCTURE — the schema states exactly the constraints of the implementation's own
 *      schema (schema.ts), field for field. Catches a field, bound or type that differs,
 *      whether or not any document happens to exercise it.
 *   2. REFINEMENTS — the patterns that stand in for code (calendar dates, trimmed strings)
 *      accept exactly what that code accepts. Structure cannot see these: zod has no
 *      JSON Schema form for a refinement.
 *   3. DOCUMENTS — every traveler and quote in the repository (conformance vectors, the
 *      fuzz corpus, the examples, the signed vectors, the seed fixtures), found by
 *      listing directories, never by a list of names in this file. A document both
 *      refuse has to be refused at the same place: the old schema "refused" a malformed
 *      award signature too, as an unknown member. Then the list of rules the schemas do
 *      not state is itself held to account: nothing stale, nothing unshown.
 *   4. BEHAVIOUR (schema-probes.test.ts) — at every field of a traveler that carries all
 *      of them, a battery of boundary values gets the same verdict from the schema and
 *      from the implementation. Catches a difference in what a keyword *means* (code
 *      points vs UTF-16 units, an inclusive bound) and a refinement attached to the
 *      wrong field.
 *
 *  "The implementation" here is the TypeScript one, through its wire entry point. That the
 *  Rust core gives the same verdicts is established elsewhere (vectors.rs, fuzz_corpus.rs,
 *  the differential).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { parseQuote, parseTravelerJson } from "./conformance.ts";
import { isoDateTimeMs, isoDayOk } from "./datetime.ts";
import { seedTravelers } from "./fixtures.ts";
import { MAX_TRAVELER_JSON_BYTES } from "./types.ts";
import {
  LENIENT,
  RULES,
  compilePublished,
  explain,
  fullTraveler,
  implementationObjections,
  implemented,
  notExpressible,
  published,
  refusal,
  ruleNamed,
  ruleOf,
  schemaErrors,
  schemaObjections,
  shapeOf,
  strictValue,
  utf8,
  type Aside,
  type NotExpressibleRule,
  type Shape,
} from "./schema-testkit.ts";

const repo = new URL("../../../", import.meta.url);
const read = (path: string): Uint8Array => readFileSync(new URL(path, repo));
const list = (dir: string): string[] => readdirSync(new URL(dir, repo)).sort();

const validate = compilePublished();

/* ------------------------------------------------------------------------------------ */
/* 1. Structure                                                                          */
/* ------------------------------------------------------------------------------------ */

const asides = { traveler: [] as Aside[], quote: [] as Aside[] };
const shape = {
  traveler: shapeOf(published.traveler, asides.traveler),
  quote: shapeOf(published.quote, asides.quote),
};
const member = (s: Shape, ...path: string[]): Shape => {
  let at = s;
  for (const name of path) {
    if (at.kind === "array") at = at.items;
    assert.ok(at.kind === "object" && name in at.members, `no member ${path.join(".")}`);
    at = at.members[name]!;
  }
  return at;
};
const patternsOf = (s: Shape): string[] => {
  assert.ok(s.kind === "string");
  return s.patterns;
};
/** The patterns that stand in for a refinement, read from the fields they are attached
 *  to. Each family is held to the code it mirrors in section 2. */
const REFINEMENT = {
  datetime: patternsOf(member(shape.traveler, "created_at")),
  dayOrDatetime: patternsOf(member(shape.traveler, "need_by")),
  trimmed: patternsOf(member(shape.traveler, "buyer", "name")),
};
const VERIFIED_PATTERNS = new Set(Object.values(REFINEMENT).flat());

/** Remove from `ours` every pattern `theirs` does not have, and return where they were. */
function setAsidePatterns(
  ours: Shape,
  theirs: Shape,
  path = "",
  found: { path: string; pattern: string }[] = [],
) {
  if (ours.kind === "string" && theirs.kind === "string") {
    for (const pattern of ours.patterns)
      if (!theirs.patterns.includes(pattern)) found.push({ path, pattern });
    ours.patterns = ours.patterns.filter((p) => theirs.patterns.includes(p));
  } else if (ours.kind === "object" && theirs.kind === "object") {
    for (const [name, m] of Object.entries(ours.members)) {
      if (name in theirs.members)
        setAsidePatterns(m, theirs.members[name]!, path === "" ? name : `${path}.${name}`, found);
    }
  } else if (ours.kind === "array" && theirs.kind === "array") {
    setAsidePatterns(ours.items, theirs.items, path, found);
  }
  return found;
}

describe("published JSON Schemas — 1. structure", () => {
  for (const which of ["traveler", "quote"] as const) {
    it(`${which}: states exactly the constraints of the implementation's schema, field for field`, () => {
      const ours = structuredClone(shape[which]);
      const theirs = shapeOf(implemented[which]);
      // zod cannot render a refinement, so the published schema carries patterns the
      // rendering lacks. They are set aside here and only here — and each must be one of
      // the patterns section 2 proves equivalent to the refinement it replaces.
      const extra = setAsidePatterns(ours, theirs);
      assert.deepEqual(
        extra.filter((e) => !VERIFIED_PATTERNS.has(e.pattern)),
        [],
        "a pattern the implementation's schema does not state, and that no test proves equivalent to a refinement",
      );
      assert.ok(extra.length > 0, "the published schema states the refinements as patterns");
      // Everything else — member sets, required, nullability, types, numeric bounds, length
      // bounds, item counts, constants, the implementation's own patterns — is identical.
      assert.deepEqual(ours, theirs);
    });
  }

  it("what the schemas state beyond that is exactly: the ITAR rule, and no __proto__ in a free-form object", () => {
    // Rules the implementation enforces where zod's rendering cannot show them: the first
    // is a cross-field refinement in schema.ts, the second a guard in conformance.ts.
    // schema-probes.test.ts holds each to the implementation's behaviour.
    const noProto = 'propertyNames {"not":{"const":"__proto__"}}';
    assert.deepEqual(asides.traveler, [
      { path: "", what: "if/then" },
      { path: "quotes.assumptions", what: noProto },
      { path: "quotes.capacity", what: noProto },
      { path: "as_built", what: noProto },
    ]);
    assert.deepEqual(asides.quote, [
      { path: "assumptions", what: noProto },
      { path: "capacity", what: noProto },
    ]);
  });

  it("exactly five fields accept null", () => {
    const nullable = (s: Shape, path = ""): string[] => [
      ...(s.nullable ? [path] : []),
      ...(s.kind === "object"
        ? Object.entries(s.members).flatMap(([n, m]) =>
            nullable(m, path === "" ? n : `${path}.${n}`),
          )
        : s.kind === "array"
          ? nullable(s.items, path)
          : []),
    ];
    assert.deepEqual(nullable(shape.traveler).sort(), [
      "as_built",
      "award",
      "incoterms",
      "need_by",
      "ship_to",
    ]);
    assert.deepEqual(nullable(shape.quote), []);
  });
});

/* ------------------------------------------------------------------------------------ */
/* 2. Refinements                                                                        */
/* ------------------------------------------------------------------------------------ */

/** A predicate for "matches every pattern", compiled the way a 2020-12 validator does. */
const matchesAll = (patterns: string[]) => {
  const compiled = patterns.map((p) => new RegExp(p, "u"));
  return (s: string) => compiled.every((re) => re.test(s));
};
const pad = (n: number, width: number) => String(n).padStart(width, "0");

describe("published JSON Schemas — 2. the patterns that stand in for code", () => {
  it("calendar dates: the patterns accept exactly the days and instants the implementation accepts", () => {
    const schemaDatetime = matchesAll(REFINEMENT.datetime);
    const schemaNeedBy = matchesAll(REFINEMENT.dayOrDatetime);
    const implDatetime = (s: string) => isoDateTimeMs(s) !== null;
    const implNeedBy = (s: string) => isoDayOk(s) || implDatetime(s);
    let compared = 0;
    const same = (s: string) => {
      compared++;
      if (schemaDatetime(s) !== implDatetime(s))
        assert.fail(
          `datetime ${JSON.stringify(s)}: schema ${schemaDatetime(s)}, implementation ${implDatetime(s)}`,
        );
      if (schemaNeedBy(s) !== implNeedBy(s))
        assert.fail(
          `need_by ${JSON.stringify(s)}: schema ${schemaNeedBy(s)}, implementation ${implNeedBy(s)}`,
        );
    };
    // Every year, every month and the two beside the range, and the days on which a
    // month's length can matter — as a bare day and as an instant.
    for (let y = 0; y <= 9999; y++) {
      for (let m = 0; m <= 13; m++) {
        for (const d of [0, 1, 27, 28, 29, 30, 31, 32]) {
          const day = `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}`;
          same(day);
          same(`${day}T00:00:00Z`);
        }
      }
    }
    // Every time of day and the values beside the range, with each shape of fraction.
    for (const day of ["2024-02-29", "2026-02-29", "2026-12-31"]) {
      for (let h = 0; h <= 25; h++) {
        for (const min of [0, 59, 60, 99]) {
          for (const sec of [0, 59, 60, 99]) {
            for (const fraction of ["", ".0", ".123", ".123456789", ".1234567890", ".", ".x"]) {
              same(`${day}T${pad(h, 2)}:${pad(min, 2)}:${pad(sec, 2)}${fraction}Z`);
            }
          }
        }
      }
    }
    // Shapes a lenient reader would coerce. (Built from code points where the character
    // is not plain ASCII, so this file holds none.)
    const fullwidthTwo = String.fromCodePoint(0xff12);
    // prettier-ignore
    for (const s of [
      "", " ", "2026", "2026-05", "2026-05-01T", "2026-05-01T12", "2026-05-01T12:00", "2026-05-01T12:00Z",
      "2026-05-01T12:00:00", "2026-05-01T12:00:00z", "2026-05-01t12:00:00Z", "2026-05-01 12:00:00Z",
      "2026-05-01T12:00:00+00:00", "2026-05-01T12:00:00.000+00:00", "2026-05-01T12:00:00-07:00", "2026-05-01T12:00:00ZZ",
      "2026-5-1", "2026-5-1T12:00:00Z", "2026-05-1", "26-05-01", "02026-05-01", "+2026-05-01", "-2026-05-01",
      "2026/05/01", "20260501", "2026-05-01T120000Z", "2026-05-01T1:00:00Z", "2026-05-01T12:0:00Z",
      " 2026-05-01", "2026-05-01 ", "2026-05-01\n", "\n2026-05-01", "2026-05-01T12:00:00Z\n", "2026-05-01T12:00:00Z ",
      " 2026-05-01T12:00:00Z", `2026-05-01T12:00:00Z${String.fromCodePoint(0)}`, `${fullwidthTwo}026-05-01`, `2026-05-01T1${fullwidthTwo}:00:00Z`,
      "2026-05-01T12:00:00,5Z", "2026-05-01T12:00:00.5", "2026-W18-5", "2026-121", "today", "null",
    ]) {
      same(s);
    }
    assert.ok(compared > 2_000_000);
  });

  it("trimmed strings: the patterns refuse exactly the strings the implementation refuses as untrimmed", () => {
    const schemaTrimmed = matchesAll(REFINEMENT.trimmed);
    // The implementation's rule (schema.ts `trimmedMax`): non-empty, and unchanged by trim().
    const implTrimmed = (s: string) => s.length > 0 && s === s.trim();
    const same = (s: string) => {
      if (schemaTrimmed(s) !== implTrimmed(s)) {
        const cps = [...s]
          .map((c) => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`)
          .join(" ");
        assert.fail(`[${cps}]: schema ${schemaTrimmed(s)}, implementation ${implTrimmed(s)}`);
      }
    };
    // Every code point of the Basic Multilingual Plane (lone surrogates included), and a
    // spread of the planes above it: alone, leading, trailing, and in the middle.
    const codePoints: number[] = [];
    for (let cp = 0; cp <= 0xffff; cp++) codePoints.push(cp);
    for (let cp = 0x10000; cp <= 0x10ffff; cp += 0x101) codePoints.push(cp);
    codePoints.push(0x10ffff);
    for (const cp of codePoints) {
      const c = String.fromCodePoint(cp);
      same(c);
      same(`${c}x`);
      same(`x${c}`);
      same(`x${c}x`);
    }
    same("");
    same("a b");
    same(" a b ");
    same("\n");
  });
});

/* ------------------------------------------------------------------------------------ */
/* 3. Documents                                                                          */
/* ------------------------------------------------------------------------------------ */

type Doc = { label: string; wire: Uint8Array; expect?: "accept" | "refuse" };

/** Every traveler in the repository, by listing where they live. `expect` is what the
 *  repository itself says about the document, when it says anything. */
function travelerDocuments(): Record<string, Doc[]> {
  const vectorDir = "conformance/travelers/";
  const manifests = new Set(["expected.json", "reject-reasons.json"]);
  const acceptVectors = list(vectorDir).filter((f) => f.endsWith(".json") && !manifests.has(f));
  const expected = JSON.parse(
    new TextDecoder().decode(read(`${vectorDir}expected.json`)),
  ) as Record<string, unknown>;
  assert.deepEqual(
    acceptVectors,
    Object.keys(expected).sort(),
    "conformance/travelers/*.json and expected.json list the same vectors",
  );

  const corpus = new TextDecoder()
    .decode(read("conformance/fuzz/travelers.jsonl"))
    .split("\n")
    .filter((l) => l !== "");
  const verdicts = new TextDecoder()
    .decode(read("conformance/fuzz/expected.jsonl"))
    .split("\n")
    .filter((l) => l !== "");
  assert.equal(corpus.length, verdicts.length, "one corpus verdict per corpus document");

  const signed: Doc[] = [];
  for (const file of list("conformance/signatures/").filter((f) => f.endsWith(".json"))) {
    const vector = JSON.parse(
      new TextDecoder().decode(read(`conformance/signatures/${file}`)),
    ) as Record<string, unknown>;
    if ("traveler" in vector)
      signed.push({
        label: `conformance/signatures/${file} traveler`,
        wire: utf8(JSON.stringify(vector.traveler)),
        expect: "accept",
      });
  }

  return {
    "accept vectors": acceptVectors.map((f) => ({
      label: vectorDir + f,
      wire: read(vectorDir + f),
      expect: "accept" as const,
    })),
    "reject vectors": list(`${vectorDir}reject/`).map((f) => ({
      label: f,
      wire: read(`${vectorDir}reject/${f}`),
      expect: "refuse" as const,
    })),
    "fuzz corpus": corpus.map((line, i) => ({
      label: `conformance/fuzz/travelers.jsonl line ${i + 1}`,
      wire: utf8(line),
      expect: (JSON.parse(verdicts[i]!) as { accept: boolean }).accept
        ? ("accept" as const)
        : ("refuse" as const),
    })),
    examples: list("examples/")
      .filter((f) => f.endsWith(".traveler.json"))
      .map((f) => ({
        label: `examples/${f}`,
        wire: read(`examples/${f}`),
        expect: "accept" as const,
      })),
    "signed vectors": signed,
    "seed fixtures": seedTravelers().map((t) => ({
      label: `seed fixture ${t.traveler_id}`,
      wire: utf8(JSON.stringify(t)),
      expect: "accept" as const,
    })),
  };
}

/** The rule that lists a reject vector by name, if one does. */
const listedUnder = (vector: string): NotExpressibleRule | undefined => {
  const rules = RULES.filter((r) => r.reject_vectors.includes(vector));
  assert.ok(rules.length <= 1, `${vector} is listed under more than one rule`);
  return rules[0];
};

describe("published JSON Schemas — 3. every document in the repository", () => {
  const sources = travelerDocuments();

  it("finds documents in every place they live, and the implementation's verdict is the recorded one", () => {
    // Floors, not counts: enough to notice a listing that silently found (almost) nothing.
    // prettier-ignore
    const minimum: Record<string, number> = {
      "accept vectors": 5, "reject vectors": 20, "fuzz corpus": 100, examples: 1, "signed vectors": 2, "seed fixtures": 1,
    };
    for (const [source, docs] of Object.entries(sources)) {
      assert.ok(
        docs.length >= minimum[source]!,
        `${source}: found ${docs.length}, expected at least ${minimum[source]}`,
      );
      for (const doc of docs) {
        assert.equal(refusal(doc.wire) === undefined ? "accept" : "refuse", doc.expect, doc.label);
      }
    }
  });

  it("the schema accepts every document the implementation accepts (it is never the stricter of the two)", (t) => {
    const counts: string[] = [];
    let quotes = 0;
    for (const [source, docs] of Object.entries(sources)) {
      const accepted = docs.filter((d) => refusal(d.wire) === undefined);
      for (const doc of accepted) {
        const value = strictValue(doc.wire) as { quotes?: unknown[] };
        assert.ok(validate.traveler(value), `${doc.label}: ${schemaErrors(validate.traveler)}`);
        // Each quote it carries is also a valid quote on its own, by both.
        for (const quote of value.quotes ?? []) {
          parseQuote(quote);
          assert.ok(
            validate.quote(quote),
            `${doc.label}, a quote: ${schemaErrors(validate.quote)}`,
          );
          quotes++;
        }
      }
      if (accepted.length > 0) counts.push(`${accepted.length} ${source}`);
    }
    // Standalone quotes among the signed vectors.
    let standalone = 0;
    for (const file of list("conformance/signatures/").filter((f) => f.endsWith(".json"))) {
      const vector = JSON.parse(
        new TextDecoder().decode(read(`conformance/signatures/${file}`)),
      ) as Record<string, unknown>;
      if (!("quote" in vector)) continue;
      parseQuote(vector.quote);
      assert.ok(
        validate.quote(vector.quote),
        `conformance/signatures/${file} quote: ${schemaErrors(validate.quote)}`,
      );
      standalone++;
    }
    assert.ok(standalone >= 1, "a standalone signed quote exists");
    t.diagnostic(
      `validated: ${counts.join(", ")}; ${quotes} quotes inside them; ${standalone} standalone signed quote(s)`,
    );
  });

  it("the schema accepts the award the desk itself produces", async () => {
    // The desk (store.ts) records an award with the awarded quote's content hash attached;
    // the MCP server builds its award the same way (`quote_hash: quoteContentHash(quote)`).
    // The schema used to refuse every one of them: it did not know `award.quote_hash`.
    const stored = new Map<string, string>();
    (globalThis as Record<string, unknown>).localStorage = {
      getItem: (k: string) => stored.get(k) ?? null,
      setItem: (k: string, v: string) => void stored.set(k, v),
      removeItem: (k: string) => void stored.delete(k),
    };
    const { useTravelerStore } = await import("./store.ts");
    const quoted = parseTravelerJson(read("conformance/travelers/l1-quoted.json"));
    useTravelerStore.getState().upsert(quoted);
    useTravelerStore.getState().award(
      quoted.traveler_id,
      { quote_id: quoted.quotes![0]!.quote_id, awarded_at: "2026-09-17T09:00:00.000Z", qty: 250 },
      {
        name: "Dock 4",
        line1: "1800 Industrial Way",
        city: "Reno",
        region: "NV",
        postal: "89502",
        country: "US",
      },
      [{ seq: 1, code: "laser" }],
    );
    const awarded = useTravelerStore.getState().get(quoted.traveler_id)!;
    assert.match(
      awarded.award?.quote_hash ?? "",
      /^sha384:[0-9a-f]{96}$/,
      "the desk attaches quote_hash",
    );
    const wire = utf8(JSON.stringify(awarded));
    assert.equal(refusal(wire), undefined);
    assert.ok(validate.traveler(strictValue(wire)), schemaErrors(validate.traveler));
  });

  it("a schema-driven clean-up pass deletes nothing from a document the implementation accepts", () => {
    // A gateway that validates with ajv's stock `removeAdditional` deletes, in place, the
    // members a schema does not provide for. When the schema had no `award.sig`, that
    // pass removed the buyer's signature from a signed award and then reported the
    // document valid. Every mode is held to "valid, and byte-for-byte what went in" —
    // including "all", which deletes whatever a `properties` block does not list and so
    // also punishes a schema that describes an object in two places.
    const all = [
      ...Object.values(sources)
        .flat()
        .filter((d) => refusal(d.wire) === undefined),
      { label: "the all-fields traveler", wire: utf8(JSON.stringify(fullTraveler())) },
    ];
    for (const mode of [true, "failing", "all"] as const) {
      const cleaner = compilePublished(mode).traveler;
      for (const doc of all) {
        const value = strictValue(doc.wire);
        const before = structuredClone(value);
        assert.ok(
          cleaner(value),
          `removeAdditional ${JSON.stringify(mode)}, ${doc.label}: ${schemaErrors(cleaner)}`,
        );
        assert.deepEqual(
          value,
          before,
          `removeAdditional ${JSON.stringify(mode)} changed ${doc.label}`,
        );
      }
    }
    // The case that was broken, by name: the signed award keeps its signature and its quote hash.
    const signedAward = all.find(
      (d) => d.label === "conformance/signatures/signed-award.json traveler",
    );
    assert.ok(signedAward, "the signed-award vector is among the documents");
    const cleaned = strictValue(signedAward.wire) as { award: Record<string, unknown> };
    compilePublished("all").traveler(cleaned);
    assert.deepEqual(Object.keys(cleaned.award).sort(), [
      "awarded_at",
      "qty",
      "quote_hash",
      "quote_id",
      "sig",
      "terms",
    ]);
  });

  it("the schema refuses every reject vector, and where the implementation does — except those listed under a rule the schemas do not state", (t) => {
    let bySchema = 0;
    const byRule = new Map<string, string[]>();
    for (const doc of sources["reject vectors"]!) {
      const refused = refusal(doc.wire);
      assert.ok(
        refused !== undefined,
        `${doc.label}: the implementation must refuse a reject vector`,
      );
      const rule = listedUnder(doc.label);
      if (rule === undefined) {
        // Not listed: the schema itself must refuse it — judged on the value a strict
        // reader takes from the text. A text only a lenient reader can turn into a value
        // (a repeated member name, a byte-order mark) is never judged by guessing a
        // reading: it has to be listed, with the reading named.
        assert.doesNotThrow(
          () => strictValue(doc.wire),
          `${doc.label}: a strict reader refuses this text, so a schema validator never sees it as written. ` +
            `List it in not-expressible-0.1.0.json under a wire-text rule that names the lenient reading.`,
        );
        const value = strictValue(doc.wire);
        assert.equal(
          validate.traveler(value),
          false,
          `${doc.label}: the schema accepts a document both implementations refuse ("${refused}"). ` +
            `Tighten the schema, or — only if JSON Schema cannot state the rule — list the vector in not-expressible-0.1.0.json.`,
        );
        // And for the defect the vector is named for, not for some other: when the schema
        // had no `award.sig`, it "refused" award-sig-uppercase-hex.json as an unknown member.
        assert.deepEqual(
          schemaObjections(validate.traveler),
          implementationObjections(value),
          `${doc.label}: the schema refuses it, but not where the implementation does ("${refused}")`,
        );
        bySchema++;
        continue;
      }
      // Listed: it is refused for that rule, a schema validator would be shown a value
      // that passes, and nothing else is wrong with it.
      assert.ok(
        rule.refusal.ts.some((f) => refused.includes(f)),
        `${doc.label}: listed under ${rule.rule} but refused for "${refused}"`,
      );
      const value = rule.lenient_reading
        ? LENIENT[rule.lenient_reading](doc.wire)
        : strictValue(doc.wire);
      assert.ok(
        validate.traveler(value),
        `${doc.label}: listed under ${rule.rule} as not expressible, but the schema refuses it (${schemaErrors(validate.traveler)}). ` +
          `The entry is stale — remove the vector from not-expressible-0.1.0.json.`,
      );
      assert.deepEqual(
        explain(doc.label, refused, value).map((r) => r.rule),
        [rule.rule],
        `${doc.label}: one rule, the one it is listed under`,
      );
      byRule.set(rule.rule, [...(byRule.get(rule.rule) ?? []), doc.label]);
    }
    t.diagnostic(
      `${sources["reject vectors"]!.length} reject vectors: ${bySchema} refused by the schema, ` +
        `${[...byRule.values()].flat().length} listed as not expressible (${[...byRule].map(([r, v]) => `${r} ${v.length}`).join(", ")})`,
    );
  });

  it("the schema refuses every refused document of the fuzz corpus, and where the implementation does — except for a rule the schemas do not state", (t) => {
    let bySchema = 0;
    const byRule = new Map<string, number>();
    const refusedDocs = sources["fuzz corpus"]!.filter((d) => refusal(d.wire) !== undefined);
    for (const doc of refusedDocs) {
      // A corpus line is plain JSON with nothing a strict reader refuses; if that ever
      // changes, strictValue throws here and the new kind of document gets handled on purpose.
      const value = strictValue(doc.wire);
      if (!validate.traveler(value)) {
        assert.deepEqual(
          schemaObjections(validate.traveler),
          implementationObjections(value),
          `${doc.label}: the schema refuses it, but not where the implementation does ("${refusal(doc.wire)}")`,
        );
        bySchema++;
        continue;
      }
      for (const rule of explain(doc.label, refusal(doc.wire)!, value))
        byRule.set(rule.rule, (byRule.get(rule.rule) ?? 0) + 1);
    }
    t.diagnostic(
      `${refusedDocs.length} refused corpus documents: ${bySchema} refused by the schema, ` +
        `${[...byRule.values()].reduce((a, b) => a + b, 0)} explained by a listed rule (${[...byRule].map(([r, n]) => `${r} ${n}`).join(", ")})`,
    );
    assert.ok(
      refusedDocs.length > 50 && bySchema > 50,
      "the corpus holds refused documents and the schema refuses them",
    );
  });
});

/* ------------------------------------------------------------------------------------ */
/* The list of what the schemas do not state                                             */
/* ------------------------------------------------------------------------------------ */

/** A document that breaks one listed rule and nothing else, for each refusal fragment
 *  that no committed reject vector shows. Built here because there is no vector to read. */
function builtWitnesses(): { rule: string; label: string; wire: Uint8Array }[] {
  const edited = (apply: (doc: any) => void) => {
    const doc = fullTraveler();
    apply(doc);
    return JSON.stringify(doc);
  };
  const plain = JSON.stringify(fullTraveler());
  // Everything before the notes text is ASCII, so the character offset is the byte offset.
  const offset = plain.indexOf("Deburr");
  assert.ok(offset > 0);
  const bytes = utf8(plain);
  const badByte = Uint8Array.from([...bytes.slice(0, offset), 0xff, ...bytes.slice(offset)]);
  return [
    { rule: "invalid-utf8", label: "a 0xFF byte inside a string", wire: badByte },
    {
      rule: "document-size",
      label: "a valid traveler followed by 512 KiB of spaces",
      wire: utf8(plain + " ".repeat(MAX_TRAVELER_JSON_BYTES)),
    },
    {
      rule: "quote-validity-window",
      label: "valid_until equal to created_at",
      wire: utf8(edited((d) => (d.quotes[0].valid_until = d.quotes[0].created_at))),
    },
    {
      rule: "blob-size",
      label: "as_built over 8 KiB",
      wire: utf8(edited((d) => (d.as_built = { blob: "x".repeat(9000) }))),
    },
    {
      rule: "blob-size",
      label: "an array of 5000 inside as_built",
      wire: utf8(edited((d) => (d.as_built = { list: Array.from({ length: 5000 }, () => 0) }))),
    },
  ];
}

describe("not-expressible-0.1.0.json — the rules the schemas leave to the implementation", () => {
  const rejectDir = "conformance/travelers/reject/";
  const vectors = new Set(list(rejectDir));

  it("is well-formed: each rule is named once, explained, and names only reject vectors that exist", () => {
    assert.deepEqual(notExpressible.schemas, [published.traveler.file, published.quote.file]);
    assert.equal(new Set(RULES.map((r) => r.rule)).size, RULES.length, "rule names are unique");
    const named: string[] = [];
    for (const rule of RULES) {
      assert.ok(
        ["wire-text", "cross-member", "serialized-size"].includes(rule.kind),
        `${rule.rule}: kind`,
      );
      for (const text of [rule.spec, rule.requires, rule.why])
        assert.ok(text.trim().length > 20, `${rule.rule}: spec, requires and why are written out`);
      assert.ok(
        rule.refusal.ts.length > 0 && rule.refusal.ts.every((f) => f.length >= 10),
        `${rule.rule}: refusal fragments`,
      );
      for (const vector of rule.reject_vectors) {
        assert.ok(
          vectors.has(vector),
          `${rule.rule} names ${vector}, which is not in ${rejectDir} — a stale entry`,
        );
        named.push(vector);
      }
      // A lenient reading is declared exactly for the rules about the text a strict
      // reader refuses; the others are judged on the value a strict reader takes.
      if (rule.lenient_reading !== undefined)
        assert.equal(
          rule.kind,
          "wire-text",
          `${rule.rule}: only a wire-text rule has a lenient reading`,
        );
    }
    assert.equal(new Set(named).size, named.length, "no reject vector is listed twice");
    // No fragment may claim another rule's refusals.
    for (const rule of RULES) {
      for (const fragment of rule.refusal.ts)
        assert.equal(ruleOf(fragment)?.rule, rule.rule, `"${fragment}" is ambiguous`);
    }
  });

  it("every rule, and every refusal fragment, is shown by a document that the schema passes and the implementation refuses for it", () => {
    // The built witnesses are edits of the all-fields traveler. If the schema refuses that
    // traveler itself, say so — rather than blame each rule below for being "stale".
    assert.ok(
      validate.traveler(fullTraveler()),
      `the all-fields traveler passes the schema: ${schemaErrors(validate.traveler)}`,
    );
    const witnesses = [
      ...RULES.flatMap((rule) =>
        rule.reject_vectors.map((v) => ({ rule: rule.rule, label: v, wire: read(rejectDir + v) })),
      ),
      ...builtWitnesses(),
    ];
    const shown = new Set<string>();
    for (const witness of witnesses) {
      const rule = ruleNamed(witness.rule);
      const label = `${rule.rule} / ${witness.label}`;
      const refused = refusal(witness.wire);
      assert.ok(refused !== undefined, `${label}: the implementation accepts it`);
      const fragment = rule.refusal.ts.find((f) => refused.includes(f));
      assert.ok(fragment !== undefined, `${label}: refused for "${refused}", not for this rule`);
      let value: unknown;
      if (rule.lenient_reading !== undefined) {
        // The strict reader itself refuses this text, and for this rule.
        assert.throws(
          () => strictValue(witness.wire),
          (e: Error) => rule.refusal.ts.some((f) => e.message.includes(f)),
          label,
        );
        value = LENIENT[rule.lenient_reading](witness.wire);
      } else {
        value = strictValue(witness.wire);
      }
      assert.ok(
        validate.traveler(value),
        `${label}: the schema refuses it (${schemaErrors(validate.traveler)}), so the schema does state this rule — the entry is stale`,
      );
      assert.deepEqual(
        explain(label, refused, value).map((r) => r.rule),
        [rule.rule],
        `${label}: breaks this rule and no other`,
      );
      shown.add(`${rule.rule} :: ${fragment}`);
    }
    const unshown = RULES.flatMap((rule) =>
      rule.refusal.ts
        .filter((f) => !shown.has(`${rule.rule} :: ${f}`))
        .map((f) => `${rule.rule}: "${f}"`),
    );
    assert.deepEqual(
      unshown,
      [],
      "a rule (or a refusal fragment) that no document shows cannot be told from a stale entry",
    );
  });
});
