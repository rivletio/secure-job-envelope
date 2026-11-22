/** The published JSON Schemas, held to the implementation's behaviour field by field.
 *
 *  schema-contract.test.ts shows that the schema STATES the implementation's constraints
 *  (same fields, same bounds) and judges every document in the repository the same way.
 *  Neither can show that a stated constraint MEANS the same thing to a schema validator
 *  as to the implementation (whether a length is counted in code points or UTF-16 units,
 *  whether a bound is inclusive, which characters count as white space) or that a
 *  pattern sits on the right field; and the repository's documents leave most fields
 *  at ordinary values.
 *
 *  So this file starts from one traveler that carries every field, changes one thing at a
 *  time (each field to each boundary of its own constraints, to every other JSON type, to
 *  null, to absent) and requires the schema and the implementation to give the same
 *  verdict on every result — and, when both refuse, to object at the same place. The one
 *  permitted difference is a document the implementation refuses for a rule listed in
 *  public/schemas/not-expressible-0.1.0.json.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseQuote } from "./conformance.ts";
import {
  compilePublished,
  explain,
  fieldsOf,
  fullTraveler,
  implementationObjections,
  published,
  refusal,
  schemaErrors,
  schemaObjections,
  shapeOf,
  sitesOf,
  strictValue,
  utf8,
  type Site,
} from "./schema-testkit.ts";

const validate = compilePublished();
const shape = { traveler: shapeOf(published.traveler) };
const pad = (n: number, width: number) => String(n).padStart(width, "0");

type Edit = { what: string; apply: (doc: unknown) => unknown };

const at = (doc: unknown, pointer: (string | number)[]): any =>
  pointer.reduce((v: any, key) => v[key], doc);
/** Replace the value at `pointer` (the whole document if the pointer is empty). */
const put = (pointer: (string | number)[], value: unknown) => (doc: unknown) => {
  if (pointer.length === 0) return value;
  at(doc, pointer.slice(0, -1))[pointer[pointer.length - 1]!] = value;
  return doc;
};
const drop = (pointer: (string | number)[]) => (doc: unknown) => {
  delete at(doc, pointer.slice(0, -1))[pointer[pointer.length - 1]!];
  return doc;
};
/** Give the object at `pointer` an own member called `name` — including `__proto__`,
 *  which a plain assignment would not create. */
const addMember =
  (pointer: (string | number)[], name: string, value: unknown) => (doc: unknown) => {
    Object.defineProperty(at(doc, pointer), name, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    return doc;
  };
const withProto = (value: unknown): object => {
  const o = {};
  Object.defineProperty(o, "__proto__", {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return o;
};

const cp = (...codes: number[]) => String.fromCodePoint(...codes);
const ASTRAL = cp(0x1f600);
/** One string battery for every string field: the verdicts decide what is valid where. */
// prettier-ignore
const STRINGS: string[] = [
  // emptiness and each kind of white space String.prototype.trim removes, at an edge
  "", " ", "x", "ab", "a b", `a${cp(0x0a)}b`,
  ...[0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff].flatMap(
    (ws) => [`${cp(ws)}x`, `x${cp(ws)}`],
  ),
  // characters other definitions of white space include and this one does not
  ...[0x85, 0x1c, 0x1f, 0x180e, 0x200b, 0x2060].flatMap((c) => [`${cp(c)}x`, `x${cp(c)}`, cp(c)]),
  // a lone surrogate: a text-level rule the schemas do not state (it must be *explained*, not agreed on)
  `x${String.fromCharCode(0xd800)}`,
  // days and instants
  "2026-10-24", "2024-02-29", "2026-02-29", "1900-02-29", "2000-02-29", "0000-02-29", "2026-02-30", "2026-04-31",
  "2026-13-01", "2026-00-10", "2026-01-00", "2026-01-32", "2026-1-01", "2026-01-01 ", `2026-01-01${cp(0x0a)}`,
  "2026-05-01T12:00:00Z", "2026-05-01T12:00:00.5Z", "2026-05-01T12:00:00.123456789Z", "2026-05-01T12:00:00.1234567890Z",
  "2026-05-01T12:00:00.Z", "2026-05-01T23:59:59Z", "2026-05-01T24:00:00Z", "2026-05-01T12:60:00Z", "2026-05-01T12:00:60Z",
  "2026-05-01T12:00:00+00:00", "2026-05-01T12:00:00", "2026-05-01t12:00:00z", "2026-05-01 12:00:00Z",
  "2026-02-31T12:00:00.000Z", "2024-02-29T00:00:00Z", "2026-02-29T00:00:00Z", "9999-12-31T23:59:59.999999999Z",
  "0000-01-01T00:00:00Z", `2026-05-01T12:00:00Z${cp(0x0a)}`, `${cp(0xff12)}026-05-01T12:00:00Z`,
  // identifiers, hashes, org ids
  "tvl_abcdef", "tvl_abcde", `tvl_${"a".repeat(24)}`, `tvl_${"a".repeat(25)}`, "TVL_ABCDEF", "tv_abcdef", "tvl-abcdef",
  "tvl_abc_def", `tvl_abcdef${cp(0x0a)}`, "tvl_abcdeF",
  `sha384:${"a".repeat(96)}`, `sha384:${"A".repeat(96)}`, `sha384:${"a".repeat(95)}`, `sha384:${"a".repeat(97)}`,
  `sha384:${"g".repeat(96)}`, `sha256:${"a".repeat(64)}`, `SHA384:${"a".repeat(96)}`,
  "org_ab", "ab", "a", `a${"b".repeat(63)}`, `a${"b".repeat(64)}`, "1abc", "Org_x", "org-x", "_org",
  // currency, country, hex, constants
  "USD", "usd", "USDX", "US", "us", "U1", "USA", "0a1b", "AB", "xyz", "0", "a".repeat(20000), "a".repeat(20001),
  "ML-DSA-87", "ml-dsa-87", "RSA-2048", "sje/0.1.0", "sje/0.2.0",
];

/** Every array whose items must differ in one member (not-expressible: unique-*). A
 *  boundary probe fills an array to its limit; it must not trip these on the way. */
const DISTINCT: Record<string, (item: any, i: number) => void> = {
  ops: (op, i) => (op.seq = i + 1),
  quotes: (quote, i) => (quote.quote_id = `qot_fill${pad(i, 4)}`),
  lines: (line, i) => (line.qty = i + 1),
};

function editsAt(site: Site): Edit[] {
  const { pointer, shape: s, value } = site;
  const name = pointer.length === 0 ? "" : String(pointer[pointer.length - 1]);
  const edits: Edit[] = [];
  const set = (what: string, v: unknown) => edits.push({ what, apply: put(pointer, v) });

  // Any field: null, and a value of each other JSON type.
  set("null", null);
  // prettier-ignore
  const others: [string, unknown][] = [["true", true], ["7", 7], ['"x"', "x"], ["[]", []], ["{}", {}]];
  const own = {
    string: '"x"',
    number: "7",
    integer: "7",
    boolean: "true",
    array: "[]",
    object: "{}",
    "free-form": "{}",
  }[s.kind];
  for (const [label, v] of others) if (label !== own) set(label, v);
  // A member of an object: absent.
  if (typeof pointer[pointer.length - 1] === "string")
    edits.push({ what: "absent", apply: drop(pointer) });

  switch (s.kind) {
    case "string": {
      for (const str of STRINGS) set(JSON.stringify(str).slice(0, 48), str);
      for (const n of [
        s.minLength - 1,
        s.minLength,
        s.maxLength,
        s.maxLength === null ? null : s.maxLength + 1,
      ]) {
        if (n === null || n < 0) continue;
        set(`${n} ASCII characters`, "x".repeat(n));
        set(`${n} astral characters`, ASTRAL.repeat(n)); // n code points, 2n UTF-16 units
      }
      break;
    }
    case "integer":
    case "number": {
      const { minimum: lo, maximum: hi } = s;
      // prettier-ignore
      const values = [0, -0, 1, -1, 2, 0.5, 1.5, 0.00001, 0.00005, 0.0001, 0.000099, 0.000001, 1e-7, 1e21, 2 ** 53 - 1, 2 ** 53, -(2 ** 53)];
      if (lo !== null) values.push(lo, lo - 1, lo + 1, lo + 0.5, lo - 0.5);
      if (hi !== null) values.push(hi, hi + 1, hi - 1, hi - 0.5, hi + 0.5);
      for (const n of new Set(values)) set(String(n), n);
      break;
    }
    case "boolean":
      set(String(!value), !value);
      break;
    case "array": {
      const items = value as unknown[];
      const fill = (n: number) =>
        Array.from({ length: n }, (_, i) => {
          const item = structuredClone(items[0]);
          DISTINCT[name]?.(item, i);
          return item;
        });
      set("no items", []);
      for (const n of [s.minItems, s.maxItems, s.maxItems === null ? null : s.maxItems + 1]) {
        if (n !== null && n > 0) set(`${n} items`, fill(n));
      }
      break;
    }
    case "object":
      set("its values as a positional array", Object.values(value as object));
      set("no members", {});
      edits.push({ what: "an unknown member", apply: addMember(pointer, "zz_unknown", 1) });
      edits.push({ what: "a member named __proto__", apply: addMember(pointer, "__proto__", 1) });
      break;
    case "free-form":
      set("no members", {});
      set("any members at all", {
        "": 1,
        proto: "__proto__",
        __proto: null,
        nested: { deep: [{ deeper: [[]] }] },
      });
      edits.push({ what: "a member named __proto__", apply: addMember(pointer, "__proto__", 1) });
      set("__proto__ inside a nested object", { a: { b: withProto(null) } });
      set("__proto__ inside a nested array", { a: [1, [withProto({})]] });
      set("more than 8 KiB", { blob: "x".repeat(9000) });
      set("an array of 5000", { list: Array.from({ length: 5000 }, () => 0) });
      // Numbers inside it are canonical numbers, at any depth: the schema says so with
      // bounds, the implementation by asking whether the number has a canonical form.
      // Both must object at the number itself. Both sides of each bound:
      for (const [what, n] of [
        ["2^53-1", 9007199254740991],
        ["2^53", 9007199254740992],
        ["-(2^53-1)", -9007199254740991],
        ["-(2^53)", -9007199254740992],
        ["1e20", 1e20],
        ["1e21", 1e21],
        ["the largest binary64", Number.MAX_VALUE],
        ["0.00001", 0.00001],
        ["just under 0.00001", 0.000009999999999999999],
        ["-0.00001", -0.00001],
        ["just over -0.00001", -0.000009999999999999999],
        ["1e-7", 1e-7],
        ["the smallest binary64", Number.MIN_VALUE],
        ["zero", 0],
        ["minus zero", -0],
        ["a fraction", 1.5],
        ["a large fraction", 4503599627370495.5],
      ] as const) {
        set(`the number ${what} as a member`, { n });
        set(`the number ${what} nested in an array in an object`, { a: [true, { b: [n] }] });
      }
      set("two numbers with no canonical form", { a: 1e20, b: [1, 1e-7] });
      break;
  }
  return edits;
}

describe("published JSON Schemas — behaviour at every field", () => {
  const base = fullTraveler();

  it("the traveler these probes start from carries every field, and both sides accept it", () => {
    const wire = utf8(JSON.stringify(base));
    assert.equal(refusal(wire), undefined);
    assert.ok(validate.traveler(strictValue(wire)), schemaErrors(validate.traveler));
    // sitesOf throws on a field the schema defines and the traveler lacks (or the reverse).
    const leaves = new Set(
      sitesOf(shape.traveler, base).map((s) =>
        s.pointer.filter((k) => typeof k === "string").join("."),
      ),
    );
    for (const field of fieldsOf(shape.traveler))
      assert.ok(leaves.has(field.path), `not carried: ${field.path}`);
  });

  it("schema and implementation give the same verdict, at the same place, for every probe at every field", (t) => {
    let probes = 0;
    let bothAccept = 0;
    let bothRefuse = 0;
    const excused = new Map<string, number>();
    const elsewhere: string[] = [];
    for (const site of sitesOf(shape.traveler, base)) {
      for (const edit of editsAt(site)) {
        const label = `${site.pointer.join(".") || "(the traveler)"} := ${edit.what}`;
        const doc = edit.apply(structuredClone(base));
        const wire = utf8(JSON.stringify(doc));
        const refused = refusal(wire);
        const value = strictValue(wire);
        const passes = validate.traveler(value);
        probes++;
        if (refused === undefined && passes) bothAccept++;
        else if (refused !== undefined && !passes) {
          // Refused by both — which is agreement only if it is for the same defect.
          bothRefuse++;
          const schemaAt = schemaObjections(validate.traveler);
          const implementationAt = implementationObjections(value);
          if (JSON.stringify(schemaAt) !== JSON.stringify(implementationAt))
            elsewhere.push(
              `${label}: implementation at ${JSON.stringify(implementationAt)}, schema at ${JSON.stringify(schemaAt)}`,
            );
        } else if (refused === undefined) {
          assert.fail(
            `${label}: the implementation accepts it and the schema refuses it (${schemaErrors(validate.traveler)})`,
          );
        } else {
          for (const rule of explain(label, refused, value))
            excused.set(rule.rule, (excused.get(rule.rule) ?? 0) + 1);
        }
      }
    }
    assert.deepEqual(
      elsewhere.slice(0, 20),
      [],
      `${elsewhere.length} probe(s) refused by both, but not at the same place`,
    );
    t.diagnostic(
      `${probes} probes: ${bothAccept} accepted by both, ${bothRefuse} refused by both, ` +
        `${[...excused.values()].reduce((a, b) => a + b, 0)} refused by the implementation alone for a listed rule ` +
        `(${[...excused].map(([rule, n]) => `${rule} ${n}`).join(", ")})`,
    );
    assert.ok(probes > 5000 && bothAccept > 500 && bothRefuse > 2500, "the battery ran");
  });

  it("the ITAR rule: an ITAR traveler carries quotes only from sellers that declare itar: true", () => {
    const flags = [undefined, false, true];
    let refusedCount = 0;
    for (const travelerItar of flags) {
      for (const first of flags) {
        for (const second of [...flags, "no second quote"] as const) {
          const doc = fullTraveler() as any;
          const quote = (itar: boolean | undefined, id: string) => {
            const q = structuredClone(doc.quotes[0]);
            q.quote_id = id;
            if (itar === undefined) delete q.seller.itar;
            else q.seller.itar = itar;
            return q;
          };
          if (travelerItar === undefined) delete doc.itar;
          else doc.itar = travelerItar;
          doc.quotes = [
            quote(first, "qot_itarfirst1"),
            ...(second === "no second quote" ? [] : [quote(second, "qot_itarsecond")]),
          ];
          const wire = utf8(JSON.stringify(doc));
          const expectRefused =
            travelerItar === true &&
            (first !== true || (second !== "no second quote" && second !== true));
          const label = `traveler.itar=${travelerItar}, sellers ${first} / ${second}`;
          const refused = refusal(wire);
          assert.equal(refused !== undefined, expectRefused, `${label}: implementation`);
          if (refused !== undefined)
            assert.match(
              refused,
              /ITAR traveler cannot carry a quote from a non-ITAR seller/,
              label,
            );
          const value = strictValue(wire);
          assert.equal(validate.traveler(value), !expectRefused, `${label}: schema`);
          // Both name each seller that does not declare itar: true, and nothing else.
          const sellers = second === "no second quote" ? [first] : [first, second];
          const offenders = expectRefused
            ? sellers.flatMap((itar, i) => (itar === true ? [] : [`/quotes/${i}/seller/itar`]))
            : [];
          assert.deepEqual(schemaObjections(validate.traveler), offenders, `${label}: schema`);
          assert.deepEqual(implementationObjections(value), offenders, `${label}: implementation`);
          if (expectRefused) refusedCount++;
        }
      }
    }
    assert.equal(refusedCount, 10);
    // No quotes at all: nothing to refuse.
    const none = fullTraveler() as any;
    none.itar = true;
    none.quotes = [];
    delete none.award;
    assert.equal(refusal(utf8(JSON.stringify(none))), undefined);
    assert.ok(validate.traveler(none), schemaErrors(validate.traveler));
  });

  it("string lengths are counted in code points by both (128 astral characters fit a 128-character name; 129 do not)", () => {
    for (const [n, accepted] of [
      [128, true],
      [129, false],
    ] as const) {
      const doc = fullTraveler() as any;
      doc.part.family = ASTRAL.repeat(n);
      assert.equal(doc.part.family.length, 2 * n, "two UTF-16 units each");
      const wire = utf8(JSON.stringify(doc));
      assert.equal(
        refusal(wire),
        accepted ? undefined : "part.family: Too big: expected string to have <=128 characters",
        `implementation, ${n}`,
      );
      assert.equal(validate.traveler(strictValue(wire)), accepted, `schema, ${n}`);
      assert.deepEqual(
        (validate.traveler.errors ?? []).map((e) => `${e.instancePath} ${e.keyword}`),
        accepted ? [] : ["/part/family maxLength"],
        `schema, ${n}`,
      );
    }
  });

  it("the quote schema on its own refuses what the implementation refuses in a quote, at the same field", () => {
    const quote = () => structuredClone((fullTraveler() as any).quotes[0]);
    /** Where each side objects. A bare "refused" would not do: it cannot tell the defect
     *  under test from any other. */
    const objections = (q: unknown) => {
      validate.quote(q);
      return {
        implementation: implementationObjections(q, "quote"),
        schema: schemaObjections(validate.quote),
      };
    };
    assert.doesNotThrow(() => parseQuote(quote()));
    assert.ok(validate.quote(quote()), schemaErrors(validate.quote));
    assert.deepEqual(objections(quote()), { implementation: [], schema: [] });
    // [the change, how to make it, the one place both object to it ("" is the quote itself)]
    const edits: [string, (q: any) => void, string][] = [
      ["no pricing", (q) => delete q.pricing, "/pricing"],
      ["fractional unit", (q) => (q.pricing.lines[0].unit = 14.2), "/pricing/lines/0/unit"],
      ["negative unit", (q) => (q.pricing.lines[0].unit = -1), "/pricing/lines/0/unit"],
      ["unit over 1e12", (q) => (q.pricing.lines[0].unit = 1e12 + 1), "/pricing/lines/0/unit"],
      ["lowercase currency", (q) => (q.pricing.currency = "usd"), "/pricing/currency"],
      ["an unknown member", (q) => (q.zz_unknown = 1), ""],
      ["untrimmed seller name", (q) => (q.seller.name = " Summit"), "/seller/name"],
      [
        "valid_until on 31 February",
        (q) => (q.valid_until = "2039-02-31T00:00:00Z"),
        "/valid_until",
      ],
      ["sig with an unknown member", (q) => (q.sig.extra = 1), "/sig"],
      ["uppercase sig hex", (q) => (q.sig.sig = "0A1B"), "/sig/sig"],
      ["assumptions as an array", (q) => (q.assumptions = []), "/assumptions"],
      ["capacity null", (q) => (q.capacity = null), "/capacity"],
      [
        "a 64-hex traveler hash",
        (q) => (q.traveler_hash_quoted = `sha384:${"a".repeat(64)}`),
        "/traveler_hash_quoted",
      ],
    ];
    for (const [what, apply, place] of edits) {
      const q = quote();
      apply(q);
      assert.throws(() => parseQuote(q), /^Error: Invalid quote\. /, what);
      assert.equal(validate.quote(q), false, what);
      assert.deepEqual(objections(q), { implementation: [place], schema: [place] }, what);
    }
  });
});
