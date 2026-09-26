/** Regenerates the conformance vectors from the TypeScript reference
 *  implementation. The Rust implementation then verifies the same files
 *  independently — agreement across two codebases with no shared code is
 *  the proof the vectors encode.
 *
 *  Run: node --experimental-strip-types conformance/generate.ts
 */
import { writeFileSync, readFileSync } from "node:fs";
import { canonicalJson } from "../src/lib/traveler/canonical.ts";
import { travelerHash, hashQuoteable, quoteableBody } from "../src/lib/traveler/hash.ts";
import { parseTraveler, levelOf } from "../src/lib/traveler/conformance.ts";
import { sha384 } from "js-sha512";
import type { Traveler, Quote } from "../src/lib/traveler/types.ts";

const here = new URL(".", import.meta.url).pathname;

/* ---------- canonicalization vectors ---------- */

const validValues: Array<{ name: string; value: unknown }> = [
  { name: "sorted-keys", value: { b: 1, a: 2 } },
  { name: "nested-sort", value: { z: { d: 4, c: [3, { b: 2, a: 1 }] }, a: null } },
  { name: "integer", value: { t: 10 } },
  { name: "decimal", value: { t: 9.53 } },
  { name: "negative-zero", value: { t: -0 } },
  { name: "min-fraction", value: { t: 0.00001 } },
  { name: "max-safe-integer", value: { t: 9007199254740991 } },
  { name: "negative-decimal", value: { t: -12.75 } },
  { name: "string-escapes", value: { s: 'a"b\\c\nd\te' } },
  { name: "unicode-raw-utf8", value: { s: "café ± µm Ø12" } },
  { name: "empty-structures", value: { obj: {}, arr: [], s: "" } },
  { name: "booleans-null", value: { t: true, f: false, n: null } },
  { name: "key-order-digits", value: { "10": 1, "2": 2, A: 3, a: 4 } },
];

const invalidValues: Array<{ name: string; value: unknown; reason: string }> = [
  { name: "exp-large", value: { t: 1e21 }, reason: "renders exponential (1e+21 vs 1e21)" },
  { name: "exp-small", value: { t: 1e-7 }, reason: "renders exponential" },
  { name: "below-min-fraction", value: { t: 0.000001 }, reason: "ryu renders 1e-6, JS stays fixed" },
  { name: "negative-exp-large", value: { t: -1e21 }, reason: "renders exponential" },
];

const canonical = {
  spec: "sje/0.0.1",
  note:
    "Valid: implementations MUST produce exactly `canonical` and `sha384` for `value`. " +
    "Invalid: implementations MUST refuse to canonicalize `value`. " +
    "Integers above 2^53-1 are also refused but cannot be expressed in a shared JSON " +
    "vector file (JSON.parse in JavaScript loses their precision), so that rule is " +
    "covered by language-local unit tests on both sides.",
  valid: validValues.map(({ name, value }) => {
    const c = canonicalJson(value);
    return { name, value, canonical: c, sha384: `sha384:${sha384(c)}` };
  }),
  invalid: invalidValues,
};

writeFileSync(`${here}/canonical.json`, JSON.stringify(canonical, null, 2) + "\n");

/* ---------- traveler vectors ---------- */

const l0: Traveler = JSON.parse(
  readFileSync(`${here}/../examples/bracket.traveler.json`, "utf8"),
) as Traveler;
l0.traveler_id = "tvl_conform0l0";

const l0Hash = travelerHash(l0);

const quote: Quote = {
  quote_id: "qot_conform01",
  seller: {
    org_id: "org_summitfab",
    name: "Summit Fabrication",
    city: "Sparks",
    region: "NV",
    certs: ["ISO 9001"],
  },
  traveler_hash_quoted: l0Hash,
  created_at: "2026-09-16T12:00:00.000Z",
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: {
    currency: "USD",
    nre: 350,
    lines: [
      { qty: 100, unit: 18.5 },
      { qty: 250, unit: 14.2 },
      { qty: 500, unit: 11.75 },
    ],
  },
};

const l1: Traveler = { ...structuredClone(l0), traveler_id: "tvl_conform0l1", quotes: [] };
const l1Hash = travelerHash(l1);
l1.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l1Hash }];

const l2: Traveler = { ...structuredClone(l1), traveler_id: "tvl_conform0l2" };
const l2Hash = travelerHash(l2);
l2.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l2Hash }];
l2.award = { quote_id: "qot_conform01", awarded_at: "2026-09-17T09:00:00.000Z", qty: 250 };
l2.ops = [
  { seq: 1, code: "laser" },
  { seq: 2, code: "cnc-mill" },
  { seq: 3, code: "deburr" },
];
l2.ship_to = {
  name: "Northline Equipment — Dock 4",
  line1: "1800 Industrial Way",
  city: "Reno",
  region: "NV",
  postal: "89502",
  country: "US",
};

// Empty arrays / strings MUST be dropped from the quoteable body identically
// on both implementations. This vector pins that: a naive Rust serializer that
// keeps `Some(vec![])` as `[]` produces a different hash and fails here.
const emptyArrays: Traveler = {
  spec: "sje/0.0.1",
  traveler_id: "tvl_conformempt",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment", certs: [] },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50, breaks: [] },
    processes: [],
  },
  itar: false,
};

const expected: Record<string, { traveler_hash: string; level: string }> = {};
for (const [file, p] of [
  ["l0-bracket.json", l0],
  ["l0-empty-arrays.json", emptyArrays],
  ["l1-quoted.json", l1],
  ["l2-awarded.json", l2],
] as const) {
  const parsed = parseTraveler(JSON.parse(JSON.stringify(p)));
  expected[file] = { traveler_hash: travelerHash(parsed), level: levelOf(parsed).code };
  writeFileSync(`${here}/travelers/${file}`, JSON.stringify(p, null, 2) + "\n");
}
writeFileSync(`${here}/travelers/expected.json`, JSON.stringify(expected, null, 2) + "\n");

// sanity: golden vector must still hold
const golden = JSON.parse(
  readFileSync(`${here}/../crates/secure-job-envelope/tests/golden.json`, "utf8"),
);
console.log("golden:", hashQuoteable(golden));
console.log("levels:", Object.fromEntries(Object.entries(expected).map(([k, v]) => [k, v.level])));
console.log("vectors written");

// keep quoteableBody import used (documents that hashes cover the closed body)
void quoteableBody;
