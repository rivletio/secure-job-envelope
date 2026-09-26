/** The published JSON Schemas (public/schemas/*.json) are the contract a third
 *  party validates against. These tests keep that contract honest:
 *   - it accepts every traveler this repo ships (example, conformance vectors,
 *     seed fixtures), so the published schema never rejects our own data; and
 *   - it enforces the canonical numeric range the SPEC claims it enforces —
 *     integers within 2^53-1, and the fixed-notation money rule (an integer or
 *     a non-integer of magnitude >= 1e-5, <= 1e12). See docs/SPEC.md §Canonical
 *     JSON and docs/CLAIMS.md.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import { seedTravelers } from "./fixtures.ts";

const schemaDir = new URL("../../../public/schemas/", import.meta.url).pathname;
const conformanceDir = new URL("../../../conformance/", import.meta.url).pathname;
const examplesDir = new URL("../../../examples/", import.meta.url).pathname;

const travelerSchema = JSON.parse(readFileSync(`${schemaDir}traveler-0.0.1.json`, "utf8"));
const quoteSchema = JSON.parse(readFileSync(`${schemaDir}quote-0.0.1.json`, "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addSchema(quoteSchema, "quote-0.0.1.json");
const validateTraveler = ajv.compile(travelerSchema);
const validateQuote = ajv.getSchema("quote-0.0.1.json")!;

describe("published JSON Schemas", () => {
  it("accept the example, every conformance traveler, and every seed fixture", () => {
    const files = [
      `${examplesDir}bracket.traveler.json`,
      `${conformanceDir}travelers/l0-bracket.json`,
      `${conformanceDir}travelers/l0-empty-arrays.json`,
      `${conformanceDir}travelers/l1-quoted.json`,
      `${conformanceDir}travelers/l2-awarded.json`,
    ];
    for (const f of files) {
      const data = JSON.parse(readFileSync(f, "utf8"));
      assert.ok(validateTraveler(data), `${f}: ${JSON.stringify(validateTraveler.errors)}`);
    }
    for (const t of seedTravelers()) {
      assert.ok(validateTraveler(t), `${t.traveler_id}: ${JSON.stringify(validateTraveler.errors)}`);
    }
  });

  it("bound every numeric field inside the canonical range", () => {
    const base = JSON.parse(readFileSync(`${examplesDir}bracket.traveler.json`, "utf8"));
    const rejects = (mut: (t: Record<string, unknown>) => void) => {
      const t = structuredClone(base);
      mut(t);
      return validateTraveler(t) === false;
    };
    assert.ok(rejects((t: any) => (t.revision = 9007199254740992)), "revision > 2^53-1");
    assert.ok(rejects((t: any) => (t.part.material.thickness_mm = 0.000001)), "thickness < 1e-5");
    assert.ok(rejects((t: any) => (t.part.qty.target = 2000000)), "qty.target > 1e6");
    // boundary value still accepted
    const okBoundary = structuredClone(base);
    okBoundary.part.material.thickness_mm = 0.0001;
    assert.ok(validateTraveler(okBoundary), "thickness minimum 0.0001 accepted");
  });

  it("enforce the fixed-notation money rule (integer or |x| >= 1e-5, <= 1e12)", () => {
    const quote = (unit: number) => ({
      quote_id: "qot_schema001",
      seller: { name: "Summit Fabrication" },
      traveler_hash_quoted: "sha384:" + "a".repeat(96),
      created_at: "2026-01-01T00:00:00.000Z",
      valid_until: "2026-02-01T00:00:00.000Z",
      lead_time_days: 5,
      pricing: { currency: "USD", lines: [{ qty: 1, unit }] },
    });
    assert.equal(validateQuote(quote(0.000001)), false, "sub-1e-5 non-integer refused");
    assert.equal(validateQuote(quote(5_000_000_000_000)), false, "> 1e12 refused");
    assert.equal(validateQuote(quote(0.00001)), true, "1e-5 boundary accepted");
    assert.equal(validateQuote(quote(0)), true, "zero accepted");
    assert.equal(validateQuote(quote(14.2)), true, "normal price accepted");
  });
});
