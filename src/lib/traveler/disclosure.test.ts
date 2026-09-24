import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { courierMaySay, courierView, FIELD_DISCLOSURE } from "./disclosure.ts";
import { seedTravelers } from "./fixtures.ts";

type SchemaNode = {
  properties?: Record<string, SchemaNode>;
  items?: SchemaNode;
  $ref?: string;
};

function paths(node: SchemaNode, prefix: string, out: string[]) {
  const props = node.properties ?? {};
  for (const [key, child] of Object.entries(props)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (child.$ref) {
      out.push(path);
      continue;
    }
    if (child.properties) {
      paths(child, path, out);
      continue;
    }
    if (child.items?.properties) {
      paths(child.items, path, out);
      continue;
    }
    out.push(path);
  }
}

describe("disclosure", () => {
  it("classifies every field in the traveler and quote schemas", () => {
    const traveler = JSON.parse(
      readFileSync(new URL("../../../public/schemas/traveler-0.0.1.json", import.meta.url), "utf8"),
    ) as SchemaNode;
    const quote = JSON.parse(
      readFileSync(new URL("../../../public/schemas/quote-0.0.1.json", import.meta.url), "utf8"),
    ) as SchemaNode;
    const list: string[] = [];
    paths(traveler, "", list);
    const withoutQuoteRef = list.filter((p) => p !== "quotes");
    const quotePaths: string[] = [];
    paths(quote, "quotes", quotePaths);
    const all = [...withoutQuoteRef, ...quotePaths];
    const classified = new Set(FIELD_DISCLOSURE.map((f) => f.path));
    const missing = all.filter((p) => !classified.has(p));
    const extra = [...classified].filter((p) => !all.includes(p));
    assert.deepEqual(missing, [], `unclassified fields: ${missing.join(", ")}`);
    assert.deepEqual(extra, [], `classified but not in schema: ${extra.join(", ")}`);
  });

  it("the courier view contains no name, contact, price, part number, or address", () => {
    const traveler = seedTravelers()[0]!;
    const view = courierView(traveler);
    const dumped = JSON.stringify(view);
    const hidden = [
      traveler.buyer.name,
      traveler.buyer.contact ?? "",
      traveler.buyer.city ?? "",
      traveler.part.part_number,
      traveler.part.description ?? "",
      traveler.part.notes ?? "",
      traveler.ship_to?.line1 ?? "",
      traveler.ship_to?.city ?? "",
      traveler.quotes?.[0]?.seller.name ?? "",
      String(traveler.quotes?.[0]?.pricing.lines[0]?.unit ?? ""),
      String(traveler.quotes?.[0]?.pricing.nre ?? ""),
    ].filter((s) => s.length > 2);
    for (const secret of hidden) {
      assert.equal(dumped.includes(secret), false, `courier view leaked: ${secret}`);
    }
    assert.equal(view.family, traveler.part.family);
    assert.equal(view.material, traveler.part.material.spec);
    assert.equal(view.qty, traveler.part.qty.target);
    assert.equal(courierMaySay("buyer.name"), false);
    assert.equal(courierMaySay("quotes.pricing"), false);
    assert.equal(courierMaySay("part.family"), true);
    assert.equal(courierMaySay("buyer.contact"), false);
    assert.equal(courierMaySay("quotes.pricing.lines.unit"), false);
  });
});
