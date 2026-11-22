import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { courierMaySay, courierView, FIELD_DISCLOSURE } from "./disclosure.ts";
import { seedTravelers } from "./fixtures.ts";
import { quoteableBody } from "./hash.ts";
import {
  fieldPaths,
  fullTraveler,
  implemented,
  published,
  shapeOf,
  sitesOf,
  type Site,
} from "./schema-testkit.ts";
import type { Traveler } from "./types.ts";

/** The dotted field path of a place in a traveler: array positions add no segment. */
const dotted = (pointer: (string | number)[]): string =>
  pointer.filter((k) => typeof k === "string").join(".");

/** The places in the all-fields traveler that are a member of an object (not an array
 *  element), each with what the implementation's schema says about it. Computed on first
 *  use: if the traveler and the schema ever disagree, the case that needs the walk fails
 *  with that message, and the classification case still reports on its own terms. */
const full = fullTraveler();
let walked: Site[] | undefined;
const memberSites = (): Site[] =>
  (walked ??= sitesOf(shapeOf(implemented.traveler), full).filter(
    (s) => typeof s.pointer[s.pointer.length - 1] === "string",
  ));
/** A leaf field: a scalar, a free-form object, or an array of scalars. */
const isLeaf = (s: Site): boolean =>
  s.shape.kind !== "object" && !(s.shape.kind === "array" && s.shape.items.kind === "object");

const edited = (
  pointer: (string | number)[],
  change: (parent: any, key: string | number) => void,
): Traveler => {
  const doc = structuredClone(full) as any;
  const key = pointer[pointer.length - 1]!;
  change(
    pointer.slice(0, -1).reduce((v, k) => v[k], doc),
    key,
  );
  return doc as Traveler;
};
/** A different value of the same kind. */
const another = (v: unknown): unknown =>
  typeof v === "string"
    ? `${v}x`
    : typeof v === "number"
      ? v + 1
      : typeof v === "boolean"
        ? !v
        : Array.isArray(v)
          ? [...v, v[0]]
          : { ...(v as object), added: 1 };

describe("disclosure", () => {
  const classified = FIELD_DISCLOSURE.map((f) => f.path);
  const rows = (keep: (f: (typeof FIELD_DISCLOSURE)[number]) => boolean) =>
    FIELD_DISCLOSURE.filter(keep)
      .map((f) => f.path)
      .sort();

  it("classifies every field of the format, once: the published schema's fields and the implementation's own", () => {
    // Two independent enumerations. The published schema is what a reader of this table
    // holds; schema.ts is what the code enforces. Reading only the first is how
    // `award.quote_hash` and `award.sig` went unclassified: the published schema did not
    // list them, so this test had nothing to complain about.
    const sources = {
      "public/schemas/traveler-0.1.0.json": fieldPaths(published.traveler),
      "schema.ts (travelerSchema)": fieldPaths(implemented.traveler),
    };
    for (const [source, paths] of Object.entries(sources)) {
      assert.ok(paths.length > 70, `${source}: the enumeration found the format's fields`);
      assert.deepEqual(
        paths.filter((p) => !classified.includes(p)),
        [],
        `fields of ${source} with no classification`,
      );
      assert.deepEqual(
        classified.filter((p) => !paths.includes(p)),
        [],
        `classified, but not a field of ${source}`,
      );
    }
    assert.deepEqual(
      classified.filter((p, i) => classified.indexOf(p) !== i),
      [],
      "a field classified twice",
    );
    // A standalone quote has the same fields as a quote inside a traveler.
    for (const quote of [published.quote, implemented.quote]) {
      assert.deepEqual(
        fieldPaths(quote).map((p) => `quotes.${p}`),
        sources["schema.ts (travelerSchema)"].filter((p) => p.startsWith("quotes.")),
      );
    }
    // The all-fields traveler the next two cases walk really carries every field.
    assert.deepEqual(
      [
        ...new Set(
          memberSites()
            .filter(isLeaf)
            .map((s) => dotted(s.pointer)),
        ),
      ].sort(),
      sources["schema.ts (travelerSchema)"],
    );
  });

  it("inQuoteableHash is true for exactly the fields the hashed body carries", () => {
    // The hashed body of a traveler in which every field is present: its leaves are the
    // fields inside the hash. (Arrays of scalars are leaves, as in the table.)
    const leaves: string[] = [];
    const walk = (v: unknown, path: string): void => {
      if (typeof v === "object" && v !== null && !Array.isArray(v)) {
        for (const [name, child] of Object.entries(v))
          walk(child, path === "" ? name : `${path}.${name}`);
      } else leaves.push(path);
    };
    walk(quoteableBody(full as unknown as Traveler), "");
    assert.deepEqual(
      leaves.sort(),
      rows((f) => f.inQuoteableHash),
    );
  });

  it("the courier view depends on exactly the fields classified clear, and on nothing else in the file", () => {
    const view = (t: Traveler): string => {
      try {
        return JSON.stringify(courierView(t));
      } catch {
        return "threw"; // a missing member it reads: also a dependence
      }
    };
    const before = view(full as unknown as Traveler);
    const clear = rows((f) => f.courierBeforeReveal === "clear");
    // Changing a field's value changes the view exactly when the field is classified clear.
    const says = new Set<string>();
    for (const site of memberSites().filter(isLeaf)) {
      if (
        view(edited(site.pointer, (parent, key) => (parent[key] = another(site.value)))) !== before
      )
        says.add(dotted(site.pointer));
    }
    assert.deepEqual([...says].sort(), clear);
    // Removing any member — a whole award, the quotes, a ship-to — can change the view only
    // if a clear field lives there. (A view that said "an award exists" would fail here.)
    const removalsSeen: string[] = [];
    for (const site of memberSites()) {
      const path = dotted(site.pointer);
      if (view(edited(site.pointer, (parent, key) => delete parent[key])) === before) continue;
      assert.ok(
        clear.some((c) => c === path || c.startsWith(`${path}.`)),
        `removing ${path} changes the courier view, but no field there is classified clear`,
      );
      removalsSeen.push(path);
    }
    for (const path of ["part", "part.material", "buyer.certs", "need_by"]) {
      assert.ok(
        removalsSeen.includes(path),
        `removing ${path} is visible in the view (the probe works)`,
      );
    }
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
    // The courier view exposes only the matchable spec — no workflow state (award
    // presence, quote count, or level) derived from fields the disclosure table marks
    // "omitted". Pin the key set so a future addition from an omitted path is caught.
    assert.deepEqual(
      Object.keys(view).sort(),
      [
        "buyer_certs",
        "family",
        "finish",
        "form",
        "itar",
        "material",
        "need_by",
        "processes",
        "qty",
      ].sort(),
    );
    assert.equal(courierMaySay("buyer.name"), false);
    assert.equal(courierMaySay("quotes.pricing"), false);
    assert.equal(courierMaySay("part.family"), true);
    assert.equal(courierMaySay("buyer.contact"), false);
    assert.equal(courierMaySay("quotes.pricing.lines.unit"), false);
    // Award-stage data stays out, including the fields that were once missing from the table.
    for (const path of [
      "award.quote_id",
      "award.quote_hash",
      "award.sig.alg",
      "award.sig.kid",
      "award.sig.sig",
    ]) {
      assert.equal(courierMaySay(path), false, path);
    }
  });
});
