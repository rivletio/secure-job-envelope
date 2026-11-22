/** Seeded generators of *valid* SJE domain objects for the soak + differential.
 *
 *  Everything here is deterministic in the Rng seed, so any run reproduces from
 *  its seed alone. These builders aim to produce schema-valid travelers and
 *  quotes across the whole level ladder (Draft..L3); the adversarial mutations
 *  that deliberately break them live in the harness that consumes this module
 *  (the mutation catalog behind case.ts, and soak.ts), not here.
 */
import { Rng } from "./rng.ts";
import { MATERIAL_PRESETS, PROCESS_OPTIONS } from "../src/lib/traveler/types.ts";
import type { Org, Part, Quote, Traveler } from "../src/lib/traveler/types.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";

/** A small cast of shops, mirroring src/lib/network.ts closely enough for the
 *  soak without coupling the harness to the desk app. org_huron is ITAR-capable. */
export const SHOPS: ReadonlyArray<{ org_id: string; name: string; region: string; itar: boolean }> = [
  { org_id: "org_huron", name: "Huron Precision", region: "MI", itar: true },
  { org_id: "org_redriver", name: "Red River Machining", region: "ND", itar: false },
  { org_id: "org_cascade", name: "Cascade CNC", region: "OR", itar: false },
  { org_id: "org_lakeshore", name: "Lakeshore Fabrication", region: "WI", itar: false },
  { org_id: "org_ironrange", name: "Iron Range Tool", region: "MN", itar: false },
  { org_id: "org_summitfab", name: "Summit Fabrication", region: "NV", itar: false },
];

const CURRENCIES = ["USD", "EUR", "CAD", "GBP", "JPY"] as const;
const FAMILIES = ["CNC bracket", "Turned shaft", "Sheet enclosure", "Weldment", "Machined housing"] as const;

/** A lowercase-alphanumeric id of the shape `pfx_[a-z0-9]{6..24}` (TRAVELER_ID_RE). */
export function genId(rng: Rng, pfx: string): string {
  return `${pfx}_${rng.token(rng.int(6, 24))}`;
}

/** An ISO-8601 UTC datetime with millisecond precision (ISO_DT_RE) at an absolute
 *  day offset from 2026-01-01 (plus a random time of day). Taking the day as an
 *  argument lets callers order created < valid_until deterministically instead of
 *  rolling two independent days and hoping. */
export function isoAtDay(rng: Rng, day: number): string {
  const t = Date.UTC(2026, 0, 1) + day * 86_400_000 + rng.int(0, 86_399) * 1000 + rng.int(0, 999);
  return new Date(t).toISOString();
}

/** A thickness in the canonical numeric range: either an integer, or a decimal of
 *  magnitude >= 1e-5 that renders in fixed notation. Long decimals are the point —
 *  they exercise cross-implementation float parse/round (D1). */
export function genThickness(rng: Rng): number {
  if (rng.bool(0.4)) return rng.int(1, 500); // integer mm
  const mag = rng.pick([1, 10, 100, 1000]);
  const v = rng.next() * mag + 0.001;
  return Math.min(999_999, Math.max(0.0001, v)); // within schema [1e-4, 1e6]
}

export function genOrg(rng: Rng, opts: { itar?: boolean; withId?: boolean } = {}): Org {
  const shop = rng.pick(SHOPS);
  const org: Org = { name: shop.name };
  if (opts.withId ?? true) org.org_id = shop.org_id;
  if (rng.bool(0.7)) org.region = shop.region;
  if (rng.bool(0.3)) org.city = "Somewhere";
  if (rng.bool(0.3)) org.certs = rng.sample(["ISO 9001", "AS9100", "ITAR", "Nadcap"], rng.int(1, 3));
  if (opts.itar !== undefined) org.itar = opts.itar;
  else if (shop.itar && rng.bool(0.5)) org.itar = true;
  return org;
}

export function genPart(rng: Rng): Part {
  const part: Part = {
    family: rng.pick(FAMILIES),
    part_number: `NL-${rng.token(4).toUpperCase()}-${rng.int(1000, 9999)}`,
    material: { spec: rng.pick(MATERIAL_PRESETS) },
    qty: { target: rng.int(1, 10_000) },
  };
  if (rng.bool(0.6)) part.material.thickness_mm = genThickness(rng);
  if (rng.bool(0.3)) part.material.form = rng.pick(["plate", "bar", "sheet", "tube"]);
  if (rng.bool(0.4)) part.qty.breaks = [rng.int(1, 100), rng.int(100, 1000)];
  if (rng.bool(0.5)) part.processes = rng.sample(PROCESS_OPTIONS, rng.int(1, 4));
  if (rng.bool(0.2)) part.notes = "handle with care";
  return part;
}

const cp = String.fromCodePoint;

/** Text a real shop would type, beyond ASCII: accented Latin, CJK, Cyrillic, a
 *  combining mark, an astral symbol, right-to-left letters. Built from code points so
 *  this source file stays plain ASCII. None starts or ends with whitespace. */
export const WORLD_TEXT: readonly string[] = [
  `Caf${cp(0xe9)} M${cp(0xfc)}ller GmbH`,
  cp(0x7cbe, 0x5bc6, 0x6a5f, 0x68b0),
  `Zak${cp(0x142)}ad ${cp(0x141, 0xf3)}d${cp(0x17a)}`,
  cp(0x41c, 0x435, 0x442, 0x430, 0x43b, 0x43b),
  `re${cp(0x301)}sume${cp(0x301)}`,
  `torque ${cp(0x1f529)} 12 N${cp(0xb7)}m`,
  cp(0x5d1, 0x5e8, 0x5d2),
  `10 ${cp(0xb1)} 0.05 mm, Ra ${cp(0x2264)} 1.6 ${cp(0x3bc)}m`,
  `"quoted" \\ back/slash`,
];

/** A syntactically valid ML-DSA-87 signature object (the parsers check its shape,
 *  not the cryptography — that is the soak's job). */
export function genSignature(rng: Rng): { alg: string; kid: string; sig: string } {
  const hex = "0123456789abcdef";
  let sig = "";
  for (let i = 0, n = rng.int(2, 64); i < n; i++) sig += hex[rng.int(0, 15)];
  return { alg: "ML-DSA-87", kid: `${rng.pick(SHOPS).org_id.slice(4)}-${rng.int(2024, 2027)}`, sig };
}

/** Optional quote content (none of it hashed): the blobs, exceptions, flags, a
 *  signature. Only the differential asks for it — the soak's quotes stay minimal. */
function enrichQuote(rng: Rng, quote: Quote): void {
  if (rng.bool(0.4)) quote.need_by_feasible = rng.bool(0.8);
  if (rng.bool(0.3)) quote.pricing.tax_excluded = rng.bool();
  if (rng.bool(0.45)) {
    quote.assumptions = {
      material_cert: true,
      min_order: rng.int(1, 50),
      stock: { form: "plate", sizes_mm: [6, 6.35, 12.7] },
      note: rng.pick(WORLD_TEXT),
    };
  }
  if (rng.bool(0.35)) {
    quote.exceptions = Array.from({ length: rng.int(1, 2) }, (_, i) => {
      const ex: NonNullable<Quote["exceptions"]>[number] = { code: `EX-${i + 1}`, proposal: rng.pick(WORLD_TEXT) };
      if (rng.bool()) ex.on = "part.tolerances";
      if (rng.bool()) ex.price_delta = rng.int(-5000, 5000);
      return ex;
    });
  }
  if (rng.bool(0.3)) quote.capacity = { weeks: [rng.int(1, 4), rng.int(5, 9)], shift: "2nd", ok: null };
  if (rng.bool(0.25)) quote.sig = genSignature(rng);
}

/** A quote that binds to `hash`. `sellerItar` forces the seller's ITAR flag (needed
 *  when the traveler is ITAR: an ITAR traveler only binds ITAR sellers). */
export function genQuote(
  rng: Rng,
  hash: string,
  opts: { sellerItar?: boolean; rich?: boolean } = {},
): Quote {
  const createdDay = rng.int(0, 400);
  const nLines = rng.int(1, 6);
  // No two price lines share a quantity: a quote that prices one quantity twice is
  // refused (SPEC, parsing rule 5), and a base document that is already refused hides
  // whatever a mutation was meant to test. A repeated draw is redrawn — after the
  // line's unit, so every seed that had no repeat generates exactly what it always did.
  const taken = new Set<number>();
  const line = () => {
    let qty = rng.int(1, 5000);
    const unit = rng.int(100, 5_000_00);
    while (taken.has(qty)) qty = rng.int(1, 5000);
    taken.add(qty);
    return { qty, unit };
  };
  const quote: Quote = {
    quote_id: genId(rng, "qot"),
    seller: genOrg(rng, opts.sellerItar !== undefined ? { itar: opts.sellerItar } : {}),
    traveler_hash_quoted: hash,
    created_at: isoAtDay(rng, createdDay),
    valid_until: isoAtDay(rng, createdDay + rng.int(30, 600)),
    lead_time_days: rng.int(0, 365),
    pricing: {
      currency: rng.pick(CURRENCIES),
      lines: Array.from({ length: nLines }, line),
    },
  };
  if (rng.bool(0.5)) quote.pricing.nre = rng.int(0, 100_000_00);
  if (rng.bool(0.3)) quote.pricing.freight_estimate = rng.int(0, 5_000_00);
  if (opts.rich) enrichQuote(rng, quote);
  return quote;
}

export type TravelerPlan = {
  /** Target level to build toward; the builder adds exactly the ingredients each
   *  level needs so the produced traveler lands there. */
  level: "L0" | "L1" | "L2" | "L3";
  itar?: boolean;
  /** Also fill in the optional fields (hashed and not) with realistic content,
   *  non-ASCII text included — more for the differential's mutations to bite on. Off
   *  by default, and the plain path draws nothing extra, so the soak's travelers are
   *  what they always were. */
  rich?: boolean;
};

/** Optional HASHED body fields. Must run before any quote binds to the body. */
function enrichBody(rng: Rng, traveler: Traveler): void {
  if (rng.bool(0.25)) traveler.buyer.name = rng.pick(WORLD_TEXT);
  if (rng.bool(0.3)) traveler.buyer.contact = "buyer@northline.example";
  if (rng.bool(0.5)) traveler.need_by = rng.bool() ? isoAtDay(rng, rng.int(400, 800)).slice(0, 10) : isoAtDay(rng, rng.int(400, 800));
  if (rng.bool(0.4)) traveler.incoterms = rng.pick(["FOB", "EXW", "DAP", "CIF Rotterdam"]);
  const part = traveler.part;
  if (rng.bool(0.4)) part.description = rng.pick(WORLD_TEXT);
  if (rng.bool(0.4)) part.drawing_rev = rng.pick(["A", "B", "C2", "rev 7"]);
  if (rng.bool(0.3)) part.finish = `anodize ${rng.pick(WORLD_TEXT)}`;
  if (rng.bool(0.3)) part.tolerances = rng.pick(WORLD_TEXT);
  if (rng.bool(0.3)) part.notes = `line one\nline two\t${rng.pick(WORLD_TEXT)}`;
}

/** Optional lifecycle fields (not hashed): award terms and signature, op notes,
 *  traveler signatures, a deeper as-built record. */
function enrichLifecycle(rng: Rng, traveler: Traveler): void {
  if (traveler.award) {
    if (rng.bool(0.4)) traveler.award.terms = { governing_law: "State of Nevada", payment_terms: "Net 30" };
    if (rng.bool(0.3)) traveler.award.quote_hash = `sha384:${rng.token(8).replace(/[g-z]/g, "a").padEnd(96, "0")}`;
    if (rng.bool(0.3)) traveler.award.sig = genSignature(rng);
  }
  for (const op of traveler.ops ?? []) if (rng.bool(0.3)) op.notes = rng.pick(WORLD_TEXT);
  if (rng.bool(0.3)) traveler.signatures = Array.from({ length: rng.int(1, 2) }, () => genSignature(rng));
  if (traveler.as_built && rng.bool(0.6)) {
    traveler.as_built.measurements = [
      { feature: "bore", mm: 12.7, ok: true },
      { feature: "flatness", mm: 0.02, ok: null },
    ];
    traveler.as_built.operator = rng.pick(WORLD_TEXT);
  }
}

/** Build a schema-valid traveler that lands at the requested level. The hash is
 *  computed on the L0 body and quotes are bound to it, so binding is real. */
export function genTraveler(rng: Rng, plan: TravelerPlan): Traveler {
  const itar = plan.itar ?? false;
  const rich = plan.rich ?? false;
  const traveler: Traveler = {
    spec: "sje/0.1.0",
    traveler_id: genId(rng, "tvl"),
    revision: rng.int(1, 50),
    created_at: isoAtDay(rng, rng.int(0, 400)),
    buyer: genOrg(rng, { itar: itar ? true : undefined }),
    part: genPart(rng),
    itar,
  };
  if (rich) enrichBody(rng, traveler);

  if (plan.level === "L0") {
    if (rich) enrichLifecycle(rng, traveler);
    return traveler;
  }

  // L1+ need a bound quote. Bind to the current (quote-less) body hash.
  const hash = travelerHash(traveler);
  const quote = genQuote(rng, hash, { ...(itar ? { sellerItar: true } : {}), rich });
  traveler.quotes = [quote];
  // add a couple of stale/other quotes sometimes to exercise filtering
  if (rng.bool(0.4)) {
    const other = genQuote(rng, hash, { ...(itar ? { sellerItar: true } : {}), rich });
    traveler.quotes.push(other);
  }

  if (plan.level === "L1") {
    // Awardable-but-not-executable: give it *some* of award/ops/ship, not all.
    if (rng.bool(0.5)) traveler.ops = [{ seq: 1, code: "laser" }];
    if (rich) enrichLifecycle(rng, traveler);
    return traveler;
  }

  // L2/L3 need award (bound), ops, ship_to.
  traveler.award = {
    quote_id: quote.quote_id,
    awarded_at: isoAtDay(rng, rng.int(400, 900)),
    qty: rng.int(1, 5000),
  };
  traveler.ops = [
    { seq: 1, code: "laser" },
    { seq: 2, code: "cnc-mill" },
    { seq: 3, code: "deburr" },
  ];
  traveler.ship_to = {
    name: "Northline Equipment — Dock 4",
    line1: "1800 Industrial Way",
    city: "Reno",
    region: "NV",
    postal: "89502",
    country: "US",
  };

  if (plan.level === "L3") {
    traveler.as_built = { lot: rng.token(8), inspected: true };
  }
  if (rich) enrichLifecycle(rng, traveler);
  return traveler;
}

/** Pick a level plan with a realistic spread across the ladder. */
export function genPlan(rng: Rng): TravelerPlan {
  const level = rng.pick(["L0", "L0", "L1", "L1", "L2", "L2", "L3"] as const);
  return { level, itar: rng.bool(0.2) };
}
