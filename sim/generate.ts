/** Seeded generators of *valid* SJE domain objects for the soak + differential.
 *
 *  Everything here is deterministic in the Rng seed, so any run reproduces from
 *  its seed alone. These builders aim to produce schema-valid travelers and
 *  quotes across the whole level ladder (Draft..L3); the adversarial mutations
 *  that deliberately break them live in the harness that consumes this module
 *  (differential.ts / soak.ts), not here.
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

/** A quote that binds to `hash`. `sellerItar` forces the seller's ITAR flag (needed
 *  when the traveler is ITAR: an ITAR traveler only binds ITAR sellers). */
export function genQuote(
  rng: Rng,
  hash: string,
  opts: { sellerItar?: boolean } = {},
): Quote {
  const createdDay = rng.int(0, 400);
  const nLines = rng.int(1, 6);
  const quote: Quote = {
    quote_id: genId(rng, "qot"),
    seller: genOrg(rng, opts.sellerItar !== undefined ? { itar: opts.sellerItar } : {}),
    traveler_hash_quoted: hash,
    created_at: isoAtDay(rng, createdDay),
    valid_until: isoAtDay(rng, createdDay + rng.int(30, 600)),
    lead_time_days: rng.int(0, 365),
    pricing: {
      currency: rng.pick(CURRENCIES),
      lines: Array.from({ length: nLines }, () => ({
        qty: rng.int(1, 5000),
        unit: rng.int(100, 5_000_00),
      })),
    },
  };
  if (rng.bool(0.5)) quote.pricing.nre = rng.int(0, 100_000_00);
  if (rng.bool(0.3)) quote.pricing.freight_estimate = rng.int(0, 5_000_00);
  return quote;
}

export type TravelerPlan = {
  /** Target level to build toward; the builder adds exactly the ingredients each
   *  level needs so the produced traveler lands there. */
  level: "L0" | "L1" | "L2" | "L3";
  itar?: boolean;
};

/** Build a schema-valid traveler that lands at the requested level. The hash is
 *  computed on the L0 body and quotes are bound to it, so binding is real. */
export function genTraveler(rng: Rng, plan: TravelerPlan): Traveler {
  const itar = plan.itar ?? false;
  const traveler: Traveler = {
    spec: "sje/0.1.0",
    traveler_id: genId(rng, "tvl"),
    revision: rng.int(1, 50),
    created_at: isoAtDay(rng, rng.int(0, 400)),
    buyer: genOrg(rng, { itar: itar ? true : undefined }),
    part: genPart(rng),
    itar,
  };

  if (plan.level === "L0") return traveler;

  // L1+ need a bound quote. Bind to the current (quote-less) body hash.
  const hash = travelerHash(traveler);
  const quote = genQuote(rng, hash, itar ? { sellerItar: true } : {});
  traveler.quotes = [quote];
  // add a couple of stale/other quotes sometimes to exercise filtering
  if (rng.bool(0.4)) {
    const other = genQuote(rng, hash, itar ? { sellerItar: true } : {});
    traveler.quotes.push(other);
  }

  if (plan.level === "L1") {
    // Awardable-but-not-executable: give it *some* of award/ops/ship, not all.
    if (rng.bool(0.5)) traveler.ops = [{ seq: 1, code: "laser" }];
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
  return traveler;
}

/** Pick a level plan with a realistic spread across the ladder. */
export function genPlan(rng: Rng): TravelerPlan {
  const level = rng.pick(["L0", "L0", "L1", "L1", "L2", "L2", "L3"] as const);
  return { level, itar: rng.bool(0.2) };
}
