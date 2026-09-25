import { levelOf } from "./conformance.ts";
import type { Traveler } from "./types.ts";

/**
 * What a reader can learn. This is the list a shop can audit.
 *
 * "clear" means the bytes of the traveler file contain the value.
 * A hash does not hide it. Anyone who holds the file can read it.
 *
 * "courier" is what a matcher may repeat before both sides opt in.
 * Anything omitted stays out of that view even if it is inside the file.
 */
export type Disclosure = "clear" | "omitted";

export type FieldDisclosure = {
  path: string;
  inFile: "clear";
  inQuoteableHash: boolean;
  courierBeforeReveal: Disclosure;
};

/** Every schema field. A new field that is not listed here fails the test. */
export const FIELD_DISCLOSURE: readonly FieldDisclosure[] = [
  { path: "spec", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "traveler_id", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "revision", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "created_at", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.name", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.org_id", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.city", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.region", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.contact", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "buyer.certs", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "buyer.itar", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.family", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.part_number", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.description", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.drawing_rev", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.material.spec", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.material.form", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.material.thickness_mm", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.qty.target", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.qty.breaks", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.processes", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.finish", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "part.tolerances", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "part.notes", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "need_by", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "incoterms", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "omitted" },
  { path: "itar", inFile: "clear", inQuoteableHash: true, courierBeforeReveal: "clear" },
  { path: "ship_to.name", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.line1", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.line2", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.city", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.region", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.postal", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ship_to.country", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ops.seq", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ops.code", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "ops.notes", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.quote_id", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.org_id", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.name", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.city", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.region", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.contact", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.certs", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.seller.itar", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.traveler_hash_quoted", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.created_at", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.valid_until", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.lead_time_days", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.need_by_feasible", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.currency", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.nre", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.lines.qty", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.lines.unit", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.freight_estimate", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.pricing.tax_excluded", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.assumptions", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.exceptions.code", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.exceptions.on", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.exceptions.proposal", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.exceptions.price_delta", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "quotes.capacity", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "award.quote_id", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "award.awarded_at", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "award.qty", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
  { path: "as_built", inFile: "clear", inQuoteableHash: false, courierBeforeReveal: "omitted" },
];

const COURIER_ALLOWED = new Set(
  FIELD_DISCLOSURE.filter((f) => f.courierBeforeReveal === "clear").map((f) => f.path),
);

export function courierMaySay(path: string): boolean {
  return COURIER_ALLOWED.has(path);
}

/** The only projection a courier may compute before both sides opt in. */
export type CourierView = {
  family: string;
  material: string;
  form: string | null;
  processes: string[];
  finish: string | null;
  qty: number;
  need_by: string | null;
  itar: boolean;
  buyer_certs: string[];
  quote_count: number;
  awarded: boolean;
  level: "D" | "L0" | "L1" | "L2" | "L3";
};

export function courierView(traveler: Traveler): CourierView {
  return {
    family: traveler.part.family,
    material: traveler.part.material.spec,
    form: traveler.part.material.form ?? null,
    processes: traveler.part.processes ?? [],
    finish: traveler.part.finish ?? null,
    qty: traveler.part.qty.target,
    need_by: traveler.need_by ?? null,
    itar: traveler.itar ?? false,
    buyer_certs: traveler.buyer.certs ?? [],
    quote_count: traveler.quotes?.length ?? 0,
    awarded: Boolean(traveler.award),
    level: levelOf(traveler).code,
  };
}
