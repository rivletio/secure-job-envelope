import { sha384 } from "js-sha512";
import { canonicalJson } from "./canonical.ts";
import type { Org, Traveler, Part, QuoteableBody } from "./types.ts";
import { TRAVELER_SPEC } from "./types.ts";

export const GOLDEN_HASH =
  "sha384:607816f3d5f7e7b7afbf56e78c5013e5d400044fa78fb2ee459e299dc694a2638dcaf3620b8f38923f152d124340eeb2";

function present(s?: string): string | undefined {
  return s && s.length > 0 ? s : undefined;
}

/** Closed field set — extra keys on in-memory objects must not enter the hash. */
export function quoteableOrg(org: Org): Org {
  const out: Org = { name: org.name };
  if (present(org.org_id)) out.org_id = org.org_id;
  if (present(org.city)) out.city = org.city;
  if (present(org.region)) out.region = org.region;
  if (present(org.contact)) out.contact = org.contact;
  if (org.certs?.length) out.certs = org.certs;
  if (org.itar !== undefined) out.itar = org.itar;
  return out;
}

export function quoteablePart(part: Part): Part {
  const material: Part["material"] = { spec: part.material.spec };
  if (present(part.material.form)) material.form = part.material.form;
  if (part.material.thickness_mm !== undefined) material.thickness_mm = part.material.thickness_mm;
  const qty: Part["qty"] = { target: part.qty.target };
  if (part.qty.breaks?.length) qty.breaks = part.qty.breaks;
  const out: Part = {
    family: part.family,
    part_number: part.part_number,
    material,
    qty,
  };
  if (present(part.description)) out.description = part.description;
  if (present(part.drawing_rev)) out.drawing_rev = part.drawing_rev;
  if (part.processes?.length) out.processes = part.processes;
  if (present(part.finish)) out.finish = part.finish;
  if (present(part.tolerances)) out.tolerances = part.tolerances;
  if (present(part.notes)) out.notes = part.notes;
  return out;
}

export function quoteableBody(traveler: Traveler): QuoteableBody {
  return {
    spec: TRAVELER_SPEC,
    traveler_id: traveler.traveler_id,
    revision: traveler.revision,
    created_at: traveler.created_at,
    buyer: quoteableOrg(traveler.buyer),
    part: quoteablePart(traveler.part),
    need_by: traveler.need_by ?? null,
    incoterms: traveler.incoterms ?? null,
    itar: traveler.itar ?? false,
  };
}

export function travelerHash(traveler: Traveler): string {
  return hashQuoteable(quoteableBody(traveler));
}

export function hashQuoteable(body: QuoteableBody): string {
  return `sha384:${sha384(canonicalJson(body))}`;
}

export function sha384Hex(bytes: string): string {
  return `sha384:${sha384(bytes)}`;
}

export function shortHash(hash: string): string {
  const hex = hash.startsWith("sha384:") ? hash.slice(7) : hash;
  if (hex.length < 12) return hash;
  return `sha384:${hex.slice(0, 8)}…${hex.slice(-6)}`;
}

export function isBoundQuote(traveler: Traveler, quote: { traveler_hash_quoted: string }): boolean {
  return quote.traveler_hash_quoted === travelerHash(traveler);
}
