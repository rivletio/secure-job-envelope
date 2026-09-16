import { sha256 } from "js-sha256";
import { canonicalJson } from "./canonical.ts";
import type { Org, Packet, Part, QuoteableBody } from "./types.ts";
import { PACKET_SPEC } from "./types.ts";

export const GOLDEN_HASH =
  "sha256:f1acf3b6822b1c27918d67c9aad36090b9fb90637e74db99b0bf52aea9ef2cd2";

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

export function quoteableBody(packet: Packet): QuoteableBody {
  return {
    spec: PACKET_SPEC,
    packet_id: packet.packet_id,
    revision: packet.revision,
    created_at: packet.created_at,
    buyer: quoteableOrg(packet.buyer),
    part: quoteablePart(packet.part),
    need_by: packet.need_by ?? null,
    incoterms: packet.incoterms ?? null,
    itar: packet.itar ?? false,
  };
}

export function packetHash(packet: Packet): string {
  return hashQuoteable(quoteableBody(packet));
}

export function hashQuoteable(body: QuoteableBody): string {
  return `sha256:${sha256(canonicalJson(body))}`;
}

export function sha256Hex(bytes: string): string {
  return `sha256:${sha256(bytes)}`;
}

export function shortHash(hash: string): string {
  const hex = hash.startsWith("sha256:") ? hash.slice(7) : hash;
  if (hex.length < 12) return hash;
  return `sha256:${hex.slice(0, 8)}…${hex.slice(-6)}`;
}

export function isBoundQuote(packet: Packet, quote: { packet_hash_quoted: string }): boolean {
  return quote.packet_hash_quoted === packetHash(packet);
}
