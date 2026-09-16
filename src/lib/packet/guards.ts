import { boundQuotes } from "./conformance.ts";
import { pricedLine } from "./format.ts";
import { packetHash } from "./hash.ts";
import type { Packet, Quote, Shop } from "./types.ts";

export function isQuoteExpired(quote: Quote, now = new Date()): boolean {
  const t = Date.parse(quote.valid_until);
  if (Number.isNaN(t)) return true;
  return now.getTime() > t;
}

export function locked(packet: Packet): boolean {
  return Boolean(packet.award) && Boolean(packet.ops?.length) && Boolean(packet.ship_to?.name);
}

export function cannotQuote(packet: Packet, quote: Quote): string | null {
  if (locked(packet)) return "Executable packets cannot take new quotes.";
  if (quote.packet_hash_quoted !== packetHash(packet)) {
    return "Quote is not bound to the current packet hash.";
  }
  if (packet.itar && quote.seller.itar !== true) {
    return "ITAR packet cannot be quoted by a seller that is not ITAR-registered.";
  }
  if ((packet.quotes ?? []).some((q) => q.seller.org_id && q.seller.org_id === quote.seller.org_id && q.quote_id !== quote.quote_id)) {
    return "This seller already has a quote on this revision.";
  }
  return null;
}

export function cannotAward(packet: Packet, quote: Quote, now = new Date()): string | null {
  if (locked(packet)) return "Packet is already executable.";
  if (!boundQuotes(packet).some((q) => q.quote_id === quote.quote_id)) {
    return "Quote is not bound to the current hash.";
  }
  if (isQuoteExpired(quote, now)) return "Quote has expired (valid_until).";
  if (packet.itar && quote.seller.itar !== true) {
    return "Cannot award an ITAR packet to a non-ITAR seller.";
  }
  if (!pricedLine(quote.pricing.lines, packet.part.qty.target)) {
    return `Quote has no unit price at qty ${packet.part.qty.target}.`;
  }
  return null;
}

export function cannotQuoteAs(packet: Packet, seller: Shop): string | null {
  if (packet.itar && seller.itar !== true) {
    return `This packet is ITAR. ${seller.name} is not ITAR-registered.`;
  }
  return null;
}

export function itarExportWarning(packet: Packet): string | null {
  if (!packet.itar) return null;
  return "This packet is self-declared ITAR. The desk does not implement export-control, deemed-export screening, or a Technology Control Plan. Do not transfer it to foreign persons.";
}
