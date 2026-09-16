import { boundQuotes } from "./conformance.ts";
import { pricedLine } from "./format.ts";
import { travelerHash } from "./hash.ts";
import type { Traveler, Quote, Shop } from "./types.ts";

export function isQuoteExpired(quote: Quote, now = new Date()): boolean {
  const t = Date.parse(quote.valid_until);
  if (Number.isNaN(t)) return true;
  return now.getTime() > t;
}

export function locked(traveler: Traveler): boolean {
  return Boolean(traveler.award) && Boolean(traveler.ops?.length) && Boolean(traveler.ship_to?.name);
}

export function cannotQuote(traveler: Traveler, quote: Quote): string | null {
  if (locked(traveler)) return "Executable travelers cannot take new quotes.";
  if (quote.traveler_hash_quoted !== travelerHash(traveler)) {
    return "Quote is not bound to the current traveler hash.";
  }
  if (traveler.itar && quote.seller.itar !== true) {
    return "ITAR traveler cannot be quoted by a seller that is not ITAR-registered.";
  }
  if ((traveler.quotes ?? []).some((q) => q.seller.org_id && q.seller.org_id === quote.seller.org_id && q.quote_id !== quote.quote_id)) {
    return "This seller already has a quote on this revision.";
  }
  return null;
}

export function cannotAward(traveler: Traveler, quote: Quote, now = new Date()): string | null {
  if (locked(traveler)) return "Traveler is already executable.";
  if (!boundQuotes(traveler).some((q) => q.quote_id === quote.quote_id)) {
    return "Quote is not bound to the current hash.";
  }
  if (isQuoteExpired(quote, now)) return "Quote has expired (valid_until).";
  if (traveler.itar && quote.seller.itar !== true) {
    return "Cannot award an ITAR traveler to a non-ITAR seller.";
  }
  if (!pricedLine(quote.pricing.lines, traveler.part.qty.target)) {
    return `Quote has no unit price at qty ${traveler.part.qty.target}.`;
  }
  return null;
}

export function cannotQuoteAs(traveler: Traveler, seller: Shop): string | null {
  if (traveler.itar && seller.itar !== true) {
    return `This traveler is ITAR. ${seller.name} is not ITAR-registered.`;
  }
  return null;
}

export function itarExportWarning(traveler: Traveler): string | null {
  if (!traveler.itar) return null;
  return "This traveler is self-declared ITAR. The desk does not implement export-control, deemed-export screening, or a Technology Control Plan. Do not transfer it to foreign persons.";
}
