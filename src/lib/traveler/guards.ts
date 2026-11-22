import { boundQuotes, levelOf, type LevelInfo } from "./conformance.ts";
import { isoDateTimeMs } from "./datetime.ts";
import { pricedLine } from "./format.ts";
import { travelerHash } from "./hash.ts";
import type { Traveler, Quote, Shop } from "./types.ts";

export function isQuoteExpired(quote: Quote, now = new Date()): boolean {
  // Strict shared datetime parse (== Rust rfc3339_millis), not lenient Date.parse, so
  // quote expiry reads the same instant as the rest of the core; fail closed (treat an
  // unparseable valid_until as expired).
  const t = isoDateTimeMs(quote.valid_until);
  if (t === null) return true;
  return now.getTime() > t;
}

/** THE definition of "locked": a traveler is locked exactly when it is executable —
 *  conformance level 2 or above, i.e. an award that names a quote bound to the current
 *  revision, at least one op, and a complete ship-to (see `levelOf`).
 *
 *  This is the only place the rule is written. The guards below, the desk store, the
 *  MCP tools and every UI component ask this function (or `lockedAtLevel` when they
 *  already hold the level), so "locked" can never disagree with the level a reader is
 *  shown. It used to be spelled three ways; one of them — award && ops && ship_to.name
 *  — called a traveler locked while the ladder said L0 or L1, when its award named a
 *  quote that is stale or not on the traveler at all. Such an award is not in effect:
 *  the traveler stays quotable, amendable and awardable (see `awardStanding`). */
export function locked(traveler: Traveler): boolean {
  return lockedAtLevel(levelOf(traveler));
}

/** The same definition for a caller that already computed the level. */
export function lockedAtLevel(info: Pick<LevelInfo, "level">): boolean {
  return info.level >= 2;
}

/** Where a traveler's award record stands, so every surface describes it the same way:
 *  - `none`       no award;
 *  - `in-effect`  the traveler is locked (L2+): the award names a bound quote and the
 *                 ops and ship-to are complete;
 *  - `incomplete` the award names a bound quote, but the traveler is not executable
 *                 yet (`missing` says what L2 still needs);
 *  - `void`       the award names a quote that is not bound to the current revision:
 *                 `stale` (on the traveler, but not bound — priced against another
 *                 revision) or `absent` (not on the traveler). Such an award is not in
 *                 effect and locks nothing. */
export type AwardStanding =
  | { state: "none" }
  | { state: "in-effect"; quote: Quote }
  | { state: "incomplete"; quote: Quote; missing: string[] }
  | { state: "void"; quote_id: string; reason: "stale" | "absent" };

export function awardStanding(traveler: Traveler): AwardStanding {
  const award = traveler.award;
  if (!award) return { state: "none" };
  const quote = boundQuotes(traveler).find((q) => q.quote_id === award.quote_id);
  if (!quote) {
    const held = (traveler.quotes ?? []).some((q) => q.quote_id === award.quote_id);
    return { state: "void", quote_id: award.quote_id, reason: held ? "stale" : "absent" };
  }
  const info = levelOf(traveler);
  if (lockedAtLevel(info)) return { state: "in-effect", quote };
  return { state: "incomplete", quote, missing: info.missing };
}

export function cannotQuote(traveler: Traveler, quote: Quote): string | null {
  if (locked(traveler)) return "Executable travelers cannot take new quotes.";
  if (quote.traveler_hash_quoted !== travelerHash(traveler)) {
    return "Quote is not bound to the current traveler hash.";
  }
  if (traveler.itar && quote.seller.itar !== true) {
    return "ITAR traveler cannot be quoted by a seller that has not self-declared ITAR.";
  }
  // One quote per seller per REVISION, so only quotes bound to the current hash count.
  // A stale quote is history from an earlier revision: counting it stopped a seller
  // from ever re-quoting after an amend, and let anyone lock a rival out by planting an
  // unbound quote under the rival's org_id.
  if (boundQuotes(traveler).some((q) => q.seller.org_id && q.seller.org_id === quote.seller.org_id && q.quote_id !== quote.quote_id)) {
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
    return `This traveler is ITAR. ${seller.name} has not self-declared ITAR.`;
  }
  return null;
}

export function itarExportWarning(traveler: Traveler): string | null {
  if (!traveler.itar) return null;
  return "This traveler is self-declared ITAR. The desk does not implement export-control, deemed-export screening, or a Technology Control Plan. Do not transfer it to foreign persons.";
}
