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

export function cannotQuote(traveler: Traveler, quote: Quote, now = new Date()): string | null {
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
  // …and only quotes that are still LIVE: an expired quote can no longer be awarded, so
  // it must not stop its own seller from replacing it (it used to — the seller was shut
  // out of the revision for good once its quote lapsed).
  const holdsTheSlot = (q: Quote) =>
    !isQuoteExpired(q, now) &&
    Boolean(q.seller.org_id) &&
    q.seller.org_id === quote.seller.org_id &&
    q.quote_id !== quote.quote_id;
  if (boundQuotes(traveler).some(holdsTheSlot)) {
    return "This seller already has a live quote on this revision.";
  }
  return null;
}

/** Why `quote` cannot be awarded for `qty` parts — or `null` if it can. `qty` is the
 *  quantity the award is for (the traveler's target unless the caller awards another
 *  priced quantity). The quote must carry a price for exactly that quantity: it is the
 *  rule verification applies to a signed award (`verifyAwardSignature`), so an award this
 *  guard lets through is one that can verify. It used to ask for a price at the TARGET
 *  quantity whatever was being awarded — refusing a priced break quantity when the
 *  target was not quoted, and saying nothing about the quantity actually awarded. */
export function cannotAward(
  traveler: Traveler,
  quote: Quote,
  now = new Date(),
  qty: number = traveler.part.qty.target,
): string | null {
  return awardBlockerIn(awardState(traveler), traveler, quote, now, qty);
}

/** `cannotAward` for every quote on the traveler, in order — with the traveler's own
 *  state (is it locked; which quotes are bound) established ONCE.
 *
 *  Establishing it validates every quote, so asking `cannotAward` once per quote did
 *  that once per quote: quadratic. A traveler inside every size cap — 60 quotes, each
 *  with an 8 KiB free-form object — took six seconds to evaluate. */
export function awardBlockers(
  traveler: Traveler,
  now = new Date(),
  qty: number = traveler.part.qty.target,
): { quote_id: string; blocker: string | null }[] {
  const state = awardState(traveler);
  return (traveler.quotes ?? []).map((quote) => ({
    quote_id: quote.quote_id,
    blocker: awardBlockerIn(state, traveler, quote, now, qty),
  }));
}

/** What an award guard needs to know about the traveler itself, whatever the quote. */
type AwardState = { locked: boolean; bound: ReadonlySet<string> };

function awardState(traveler: Traveler): AwardState {
  return {
    locked: locked(traveler),
    bound: new Set(boundQuotes(traveler).map((q) => q.quote_id)),
  };
}

function awardBlockerIn(
  state: AwardState,
  traveler: Traveler,
  quote: Quote,
  now: Date,
  qty: number,
): string | null {
  if (state.locked) return "Traveler is already executable.";
  if (!state.bound.has(quote.quote_id)) return "Quote is not bound to the current hash.";
  if (isQuoteExpired(quote, now)) return "Quote has expired (valid_until).";
  if (traveler.itar && quote.seller.itar !== true) {
    return "Cannot award an ITAR traveler to a non-ITAR seller.";
  }
  if (!pricedLine(quote.pricing.lines, qty)) {
    return `Quote has no unit price at qty ${String(qty)}.`;
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
