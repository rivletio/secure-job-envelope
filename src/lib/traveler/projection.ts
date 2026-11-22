/** What a recipient is entitled to see of a traveler — applied when one is sealed.
 *
 *  A traveler accumulates every seller's quote, and the whole traveler used to be the
 *  unit of exchange. So a buyer re-sending an RFQ handed seller B seller A's price, and
 *  the winner's copy carried every losing bid; a losing bidder learned who won and where
 *  the parts ship. None of that is needed for the recipient to do its job, and none of
 *  it is covered by a signature that would break without it: the traveler hash and the
 *  buyer's authorship signature cover the quoteable body only, and an award signature
 *  covers the award, the ship-to and the awarded quote's content hash.
 *
 *  The rule:
 *    - The traveler's buyer receives everything.
 *    - Anyone else receives the quoteable body and its signatures, the quotes that are
 *      ITS OWN (`seller.org_id` is the recipient) or the SENDER's own, and — only if the
 *      awarded quote is one of those — the award, ship-to, ops and as-built data.
 *
 *  Org ids here are the document's own claims; this decides what to DISCLOSE, not whom to
 *  trust. A quote that names no seller org belongs to nobody identifiable and is sent
 *  only to the buyer.
 */
import type { Traveler } from "./types.ts";

export type Projection = {
  /** What to seal for this recipient. A valid traveler with the same hash. */
  traveler: Traveler;
  /** What was left out, so a sender can be shown it. */
  withheld: { quotes: number; award: boolean };
};

export function projectForRecipient(
  traveler: Traveler,
  recipientOrg: string,
  opts: { senderOrg?: string } = {},
): Projection {
  if (traveler.buyer.org_id !== undefined && traveler.buyer.org_id === recipientOrg) {
    return { traveler, withheld: { quotes: 0, award: false } };
  }
  const mine = (org: string | undefined): boolean =>
    org !== undefined && (org === recipientOrg || org === opts.senderOrg);
  const all = traveler.quotes ?? [];
  const kept = all.filter((q) => mine(q.seller.org_id));
  const keepAward =
    traveler.award != null && kept.some((q) => q.quote_id === traveler.award!.quote_id);
  const withholdAward = traveler.award != null && !keepAward;

  const { quotes: _quotes, ...rest } = traveler;
  void _quotes;
  let out: Traveler = kept.length ? { ...rest, quotes: kept } : rest;
  if (withholdAward) {
    // Who won, where it ships, how it will be made and how it turned out are the
    // winner's business. (Before an award, ship-to and ops are the buyer's drafts and
    // travel with the RFQ as the buyer left them.)
    const { award: _a, ship_to: _s, ops: _o, as_built: _b, ...body } = out;
    void _a;
    void _s;
    void _o;
    void _b;
    out = body;
  }
  return { traveler: out, withheld: { quotes: all.length - kept.length, award: withholdAward } };
}

/** What a projection left out, in words for the person sealing — or null when it left
 *  nothing out. Counts only: nothing here is taken from the document's text. */
export function withheldSummary(withheld: Projection["withheld"]): string | null {
  const parts: string[] = [];
  if (withheld.quotes > 0) {
    parts.push(
      withheld.quotes === 1
        ? "1 quote that is neither the recipient's nor yours"
        : `${withheld.quotes} quotes that are neither the recipient's nor yours`,
    );
  }
  if (withheld.award) parts.push("the award, with its ship-to, ops and as-built data");
  return parts.length > 0 ? parts.join(", and ") : null;
}
