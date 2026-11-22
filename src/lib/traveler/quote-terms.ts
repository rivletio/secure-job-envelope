/** Everything a quote says, laid out for the person about to award it.
 *
 *  An award carries `quote_hash` — the hash of the whole quote minus its signature —
 *  and the buyer's signature covers that hash. So awarding commits the buyer to every
 *  field of the quote, not to the handful a summary happens to print. The desk used to
 *  print the unit price, lead time, NRE and the text of each exception; a quote whose
 *  card read "$14.20 /ea" could carry an exception with a price delta of $2,500,000, a
 *  material surcharge buried in `assumptions`, or a `valid_until` already past, and
 *  none of it was on screen.
 *
 *  `quoteTerms` turns a quote into the complete, display-ready account of it: every
 *  field of the signed body appears, already formatted, with the total at the awarded
 *  quantity worked out exactly and itemized. The traveler page and the award dialog
 *  both render this one model, so what the buyer reads on the card is what the dialog
 *  asks them to commit to. quote-terms.test.ts holds the model to the schema: a field
 *  added to a quote and not shown here fails the suite.
 */
import { money, pricedLine } from "./format.ts";
import { isQuoteExpired } from "./guards.ts";
import type { Quote } from "./types.ts";

/** Every member of a quote, and where the model shows it. `sig` is the one member not
 *  shown here: it is outside the hashed body and the Authenticity panel reports it. */
export const QUOTE_MEMBERS_SHOWN = [
  "quote_id",
  "seller",
  "traveler_hash_quoted",
  "created_at",
  "valid_until",
  "lead_time_days",
  "need_by_feasible",
  "pricing",
  "assumptions",
  "exceptions",
  "capacity",
] as const;
export const SELLER_MEMBERS_SHOWN = ["org_id", "name", "city", "region", "contact", "certs", "itar"] as const;
export const PRICING_MEMBERS_SHOWN = ["currency", "nre", "lines", "freight_estimate", "tax_excluded"] as const;
export const EXCEPTION_MEMBERS_SHOWN = ["code", "on", "proposal", "price_delta"] as const;

const NOT_STATED = "not stated";
const EXACT = { minorDigits: "always" } as const;

export type TotalRow = { label: string; detail: string; amount: string };

export type QuoteTerms = {
  quoteId: string;
  /** The traveler hash this quote says it priced. */
  travelerHashQuoted: string;
  seller: {
    /** As written in the quote. The desk does not verify it; `orgId` is the handle a
     *  key directory can attest. */
    name: string;
    orgId: string | null;
    place: string | null;
    contact: string | null;
    certs: string[];
    itar: string;
  };
  currency: string;
  quotedOn: string;
  validUntil: string;
  expired: boolean;
  leadTime: string;
  needBy: string;
  nre: string;
  freight: string;
  tax: string;
  /** Every price line, in the order the quote lists them. */
  lines: Array<{ qty: number; unit: string; extended: string; atQty: boolean }>;
  /** The unit price at `total.qty`, or null when the quote does not price it. */
  unitAtQty: string | null;
  total: {
    qty: number;
    /** One row per component of the total; nothing is folded into another row. */
    rows: TotalRow[];
    /** Null when the quote has no price line at exactly `qty`. */
    total: string | null;
    negative: boolean;
    notes: string[];
  };
  exceptions: Array<{
    code: string;
    on: string | null;
    proposal: string;
    /** Signed, e.g. "+$2.40"; null when the exception states no price delta. */
    priceDelta: string | null;
  }>;
  /** Escaped JSON text of the free-form blobs, or null when the quote has none. */
  assumptions: string | null;
  capacity: string | null;
};

/** `2026-12-13T09:30:00.000Z` as `2026-12-13 09:30 UTC` — read straight off the
 *  validated string, so the reader's time zone cannot move it to another day. */
export function utcStamp(iso: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(iso);
  if (!m) return iso;
  return `${m[1]} ${m[2]}${m[3] === "00" ? "" : `:${m[3]}`} UTC`;
}

// Anything a reader cannot see, or that changes how its neighbours are drawn: control
// and format characters (bidi overrides, zero-width joiners, tags), unassigned and
// private-use code points, line/paragraph separators, default-ignorable code points
// (variation selectors, fillers), and every space that is not U+0020.
const HIDDEN = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]|[^\S\n ]/gu;

function jsonEscape(ch: string): string {
  let out = "";
  for (let i = 0; i < ch.length; i++) out += `\\u${ch.charCodeAt(i).toString(16).padStart(4, "0")}`;
  return out;
}

/** A free-form blob (`assumptions`, `capacity`) as indented JSON text in which nothing
 *  is invisible: every hidden or direction-changing character is written as its
 *  `\uXXXX` escape. The result is still JSON for exactly the same value — escapes are
 *  only ever substituted inside string literals, where JSON reads them back — so what
 *  is displayed is the content, not a rendering an attacker shaped. It is text: render
 *  it as a text node, never as markup. */
export function blobText(blob: unknown): string {
  const json = JSON.stringify(blob, null, 2) ?? "null";
  // JSON.stringify has already escaped every control character inside a string, so a
  // raw newline here is one of its own line breaks between members: keep those.
  return json.replace(HIDDEN, (ch) => (ch === "\n" ? ch : jsonEscape(ch)));
}

function days(n: number): string {
  return `${n} day${n === 1 ? "" : "s"}`;
}

/** The complete terms of `quote`, with the total worked out at `qty` (the quantity an
 *  award would be for). Amounts are exact: integer minor units, summed as BigInt —
 *  qty × unit alone can pass 2^53. */
export function quoteTerms(quote: Quote, qty: number, now = new Date()): QuoteTerms {
  const { pricing, seller } = quote;
  const currency = pricing.currency;
  const exact = (minor: number | bigint) => money(minor, currency, EXACT);

  const line = pricedLine(pricing.lines, qty);
  const parts = line ? BigInt(line.qty) * BigInt(line.unit) : null;
  const nre = BigInt(pricing.nre ?? 0);
  const freight = BigInt(pricing.freight_estimate ?? 0);
  const deltas = (quote.exceptions ?? []).filter((ex) => ex.price_delta !== undefined);
  const deltaSum = deltas.reduce((sum, ex) => sum + BigInt(ex.price_delta!), 0n);
  const total = parts === null ? null : parts + nre + freight + deltaSum;

  const rows: TotalRow[] = [
    line
      ? { label: "Parts", detail: `${line.qty} × ${exact(line.unit)}`, amount: exact(parts!) }
      : { label: "Parts", detail: `no unit price at qty ${qty}`, amount: "—" },
    {
      label: "NRE",
      detail: pricing.nre === undefined ? NOT_STATED : "one-time",
      amount: exact(nre),
    },
    {
      label: "Freight estimate",
      detail: pricing.freight_estimate === undefined ? NOT_STATED : "seller's estimate",
      amount: exact(freight),
    },
    ...deltas.map((ex) => ({
      label: `Exception ${ex.code}`,
      detail: "price delta",
      amount: money(ex.price_delta!, currency, { ...EXACT, sign: true }),
    })),
  ];

  const notes: string[] = [];
  if (deltas.length > 0) {
    notes.push(
      "Each exception price delta is counted once, as the seller stated it. sje/0.1.0 does not define whether a delta is per unit or for the lot — confirm with the seller.",
    );
  }
  if (pricing.tax_excluded === true) notes.push("Tax is excluded: these amounts are before tax.");
  else if (pricing.tax_excluded === false) notes.push("The seller states that tax is not excluded from these amounts.");
  else notes.push("The seller does not say whether tax is included.");
  if (total !== null && total < 0n) notes.push("The price deltas outweigh the price: this total is negative.");

  return {
    quoteId: quote.quote_id,
    travelerHashQuoted: quote.traveler_hash_quoted,
    seller: {
      name: seller.name,
      orgId: seller.org_id ?? null,
      place: [seller.city, seller.region].filter(Boolean).join(", ") || null,
      contact: seller.contact ?? null,
      certs: seller.certs ?? [],
      itar: seller.itar === true ? "yes (self-declared)" : seller.itar === false ? "no (self-declared)" : NOT_STATED,
    },
    currency,
    quotedOn: utcStamp(quote.created_at),
    validUntil: utcStamp(quote.valid_until),
    expired: isQuoteExpired(quote, now),
    leadTime: days(quote.lead_time_days),
    needBy:
      quote.need_by_feasible === true
        ? "feasible"
        : quote.need_by_feasible === false
          ? "not feasible"
          : NOT_STATED,
    nre: pricing.nre === undefined ? NOT_STATED : exact(nre),
    freight: pricing.freight_estimate === undefined ? NOT_STATED : exact(freight),
    tax:
      pricing.tax_excluded === true
        ? "excluded"
        : pricing.tax_excluded === false
          ? "not excluded"
          : NOT_STATED,
    lines: pricing.lines.map((l) => ({
      qty: l.qty,
      unit: exact(l.unit),
      extended: exact(BigInt(l.qty) * BigInt(l.unit)),
      atQty: l.qty === qty,
    })),
    unitAtQty: line ? exact(line.unit) : null,
    total: {
      qty,
      rows,
      total: total === null ? null : exact(total),
      negative: total !== null && total < 0n,
      notes,
    },
    exceptions: (quote.exceptions ?? []).map((ex) => ({
      code: ex.code,
      on: ex.on ?? null,
      proposal: ex.proposal,
      priceDelta:
        ex.price_delta === undefined ? null : money(ex.price_delta, currency, { ...EXACT, sign: true }),
    })),
    assumptions: quote.assumptions === undefined ? null : blobText(quote.assumptions),
    capacity: quote.capacity === undefined ? null : blobText(quote.capacity),
  };
}
