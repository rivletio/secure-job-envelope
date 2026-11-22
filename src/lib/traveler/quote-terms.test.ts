/** An award commits to the whole quote (via `quote_hash`), so the buyer must be shown
 *  the whole quote. These tests hold `quoteTerms` — the one model the quote cards and
 *  the award dialog render — to that:
 *   - every member the quote schema defines is accounted for, and every value of a
 *     fully-populated quote appears in the model (a field added to the schema and not
 *     shown fails here);
 *   - the total at the awarded quantity is exact and itemized: its rows add up to it,
 *     and it includes NRE, freight and every exception price delta;
 *   - a free-form blob is rendered as JSON text with nothing invisible in it.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { boundQuotes, parseQuote, parseTraveler } from "./conformance.ts";
import { seedTravelers } from "./fixtures.ts";
import { money } from "./format.ts";
import { travelerHash } from "./hash.ts";
import {
  EXCEPTION_MEMBERS_SHOWN,
  PRICING_MEMBERS_SHOWN,
  QUOTE_MEMBERS_SHOWN,
  SELLER_MEMBERS_SHOWN,
  blobText,
  quoteTerms,
  utcStamp,
  type QuoteTerms,
} from "./quote-terms.ts";
import { quoteSchema } from "./schema.ts";
import type { Quote, Traveler } from "./types.ts";

const base: Traveler = parseTraveler(
  JSON.parse(readFileSync(new URL("../../../conformance/travelers/l0-bracket.json", import.meta.url), "utf8")),
);
const NOW = new Date("2026-11-01T00:00:00.000Z");

/** Every string the model would put on screen, in one text. */
function shown(model: QuoteTerms): string {
  const out: string[] = [];
  const walk = (v: unknown) => {
    if (typeof v === "string") out.push(v);
    else if (typeof v === "number") out.push(String(v));
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(model);
  return out.join("\n");
}

/** A displayed USD amount back to integer cents (exact). */
function cents(amount: string): bigint {
  const m = /^([+-]?)\$([0-9,]+)\.([0-9]{2})$/.exec(amount);
  assert.ok(m, `not a full-precision USD amount: ${amount}`);
  const n = BigInt(m[2]!.replaceAll(",", "") + m[3]!);
  return m[1] === "-" ? -n : n;
}

function quote(over: Partial<Quote> = {}): Quote {
  return parseQuote({
    quote_id: "qot_terms00001",
    seller: { org_id: "org_huron", name: "Huron Precision" },
    traveler_hash_quoted: travelerHash(base),
    created_at: "2026-09-16T12:00:00.000Z",
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: { currency: "USD", lines: [{ qty: 250, unit: 1420 }] },
    ...over,
  });
}

describe("the terms of a quote — everything an award commits to", () => {
  it("shows the terms the desk used to leave out (the audit's quote: $14.20/ea on the card, $2,500,000 in an exception)", () => {
    const q = quote({
      seller: { org_id: "org_someoneelse", name: "Huron Precision" },
      need_by_feasible: true,
      pricing: { currency: "USD", nre: 0, lines: [{ qty: 250, unit: 1420 }], tax_excluded: true },
      exceptions: [
        { code: "NOTE", proposal: "Standard packaging.", price_delta: 250_000_000, on: "pricing.lines[250].unit" },
      ],
      assumptions: { unit_price_excludes_material: true, material_surcharge_minor_per_ea: 99_900, min_order_qty: 5000 },
      capacity: { earliest_start: "2027-06-01" },
    });
    const terms = quoteTerms(q, 250, NOW);

    // What the old card showed, still there…
    assert.equal(terms.unitAtQty, "$14.20");
    assert.equal(terms.seller.name, "Huron Precision");
    // …and what it did not: who is behind that name,
    assert.equal(terms.seller.orgId, "org_someoneelse");
    // the exception's price and what it attaches to,
    assert.deepEqual(terms.exceptions, [
      { code: "NOTE", on: "pricing.lines[250].unit", proposal: "Standard packaging.", priceDelta: "+$2,500,000.00" },
    ]);
    // a total that includes it, itemized,
    assert.deepEqual(terms.total.rows, [
      { label: "Parts", detail: "250 × $14.20", amount: "$3,550.00" },
      { label: "NRE", detail: "one-time", amount: "$0.00" },
      { label: "Freight estimate", detail: "not stated", amount: "$0.00" },
      { label: "Exception NOTE", detail: "price delta", amount: "+$2,500,000.00" },
    ]);
    assert.equal(terms.total.total, "$2,503,550.00");
    assert.equal(terms.total.qty, 250);
    // the seller's own free-form terms,
    assert.match(terms.assumptions!, /"material_surcharge_minor_per_ea": 99900/);
    assert.match(terms.assumptions!, /"min_order_qty": 5000/);
    assert.match(terms.assumptions!, /"unit_price_excludes_material": true/);
    assert.match(terms.capacity!, /"earliest_start": "2027-06-01"/);
    // and the tax and validity terms.
    assert.equal(terms.tax, "excluded");
    assert.equal(terms.validUntil, "2039-01-01 00:00 UTC");
    assert.equal(terms.expired, false);
  });

  it("accounts for every member the quote schema defines", () => {
    // If the schema gains a member, it must be added to quoteTerms (and to these lists)
    // before this passes: nothing a quote can carry is left out by default.
    assert.deepEqual(
      Object.keys(quoteSchema.shape).filter((k) => k !== "sig").sort(),
      [...QUOTE_MEMBERS_SHOWN].sort(),
    );
    assert.deepEqual(Object.keys(quoteSchema.shape.seller.shape).sort(), [...SELLER_MEMBERS_SHOWN].sort());
    assert.deepEqual(Object.keys(quoteSchema.shape.pricing.shape).sort(), [...PRICING_MEMBERS_SHOWN].sort());
    assert.deepEqual(
      Object.keys(quoteSchema.shape.exceptions.unwrap().element.shape).sort(),
      [...EXCEPTION_MEMBERS_SHOWN].sort(),
    );
    assert.deepEqual(Object.keys(quoteSchema.shape.pricing.shape.lines.element.shape).sort(), ["qty", "unit"]);
  });

  it("puts every value of a fully-populated quote on screen", () => {
    // One distinctive value per member, so each can be looked for.
    const q = quote({
      quote_id: "qot_everything1",
      seller: {
        org_id: "org_fullshop",
        name: "Full Disclosure Machining",
        city: "Kalamazoo",
        region: "MI",
        contact: "quotes@fullshop.example",
        certs: ["AS9100D", "NADCAP-HT"],
        itar: true,
      },
      created_at: "2026-10-03T08:15:00.000Z",
      valid_until: "2026-12-24T17:45:30.000Z",
      lead_time_days: 37,
      need_by_feasible: false,
      pricing: {
        currency: "USD",
        nre: 123_456,
        lines: [
          { qty: 100, unit: 1877 },
          { qty: 250, unit: 1433 },
          { qty: 500, unit: 1199 },
        ],
        freight_estimate: 7_891,
        tax_excluded: false,
      },
      exceptions: [
        { code: "MATL_SUB", on: "part.material.spec", proposal: "6061-T651 in place of T6.", price_delta: -4_321 },
        { code: "FAI_EXTRA", proposal: "Full FAI report billed separately.", price_delta: 55_500 },
        { code: "PACKAGING", on: "part.notes", proposal: "Bulk pack unless specified." },
      ],
      assumptions: { tooling_owned_by: "seller", scrap_allowance_pct: 3.5, nested: { resale_cert: "required" } },
      capacity: { spindle_hours_open: 412, second_shift: false },
    });
    const terms = quoteTerms(q, 250, NOW);
    const text = shown(terms);
    const expected = [
      // identity and binding
      "qot_everything1",
      q.traveler_hash_quoted,
      // seller
      "org_fullshop",
      "Full Disclosure Machining",
      "Kalamazoo, MI",
      "quotes@fullshop.example",
      "AS9100D",
      "NADCAP-HT",
      "yes (self-declared)",
      // dates, lead, feasibility
      "2026-10-03 08:15 UTC",
      "2026-12-24 17:45:30 UTC",
      "37 days",
      "not feasible",
      // pricing
      "USD",
      "$1,234.56",
      "$78.91",
      "not excluded",
      "$18.77",
      "$1,877.00",
      "$14.33",
      "$3,582.50",
      "$11.99",
      "$5,995.00",
      // exceptions, each member
      "MATL_SUB",
      "part.material.spec",
      "6061-T651 in place of T6.",
      "-$43.21",
      "FAI_EXTRA",
      "Full FAI report billed separately.",
      "+$555.00",
      "PACKAGING",
      "part.notes",
      "Bulk pack unless specified.",
      // blobs, keys and values
      '"tooling_owned_by": "seller"',
      '"scrap_allowance_pct": 3.5',
      '"resale_cert": "required"',
      '"spindle_hours_open": 412',
      '"second_shift": false',
    ];
    for (const s of expected) assert.ok(text.includes(s), `not shown: ${s}`);
    assert.deepEqual(
      terms.lines.map((l) => [l.qty, l.atQty]),
      [
        [100, false],
        [250, true],
        [500, false],
      ],
      "every price line is listed, and the one the total uses is marked",
    );
    assert.equal(terms.exceptions[2]!.priceDelta, null, "an exception without a delta says so, not $0");
    // 3,582.50 + 1,234.56 + 78.91 − 43.21 + 555.00
    assert.equal(terms.total.total, "$5,407.76");
  });

  it("the seeded Red River quote: its exception delta is in the total, not just in a footnote", () => {
    const bracket = seedTravelers().find((t) => t.traveler_id === "tvl_nlbrk4410")!;
    const redRiver = boundQuotes(bracket).find((q) => q.seller.org_id === "org_redriver")!;
    const terms = quoteTerms(redRiver, bracket.part.qty.target, new Date());
    assert.deepEqual(terms.total.rows, [
      { label: "Parts", detail: "50 × $31.00", amount: "$1,550.00" },
      { label: "NRE", detail: "one-time", amount: "$500.00" },
      { label: "Freight estimate", detail: "seller's estimate", amount: "$110.00" },
      { label: "Exception FINISH_OUTSOURCE", detail: "price delta", amount: "+$2.40" },
    ]);
    assert.equal(terms.total.total, "$2,162.40");
    assert.ok(terms.total.notes.some((n) => /per unit or for the lot/.test(n)), "the delta's basis is flagged");
  });
});

describe("the total at the awarded quantity", () => {
  it("is itemized: the rows add up to the total, whatever the quote", () => {
    // Deterministic PRNG (mulberry32): the same 400 quotes on every run.
    let a = 7;
    const next = () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (max: number) => Math.floor(next() * (max + 1));
    for (let i = 0; i < 400; i++) {
      const qty = 1 + int(999_999);
      const q = quote({
        pricing: {
          currency: "USD",
          lines: [{ qty, unit: int(1_000_000_000_000) }],
          ...(next() < 0.7 ? { nre: int(1_000_000_000_000) } : {}),
          ...(next() < 0.7 ? { freight_estimate: int(50_000_000) } : {}),
        },
        exceptions: Array.from({ length: int(4) }, (_, k) => ({
          code: `EX${k}`,
          proposal: "p",
          ...(next() < 0.8 ? { price_delta: int(2_000_000_000) - 1_000_000_000 } : {}),
        })),
      });
      const terms = quoteTerms(q, qty, NOW);
      const sum = terms.total.rows.reduce((acc, row) => acc + cents(row.amount), 0n);
      assert.equal(cents(terms.total.total!), sum, `quote ${i}`);
      // and it is the sum of the quote's own numbers, exactly
      const direct =
        BigInt(qty) * BigInt(q.pricing.lines[0]!.unit) +
        BigInt(q.pricing.nre ?? 0) +
        BigInt(q.pricing.freight_estimate ?? 0) +
        (q.exceptions ?? []).reduce((acc, ex) => acc + BigInt(ex.price_delta ?? 0), 0n);
      assert.equal(sum, direct, `quote ${i}`);
      assert.equal(terms.total.negative, direct < 0n);
      // one row per delta-carrying exception: none is folded into another
      assert.equal(
        terms.total.rows.length,
        3 + (q.exceptions ?? []).filter((ex) => ex.price_delta !== undefined).length,
      );
    }
  });

  it("is exact past 2^53, where the old float rollup was not", () => {
    const q = quote({
      pricing: {
        currency: "USD",
        nre: 1,
        freight_estimate: 1,
        lines: [{ qty: 1_000_000, unit: 999_999_999_999 }],
      },
    });
    const terms = quoteTerms(q, 1_000_000, NOW);
    assert.equal(terms.total.total, "$9,999,999,999,990,000.02");
    assert.equal(Number.isSafeInteger(1_000_000 * 999_999_999_999 + 2), false, "this sum is beyond a double");
  });

  it("says so when the quote does not price the awarded quantity — no fallback to another line", () => {
    const q = quote({ pricing: { currency: "USD", nre: 5000, lines: [{ qty: 100_000, unit: 1 }] } });
    const terms = quoteTerms(q, 50, NOW);
    assert.equal(terms.unitAtQty, null, "the old card showed lines[0]'s $0.01 as the unit price here");
    assert.equal(terms.total.total, null, "and a rollup of just NRE + freight");
    assert.deepEqual(terms.total.rows[0], { label: "Parts", detail: "no unit price at qty 50", amount: "—" });
    assert.deepEqual(terms.lines, [{ qty: 100_000, unit: "$0.01", extended: "$1,000.00", atQty: false }]);
  });

  it("a negative total is flagged, not hidden", () => {
    const q = quote({ exceptions: [{ code: "REBATE", proposal: "Volume rebate.", price_delta: -1_000_000 }] });
    const terms = quoteTerms(q, 250, NOW);
    assert.equal(terms.total.total, "-$6,450.00");
    assert.equal(terms.total.negative, true);
    assert.ok(terms.total.notes.some((n) => /negative/.test(n)));
  });

  it("uses the quote's own currency and its ISO exponent", () => {
    const q = quote({ pricing: { currency: "KWD", nre: 1500, lines: [{ qty: 250, unit: 1420 }] } });
    const terms = quoteTerms(q, 250, NOW);
    assert.equal(terms.currency, "KWD");
    assert.equal(terms.unitAtQty, money(1420, "KWD", { minorDigits: "always" }));
    assert.match(terms.unitAtQty!, /^KWD.1\.420$/);
    assert.match(terms.total.total!, /^KWD.356\.500$/);
  });
});

describe("absent is not the same as false", () => {
  it("an unstated need-by, tax, NRE or freight reads as not stated", () => {
    const terms = quoteTerms(quote(), 250, NOW);
    assert.equal(terms.needBy, "not stated", "the old card printed 'not feasible' for an absent flag");
    assert.equal(terms.tax, "not stated");
    assert.equal(terms.nre, "not stated", "the old card printed NRE $0");
    assert.equal(terms.freight, "not stated");
    assert.equal(terms.seller.itar, "not stated");
    assert.equal(terms.seller.place, null);
    assert.equal(terms.seller.contact, null);
    assert.deepEqual(terms.exceptions, []);
    assert.equal(terms.assumptions, null);
    assert.equal(terms.capacity, null);
    assert.ok(terms.total.notes.some((n) => /does not say whether tax/.test(n)));
  });

  it("a stated false reads as stated", () => {
    const terms = quoteTerms(
      quote({
        seller: { name: "No Org Shop", itar: false },
        need_by_feasible: false,
        pricing: { currency: "USD", nre: 0, freight_estimate: 0, tax_excluded: false, lines: [{ qty: 250, unit: 1 }] },
        assumptions: {},
      }),
      250,
      NOW,
    );
    assert.equal(terms.needBy, "not feasible");
    assert.equal(terms.tax, "not excluded");
    assert.equal(terms.nre, "$0.00");
    assert.equal(terms.freight, "$0.00");
    assert.equal(terms.seller.itar, "no (self-declared)");
    assert.equal(terms.seller.orgId, null, "a quote with no org_id is shown as having none");
    assert.equal(terms.assumptions, "{}", "an empty blob is still part of the quote");
  });
});

describe("expiry", () => {
  const q = quote({ created_at: "2026-10-01T00:00:00.000Z", valid_until: "2026-10-15T12:00:00.000Z" });

  it("a quote past valid_until is marked expired, as of the instant asked", () => {
    assert.equal(quoteTerms(q, 250, new Date("2026-10-15T11:59:59.999Z")).expired, false);
    assert.equal(quoteTerms(q, 250, new Date("2026-10-15T12:00:00.000Z")).expired, false);
    assert.equal(quoteTerms(q, 250, new Date("2026-10-15T12:00:00.001Z")).expired, true);
    assert.equal(quoteTerms(q, 250, new Date("2026-10-15T12:00:00.001Z")).validUntil, "2026-10-15 12:00 UTC");
  });

  it("utcStamp reads the instant off the string, in UTC, whatever the local zone", () => {
    assert.equal(utcStamp("2026-12-13T09:30:00.000Z"), "2026-12-13 09:30 UTC");
    assert.equal(utcStamp("2026-12-13T00:00:00Z"), "2026-12-13 00:00 UTC");
    assert.equal(utcStamp("2026-12-13T23:59:59.999Z"), "2026-12-13 23:59:59 UTC");
    assert.equal(utcStamp("not a date"), "not a date");
  });
});

describe("blobText — a free-form blob as text, with nothing invisible in it", () => {
  const cp = (...points: number[]) => String.fromCodePoint(...points);
  // Built from code points: none of these characters appears in this file.
  const HIDDEN: Record<string, string> = {
    "right-to-left override": cp(0x202e),
    "left-to-right isolate": cp(0x2066),
    "pop directional isolate": cp(0x2069),
    "zero-width space": cp(0x200b),
    "zero-width joiner": cp(0x200d),
    "word joiner": cp(0x2060),
    "no-break space": cp(0x00a0),
    "narrow no-break space": cp(0x202f),
    "ideographic space": cp(0x3000),
    "byte-order mark": cp(0xfeff),
    "soft hyphen": cp(0x00ad),
    "line separator": cp(0x2028),
    "paragraph separator": cp(0x2029),
    "variation selector-16": cp(0xfe0f),
    "hangul filler": cp(0x3164),
    "tag latin capital a": cp(0xe0041),
    delete: cp(0x7f),
    "next line (C1)": cp(0x85),
    "private use": cp(0xe000),
    noncharacter: cp(0xffff),
  };

  it("is plain indented JSON for ordinary content, non-ASCII text included", () => {
    assert.equal(blobText({ a: 1, b: ["x", true, null] }), '{\n  "a": 1,\n  "b": [\n    "x",\n    true,\n    null\n  ]\n}');
    const text = cp(0xd8) + "5.5 fr" + cp(0xfc) + "h " + cp(0x65e5, 0x672c); // O-slash, u-umlaut, two kanji
    assert.equal(blobText({ note: text }), `{\n  "note": "${text}"\n}`);
    assert.equal(blobText({}), "{}");
  });

  it("writes every hidden or direction-changing character as its \\u escape", () => {
    for (const [name, ch] of Object.entries(HIDDEN)) {
      const blob = { note: `unit price${ch} is firm`, [`key${ch}`]: 1 };
      const text = blobText(blob);
      assert.equal(text.includes(ch), false, `${name} is still in the output`);
      const escaped = [...ch]
        .flatMap((c) => (c.length === 2 ? [c.charCodeAt(0), c.charCodeAt(1)] : [c.charCodeAt(0)]))
        .map((u) => `\\u${u.toString(16).padStart(4, "0")}`)
        .join("");
      assert.ok(text.includes(`unit price${escaped} is firm`), `${name} in a value → ${escaped}`);
      assert.ok(text.includes(`"key${escaped}"`), `${name} in a key → ${escaped}`);
      assert.deepEqual(JSON.parse(text), blob, `${name}: still JSON for exactly the same value`);
    }
  });

  it("leaves nothing in the output but visible characters, spaces and its own line breaks", () => {
    const everything = { [Object.values(HIDDEN).join("k")]: Object.values(HIDDEN).join("v"), tab: "\t", nl: "a\nb" };
    const text = blobText(everything);
    assert.match(text, /^[\n\x20-\x7e]*$/, "this blob renders in printable ASCII alone");
    assert.deepEqual(JSON.parse(text), everything);
  });

  it("does not interpret markup: it is text for a text node", () => {
    const html = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    assert.ok(blobText({ note: html }).includes(html), "the characters are shown as they are");
  });

  it("is what quoteTerms puts in the model", () => {
    const rlo = cp(0x202e);
    const q = quote({ assumptions: { terms: `net 30${rlo}09 ten` }, capacity: { ok: true } });
    const terms = quoteTerms(q, 250, NOW);
    assert.equal(terms.assumptions, blobText(q.assumptions));
    assert.equal(terms.assumptions!.includes(rlo), false);
    assert.match(terms.assumptions!, /net 30\\u202e09 ten/);
    assert.equal(terms.capacity, '{\n  "ok": true\n}');
  });
});
