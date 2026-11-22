/** What a person types is what the traveler stores — or it is refused.
 *
 *  These pin the desk's form parsing (input.ts) and money formatting (format.ts):
 *   - every lenient reading the old `Number()` / `|| 0` / `.filter()` code produced is
 *     now a refusal with a message for the field (the typed → stored table below is the
 *     audit's own list of inputs);
 *   - a currency's exponent comes from a fixed ISO 4217 table, never from the
 *     runtime's ICU data;
 *   - formatting and parsing are inverses, for every amount, by construction.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { parseQuote, parseTraveler } from "./conformance.ts";
import { currencyExponent, money, moneyInputText } from "./format.ts";
import {
  LIMITS,
  NO_PRICED_LINE,
  optional,
  parseComposeNumbers,
  parseDecimal,
  parseInteger,
  parseIntegerList,
  parseMoney,
  parseQuoteForm,
  type Parsed,
} from "./input.ts";

const NBSP = String.fromCharCode(0xa0);
/** Characters that look like, or hide among, ASCII digits — built from code points so
 *  none of them sits in this file. */
const FULLWIDTH_12 = String.fromCodePoint(0xff11, 0xff12);
const ARABIC_INDIC_12 = String.fromCodePoint(0x0661, 0x0662);
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const RIGHT_TO_LEFT_OVERRIDE = String.fromCodePoint(0x202e);
const THIN_SPACE = String.fromCodePoint(0x2009);

const value = <T>(p: Parsed<T>): T => {
  assert.ok(p.ok, p.ok ? "" : `expected a value, got refusal: ${p.error}`);
  return (p as { value: T }).value;
};
const refusal = (p: Parsed<unknown>, label: string): string => {
  assert.equal(p.ok, false, `${label} must be refused, but parsed to ${JSON.stringify(p)}`);
  const { error } = p as { error: string };
  assert.ok(error.length > 0, `${label}: a refusal carries a message for the field`);
  return error;
};

/** Deterministic PRNG (mulberry32) — the property tests are the same on every run. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("parseInteger — plain digits only, range-checked", () => {
  const qty = (s: string) => parseInteger(s, LIMITS.qty);

  it("accepts plain digits and stores exactly the number typed", () => {
    for (const s of ["1", "50", "5000", "250", "1000000"]) {
      assert.equal(String(value(qty(s))), s);
    }
    assert.equal(value(qty("  50  ")), 50, "surrounding whitespace is not part of the number");
    assert.equal(value(parseInteger("0", LIMITS.leadTimeDays)), 0);
  });

  it("refuses everything the old Number() parse silently reinterpreted", () => {
    const bad = [
      "5,000", // was stored as 1
      "5 000",
      "5_000",
      "5'000",
      `5${NBSP}000`,
      `5${THIN_SPACE}000`,
      "-50", // was stored as 1
      "+50",
      "2e3", // was stored as 2000
      "0x10", // was stored as 16
      "0b11",
      "050",
      "00",
      "5.0",
      "5.",
      ".5",
      "10.5",
      "3 weeks", // lead time: was stored as 0
      "Infinity",
      "NaN",
      FULLWIDTH_12,
      ARABIC_INDIC_12,
      `5${ZERO_WIDTH_SPACE}0`,
      `${RIGHT_TO_LEFT_OVERRIDE}50`,
    ];
    for (const s of bad) refusal(qty(s), JSON.stringify(s));
  });

  it("refuses a blank, and out-of-range values, with the bound in the message", () => {
    assert.equal(refusal(qty(""), "blank"), "Required.");
    assert.equal(refusal(qty("   "), "spaces"), "Required.");
    assert.match(refusal(qty("0"), "below min"), /at least 1/);
    assert.match(refusal(qty("1000001"), "above max"), /at most 1000000/);
    assert.match(refusal(qty("9".repeat(400)), "400 digits"), /at most 1000000/);
    assert.match(refusal(parseInteger("3651", LIMITS.leadTimeDays), "lead"), /at most 3650/);
  });

  it("round-trips: an accepted entry is the decimal spelling of the stored number", () => {
    const next = rng(1);
    for (let i = 0; i < 2000; i++) {
      const n = 1 + Math.floor(next() * 1_000_000);
      assert.equal(value(qty(String(n))), n);
    }
  });
});

describe("parseIntegerList — every entry parses or the whole field is refused", () => {
  const breaks = (s: string) => parseIntegerList(s, LIMITS.breaks);

  it("reads a comma-separated list", () => {
    assert.deepEqual(value(breaks("10, 50, 200")), [10, 50, 200]);
    assert.deepEqual(value(breaks(" 10,50 ")), [10, 50]);
    assert.deepEqual(value(breaks("250")), [250]);
  });

  it("never filters a bad entry out: the old code turned these into shorter lists", () => {
    assert.match(refusal(breaks("1,000, 5,000"), "thousands separators"), /Entry 2/); // was [1, 5]
    assert.match(refusal(breaks("10;50;200"), "semicolons"), /Entry 1/); // was dropped entirely
    assert.match(refusal(breaks("10, x, 200"), "a word"), /Entry 2/);
    assert.match(refusal(breaks("10, -50"), "a sign"), /Entry 2/);
    assert.match(refusal(breaks("10, 2e3"), "an exponent"), /Entry 2/);
    assert.match(refusal(breaks("10, 0"), "below min"), /Entry 2.*at least 1/);
    assert.match(refusal(breaks("10,,50"), "empty entry"), /Entry 2 is empty/);
    assert.match(refusal(breaks("10, 50,"), "trailing comma"), /Entry 3 is empty/);
    assert.match(refusal(breaks(",10"), "leading comma"), /Entry 1 is empty/);
  });

  it("caps the number of entries at the schema's", () => {
    const sixteen = Array.from({ length: 16 }, (_, i) => i + 1).join(", ");
    assert.equal(value(breaks(sixteen)).length, 16);
    assert.match(refusal(breaks(`${sixteen}, 17`), "17 entries"), /At most 16/);
  });

  it("a comma always separates entries — 1,250 is two breaks, which is why the form echoes the list", () => {
    assert.deepEqual(value(breaks("1,250")), [1, 250]);
  });
});

describe("parseDecimal — the stored number prints back as what was typed", () => {
  const mm = (s: string) => parseDecimal(s, LIMITS.thicknessMm);

  it("accepts plain decimals exactly", () => {
    for (const s of ["9.53", "6.35", "0.0001", "1000000", "12", "0.5"]) {
      assert.equal(String(value(mm(s))), s);
    }
    assert.equal(value(mm("10.50")), 10.5, "trailing zeros do not change the value");
    assert.equal(value(mm(" 9.53 ")), 9.53);
  });

  it("refuses what the old Number() parse dropped or reinterpreted", () => {
    const bad = [
      "9,53", // decimal comma: the field was silently omitted
      "3/8 in", // omitted
      "0x10", // stored as 16
      "1e3",
      "-1",
      "+1",
      ".5",
      "5.",
      "9.53mm",
      "1,000.5",
      "09.53",
      FULLWIDTH_12,
    ];
    for (const s of bad) refusal(mm(s), JSON.stringify(s));
  });

  it("refuses a value it could not store exactly, instead of rounding it", () => {
    assert.match(refusal(mm("0.1234567890123456789"), "19 significant digits"), /store exactly/);
    assert.match(refusal(mm("9.530000000000000000001"), "an invisible tail"), /store exactly/);
  });

  it("range-checks against the schema's bounds", () => {
    assert.equal(refusal(mm(""), "blank"), "Required.");
    assert.match(refusal(mm("0"), "zero"), /at least 0.0001/);
    assert.match(refusal(mm("0.00009"), "below min"), /at least 0.0001/);
    assert.match(refusal(mm("1000000.5"), "above max"), /at most 1000000/);
    assert.match(refusal(mm("9".repeat(400)), "400 digits"), /at most 1000000/);
  });
});

describe("the currency exponent is a fixed ISO 4217 table, not the runtime's ICU data", () => {
  it("knows the currencies whose minor unit is not 1/100", () => {
    const expected: Record<string, number> = {
      USD: 2, EUR: 2, GBP: 2, CAD: 2, MXN: 2, CNY: 2, CHF: 2, INR: 2,
      JPY: 0, KRW: 0, VND: 0, CLP: 0, ISK: 0, UGX: 0, XOF: 0, XAF: 0, XPF: 0, PYG: 0, UYI: 0,
      BHD: 3, KWD: 3, OMR: 3, JOD: 3, TND: 3, LYD: 3, IQD: 3,
      CLF: 4, UYW: 4,
    };
    for (const [code, exponent] of Object.entries(expected)) {
      assert.equal(currencyExponent(code), exponent, code);
    }
  });

  it("follows ISO 4217 where CLDR/ICU says otherwise, and treats an unlisted code as 2", () => {
    // CLDR (and so ICU) reports 0 fraction digits for these — cash practice — where
    // ISO 4217 says 2, and 3 for IQD: under ICU the same stored 1420 read "IQD 1,420",
    // a thousandfold misreading that also changed with the runtime's CLDR release.
    for (const code of ["AFN", "ALL", "COP", "HUF", "IDR", "IRR", "KPW", "LAK", "LBP", "MGA", "MMK", "PKR", "SOS", "SYP", "YER"]) {
      assert.equal(currencyExponent(code), 2, code);
    }
    // A code ISO does not list, or lists without a minor unit, falls to the default.
    for (const code of ["ZZZ", "XAU", "XXX"]) assert.equal(currencyExponent(code), 2, code);
    assert.equal(money(1420, "IQD"), `IQD${NBSP}1.420`);
    assert.equal(money(1420, "AFN"), `AFN${NBSP}14.20`);
    assert.equal(money(1420, "JPY"), `JPY${NBSP}1,420`);
    assert.equal(money(1420, "ZZZ"), `ZZZ${NBSP}14.20`);
    assert.equal(money(1420, "CLF"), `CLF${NBSP}0.1420`);
  });

  it("does not consult Intl at all", () => {
    const real = Intl.NumberFormat;
    try {
      (Intl as { NumberFormat: unknown }).NumberFormat = function () {
        throw new Error("money must not depend on the runtime's locale data");
      };
      assert.equal(money(125000, "USD"), "$1,250");
      assert.equal(money(1420, "KWD"), `KWD${NBSP}1.420`);
      assert.equal(value(parseMoney("1250.00", "USD")), 125000);
    } finally {
      Intl.NumberFormat = real;
    }
  });
});

describe("money — exact formatting of integer minor units", () => {
  it("prints dollars the way the desk always has", () => {
    assert.equal(money(1420), "$14.20");
    assert.equal(money(35000), "$350");
    assert.equal(money(0), "$0");
    assert.equal(money(5), "$0.05");
    assert.equal(money(250_000_000), "$2,500,000");
    assert.equal(money(1_000_000_000_000), "$10,000,000,000");
  });

  it("prints every minor digit, a sign, or an exact bigint on request", () => {
    assert.equal(money(35000, "USD", { minorDigits: "always" }), "$350.00");
    assert.equal(money(1250, "JPY", { minorDigits: "always" }), `JPY${NBSP}1,250`);
    assert.equal(money(-240), "-$2.40");
    assert.equal(money(240, "USD", { sign: true }), "+$2.40");
    assert.equal(money(-240, "USD", { sign: true }), "-$2.40");
    assert.equal(money(0, "USD", { sign: true }), "$0");
    // qty 1,000,000 × unit 999,999,999,999 + 2 is past 2^53: a float total printed
    // $9,999,999,999,990,000.00 for this amount.
    assert.equal(money(999_999_999_999_000_002n), "$9,999,999,999,990,000.02");
  });

  it("never rounds or throws on a value that is not whole minor units", () => {
    assert.match(money(14.5), /not a whole minor-unit amount/);
    assert.match(money(Number.NaN), /not a whole minor-unit amount/);
    assert.throws(() => moneyInputText(-1), RangeError);
    assert.throws(() => moneyInputText(0.5), RangeError);
  });
});

describe("parseMoney — a decimal string to integer minor units", () => {
  const usd = (s: string, range?: { min?: number; max?: number }) => parseMoney(s, "USD", range);

  it("accepts a plain amount and scales it by the currency's exponent", () => {
    const cases: Array<[string, string, number]> = [
      ["0", "USD", 0],
      ["12", "USD", 1200],
      ["12.5", "USD", 1250],
      ["12.50", "USD", 1250],
      ["0.01", "USD", 1],
      ["0.29", "USD", 29],
      ["1.15", "USD", 115],
      ["19.99", "USD", 1999],
      ["1250.00", "USD", 125000],
      [" 1250.00 ", "USD", 125000],
      ["10000000000", "USD", 1_000_000_000_000],
      ["10000000000.00", "USD", 1_000_000_000_000],
      ["1250", "JPY", 1250],
      ["1.234", "KWD", 1234],
      ["1.2", "KWD", 1200],
      ["1.2345", "CLF", 12345],
    ];
    for (const [text, currency, minor] of cases) {
      assert.equal(value(parseMoney(text, currency)), minor, `${text} ${currency}`);
    }
  });

  it("refuses grouping separators, symbols, signs and exponents (each was once misread)", () => {
    const bad = [
      "1,250.00", // the price line was silently dropped
      "1,500", // NRE: stored as 0
      "12,50", // decimal comma: dropped
      "1.250,00",
      "1 250.00",
      `1${NBSP}250.00`,
      `1${THIN_SPACE}250`,
      "1'250.00",
      "1_250",
      "$12.50", // dropped
      "$400", // NRE: stored as 0
      "12.50 USD",
      "USD 12.50",
      "-500", // NRE: stored as 0
      "+5",
      "(5.00)",
      "1e3", // stored as 100000
      "1E3",
      "0x10", // stored as 1600
      ".5",
      "5.",
      "5..0",
      "5.0.0",
      "007",
      "00.50",
      "Infinity",
      "NaN",
      FULLWIDTH_12,
      ARABIC_INDIC_12,
      `12${ZERO_WIDTH_SPACE}.50`,
      `${RIGHT_TO_LEFT_OVERRIDE}12.50`,
    ];
    for (const s of bad) {
      assert.match(refusal(usd(s), JSON.stringify(s)), /Plain USD amount, like 1250\.00/);
    }
  });

  it("refuses more fraction digits than the currency has — never rounds them away", () => {
    assert.match(refusal(usd("0.004"), "0.004"), /USD has 2 decimal places; 0\.004 has 3/); // stored as 0
    assert.match(refusal(usd("1.005"), "1.005"), /USD has 2 decimal places/); // stored as 100
    assert.match(refusal(usd("0.285"), "0.285"), /USD has 2 decimal places/);
    assert.match(refusal(usd("12.500"), "12.500"), /USD has 2 decimal places/);
    assert.match(refusal(parseMoney("1250.5", "JPY"), "JPY fraction"), /JPY has no minor unit/);
    assert.match(refusal(parseMoney("1250.0", "JPY"), "JPY .0"), /JPY has no minor unit/);
    assert.match(refusal(parseMoney("1.2345", "KWD"), "KWD 4dp"), /KWD has 3 decimal places/);
    assert.match(refusal(parseMoney("1.23456", "CLF"), "CLF 5dp"), /CLF has 4 decimal places/);
  });

  it("refuses a blank and anything out of range", () => {
    assert.equal(refusal(usd(""), "blank"), "Required.");
    assert.equal(refusal(usd(" \t"), "whitespace"), "Required.");
    assert.match(refusal(usd("10000000000.01"), "one cent over"), /at most \$10,000,000,000/);
    assert.match(refusal(usd("9".repeat(400)), "400 digits"), /at most \$10,000,000,000/);
    assert.match(refusal(usd("0", { min: 1 }), "zero where a price is required"), /at least \$0\.01/);
    assert.match(refusal(usd("0.00", { min: 1 }), "zero where a price is required"), /at least \$0\.01/);
    assert.match(refusal(usd("5.01", { max: 500 }), "caller's cap"), /at most \$5/);
  });

  it("is exact where a float multiply is not", () => {
    // Every cent amount up to $100.00, through text and back.
    for (let cents = 0; cents <= 10_000; cents++) {
      assert.equal(value(usd(moneyInputText(cents))), cents);
    }
    // The classic: 1.005 * 100 === 100.49999999999999. Three decimals are refused in
    // USD; in a three-decimal currency the same digits are exactly 1005.
    assert.equal(value(parseMoney("1.005", "KWD")), 1005);
  });
});

describe("formatting and parsing agree, for every amount", () => {
  const currencies = ["USD", "EUR", "JPY", "KWD", "CLF", "ZZZ"];
  /** What a person would retype from a displayed amount: drop the currency mark and
   *  the thousands separators. */
  const retype = (shown: string) => shown.replace(/^[^0-9]*/, "").replaceAll(",", "");

  it("parse(format(n)) === n", () => {
    const next = rng(2);
    for (const c of currencies) {
      const amounts = [0, 1, 9, 10, 99, 100, 101, 999_999, 1_000_000_000_000];
      for (let i = 0; i < 1500; i++) amounts.push(Math.floor(next() * 10 ** (1 + Math.floor(next() * 12))));
      for (const n of amounts) {
        assert.equal(value(parseMoney(moneyInputText(n, c), c)), n, `${n} ${c} via moneyInputText`);
        assert.equal(value(parseMoney(retype(money(n, c)), c)), n, `${n} ${c} via money()`);
        assert.equal(
          value(parseMoney(retype(money(n, c, { minorDigits: "always" })), c)),
          n,
          `${n} ${c} via money(always)`,
        );
      }
    }
  });

  it("format(parse(x)) is x, written out to the currency's full precision", () => {
    const next = rng(3);
    const digits = (n: number) => Array.from({ length: n }, () => Math.floor(next() * 10)).join("");
    for (const c of currencies) {
      const exponent = currencyExponent(c);
      for (let i = 0; i < 1500; i++) {
        const wholeLength = 1 + Math.floor(next() * (12 - exponent));
        const whole = wholeLength === 1 ? digits(1) : `${1 + Math.floor(next() * 9)}${digits(wholeLength - 1)}`;
        const fraction = digits(Math.floor(next() * (exponent + 1)));
        const typed = fraction === "" ? whole : `${whole}.${fraction}`;
        const minor = value(parseMoney(typed, c));
        const full = exponent === 0 ? whole : `${whole}.${fraction.padEnd(exponent, "0")}`;
        assert.equal(moneyInputText(minor, c), full, `${typed} ${c}`);
        // …and the value shown to the buyer is that same number.
        assert.equal(retype(money(minor, c, { minorDigits: "always" })), full, `${typed} ${c} shown`);
      }
    }
  });
});

describe("the quote dialog — typed → stored", () => {
  const QTYS = [50, 200];
  const form = (over: Partial<{ u50: string; u200: string; nre: string; lead: string; freight: string }>) =>
    parseQuoteForm(
      {
        units: { 50: over.u50 ?? "", 200: over.u200 ?? "" },
        nre: over.nre ?? "0",
        lead: over.lead ?? "14",
        freight: over.freight ?? "",
      },
      QTYS,
      "USD",
    );

  it("stores exactly what was typed", () => {
    const r = form({ u50: "1250.00", u200: "900", nre: "1500", lead: "21", freight: "85.50" });
    assert.deepEqual(r.values, {
      lines: [
        { qty: 50, unit: 125000 },
        { qty: 200, unit: 90000 },
      ],
      nre: 150000,
      lead_time_days: 21,
      freight_estimate: 8550,
    });
    assert.deepEqual(r.errors, { units: {} });
  });

  it("a blank unit price skips that quantity; a blank freight is not stated", () => {
    const r = form({ u200: "11" });
    assert.deepEqual(r.values, { lines: [{ qty: 200, unit: 1100 }], nre: 0, lead_time_days: 14 });
    assert.equal("freight_estimate" in r.values!, false);
  });

  it("refuses every entry the old dialog silently changed, with the error on that field", () => {
    type Field = "u50" | "nre" | "lead" | "freight";
    // [what is typed, the field it is typed in, what the old dialog stored instead]
    const rows: Array<[string, Field, string]> = [
      ["1,250.00", "u50", "the qty-50 line dropped; a quote for qty 200 only"],
      ["$12.50", "u50", "the line dropped"],
      ["0.004", "u50", "unit 0"],
      ["12,50", "u50", "the line dropped"],
      ["1e3", "u50", "unit 100000"],
      ["0x10", "u50", "unit 1600"],
      ["1.005", "u50", "unit 100"],
      ["0", "u50", "the line dropped"],
      ["1,500", "nre", "nre 0"],
      ["-500", "nre", "nre 0"],
      ["$400", "nre", "nre 0"],
      ["", "nre", "nre 0"],
      ["3 weeks", "lead", "lead_time_days 0"],
      ["10.5", "lead", "lead_time_days 10.5 (then a schema error)"],
      ["-5", "lead", "lead_time_days 0"],
      ["", "lead", "lead_time_days 0"],
      ["3651", "lead", "a schema error"],
      ["0.004", "freight", "freight_estimate 0"],
      ["-1", "freight", "a toast"],
      ["1,000", "freight", "a toast"],
    ];
    for (const [typed, field, was] of rows) {
      const r = form({ u50: "10", u200: "9", [field]: typed });
      const label = `${field}=${JSON.stringify(typed)} (was: ${was})`;
      assert.equal(r.values, null, `${label}: nothing may be submitted`);
      const error = field === "u50" ? r.errors.units[50] : r.errors[field];
      assert.ok(error, `${label}: the error is reported on its own field`);
      const others = { ...r.errors, units: { ...r.errors.units } };
      if (field === "u50") delete others.units[50];
      else delete others[field];
      assert.deepEqual(others, { units: {} }, `${label}: and on no other field`);
    }
  });

  it("a refused unit price does not take the other lines down with it, and is echoed back", () => {
    const r = form({ u50: "1,250.00", u200: "900" });
    assert.equal(r.values, null);
    assert.deepEqual(r.priced, [{ qty: 200, unit: 90000 }], "the valid line is still known, for the echo");
    assert.match(r.errors.units[50]!, /Leave blank to skip this quantity/);
  });

  it("needs at least one priced line", () => {
    const r = form({});
    assert.equal(r.values, null);
    assert.deepEqual(r.errors, { units: {}, form: NO_PRICED_LINE });
    assert.equal(NO_PRICED_LINE, "Price at least one quantity break.");
  });

  it("what it accepts, the quote schema accepts", () => {
    const r = form({ u50: "10000000000", u200: "0.01", nre: "10000000000.00", lead: "3650", freight: "0" });
    assert.ok(r.values);
    const { lead_time_days, ...pricing } = r.values;
    assert.doesNotThrow(() =>
      parseQuote({
        quote_id: "qot_inputtest1",
        seller: { name: "S" },
        traveler_hash_quoted: `sha384:${"0".repeat(96)}`,
        created_at: "2026-01-01T00:00:00Z",
        valid_until: "2026-02-01T00:00:00Z",
        lead_time_days,
        pricing: { currency: "USD", ...pricing },
      }),
    );
  });
});

describe("the compose form — typed → stored", () => {
  const compose = (qty: string, breaks: string, thickness: string) =>
    parseComposeNumbers({ qty, breaks, thickness });

  it("stores exactly what was typed", () => {
    assert.deepEqual(compose("50", "10, 50, 200", "9.53"), {
      values: { target: 50, breaks: [10, 50, 200], thickness_mm: 9.53 },
      errors: {},
    });
  });

  it("blank breaks and thickness are left out, not defaulted", () => {
    assert.deepEqual(compose("50", "", " "), { values: { target: 50 }, errors: {} });
  });

  it("refuses what the old form sealed as something else", () => {
    // Was sealed as {"target":1,"breaks":[1,5]} with no thickness.
    let r = compose("5,000", "1,000, 5,000", "9,53");
    assert.equal(r.values, null);
    assert.deepEqual(Object.keys(r.errors).sort(), ["breaks", "qty", "thickness"]);
    // Was sealed as {"target":1} — breaks and thickness silently dropped.
    r = compose("-50", "10;50;200", "3/8 in");
    assert.equal(r.values, null);
    assert.deepEqual(Object.keys(r.errors).sort(), ["breaks", "qty", "thickness"]);
    // Was sealed as {"target":2000,"breaks":[10,50,200],"thickness_mm":16}.
    r = compose("2e3", "10, 50, 200", "0x10");
    assert.equal(r.values, null);
    assert.deepEqual(Object.keys(r.errors).sort(), ["qty", "thickness"]);
    // A blank target qty was sealed as 1.
    r = compose("", "10, 50", "9.53");
    assert.equal(r.values, null);
    assert.deepEqual(r.errors, { qty: "Required." });
  });
});

describe("the form limits are the schema's limits", () => {
  const base = JSON.parse(
    readFileSync(new URL("../../../conformance/travelers/l0-bracket.json", import.meta.url), "utf8"),
  );
  const travelerOk = (mut: (t: any) => void) => {
    const t = structuredClone(base);
    mut(t);
    try {
      parseTraveler(t);
      return true;
    } catch {
      return false;
    }
  };
  const quoteOk = (mut: (q: any) => void) => {
    const q = {
      quote_id: "qot_limits0001",
      seller: { name: "S" },
      traveler_hash_quoted: `sha384:${"0".repeat(96)}`,
      created_at: "2026-01-01T00:00:00Z",
      valid_until: "2026-02-01T00:00:00Z",
      lead_time_days: 5,
      pricing: { currency: "USD", lines: [{ qty: 1, unit: 100 }] },
    };
    mut(q);
    try {
      parseQuote(q);
      return true;
    } catch {
      return false;
    }
  };
  /** Both sides must give the same verdict at, and just past, each bound. */
  const agree = (label: string, parser: boolean, schema: boolean, expected: boolean) => {
    assert.equal(parser, expected, `${label}: form parser`);
    assert.equal(schema, expected, `${label}: schema`);
  };

  it("target qty", () => {
    const { min, max } = LIMITS.qty;
    for (const [n, ok] of [[min, true], [max, true], [min - 1, false], [max + 1, false]] as const) {
      agree(`qty ${n}`, parseInteger(String(n), LIMITS.qty).ok, travelerOk((t) => (t.part.qty.target = n)), ok);
    }
  });

  it("breaks", () => {
    const { min, max, maxItems } = LIMITS.breaks;
    for (const [n, ok] of [[min, true], [max, true], [min - 1, false], [max + 1, false]] as const) {
      agree(`break ${n}`, parseIntegerList(String(n), LIMITS.breaks).ok, travelerOk((t) => (t.part.qty.breaks = [n])), ok);
    }
    for (const [count, ok] of [[maxItems, true], [maxItems + 1, false]] as const) {
      const list = Array.from({ length: count }, (_, i) => i + 1);
      agree(`${count} breaks`, parseIntegerList(list.join(","), LIMITS.breaks).ok, travelerOk((t) => (t.part.qty.breaks = list)), ok);
    }
  });

  it("thickness", () => {
    for (const [s, ok] of [["0.0001", true], ["1000000", true], ["0.00009", false], ["1000000.5", false]] as const) {
      agree(`thickness ${s}`, parseDecimal(s, LIMITS.thicknessMm).ok, travelerOk((t) => (t.part.material.thickness_mm = Number(s))), ok);
    }
  });

  it("lead time", () => {
    const { min, max } = LIMITS.leadTimeDays;
    for (const [n, ok] of [[min, true], [max, true], [max + 1, false]] as const) {
      agree(`lead ${n}`, parseInteger(String(n), LIMITS.leadTimeDays).ok, quoteOk((q) => (q.lead_time_days = n)), ok);
    }
  });

  it("money", () => {
    const { min, max } = LIMITS.moneyMinor;
    for (const [n, ok] of [[min, true], [max, true], [max + 1, false]] as const) {
      // max + 1 minor units is one cent past the largest amount: "10000000000.01".
      const typed = `${Math.floor(n / 100)}.${String(n % 100).padStart(2, "0")}`;
      agree(`money ${n}`, parseMoney(typed, "USD").ok, quoteOk((q) => (q.pricing.lines[0].unit = n)), ok);
      agree(`nre ${n}`, parseMoney(typed, "USD").ok, quoteOk((q) => (q.pricing.nre = n)), ok);
    }
  });

  it("optional() lets a field be blank and nothing else", () => {
    assert.deepEqual(optional("", (t) => parseMoney(t, "USD")), { ok: true, value: undefined });
    assert.deepEqual(optional("  ", (t) => parseMoney(t, "USD")), { ok: true, value: undefined });
    assert.deepEqual(optional("12.5", (t) => parseMoney(t, "USD")), { ok: true, value: 1250 });
    assert.equal(optional("1,250", (t) => parseMoney(t, "USD")).ok, false);
  });
});
