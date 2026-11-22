import type { PriceLine } from "./types.ts";

// ---------------------------------------------------------------------------------
// Money. An amount is an integer count of the currency's minor unit (SPEC 0.1). How
// many minor units make one major unit — the exponent — comes from the fixed table
// below and from nowhere else. It used to be read from the runtime's ICU data
// (Intl.NumberFormat), which follows CLDR's "digits in everyday use", not ISO 4217,
// and changes between engines and releases: the same stored 1420 IQD read "IQD 1,420"
// on one runtime and "IQD 1.420" on another, and a typed amount was scaled by
// whichever exponent the seller's browser happened to carry. Formatting (`money`) and
// parsing (`parseMoney` in input.ts) both go through `currencyExponent`, and both are
// plain integer arithmetic on decimal digits — no floating point, no Intl — so they
// agree by construction on every runtime.
// ---------------------------------------------------------------------------------

/** ISO 4217 minor-unit exponents that are not 2. Every other code is 2 — the ISO
 *  default, which is also what a code ISO does not list (or lists with no minor unit,
 *  such as XAU or XXX) falls to; the code itself is always displayed, so a reader sees
 *  which currency an amount claims to be in. */
const NON_DEFAULT_EXPONENTS: ReadonlyArray<readonly [exponent: number, codes: string]> = [
  [0, "BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF"],
  [3, "BHD IQD JOD KWD LYD OMR TND"],
  [4, "CLF UYW"],
];
const DEFAULT_EXPONENT = 2;
const EXPONENT_BY_CODE: ReadonlyMap<string, number> = new Map(
  NON_DEFAULT_EXPONENTS.flatMap(([exponent, codes]) =>
    codes.split(" ").map((code) => [code, exponent] as const),
  ),
);

/** The number of decimal places between a currency's major and minor unit. */
export function currencyExponent(currency: string): number {
  return EXPONENT_BY_CODE.get(currency) ?? DEFAULT_EXPONENT;
}

/** U+00A0, built from its code point so no invisible character sits in this source. */
const NBSP = String.fromCharCode(0xa0);

/** What stands in front of an amount: "$" for US dollars (the currency the desk
 *  quotes in), otherwise the ISO code itself — never a symbol looked up at runtime,
 *  which would differ between engines and is ambiguous across currencies. */
function currencyPrefix(currency: string): string {
  return currency === "USD" ? "$" : `${currency}${NBSP}`;
}

function toMinorBigInt(minorUnits: number | bigint): bigint | null {
  if (typeof minorUnits === "bigint") return minorUnits;
  return Number.isInteger(minorUnits) ? BigInt(minorUnits) : null;
}

function groupThousands(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** The digits of an amount: whole part, and the minor-unit part padded to the
 *  currency's exponent. Exact for any integer (numbers and bigints alike). */
function decimalParts(abs: bigint, exponent: number): { whole: string; fraction: string } {
  const scale = 10n ** BigInt(exponent);
  return {
    whole: (abs / scale).toString(),
    fraction: exponent === 0 ? "" : (abs % scale).toString().padStart(exponent, "0"),
  };
}

export type MoneyStyle = {
  /** Always print the minor-unit digits ("$350.00"). Default: a whole amount prints
   *  without them ("$350"), anything else prints all of them ("$14.20"). */
  minorDigits?: "always" | "auto";
  /** Print "+" in front of a positive amount (a price delta). */
  sign?: boolean;
};

/** Format an integer amount of a currency's minor unit (e.g. cents) for display.
 *  Never rounds: every minor-unit digit that is not zero is printed. A value that is
 *  not a whole number of minor units cannot come from a valid traveler; it is shown as
 *  what it is rather than rounded into something plausible. */
export function money(minorUnits: number | bigint, currency = "USD", style: MoneyStyle = {}): string {
  const minor = toMinorBigInt(minorUnits);
  if (minor === null) return `${currencyPrefix(currency)}${String(minorUnits)} (not a whole minor-unit amount)`;
  const negative = minor < 0n;
  const { whole, fraction } = decimalParts(negative ? -minor : minor, currencyExponent(currency));
  const showFraction = fraction !== "" && (style.minorDigits === "always" || /[1-9]/.test(fraction));
  const sign = negative ? "-" : style.sign && minor > 0n ? "+" : "";
  return `${sign}${currencyPrefix(currency)}${groupThousands(whole)}${showFraction ? `.${fraction}` : ""}`;
}

/** The same amount as plain typed text — digits, a period, every minor-unit digit, no
 *  grouping and no currency mark ("1250.00"). This is the exact inverse of `parseMoney`
 *  (input.ts): `parseMoney(moneyInputText(n, c), c)` is `n` for every valid amount. */
export function moneyInputText(minorUnits: number | bigint, currency = "USD"): string {
  const minor = toMinorBigInt(minorUnits);
  if (minor === null || minor < 0n) throw new RangeError("a typed amount is a non-negative integer of minor units");
  const { whole, fraction } = decimalParts(minor, currencyExponent(currency));
  return fraction === "" ? whole : `${whole}.${fraction}`;
}

export function pricedLine(
  lines: PriceLine[],
  pickQty?: number,
): PriceLine | undefined {
  if (pickQty != null) return lines.find((l) => l.qty === pickQty);
  return lines[0];
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A calendar day for display: "30 Oct 2026". The day shown is the one WRITTEN in the
 *  document — its UTC date — never shifted into the viewer's time zone. (It used to go
 *  through a local-time formatter: a need-by of 2026-10-30 read "29 Oct 2026" to anyone
 *  west of UTC, and two people looking at one traveler saw two different dates.) */
export function formatDay(iso?: string | null): string {
  if (!iso) return "—";
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:$|T)/.exec(iso);
  const month = m ? MONTHS[Number(m[2]) - 1] : undefined;
  return m && month ? `${Number(m[3])} ${month} ${m[1]}` : iso;
}

export function processLabel(code: string): string {
  return code.replaceAll("_", " ");
}
