/** Strict parsers for what a person types into the desk's forms.
 *
 *  A form field is text; the traveler stores numbers. The desk used to bridge the two
 *  with `Number()`, `|| 0`, `Math.max` and `.filter()`, which never refuse — they
 *  guess. So a unit price typed "1,250.00" silently dropped its price line, "0.004"
 *  was stored as 0, an NRE of "1,500" became 0, a target quantity of "5,000" became 1,
 *  "0x10" mm became 16 — and the wrong number was then hashed into the award.
 *
 *  Everything here is the opposite: a pure function from the typed text to either the
 *  exact value it denotes or a refusal with a message for the field. Nothing is
 *  rounded, defaulted, clamped or dropped. The accepted grammar is deliberately the
 *  narrow one that cannot be misread — ASCII digits, at most one period:
 *
 *    integer   0 | [1-9][0-9]*                 no sign, separator, exponent, leading zero
 *    decimal   integer [ "." [0-9]+ ]
 *    money     decimal, with no more fraction digits than the currency's minor unit
 *
 *  Surrounding whitespace is ignored; a blank field is always a refusal (use
 *  `optional` for a field that may be left empty). Limits mirror schema.ts, which
 *  stays the authority — input.test.ts pins each limit against it.
 */
import { currencyExponent, money } from "./format.ts";
import type { PriceLine } from "./types.ts";

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

const accept = <T>(value: T): Parsed<T> => ({ ok: true, value });
const refuse = (error: string): Parsed<never> => ({ ok: false, error });

/** Field limits, mirrored from schema.ts. */
export const LIMITS = {
  qty: { min: 1, max: 1_000_000 },
  breaks: { min: 1, max: 1_000_000, maxItems: 16 },
  thicknessMm: { min: 0.0001, max: 1_000_000 },
  leadTimeDays: { min: 0, max: 3650 },
  /** Any money field, in minor units. */
  moneyMinor: { min: 0, max: 1_000_000_000_000 },
} as const;

const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/;
/** Longest run of digits that is always an exact JavaScript integer (2^53 has 16). */
const SAFE_DIGITS = 15;

export function isBlank(text: string): boolean {
  return text.trim() === "";
}

/** A field that may be left empty: blank means "not stated" (`undefined`); anything
 *  else must parse — a non-blank value is never quietly treated as absent. */
export function optional<T>(text: string, parse: (text: string) => Parsed<T>): Parsed<T | undefined> {
  return isBlank(text) ? accept(undefined) : parse(text);
}

/** A whole number written as plain digits, within `range`. */
export function parseInteger(text: string, range: { min: number; max: number }): Parsed<number> {
  const s = text.trim();
  if (s === "") return refuse("Required.");
  if (!INTEGER.test(s)) {
    return refuse(
      "Whole number in plain digits — no separators, signs, decimals, exponents or leading zeros.",
    );
  }
  if (s.length > SAFE_DIGITS || Number(s) > range.max) return refuse(`Must be at most ${range.max}.`);
  const n = Number(s);
  if (n < range.min) return refuse(`Must be at least ${range.min}.`);
  return accept(n);
}

/** A comma-separated list of whole numbers ("10, 50, 200"). Every entry must parse:
 *  a bad entry refuses the whole field rather than being filtered out of it. */
export function parseIntegerList(
  text: string,
  range: { min: number; max: number; maxItems: number },
): Parsed<number[]> {
  if (isBlank(text)) return refuse("Required.");
  const parts = text.split(",").map((p) => p.trim());
  const values: number[] = [];
  for (const [i, part] of parts.entries()) {
    if (part === "") return refuse(`Entry ${i + 1} is empty — remove the extra comma.`);
    const parsed = parseInteger(part, range);
    if (!parsed.ok) return refuse(`Entry ${i + 1}: ${parsed.error}`);
    values.push(parsed.value);
  }
  if (values.length > range.maxItems) {
    return refuse(`At most ${range.maxItems} entries (${values.length} given).`);
  }
  return accept(values);
}

/** A plain decimal ("9.53") that the stored number reproduces exactly: the value must
 *  print back as the digits that were typed, so nothing is rounded on the way in. */
export function parseDecimal(text: string, range: { min: number; max: number }): Parsed<number> {
  const s = text.trim();
  if (s === "") return refuse("Required.");
  const m = DECIMAL.exec(s);
  if (!m) {
    return refuse(
      "Plain decimal with a period, like 9.53 — no commas, units, fractions, signs or exponents.",
    );
  }
  const whole = m[1]!;
  // Trailing zeros of the fraction do not change the value ("10.50" is 10.5).
  const digits = m[2] ?? "";
  let end = digits.length;
  while (end > 0 && digits[end - 1] === "0") end--;
  const fraction = digits.slice(0, end);
  const typed = fraction === "" ? whole : `${whole}.${fraction}`;
  const n = Number(typed);
  if (n > range.max) return refuse(`Must be at most ${range.max}.`);
  if (n < range.min) return refuse(`Must be at least ${range.min}.`);
  if (String(n) !== typed) return refuse("Too many digits to store exactly — shorten the number.");
  return accept(n);
}

/** An amount of money, typed in the currency's major unit ("1250.00"), as an integer
 *  count of its minor unit (125000). The exponent comes from the same fixed table
 *  `money()` formats with; the conversion is digit arithmetic, never a float multiply. */
export function parseMoney(
  text: string,
  currency: string,
  range: { min?: number; max?: number } = {},
): Parsed<number> {
  const exponent = currencyExponent(currency);
  const min = range.min ?? LIMITS.moneyMinor.min;
  const max = range.max ?? LIMITS.moneyMinor.max;
  const s = text.trim();
  if (s === "") return refuse("Required.");
  const m = DECIMAL.exec(s);
  if (!m) {
    const shape = exponent === 0 ? "digits only" : `digits and up to ${exponent} decimals`;
    return refuse(
      `Plain ${currency} amount, like ${exponent === 0 ? "1250" : `1250.${"0".repeat(exponent)}`} — ${shape}; no thousands separators, currency symbols, signs or exponents.`,
    );
  }
  const whole = m[1]!;
  const fraction = m[2] ?? "";
  if (fraction.length > exponent) {
    return refuse(
      exponent === 0
        ? `${currency} has no minor unit — whole amounts only.`
        : `${currency} has ${exponent} decimal places; ${s} has ${fraction.length}.`,
    );
  }
  // Scale by appending digits and compare as integers — exact, where a float multiply
  // (1.005 * 100 = 100.49999999999999) is not. No amount has more than 13 minor-unit
  // digits, so an over-long entry is refused on its length before it is ever a number.
  const atMost = `Must be at most ${money(max, currency)}.`;
  if (whole.length > SAFE_DIGITS) return refuse(atMost);
  const minor = BigInt(whole + fraction.padEnd(exponent, "0"));
  if (minor > BigInt(max)) return refuse(atMost);
  if (minor < BigInt(min)) return refuse(`Must be at least ${money(min, currency)}.`);
  return accept(Number(minor));
}

// ---------------------------------------------------------------------------------
// The two forms. Each takes the text exactly as it sits in the inputs and returns the
// values to store plus an error per field; `values` is null unless every field parsed,
// so a form can only ever submit what was typed.
// ---------------------------------------------------------------------------------

export type QuoteFormText = {
  /** Unit price typed for each quantity break, keyed by qty. */
  units: Readonly<Record<number, string>>;
  nre: string;
  lead: string;
  freight: string;
};

export type QuoteFormValues = {
  lines: PriceLine[];
  nre: number;
  lead_time_days: number;
  freight_estimate?: number;
};

export type QuoteFormErrors = {
  units: Record<number, string>;
  nre?: string;
  lead?: string;
  freight?: string;
  /** No field is wrong, but the form as a whole cannot be a quote. */
  form?: string;
};

export const NO_PRICED_LINE = "Price at least one quantity break.";

export type QuoteFormResult = {
  /** What to store: null unless every field parsed and at least one line is priced. */
  values: QuoteFormValues | null;
  errors: QuoteFormErrors;
  /** The unit prices that did parse, so each can be echoed back beside its field. */
  priced: PriceLine[];
};

/** The quote dialog's fields. A unit price may be left blank (that quantity is simply
 *  not quoted) but at least one must be priced, and a priced line is at least one minor
 *  unit — a line at 0 would be an offer to make the parts for nothing. NRE and lead
 *  time must be stated; freight may be left blank. */
export function parseQuoteForm(
  text: QuoteFormText,
  qtys: readonly number[],
  currency: string,
): QuoteFormResult {
  const errors: QuoteFormErrors = { units: {} };
  const lines: PriceLine[] = [];
  for (const qty of qtys) {
    const unit = optional(text.units[qty] ?? "", (t) => parseMoney(t, currency, { min: 1 }));
    if (!unit.ok) errors.units[qty] = `${unit.error} Leave blank to skip this quantity.`;
    else if (unit.value !== undefined) lines.push({ qty, unit: unit.value });
  }
  const nre = parseMoney(text.nre, currency);
  if (!nre.ok) errors.nre = isBlank(text.nre) ? "Required — enter 0 if there is none." : nre.error;
  const lead = parseInteger(text.lead, LIMITS.leadTimeDays);
  if (!lead.ok) errors.lead = lead.error;
  const freight = optional(text.freight, (t) => parseMoney(t, currency));
  if (!freight.ok) errors.freight = freight.error;

  const unitsOk = Object.keys(errors.units).length === 0;
  if (unitsOk && lines.length === 0) errors.form = NO_PRICED_LINE;
  if (!unitsOk || lines.length === 0 || !nre.ok || !lead.ok || !freight.ok) {
    return { values: null, errors, priced: lines };
  }
  return {
    values: {
      lines,
      nre: nre.value,
      lead_time_days: lead.value,
      ...(freight.value === undefined ? {} : { freight_estimate: freight.value }),
    },
    errors,
    priced: lines,
  };
}

export type ComposeNumbersText = { qty: string; breaks: string; thickness: string };

export type ComposeNumbers = { target: number; breaks?: number[]; thickness_mm?: number };

export type ComposeNumbersErrors = { qty?: string; breaks?: string; thickness?: string };

/** The compose form's numeric fields: target quantity (required), quantity breaks and
 *  material thickness (each may be left blank). */
export function parseComposeNumbers(text: ComposeNumbersText): {
  values: ComposeNumbers | null;
  errors: ComposeNumbersErrors;
} {
  const errors: ComposeNumbersErrors = {};
  const target = parseInteger(text.qty, LIMITS.qty);
  if (!target.ok) errors.qty = target.error;
  const breaks = optional(text.breaks, (t) => parseIntegerList(t, LIMITS.breaks));
  if (!breaks.ok) errors.breaks = breaks.error;
  const thickness = optional(text.thickness, (t) => parseDecimal(t, LIMITS.thicknessMm));
  if (!thickness.ok) errors.thickness = thickness.error;
  if (!target.ok || !breaks.ok || !thickness.ok) return { values: null, errors };
  return {
    values: {
      target: target.value,
      ...(breaks.value === undefined ? {} : { breaks: breaks.value }),
      ...(thickness.value === undefined ? {} : { thickness_mm: thickness.value }),
    },
    errors,
  };
}
