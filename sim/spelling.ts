/** Spellings: the many ways to write one number or one string in JSON, the literals
 *  that sit on a parser's edges, and byte sequences that are not (or only just) UTF-8.
 *
 *  Pure helpers and tables for the wire mutations (mutations-wire.ts). The two
 *  respellers are exact — `respellNumber` and `respellString` return text that MEANS
 *  the same value — so any change of verdict under them is a finding.
 */
import type { Rng } from "./rng.ts";

const cp = String.fromCodePoint;

/* ---------------- numbers ---------------- */

/** A finite double's shortest decimal spelling as a digit string and a power of ten:
 *  |value| = digits x 10^exp, digits without leading zeros. */
function decimal(value: number): { neg: boolean; digits: string; exp: number } {
  let s = String(Math.abs(value));
  let exp = 0;
  const e = s.indexOf("e");
  if (e >= 0) {
    exp = Number(s.slice(e + 1));
    s = s.slice(0, e);
  }
  const dot = s.indexOf(".");
  if (dot >= 0) {
    exp -= s.length - dot - 1;
    s = s.slice(0, dot) + s.slice(dot + 1);
  }
  return { neg: value < 0 || Object.is(value, -0), digits: s.replace(/^0+(?=\d)/, ""), exp };
}

/** Another spelling of exactly the same decimal value: the point moved, an exponent
 *  added (either case, optional sign, padded), zeros appended. `250` may come back as
 *  `250.0`, `2.5e2`, `25E+1`, `0.25e03`, `2500e-1` … (Zero may come back as `-0`:
 *  equal, but a different bit pattern and a different re-rendering — on purpose.) */
export function respellNumber(value: number, rng: Rng): string {
  const { neg, digits, exp } = decimal(value);
  if (digits === "0") return rng.pick(["0.0", "0e0", "0E+7", "0.000", "0e-3", "-0", "-0.0", "-0e0"]);
  const len = digits.length;
  const left = rng.int(-2, len + 2); // digits to the left of the decimal point
  let mantissa: string;
  if (left <= 0) mantissa = `0.${"0".repeat(-left)}${digits}`;
  else if (left >= len) mantissa = `${digits}${"0".repeat(left - len)}${rng.pick(["", ".0", ".000"])}`;
  else mantissa = `${digits.slice(0, left)}.${digits.slice(left)}${rng.pick(["", "0", "000"])}`;
  const e10 = exp + len - left;
  const exponent =
    e10 === 0
      ? rng.pick(["", "e0", "E0", "e+0", "e-0", "E00"])
      : `${rng.pick(["e", "E"])}${e10 > 0 ? rng.pick(["", "+"]) : "-"}${rng.pick(["", "0", "00"])}${Math.abs(e10)}`;
  return `${neg ? "-" : ""}${mantissa}${exponent}`;
}

/** The exact decimal expansion of the midpoint between |value| and the next double
 *  up — the literal a correctly-rounding parser resolves by ties-to-even, and where a
 *  parser that rounds twice (or reads only 17 digits) lands on the wrong neighbour.
 *  Always ends in the digit 5 when it has a fraction. */
export function midpointAbove(value: number): string | undefined {
  if (!Number.isFinite(value) || value === 0) return undefined;
  const bits = new BigUint64Array(new Float64Array([Math.abs(value)]).buffer)[0]!;
  const biased = Number((bits >> 52n) & 0x7ffn);
  const fraction = bits & ((1n << 52n) - 1n);
  const mantissa = biased === 0 ? fraction : fraction | (1n << 52n);
  const e2 = (biased === 0 ? -1074 : biased - 1075) - 1; // midpoint = (2m + 1) * 2^e2
  const odd = 2n * mantissa + 1n;
  if (e2 >= 0) return (odd << BigInt(e2)).toString();
  const scaled = (odd * 5n ** BigInt(-e2)).toString().padStart(1 - e2, "0");
  return `${scaled.slice(0, e2)}.${scaled.slice(e2)}`;
}

export const NUM_INVALID: readonly [string, (t: string) => string][] = [
  ["leading-plus", (t) => `+${t}`],
  ["leading-zero", (t) => (t.startsWith("-") ? `-0${t.slice(1)}` : `0${t}`)],
  ["trailing-dot", (t) => `${t.replace(/[.eE].*$/, "")}.`],
  ["leading-dot", () => ".5"],
  ["dot-then-exponent", () => "1.e5"],
  ["two-dots", () => "1.2.3"],
  ["bare-exponent", (t) => `${t.replace(/[eE].*$/, "")}e`],
  ["exponent-sign-only", (t) => `${t.replace(/[eE].*$/, "")}e+`],
  ["fractional-exponent", () => "1e1.5"],
  ["exponent-space", () => "1e 5"],
  ["hex", () => "0x1F"],
  ["octal", () => "0o17"],
  ["binary", () => "0b101"],
  ["underscore", () => "1_000"],
  ["thousands-comma", () => "1,000"],
  ["suffix-f", (t) => `${t}f`],
  ["suffix-n", (t) => `${t}n`],
  ["suffix-L", (t) => `${t}L`],
  ["lone-minus", () => "-"],
  ["double-minus", (t) => `--${t.replace(/^-/, "")}`],
  ["minus-space", (t) => `- ${t.replace(/^-/, "")}`],
  ["double-zero", () => "00"],
  ["arabic-indic-digits", () => cp(0x662, 0x665, 0x660)],
  ["fullwidth-digits", () => cp(0xff12, 0xff15, 0xff10)],
  ["infinity", () => "Infinity"],
  ["minus-infinity", () => "-Infinity"],
  ["nan", () => "NaN"],
];

/** Integers around the edges of exact representation: 2^53, i64, u64. In a typed
 *  field every one is out of range; in a blob every one is a legal JSON number that
 *  one side holds exactly and the other rounds. */
export const NUM_BIG: readonly string[] = [
  "9007199254740991",
  "9007199254740992",
  "9007199254740993",
  "-9007199254740993",
  "9007199254740992.0",
  "9007199254740993.0",
  "9.007199254740993e15",
  "0.9007199254740993e16",
  "9223372036854775807",
  "9223372036854775808",
  "-9223372036854775808",
  "-9223372036854775809",
  "18446744073709551615",
  "18446744073709551616",
  "1e15",
  "1e16",
  "1e19",
  "1e20",
  "1e21",
  "1e22",
  "123456789012345678901234567890",
];

/** Literals at the edges of the double range and of a number lexer's patience. */
export const NUM_EXTREME: readonly [string, string][] = [
  ["max-ish", "1e308"],
  ["max", "1.7976931348623157e308"],
  ["rounds-to-max-or-inf", "1.7976931348623158e308"],
  ["past-max", "1.7976931348623159e308"],
  ["overflow", "1e309"],
  ["neg-overflow", "-1e309"],
  ["min-subnormal", "5e-324"],
  ["below-min-subnormal", "2.5e-324"],
  ["half-min-subnormal", "2.4703282292062327e-324"],
  ["rounds-to-zero", "2.4e-324"],
  ["underflow", "1e-400"],
  ["neg-underflow", "-1e-400"],
  ["zero-huge-exponent", "0e99999999999999999999"],
  ["zero-huge-neg-exponent", "0e-99999999999999999999"],
  ["one-huge-neg-exponent", "1e-99999999999999999999"],
  ["one-huge-exponent", "1e99999999999999999999"],
  ["padded-exponent", "1e0000000000000000000002"],
  ["400-digit-integer", `1${"0".repeat(400)}`],
  ["400-zero-fraction", `0.${"0".repeat(400)}1`],
  ["1000-zero-fraction", `1.${"0".repeat(1000)}`],
  ["cancelling-exponent", `1${"0".repeat(25)}e-25`],
  ["cancelling-fraction", `0.${"0".repeat(20)}1e21`],
  ["long-significand", `3.${"1415926535897932384626433832795028841971".repeat(5)}`],
];

/* ---------------- strings ---------------- */

const SHORT_ESCAPE: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x2f: "\\/",
  0x5c: "\\\\",
};
const isHigh = (u: number): boolean => u >= 0xd800 && u <= 0xdbff;
const isLow = (u: number): boolean => u >= 0xdc00 && u <= 0xdfff;
const uEscape = (u: number, rng: Rng): string => {
  const hex = u.toString(16).padStart(4, "0");
  return `\\u${rng.bool() ? hex : hex.toUpperCase()}`;
};

/** The same string, each character escaped with probability `p`: `\uXXXX` in either
 *  hex case, the short escapes, `\/`, an astral character as a surrogate-pair escape. */
export function respellString(value: string, rng: Rng, p: number): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const u = value.charCodeAt(i);
    const pair = isHigh(u) && i + 1 < value.length && isLow(value.charCodeAt(i + 1));
    const must = u < 0x20 || u === 0x22 || u === 0x5c || ((isHigh(u) || isLow(u)) && !pair);
    if (!must && !rng.bool(p)) {
      out += pair ? value.slice(i, i + 2) : value[i];
    } else if (pair) {
      out += uEscape(u, rng) + uEscape(value.charCodeAt(i + 1), rng);
    } else {
      out += SHORT_ESCAPE[u] && rng.bool() ? SHORT_ESCAPE[u] : uEscape(u, rng);
    }
    if (pair) i++;
  }
  return `${out}"`;
}

/** The default spelling of `value` with `text` inserted verbatim between two of its
 *  characters (never inside an escape or a surrogate pair). */
export function spellWith(value: string, text: string, rng: Rng): string {
  const chars = Array.from(value);
  const at = rng.int(0, chars.length);
  const esc = (s: string) => JSON.stringify(s).slice(1, -1);
  return `"${esc(chars.slice(0, at).join(""))}${text}${esc(chars.slice(at).join(""))}"`;
}

/* ---------------- bytes that are not, or barely, UTF-8 ---------------- */

export const UTF8_INVALID: readonly [string, number[]][] = [
  ["lone-continuation", [0x80]],
  ["lone-continuation-bf", [0xbf]],
  ["ff", [0xff]],
  ["fe", [0xfe]],
  ["overlong-nul", [0xc0, 0x80]],
  ["overlong-slash", [0xc0, 0xaf]],
  ["overlong-c1", [0xc1, 0xbf]],
  ["overlong-3", [0xe0, 0x80, 0x80]],
  ["overlong-3-max", [0xe0, 0x9f, 0xbf]],
  ["overlong-4", [0xf0, 0x80, 0x80, 0x80]],
  ["overlong-4-max", [0xf0, 0x8f, 0xbf, 0xbf]],
  ["surrogate-d800", [0xed, 0xa0, 0x80]],
  ["surrogate-dfff", [0xed, 0xbf, 0xbf]],
  ["cesu-8-pair", [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]],
  ["past-10ffff", [0xf4, 0x90, 0x80, 0x80]],
  ["f5-lead", [0xf5, 0x80, 0x80, 0x80]],
  ["five-byte", [0xf8, 0x88, 0x80, 0x80, 0x80]],
  ["six-byte", [0xfc, 0x84, 0x80, 0x80, 0x80, 0x80]],
  ["truncated-2", [0xc3]],
  ["truncated-3", [0xe2, 0x82]],
  ["truncated-4", [0xf0, 0x9f, 0x98]],
  ["bad-continuation", [0xc3, 0x28]],
  ["bad-second-continuation", [0xe2, 0x28, 0xa1]],
  ["latin-1", [0xe9]],
];

/** Well-formed UTF-8 that a too-strict decoder refuses: both sides must take them. */
export const UTF8_RARE: readonly [string, number[]][] = [
  ["replacement-char", [0xef, 0xbf, 0xbd]],
  ["nonchar-fffe", [0xef, 0xbf, 0xbe]],
  ["nonchar-ffff", [0xef, 0xbf, 0xbf]],
  ["nonchar-fdd0", [0xef, 0xb7, 0x90]],
  ["last-code-point", [0xf4, 0x8f, 0xbf, 0xbf]],
  ["first-astral", [0xf0, 0x90, 0x80, 0x80]],
  ["before-surrogates", [0xed, 0x9f, 0xbf]],
  ["after-surrogates", [0xee, 0x80, 0x80]],
  ["first-two-byte", [0xc2, 0x80]],
  ["last-two-byte", [0xdf, 0xbf]],
  ["first-three-byte", [0xe0, 0xa0, 0x80]],
  ["del", [0x7f]],
  ["bom-inside", [0xef, 0xbb, 0xbf]],
];
