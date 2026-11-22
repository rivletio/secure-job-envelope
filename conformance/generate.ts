/** Regenerates the conformance vectors from the TypeScript reference
 *  implementation. The Rust implementation then verifies the same files
 *  independently — agreement across two codebases with no shared code is
 *  the proof the vectors encode.
 *
 *  Run: node --experimental-strip-types conformance/generate.ts
 */
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { canonicalJson } from "../src/lib/traveler/canonical.ts";
import { travelerHash, hashQuoteable, quoteableBody } from "../src/lib/traveler/hash.ts";
import { parseTraveler, parseTravelerJson, levelOf } from "../src/lib/traveler/conformance.ts";
import { keypairFromSeed, signBody, SIG_DOMAIN } from "../src/lib/traveler/signature.ts";
import { bytesToHex, hexToBytes, utf8ToBytes } from "../src/lib/traveler/bytes.ts";
import {
  signDirectory,
  verifyDirectory,
  parseDirectoryJson,
  DIRECTORY_SPEC,
  type Directory,
  type DirectoryEntry,
} from "../src/lib/traveler/directory.ts";
import {
  signTraveler,
  signQuote,
  signAward,
  quoteContentHash,
  verificationReport,
  itarAttestationBlocker,
  type SigCheck,
} from "../src/lib/traveler/authenticity.ts";
import {
  PREKEY_BUNDLE_SPEC,
  signPrekeyBundle,
  verifyPrekeyBundle,
  parsePrekeyBundleJson,
  type PrekeyBundle,
} from "../src/lib/traveler/prekeys.ts";
import {
  kemKeypairFromSeed,
  sealEnvelopeDeterministic,
  openEnvelope,
  recipientByOrg,
  sealFsEnvelopeDeterministic,
  fsRecipientFromBundle,
  ENVELOPE_SPEC,
  ENC_ALG,
  FS_ENC_ALG,
} from "../src/lib/traveler/envelope.ts";
import { sha384 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import type { Traveler, Quote } from "../src/lib/traveler/types.ts";

const here = new URL(".", import.meta.url).pathname;

/* ---------- canonicalization vectors ---------- */
//
// A case gives its input in exactly one of two ways:
//
//   value   a JSON value. How the vector file spells it is NOT part of the test: the file
//           is written by JSON.stringify, which writes -0 as 0 and 10.0 as 10.
//   text    the exact JSON text. Its spelling IS the test (`10.0`, `-0`, `1e2`, a letter
//           written as an escape): each runner parses it with its own JSON parser, then
//           canonicalizes what it got.
//
// A case named for a spelling must be a text case. `negative-zero` used to be the value
// { t: -0 }, which reached the file as {"t":0} — neither runner was ever shown a negative
// zero, and nothing was ever shown `10.0`. A value case that does not survive the trip to
// the file is refused below.
//
// No invisible character appears in this source: one that is not printable ASCII is built
// from its code point, and the vector file is written in ASCII, every other character as
// a \uXXXX escape a reviewer can see.
//
// (In a block so none of these names can collide with a later section of this file.)
{
  type Input = { value: unknown; text?: undefined } | { text: string; value?: undefined };
  type ValidCase = { name: string } & Input;
  type InvalidCase = ValidCase & {
    /** What is wrong with the input, for a reader. */
    reason: string;
    /** A fragment of each reference implementation's own refusal, so the case cannot pass
     *  by being refused for some other defect. `ts` is checked here, `rs` by the Rust
     *  runner. For TypeScript, "not JSON" means JSON.parse itself rejected the text. */
    refusal: { ts: string; rs: string };
  };

  const cp = (...codes: number[]): string => String.fromCodePoint(...codes);
  /** The text `{"t":<literal>}`, the literal exactly as written. */
  const num = (literal: string): string => `{"t":${literal}}`;
  /** The text `{"s":"<body>"}`, the body exactly as written (escapes and all). */
  const str = (body: string): string => `{"s":"${body}"}`;
  /** A JSON `\uXXXX` escape, as text. */
  const esc = (code: number): string => `\\u${code.toString(16).padStart(4, "0")}`;
  /** `open` written `n` times, then `bottom`, then `close` written `n` times. */
  const nest = (open: string, close: string, n: number, bottom = ""): string =>
    open.repeat(n) + bottom + close.repeat(n);

  const valid: ValidCase[] = [
    { name: "sorted-keys", value: { b: 1, a: 2 } },
    { name: "nested-sort", value: { z: { d: 4, c: [3, { b: 2, a: 1 }] }, a: null } },
    { name: "integer", value: { t: 10 } },
    { name: "decimal", value: { t: 9.53 } },
    { name: "min-fraction", value: { t: 0.00001 } },
    { name: "max-safe-integer", value: { t: 9007199254740991 } },
    { name: "negative-decimal", value: { t: -12.75 } },
    { name: "string-escapes", value: { s: 'a"b\\c\nd\te' } },
    { name: "unicode-raw-utf8", value: { s: "café ± µm Ø12" } },
    { name: "empty-structures", value: { obj: {}, arr: [], s: "" } },
    { name: "booleans-null", value: { t: true, f: false, n: null } },
    { name: "key-order-digits", value: { "10": 1, "2": 2, A: 3, a: 4 } },
    // Long-decimal floats (regression): both implementations must parse to the
    // same f64 and render identically. Requires serde_json's float_roundtrip on
    // the Rust side; without it these hash differently across implementations.
    { name: "long-decimal", value: { t: 223.23501793805622 } },
    { name: "long-decimal-negative", value: { t: -946696.1927003545 } },
    { name: "long-decimal-large", value: { t: 4435404841756971.5 } },
    // Astral-plane object keys must sort by code point identically on both sides
    // (JS default UTF-16 order would put U+1F600 before U+FFFF; both must agree).
    { name: "astral-key-order", value: { [cp(0x1f600)]: 1, [cp(0xffff)]: 2 } },
    { name: "astral-string-value", value: { s: `grüß ${cp(0x1f600)} ${cp(0x1f680)}` } },

    // ---- numbers, by spelling: integer-valued floats and zero ----
    { name: "integer-valued-float", text: num("10.0") },
    { name: "integer-valued-float-one", text: num("1.0") },
    { name: "negative-zero", text: num("-0") },
    { name: "negative-zero-float", text: num("-0.0") },
    { name: "zero-float", text: num("0.0") },
    { name: "zero-in-every-spelling", text: "[0,-0,0.0,-0.0,0e0,-0e-0,0E+0]" },
    // ---- exponent forms of numbers inside the canonical range ----
    { name: "exponent", text: num("1e2") },
    { name: "exponent-uppercase", text: num("1E2") },
    { name: "exponent-plus-sign", text: num("1e+2") },
    { name: "exponent-negative", text: num("100e-2") },
    { name: "exponent-with-fraction", text: num("1.5e1") },
    { name: "exponent-of-a-negative-number", text: num("-1e2") },
    { name: "exponent-min-fraction", text: num("1e-5") },
    { name: "exponent-leading-zeros", text: num("1e-05") },
    { name: "exponent-large-in-range", text: num("1e15") },
    { name: "exponent-max-safe-integer", text: num("9.007199254740991e15") },
    { name: "ten-in-five-spellings", text: "[10.0,1e1,10,1.0e1,100e-1]" },
    { name: "trailing-fraction-zeros", text: num("1.50") },
    // ---- the 2^53 and 2^52 boundaries (a double holds every integer up to 2^53; above
    //      2^52 it holds nothing but integers) ----
    { name: "max-safe-integer-as-float", text: num("9007199254740991.0") },
    { name: "min-safe-integer", text: num("-9007199254740991") },
    { name: "half-below-max-safe-integer-rounds-to-even", text: num("9007199254740990.5") },
    { name: "half-above-2-pow-52-rounds-to-even", text: num("4503599627370496.5") },
    { name: "half-below-2-pow-52-is-exact", text: num("4503599627370495.5") },
    { name: "sixteen-digit-integer-part-with-fraction", text: num("1234567890123456.7") },
    // ---- more digits than a double holds: the parse must round correctly ----
    { name: "seventeen-significant-digits", text: num("0.30000000000000004") },
    { name: "more-digits-than-a-double-holds", text: num("0.1000000000000000055511151231257827") },
    { name: "tie-rounds-to-even", text: num("1.00000000000000011102230246251565404236316680908203125") },
    { name: "just-above-a-tie-rounds-up", text: num("1.00000000000000011102230246251565404236316680908203126") },
    { name: "just-below-a-tie-rounds-down", text: num("1.00000000000000011102230246251565404236316680908203124") },
    { name: "min-fraction-reached-from-below", text: num(`0.00000${"9".repeat(18)}`) },
    { name: "small-fraction-long", text: num("0.000012345678901234567") },
    // ---- a literal too small for a double is zero, and zero is canonical ----
    { name: "underflow-to-zero", text: num("1e-400") },
    { name: "negative-underflow-to-zero", text: num("-1e-400") },
    { name: "below-half-the-smallest-double-is-zero", text: num("2e-324") },

    // ---- strings, by spelling: an escape and the character it names are one string ----
    { name: "escape-u0041-is-A", text: str(esc(0x41)) },
    { name: "escape-hex-digits-in-either-case", text: str("\\u00e9\\u00E9") },
    { name: "escape-solidus", text: str("\\/") },
    { name: "escape-short-forms", text: str('\\"\\\\\\/\\b\\f\\n\\r\\t') },
    { name: "escape-every-c0-control", text: str(Array.from({ length: 0x20 }, (_, code) => esc(code)).join("")) },
    { name: "del-escaped", text: str(esc(0x7f)) },
    { name: "del-literal", text: str(cp(0x7f)) },
    { name: "c1-controls-escaped", text: str(esc(0x80) + esc(0x85) + esc(0x9f)) },
    { name: "c1-controls-literal", text: str(cp(0x80, 0x85, 0x9f)) },
    { name: "line-separators-escaped", text: str(esc(0x2028) + esc(0x2029)) },
    { name: "line-separators-literal", text: str(cp(0x2028, 0x2029)) },
    { name: "byte-order-mark-inside-a-string-escaped", text: str(esc(0xfeff)) },
    { name: "byte-order-mark-inside-a-string-literal", text: str(cp(0xfeff)) },
    { name: "bidi-and-zero-width-escaped", text: str([0x202e, 0x2066, 0x200f, 0x200b, 0x200d, 0xad].map(esc).join("")) },
    { name: "noncharacters-escaped", text: str(esc(0xffff) + esc(0xfffe)) },
    { name: "surrogate-pair-escape", text: str("\\ud83d\\ude00") },
    { name: "surrogate-pair-escape-uppercase", text: str("\\uD83D\\uDE00") },
    { name: "astral-literal", text: str(cp(0x1f600)) },
    { name: "astral-first-and-last-escaped", text: str("\\ud800\\udc00\\udbff\\udfff") },
    // ---- member names: unescaped, then sorted by code point, never normalized ----
    { name: "key-escape-is-unescaped-before-sorting", text: `{"${esc(0x62)}":1,"a":2}` },
    { name: "key-empty-and-ascii-order", text: '{"":1,"a":2,"A":3,"0":4,"_":5," ":6}' },
    { name: "key-prefix-order", text: '{"aa":1,"a":2,"ab":3,"b":4}' },
    { name: "key-not-normalized", text: `{"e${esc(0x301)}":1,"${esc(0xe9)}":2}` },
    { name: "key-latin1-order", text: `{"${esc(0xe9)}":1,"z":2,"${esc(0xdf)}":3,"~":4,"${esc(0x7f)}":5,"${esc(0x80)}":6}` },
    {
      name: "key-order-is-code-point-not-utf16",
      text: `{"\\ud800\\udc00":1,"${esc(0xe000)}":2,"${esc(0xffff)}":3,"${esc(0xd7ff)}":4,"\\udbff\\udfff":5}`,
    },
    // ---- structure ----
    { name: "insignificant-whitespace", text: '\n\t {"b" :\r\n 1 , "a":[ 1 ,2 ] } \n' },
    { name: "array-order-is-kept", text: '[3,1,2,{"b":1,"a":2},[],"x",null,true,false]' },
    { name: "top-level-number", text: "10.0" },
    { name: "top-level-string", text: `"${esc(0x41)}"` },

    // ---- nesting: 127 containers inside one another is the deepest value there is.
    //      Scalars do not count; only containers nest. (Text cases: a value this deep
    //      could not be written into this file without the file itself being too deep
    //      for a strict reader.) ----
    { name: "nesting-127-arrays", text: nest("[", "]", 127) },
    { name: "nesting-127-arrays-around-a-number", text: nest("[", "]", 127, "1") },
    { name: "nesting-127-objects", text: nest('{"a":', "}", 126, "{}") },
    { name: "nesting-127-objects-around-a-string", text: nest('{"a":', "}", 127, '"x"') },
    { name: "nesting-127-mixed", text: nest('[{"a":', "}]", 63, "[]") },
  ];

  const TOO_BIG = { ts: "exceeds 2^53-1", rs: "exceeds 2^53-1" };
  const TOO_SMALL = { ts: "below 1e-5", rs: "below 1e-5" };
  const OVERFLOW = { ts: "non-finite number", rs: "number out of range" };
  const RAW_CONTROL = { ts: "not JSON", rs: "control character" };
  const TOO_DEEP = { ts: "nesting exceeds the maximum depth", rs: "recursion limit exceeded" };
  const exponential = "renders exponential in at least one implementation";

  const invalid: InvalidCase[] = [
    // ---- nesting: a 128th container. One implementation's parser stops here and the
    //      other's has no limit at all, so the canonicalizer holds the same line: a value
    //      has a canonical form only if both could have read its text. ----
    { name: "nesting-128-arrays", text: nest("[", "]", 128), reason: "128 containers nested", refusal: TOO_DEEP },
    { name: "nesting-128-arrays-around-a-number", text: nest("[", "]", 128, "1"), reason: "128 containers nested", refusal: TOO_DEEP },
    { name: "nesting-128-objects", text: nest('{"a":', "}", 127, "{}"), reason: "128 containers nested", refusal: TOO_DEEP },
    { name: "nesting-128-mixed", text: nest('[{"a":', "}]", 63, "[[]]"), reason: "128 containers nested", refusal: TOO_DEEP },
    { name: "nesting-129-arrays", text: nest("[", "]", 129), reason: "129 containers nested", refusal: TOO_DEEP },
    { name: "nesting-1000-arrays", text: nest("[", "]", 1000), reason: "1,000 containers nested", refusal: TOO_DEEP },

    { name: "exp-large", value: { t: 1e21 }, reason: "renders exponential (1e+21 vs 1e21)", refusal: TOO_BIG },
    { name: "exp-small", value: { t: 1e-7 }, reason: "renders exponential", refusal: TOO_SMALL },
    { name: "below-min-fraction", value: { t: 0.000001 }, reason: "ryu renders 1e-6, JS stays fixed", refusal: TOO_SMALL },
    { name: "negative-exp-large", value: { t: -1e21 }, reason: "renders exponential", refusal: TOO_BIG },

    // ---- above 2^53-1: no longer exact in a double. (A value case cannot carry these: a
    //      JavaScript reader of the vector file would already have rounded them.) ----
    { name: "integer-2-pow-53", text: num("9007199254740992"), reason: "2^53: above the largest exact integer", refusal: TOO_BIG },
    {
      name: "integer-2-pow-53-plus-1",
      text: num("9007199254740993"),
      reason: "2^53+1: a double cannot hold it (it reads as 2^53); an integer type can, and must refuse it too",
      refusal: TOO_BIG,
    },
    { name: "negative-integer-2-pow-53", text: num("-9007199254740992"), reason: "-(2^53)", refusal: TOO_BIG },
    { name: "float-2-pow-53", text: num("9007199254740992.0"), reason: "2^53 written as a float", refusal: TOO_BIG },
    { name: "exponent-2-pow-53", text: num("9.007199254740992e15"), reason: "2^53 written with an exponent", refusal: TOO_BIG },
    { name: "rounds-up-to-2-pow-53", text: num("9007199254740991.5"), reason: "halfway between 2^53-1 and 2^53: rounds to even, 2^53", refusal: TOO_BIG },
    { name: "u64-max", text: num("18446744073709551615"), reason: "2^64-1", refusal: TOO_BIG },
    { name: "above-u64", text: num("18446744073709551616"), reason: "2^64: past every 64-bit integer type", refusal: TOO_BIG },
    { name: "below-i64", text: num("-9223372036854775809"), reason: "-(2^63)-1: past every 64-bit integer type", refusal: TOO_BIG },
    { name: "exponent-1e16", text: num("1e16"), reason: "the first power of ten above 2^53", refusal: TOO_BIG },
    { name: "exponent-1e21", text: num("1e21"), reason: exponential, refusal: TOO_BIG },
    { name: "largest-double", text: num("1.7976931348623157e308"), reason: "finite, and far above 2^53-1", refusal: TOO_BIG },
    // ---- a non-integer below 1e-5 ----
    { name: "fraction-1e-7", text: num("1e-7"), reason: exponential, refusal: TOO_SMALL },
    { name: "fraction-1e-6-in-fixed-notation", text: num("0.000001"), reason: exponential, refusal: TOO_SMALL },
    { name: "fraction-49e-7", text: num("49e-7"), reason: "0.0000049", refusal: TOO_SMALL },
    {
      name: "min-fraction-missed-from-below",
      text: num(`0.00000${"9".repeat(17)}`),
      reason: "one digit short of min-fraction-reached-from-below: rounds to the double just under 1e-5",
      refusal: TOO_SMALL,
    },
    { name: "smallest-double", text: num("5e-324"), reason: "the smallest positive double", refusal: TOO_SMALL },
    // ---- too large for a double at all ----
    { name: "overflow", text: num("1e400"), reason: "no finite double", refusal: OVERFLOW },
    { name: "overflow-negative", text: num("-1e400"), reason: "no finite double", refusal: OVERFLOW },
    { name: "just-above-the-largest-double", text: num("1.7976931348623159e308"), reason: "rounds to infinity", refusal: OVERFLOW },

    // ---- an escape that names no character ----
    {
      name: "lone-high-surrogate-escape",
      text: str("\\ud800"),
      reason: "a high surrogate with no low surrogate after it",
      refusal: { ts: "lone surrogate", rs: "unexpected end of hex escape" },
    },
    {
      name: "lone-low-surrogate-escape",
      text: str("\\udc00"),
      reason: "a low surrogate with no high surrogate before it",
      refusal: { ts: "lone surrogate", rs: "lone leading surrogate" },
    },
    {
      name: "high-surrogate-then-a-character",
      text: str("\\ud83dx"),
      reason: "a high surrogate followed by an ordinary character",
      refusal: { ts: "lone surrogate", rs: "unexpected end of hex escape" },
    },
    {
      name: "high-surrogate-then-an-escaped-letter",
      text: str(`\\ud83d${esc(0x41)}`),
      reason: "a high surrogate followed by an escape that is not a low surrogate",
      refusal: { ts: "lone surrogate", rs: "lone leading surrogate" },
    },
    {
      name: "surrogates-reversed",
      text: str("\\ude00\\ud83d"),
      reason: "low surrogate first",
      refusal: { ts: "lone surrogate", rs: "lone leading surrogate" },
    },
    {
      name: "lone-surrogate-in-a-member-name",
      text: '{"\\ud800":1}',
      reason: "a member name is a string too",
      refusal: { ts: "lone surrogate", rs: "unexpected end of hex escape" },
    },
    // ---- a control character written raw inside a string is not JSON; only its escape is ----
    { name: "raw-tab-in-a-string", text: str(cp(0x09)), reason: "U+0009 unescaped", refusal: RAW_CONTROL },
    { name: "raw-newline-in-a-string", text: str(cp(0x0a)), reason: "U+000A unescaped", refusal: RAW_CONTROL },
    { name: "raw-nul-in-a-string", text: str(cp(0x00)), reason: "U+0000 unescaped", refusal: RAW_CONTROL },
    { name: "raw-unit-separator-in-a-string", text: str(cp(0x1f)), reason: "U+001F unescaped", refusal: RAW_CONTROL },
  ];

  /** True iff two JSON values are the same value, telling -0 from 0. */
  const identical = (a: unknown, b: unknown): boolean => {
    if (typeof a !== "object" || a === null || typeof b !== "object" || b === null) return Object.is(a, b);
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    const [ka, kb] = [Object.keys(a), Object.keys(b)];
    return (
      ka.length === kb.length &&
      ka.every((k) => k in b && identical((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
    );
  };

  /** What the TypeScript implementation does with a case: canonical bytes, or a refusal. */
  const outcome = (c: Input): { canonical: string } | { refusal: string } => {
    let value: unknown;
    if (c.text !== undefined) {
      try {
        value = JSON.parse(c.text);
      } catch (e) {
        if (!(e instanceof SyntaxError)) throw e;
        return { refusal: "not JSON" };
      }
    } else {
      value = c.value;
    }
    try {
      return { canonical: canonicalJson(value) };
    } catch (e) {
      return { refusal: e instanceof Error ? e.message : String(e) };
    }
  };

  const names = [...valid, ...invalid].map((c) => c.name);
  const repeated = names.filter((n, i) => names.indexOf(n) !== i);
  if (repeated.length > 0) throw new Error(`canonical vectors: name used twice: ${repeated.join(", ")}`);
  for (const c of [...valid, ...invalid]) {
    if ((c.value === undefined) === (c.text === undefined)) {
      throw new Error(`canonical vector "${c.name}": give exactly one of value and text`);
    }
    if (c.text === undefined && !identical(c.value, JSON.parse(JSON.stringify(c.value)))) {
      throw new Error(
        `canonical vector "${c.name}": its value does not survive being written to the vector file ` +
          "(JSON.stringify changes it), so no runner would be shown it. Give it as text.",
      );
    }
  }
  const input = (c: Input) => (c.text !== undefined ? { text: c.text } : { value: c.value });

  const canonical = {
    spec: "sje/0.1.0",
    note:
      "Each case gives its input as `value` (a JSON value; how this file spells it is not part of " +
      "the test) or as `text` (the exact JSON text: parse it with your own JSON parser, then " +
      "canonicalize the result; the spelling is the test, e.g. 10.0, -0, 1e2, an escaped letter). " +
      "Valid: implementations MUST produce exactly `canonical` (as UTF-8 bytes) and `sha384`. " +
      "Invalid: implementations MUST refuse, in the parser or in the canonicalizer, and produce no " +
      "bytes; `refusal` holds a fragment of each reference implementation's own message (`ts`: " +
      'TypeScript, where "not JSON" means JSON.parse rejected the text; `rs`: Rust), so a case cannot ' +
      "pass by being refused for some other defect. A number is read as an IEEE-754 binary64 value " +
      "(round to nearest, ties to even) before the canonical rule is applied to it. Every `text` is " +
      "one JSON value with no repeated member name (travelers/reject/ covers those). This file is " +
      "ASCII: any other character, in a `text` or anywhere else, is written as a \\uXXXX escape of " +
      "this file's own JSON, so a character that is literal in a `text` shows one backslash here and " +
      "an escape inside the `text` shows two.",
    valid: valid.map((c) => {
      const o = outcome(c);
      if (!("canonical" in o)) throw new Error(`canonical vector "${c.name}" is listed as valid but is refused: ${o.refusal}`);
      return { name: c.name, ...input(c), canonical: o.canonical, sha384: `sha384:${bytesToHex(sha384(utf8ToBytes(o.canonical)))}` };
    }),
    invalid: invalid.map((c) => {
      const o = outcome(c);
      if (!("refusal" in o)) throw new Error(`canonical vector "${c.name}" is listed as invalid but canonicalizes to ${o.canonical}`);
      if (!o.refusal.includes(c.refusal.ts)) {
        throw new Error(`canonical vector "${c.name}" is refused for "${o.refusal}", not for "${c.refusal.ts}"`);
      }
      return { name: c.name, ...input(c), reason: c.reason, refusal: c.refusal };
    }),
  };

  const file =
    JSON.stringify(canonical, null, 2).replace(
      /[^\n -~]/g,
      (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
    ) + "\n";
  if (!identical(JSON.parse(file), JSON.parse(JSON.stringify(canonical)))) {
    throw new Error("canonical.json: the ASCII rendering does not read back as the same vectors");
  }
  writeFileSync(`${here}/canonical.json`, file);
}

/* ---------- traveler vectors ---------- */

const l0: Traveler = JSON.parse(
  readFileSync(`${here}/../examples/bracket.traveler.json`, "utf8"),
) as Traveler;
l0.traveler_id = "tvl_conform0l0";

const l0Hash = travelerHash(l0);

const quote: Quote = {
  quote_id: "qot_conform01",
  seller: {
    org_id: "org_summitfab",
    name: "Summit Fabrication",
    city: "Sparks",
    region: "NV",
    certs: ["ISO 9001"],
  },
  traveler_hash_quoted: l0Hash,
  created_at: "2026-09-16T12:00:00.000Z",
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: {
    currency: "USD",
    nre: 35000,
    lines: [
      { qty: 100, unit: 1850 },
      { qty: 250, unit: 1420 },
      { qty: 500, unit: 1175 },
    ],
  },
};

const l1: Traveler = { ...structuredClone(l0), traveler_id: "tvl_conform0l1", quotes: [] };
const l1Hash = travelerHash(l1);
l1.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l1Hash }];

const l2: Traveler = { ...structuredClone(l1), traveler_id: "tvl_conform0l2" };
const l2Hash = travelerHash(l2);
l2.quotes = [{ ...structuredClone(quote), traveler_hash_quoted: l2Hash }];
l2.award = {
  quote_id: "qot_conform01",
  awarded_at: "2026-09-17T09:00:00.000Z",
  qty: 250,
  terms: {
    governing_law: "US-DE",
    warranty: "12 months, parts and labor",
    payment_terms: "Net 30",
  },
};
l2.ops = [
  { seq: 1, code: "laser" },
  { seq: 2, code: "cnc-mill" },
  { seq: 3, code: "deburr" },
];
l2.ship_to = {
  name: "Northline Equipment — Dock 4",
  line1: "1800 Industrial Way",
  city: "Reno",
  region: "NV",
  postal: "89502",
  country: "US",
};

// Empty arrays / strings MUST be dropped from the quoteable body identically
// on both implementations. This vector pins that: a naive Rust serializer that
// keeps `Some(vec![])` as `[]` produces a different hash and fails here.
const emptyArrays: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_conformempt",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment", certs: [] },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50, breaks: [] },
    processes: [],
  },
  itar: false,
};

// Long-decimal thickness_mm (regression): the only float in the quoteable body.
// Pins cross-implementation hash parity end to end at the traveler layer.
const longFloat: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_longfloat01",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6", thickness_mm: 223.23501793805622 },
    qty: { target: 50 },
  },
  itar: false,
};

// String length limits count Unicode CODE POINTS (zod v4's `.min`/`.max`), not UTF-16
// code units. part.family here is exactly MAX_NAME (128) code points of U+1F600 — 256
// UTF-16 units. An implementation that counts UTF-16 units (as the Rust core once did)
// refuses this document; both must accept it and hash it identically.
const codePointBoundary: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_cpboundary1",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "\u{1F600}".repeat(128),
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  itar: false,
};

// A name consisting only of U+0085 (NEL). U+0085 is NOT ECMAScript whitespace, so the
// name is non-blank and the traveler is Quoteable (L0). An implementation that decides
// "blank" with a Unicode White_Space trim (Rust's `str::trim` strips U+0085) calls the
// same document Draft — one document, two levels. Both must say L0.
const nelName: Traveler = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_nelname001",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "\u0085" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  itar: false,
};

/** Pretty JSON for a vector file, with C1 control characters written as `\u00XX`
 *  escapes so an invisible character (the U+0085 above) is reviewable in a diff. Both
 *  spellings parse to the same string. */
const wire = (p: unknown): string =>
  JSON.stringify(p, null, 2).replace(
    /[\u0080-\u009f]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ) + "\n";

const expected: Record<string, { traveler_hash: string; level: string }> = {};
for (const [file, p] of [
  ["l0-bracket.json", l0],
  ["l0-longfloat.json", longFloat],
  ["l0-empty-arrays.json", emptyArrays],
  ["l1-quoted.json", l1],
  ["l2-awarded.json", l2],
  ["part-family-128-codepoints.json", codePointBoundary],
  ["l0-nel-name.json", nelName],
] as const) {
  const parsed = parseTraveler(JSON.parse(JSON.stringify(p)));
  expected[file] = { traveler_hash: travelerHash(parsed), level: levelOf(parsed).code };
  writeFileSync(`${here}/travelers/${file}`, wire(p));
}

// Integer-valued floats on the wire (revision 1.0, qty.target 250.0, breaks [100.0,
// 250.0]). Both implementations MUST accept these — JS collapses 250.0->250, and the
// Rust core's lenient integer deserializer accepts an integer-valued float — and hash
// them identically to the all-integer form (the canonicalizer renders N.0 as N). See
// docs/SPEC.md §Canonical JSON / parsing. Authored as literal text because
// JSON.stringify of a JS number would collapse the `.0`.
const intFloatJson = `{
  "spec": "sje/0.1.0",
  "traveler_id": "tvl_conformintf",
  "revision": 1.0,
  "created_at": "2026-09-16T12:00:00.000Z",
  "buyer": { "name": "Northline Equipment" },
  "part": {
    "family": "CNC bracket",
    "part_number": "NL-BRK-4410",
    "material": { "spec": "6061-T6" },
    "qty": { "target": 250.0, "breaks": [100.0, 250.0] }
  },
  "itar": false
}
`;
writeFileSync(`${here}/travelers/l0-intfloat.json`, intFloatJson);
const intFloatParsed = parseTraveler(JSON.parse(intFloatJson));
expected["l0-intfloat.json"] = {
  traveler_hash: travelerHash(intFloatParsed),
  level: levelOf(intFloatParsed).code,
};

// Free-form blobs are measured on their canonical form, in bytes (docs/SPEC.md, parsing
// rule 12). Authored as text, because how the blob is SPELLED is the point: the same
// blob has one canonical size however its numbers and characters were written.
{
  /** A copy of the L0 vector with `as_built` holding one member `k`, spelled as given. */
  const withBlob = (travelerId: string, k: string): string =>
    JSON.stringify({ ...structuredClone(l0), traveler_id: travelerId, as_built: { k: "@@" } }, null, 2).replace(
      '"@@"',
      k,
    ) + "\n";
  const blobVectors: [file: string, text: string, canonicalBytes: number][] = [
    // The first document the byte-level fuzzer found the two implementations split on,
    // exactly as it was found (the smallest valid traveler, no whitespace): 431 numbers
    // written `1e15`. Canonically they are sixteen digits each — 7,333 bytes. One
    // implementation's own JSON writer made them eighteen characters each and refused.
    [
      "l0-blob-numbers-respelled.json",
      '{"spec":"sje/0.1.0","traveler_id":"tvl_aaaaaa","revision":1,"created_at":"2026-01-01T00:00:00Z",' +
        '"buyer":{"name":"B"},"part":{"family":"F","part_number":"P","material":{"spec":"M"},"qty":{"target":1}},' +
        `"as_built":{"":[${Array.from({ length: 431 }, () => "1e15").join(",")}]}}`,
      7333,
    ],
    // Exactly at the cap, in bytes: 2,728 three-byte characters (written here as escapes)
    // and eight bytes of framing are 8,192. In UTF-16 units it would be 2,736.
    [
      "l0-blob-at-cap.json",
      withBlob("tvl_blobatcap01", `"${"\\u6f22".repeat(2728)}"`),
      8192,
    ],
    // Twice the cap as written, under it canonically: 4,092 ones written `1.0` are
    // 16,375 characters of wire text and 8,191 canonical bytes.
    [
      "l0-blob-canonical-size.json",
      withBlob("tvl_blobcanon01", `[${Array.from({ length: 4092 }, () => "1.0").join(",")}]`),
      8191,
    ],
  ];
  for (const [file, text, canonicalBytes] of blobVectors) {
    const parsed = parseTravelerJson(text);
    const measured = utf8ToBytes(canonicalJson(parsed.as_built)).length;
    if (measured !== canonicalBytes) {
      throw new Error(`${file}: its blob is ${measured} canonical bytes, not the ${canonicalBytes} the vector is for`);
    }
    expected[file] = { traveler_hash: travelerHash(parsed), level: levelOf(parsed).code };
    writeFileSync(`${here}/travelers/${file}`, text);
  }
}

writeFileSync(`${here}/travelers/expected.json`, JSON.stringify(expected, null, 2) + "\n");

// sanity: golden vector must still hold
const golden = JSON.parse(
  readFileSync(`${here}/../crates/secure-job-envelope/tests/golden.json`, "utf8"),
);
console.log("golden:", hashQuoteable(golden));
console.log("levels:", Object.fromEntries(Object.entries(expected).map(([k, v]) => [k, v.level])));
console.log("vectors written");

// keep quoteableBody import used (documents that hashes cover the closed body)
void quoteableBody;

/* ---------- signature vector (ML-DSA-87 / FIPS 204) ---------- */
// A deterministic keypair from a fixed 32-byte seed. Both implementations MUST
// derive the same public key, produce the same signature over the same
// domain-separated canonical body, and verify it — proving cross-language
// agreement on post-quantum authorship, not just on the content hash.
const sigSeed = new Uint8Array(32);
for (let i = 0; i < 32; i++) sigSeed[i] = i;
const sigKp = keypairFromSeed(sigSeed);
const sigBody = canonicalJson(golden);
const signatureVector = {
  spec: "sje/0.1.0",
  note:
    "ML-DSA-87 (FIPS 204) authorship signature over domain-separated canonical bytes. " +
    "Implementations MUST derive public_key_hex from seed_hex, produce signature_hex " +
    "deterministically when signing canonical_body under domain, and verify it. The " +
    "signed message is domain + 0x00 + canonical_body.",
  alg: "ML-DSA-87",
  domain: SIG_DOMAIN.traveler,
  seed_hex: bytesToHex(sigSeed),
  public_key_hex: bytesToHex(sigKp.publicKey),
  canonical_body: sigBody,
  signature_hex: signBody(SIG_DOMAIN.traveler, sigBody, sigKp.secretKey),
};
mkdirSync(`${here}/signatures`, { recursive: true });
writeFileSync(
  `${here}/signatures/traveler-sig.json`,
  JSON.stringify(signatureVector, null, 2) + "\n",
);
console.log("signature vector written");

/* ---------- signed key directory vector ---------- */
// A trust root signs a directory of org -> key entries (with ITAR capability
// attested per org). Both implementations verify the directory signature over
// the canonical directory body, so org identity and capability are cross-checked.
const fill = (b: number) => new Uint8Array(32).fill(b);
const rootKp = keypairFromSeed(fill(0x11));
const huronKp = keypairFromSeed(fill(0x22));
const summitKp = keypairFromSeed(fill(0x33));
const northlineKp = keypairFromSeed(fill(0x44));
// Per-org ML-KEM-1024 encryption keys, attested alongside the signing keys so a
// sealer can resolve a recipient's key through the trust root (M3).
const huronKemSeed = new Uint8Array(64).fill(0x51);
const summitKemSeed = new Uint8Array(64).fill(0x52);
const northlineKemSeed = new Uint8Array(64).fill(0x53);
const huronKem = kemKeypairFromSeed(huronKemSeed);
const summitKem = kemKeypairFromSeed(summitKemSeed);
const northlineKem = kemKeypairFromSeed(northlineKemSeed);
const directory: Directory = {
  spec: DIRECTORY_SPEC,
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  root_kid: "root-2026",
  entries: [
    {
      org_id: "org_huron",
      kid: "huron-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(huronKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: true },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(huronKem.publicKey),
    },
    {
      org_id: "org_summitfab",
      kid: "summit-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(summitKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: false },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(summitKem.publicKey),
    },
    {
      org_id: "org_northline",
      kid: "northline-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(northlineKp.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      capabilities: { itar: false },
      enc_alg: "ML-KEM-1024",
      enc_public_key: bytesToHex(northlineKem.publicKey),
    },
  ],
};
const directoryVector = {
  note:
    "Signed key directory. Verify the directory signature (directory.sig) with " +
    "root_public_key_hex over the canonical directory body (the directory with its " +
    "own sig removed), then trust each entry's org_id -> public_key and capabilities.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  directory: { ...directory, sig: signDirectory(directory, rootKp.secretKey) },
};
writeFileSync(`${here}/signatures/directory.json`, JSON.stringify(directoryVector, null, 2) + "\n");
console.log("directory vector written");

/* ---------- signed traveler vector (end-to-end authorship) ---------- */
// A real traveler carrying a buyer authorship signature, plus the directory and
// root key needed to verify it. Both implementations run the full chain:
// directory verifies -> signature kid resolves to buyer.org_id -> ML-DSA verify.
const signedTraveler: Traveler = structuredClone(l0);
signedTraveler.traveler_id = "tvl_signed00001";
signedTraveler.buyer = { ...signedTraveler.buyer, org_id: "org_northline" };
signedTraveler.signatures = [signTraveler(signedTraveler, "northline-2026", northlineKp.secretKey)];
const signedTravelerVector = {
  note:
    "End-to-end authorship. Verify the directory against root_public_key_hex, resolve the " +
    "traveler signature's kid to a directory entry whose org_id equals buyer.org_id, then " +
    "verify the ML-DSA-87 signature over the canonical quoteable body. A tampered body, a " +
    "wrong signer org, or a broken directory all fail.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  directory: directoryVector.directory,
  traveler: signedTraveler,
};
writeFileSync(
  `${here}/signatures/signed-traveler.json`,
  JSON.stringify(signedTravelerVector, null, 2) + "\n",
);
console.log("signed traveler vector written");

/* ---------- signed award vector (buyer award authorship + quote-content binding) ---------- */
// A traveler whose award + ship-to are signed by the buyer, with the award bound to the awarded
// quote's content via `award.quote_hash`. Both implementations resolve the award sig's kid to a
// directory entry whose org_id equals buyer.org_id and verify the ML-DSA-87 signature over the
// canonical award body {spec, traveler_id, traveler_hash, award (minus sig), ship_to}, then
// require the awarded quote (qot_conform01 — present and unsigned here, the exact gap case) to be
// on the traveler and to hash to award.quote_hash. A forged award, an altered ship-to, a bumped
// revision, a non-buyer signer, OR a swapped unit price on the awarded quote all fail.
const awardTraveler: Traveler = structuredClone(l2);
awardTraveler.traveler_id = "tvl_award0000001";
awardTraveler.buyer = { ...awardTraveler.buyer, org_id: "org_northline" };
const awardHash = travelerHash(awardTraveler);
for (const q of awardTraveler.quotes ?? []) q.traveler_hash_quoted = awardHash;
// Bind the awarded quote's priced content into the award before signing it, so the buyer's award
// signature commits to the exact priced quote, not merely its id.
const awardedQuote = awardTraveler.quotes!.find((q) => q.quote_id === awardTraveler.award!.quote_id)!;
awardTraveler.award!.quote_hash = quoteContentHash(awardedQuote);
awardTraveler.signatures = [signTraveler(awardTraveler, "northline-2026", northlineKp.secretKey)];
awardTraveler.award!.sig = signAward(awardTraveler, "northline-2026", northlineKp.secretKey);
const signedAwardVector = {
  note:
    "Buyer award authorship + quote-content binding (BEC defense, completeness). Verify the " +
    "directory against root_public_key_hex, resolve the award sig's kid to a directory entry " +
    "whose org_id equals buyer.org_id, verify the ML-DSA-87 signature over the canonical award " +
    "body {spec, traveler_id, traveler_hash, award (minus its own sig), ship_to}, then require " +
    "the awarded quote (by award.quote_id) to be present in quotes and to hash (sha384 of the " +
    "quote minus its own sig) to award.quote_hash. A forged award, an altered ship_to, a bumped " +
    "revision, a non-buyer signer, OR a swapped unit price on the awarded quote all fail. " +
    "Evaluate at at_ms (inside the windows).",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2027-01-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  traveler: awardTraveler,
};
writeFileSync(
  `${here}/signatures/signed-award.json`,
  JSON.stringify(signedAwardVector, null, 2) + "\n",
);
console.log("signed award vector written");

/* ---------- expired-entry directory vector (validity-window enforcement) ---------- */
// The directory itself is valid to 2030, but the org_northline signer entry
// expires mid-window (2026-07-01). Both implementations MUST verify authorship at
// valid_at_ms (entry still valid) and MUST refuse it at expired_at_ms (entry
// expired though the directory is still valid) — proving entry-level window
// enforcement distinct from the directory-level window (audit H1).
const expiringDir: Directory = structuredClone(directory);
const expiringNorthline = expiringDir.entries.find((e) => e.org_id === "org_northline")!;
expiringNorthline.valid_until = "2026-07-01T00:00:00.000Z";
const expiredEntryVector = {
  note:
    "Entry-level validity window. The directory runs to 2030 but the org_northline " +
    "entry expires 2026-07-01. Implementations MUST verify authorship at valid_at_ms " +
    "(entry in window) and MUST refuse it at expired_at_ms (entry expired, directory " +
    "still valid).",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  valid_at_ms: Date.parse("2026-03-01T00:00:00.000Z"),
  expired_at_ms: Date.parse("2027-01-01T00:00:00.000Z"),
  directory: { ...expiringDir, sig: signDirectory(expiringDir, rootKp.secretKey) },
  traveler: signedTraveler,
};
writeFileSync(
  `${here}/signatures/directory-expired-entry.json`,
  JSON.stringify(expiredEntryVector, null, 2) + "\n",
);
console.log("expired-entry directory vector written");

/* ---------- encrypted envelope vector (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) ---------- */
// Deterministic seal (fixed CEK / nonces / KEM coins). Both implementations must
// re-seal to the same ciphertext bytes and both must decrypt it to the plaintext.
const envRecipient = recipientByOrg(
  directoryVector.directory,
  "org_northline",
  new Date("2027-01-01T00:00:00.000Z"),
)!;
const det = {
  cek: new Uint8Array(32).fill(0x2a),
  payload_nonce: new Uint8Array(12).fill(0x01),
  coins: [new Uint8Array(32).fill(0x09)],
  wrap_nonces: [new Uint8Array(12).fill(0x02)],
};
const envPlaintext = canonicalJson(golden);
const envelope = sealEnvelopeDeterministic(
  new TextEncoder().encode(envPlaintext),
  [envRecipient],
  det,
);
const envelopeVector = {
  note:
    "Encrypted envelope, deterministic seal to a directory-attested recipient. The recipient's " +
    "ML-KEM key is resolved from the signed directory (org_northline) and the recipient kid is " +
    "derived from that key (enc_kid). Implementations re-seal plaintext_utf8 with the fixed " +
    "determinism values and MUST reproduce envelope byte-for-byte, and MUST decrypt it back to " +
    "plaintext_utf8 with the recipient seed. The payload AAD binds {spec, enc_alg, recipients}.",
  recipient: {
    kid: envRecipient.kid,
    org_id: "org_northline",
    seed_hex: bytesToHex(northlineKemSeed),
    public_key_hex: envRecipient.public_key,
  },
  determinism: {
    cek_hex: bytesToHex(det.cek),
    payload_nonce_hex: bytesToHex(det.payload_nonce),
    coins_hex: bytesToHex(det.coins[0]!),
    wrap_nonce_hex: bytesToHex(det.wrap_nonces[0]!),
  },
  plaintext_utf8: envPlaintext,
  envelope,
};
writeFileSync(`${here}/signatures/envelope.json`, JSON.stringify(envelopeVector, null, 2) + "\n");
console.log("envelope vector written");

/* ---------- signed quote vector (seller authorship) ---------- */
// A seller quote carrying an ML-DSA-87 signature, with the directory and root key
// needed to verify it. Both implementations verify the directory, resolve the
// quote signature's kid to a directory entry whose org_id equals seller.org_id,
// and verify the signature over the canonical quote body (the quote with its own
// sig removed). org_huron is ITAR-attested, so the same vector exercises the
// directory-attested ITAR gate.
const signedQuote: Quote = {
  quote_id: "qot_signed00001",
  seller: {
    org_id: "org_huron",
    name: "Huron Precision",
    city: "Ann Arbor",
    region: "MI",
    certs: ["AS9100"],
    itar: true,
  },
  traveler_hash_quoted: l0Hash,
  created_at: "2026-02-01T00:00:00.000Z",
  valid_until: "2027-02-01T00:00:00.000Z",
  lead_time_days: 18,
  pricing: { currency: "USD", nre: 25000, lines: [{ qty: 100, unit: 1600 }] },
};
signedQuote.sig = signQuote(signedQuote, "huron-2026", huronKp.secretKey);
const signedQuoteVector = {
  note:
    "Seller quote authorship. Verify the directory against root_public_key_hex, resolve the " +
    "quote sig's kid to a directory entry whose org_id equals seller.org_id, then verify the " +
    "ML-DSA-87 signature over the canonical quote body (the quote with its own sig removed). " +
    "Evaluate at at_ms (inside the directory and entry windows). org_huron is ITAR-attested.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2026-06-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  quote: signedQuote,
};
writeFileSync(
  `${here}/signatures/signed-quote.json`,
  JSON.stringify(signedQuoteVector, null, 2) + "\n",
);
console.log("signed quote vector written");

/* ---------- signed one-time prekey bundle vector (forward secrecy) ---------- */
// A recipient org (org_northline) publishes one-time ML-KEM-1024 prekeys, the
// whole bundle signed by its ML-DSA identity key (kid northline-2026). Both
// implementations verify the bundle against the directory: kid -> org_northline,
// the bundle's own window covers at_ms, and the ML-DSA signature over the
// canonical body checks out. These prekeys are reused by the FS envelope vector.
const prekeySeeds = [new Uint8Array(64).fill(0x61), new Uint8Array(64).fill(0x62)];
const prekeyKps = prekeySeeds.map((s) => kemKeypairFromSeed(s));
const prekeyBundle: PrekeyBundle = {
  spec: PREKEY_BUNDLE_SPEC,
  org_id: "org_northline",
  kid: "northline-2026",
  enc_alg: "ML-KEM-1024",
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2027-01-01T00:00:00.000Z",
  prekeys: prekeyKps.map((kp, i) => ({
    prekey_id: `northline-ot-${i + 1}`,
    public_key: bytesToHex(kp.publicKey),
  })),
};
prekeyBundle.sig = signPrekeyBundle(prekeyBundle, northlineKp.secretKey);
const prekeyBundleVector = {
  note:
    "Signed one-time prekey bundle. Verify the directory against root_public_key_hex, resolve " +
    "the bundle's kid to a directory entry whose org_id equals the bundle's org_id, check the " +
    "bundle's own window covers at_ms, then verify the ML-DSA signature over the canonical bundle " +
    "body (bundle minus its own sig). prekey_seeds regenerate each one-time ML-KEM keypair.",
  root_public_key_hex: bytesToHex(rootKp.publicKey),
  at_ms: Date.parse("2026-06-01T00:00:00.000Z"),
  directory: directoryVector.directory,
  bundle: prekeyBundle,
  prekey_seeds: prekeyKps.map((_, i) => ({
    prekey_id: `northline-ot-${i + 1}`,
    seed_hex: bytesToHex(prekeySeeds[i]!),
  })),
};
writeFileSync(
  `${here}/signatures/prekey-bundle.json`,
  JSON.stringify(prekeyBundleVector, null, 2) + "\n",
);
console.log("prekey bundle vector written");

/* ---------- forward-secret envelope vector (two-KEM: one-time prekey + static) ---------- */
// Seals to org_northline using one verified one-time prekey (northline-ot-1) plus
// northline's static identity ML-KEM key from the directory. The KEK binds both
// shared secrets (one-time || static). Both implementations re-seal byte-for-byte
// and open with BOTH the static and one-time secret keys.
const fsRecipient = fsRecipientFromBundle(
  directoryVector.directory,
  prekeyBundle,
  "org_northline",
  "northline-ot-1",
  bytesToHex(rootKp.publicKey),
  new Date("2026-06-01T00:00:00.000Z"),
)!;
const fsDet = {
  cek: new Uint8Array(32).fill(0x3a),
  payload_nonce: new Uint8Array(12).fill(0x03),
  coins_onetime: [new Uint8Array(32).fill(0x0a)],
  coins_static: [new Uint8Array(32).fill(0x0b)],
  wrap_nonces: [new Uint8Array(12).fill(0x04)],
};
const fsPlaintext = canonicalJson(golden);
const fsEnvelope = sealFsEnvelopeDeterministic(
  new TextEncoder().encode(fsPlaintext),
  [fsRecipient],
  fsDet,
);
const fsEnvelopeVector = {
  note:
    "Forward-secret envelope (sje-envelope/0.2.0). Encapsulates to a one-time prekey AND the " +
    "static identity key; the KEK binds both shared secrets (one-time || static). Implementations " +
    "re-seal plaintext_utf8 with the fixed determinism values and MUST reproduce envelope " +
    "byte-for-byte, and MUST decrypt it with BOTH the static and one-time seeds. Deleting the " +
    "one-time secret after opening is what gives forward secrecy.",
  recipient: {
    kid: fsRecipient.kid,
    org_id: "org_northline",
    prekey_id: "northline-ot-1",
    static_seed_hex: bytesToHex(northlineKemSeed),
    onetime_seed_hex: bytesToHex(prekeySeeds[0]!),
    static_public_key_hex: fsRecipient.static_public_key,
    onetime_public_key_hex: fsRecipient.onetime_public_key,
  },
  determinism: {
    cek_hex: bytesToHex(fsDet.cek),
    payload_nonce_hex: bytesToHex(fsDet.payload_nonce),
    coins_onetime_hex: bytesToHex(fsDet.coins_onetime[0]!),
    coins_static_hex: bytesToHex(fsDet.coins_static[0]!),
    wrap_nonce_hex: bytesToHex(fsDet.wrap_nonces[0]!),
  },
  plaintext_utf8: fsPlaintext,
  envelope: fsEnvelope,
};
writeFileSync(
  `${here}/signatures/fs-envelope.json`,
  JSON.stringify(fsEnvelopeVector, null, 2) + "\n",
);
console.log("fs envelope vector written");

/* ---------- envelope shape + tamper vectors (accept and reject, both specs) ---------- */
// The golden vectors above prove both implementations seal and open the SAME bytes. These
// prove they REFUSE the same bytes, and why. Each case is the envelope's JSON text exactly
// as it would arrive, plus who tries to open it:
//
//   accept          shape-valid and opens to plaintext_utf8 (strictness must not over-refuse:
//                   member order and whitespace are not part of the shape; two recipients work)
//   reject / shape  refused by the SHAPE check alone, before any key is used. Most of these
//                   would decrypt successfully if the check were missing — an extra member, a
//                   hex string in the other letter case, a repeated member name, a 16-byte
//                   content key — which is exactly why they are vectors.
//   reject / crypto shape-valid, but must fail to open (tamper, reorder, drop, relabel).
//
// A runner checks the stage, not just the refusal: a "shape" case must fail the shape check
// itself, and a "crypto" case must PASS the shape check and then fail to open.
type EnvCase = {
  name: string;
  why: string;
  kid: string;
  seed_hex: string;
  onetime_seed_hex?: string;
  text: string;
};
const NUL = String.fromCharCode(0);
const BOM = String.fromCharCode(0xfeff);
const plain = new TextEncoder().encode(envPlaintext);
const goldenText = JSON.stringify(envelope);
const fsGoldenText = JSON.stringify(fsEnvelope);
const northSeedHex = bytesToHex(northlineKemSeed);
const summitSeedHex = bytesToHex(summitKemSeed);
const otSeedHex = bytesToHex(prekeySeeds[0]!);
const summitRecipient = recipientByOrg(
  directoryVector.directory,
  "org_summitfab",
  new Date("2027-01-01T00:00:00.000Z"),
)!;
const kidN = envRecipient.kid;
const kidS = summitRecipient.kid;

// Two recipients, deterministic.
const det2 = {
  cek: new Uint8Array(32).fill(0x4a),
  payload_nonce: new Uint8Array(12).fill(0x05),
  coins: [new Uint8Array(32).fill(0x0c), new Uint8Array(32).fill(0x0d)],
  wrap_nonces: [new Uint8Array(12).fill(0x06), new Uint8Array(12).fill(0x07)],
};
const two = sealEnvelopeDeterministic(plain, [envRecipient, summitRecipient], det2);
// The same recipient listed twice: the payload AAD binds [kid, kid], so without a
// uniqueness rule this opens.
const twice = sealEnvelopeDeterministic(plain, [envRecipient, envRecipient], det2);

type Mut = Record<string, unknown> & { recipients: Record<string, unknown>[] };
/** A deep copy of an envelope, edited. */
function edit(base: unknown, f: (e: Mut) => void): string {
  const e = structuredClone(base) as Mut;
  f(e);
  return JSON.stringify(e);
}
/** Flip the lowest bit of the first byte of a lowercase-hex string (stays lowercase hex). */
function flip(hex: string): string {
  const first = (parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0");
  return first + hex.slice(2);
}

/** What a non-conforming sealer would emit: everything as specified except the content
 *  key's length. Re-derived here with the primitives directly (not through the code under
 *  test); the 32-byte form is checked against openEnvelope below, so the 16- and 24-byte
 *  forms are known to be exactly "right KDF, right AAD, wrong key size" — AES-128/192-GCM
 *  under an "AES-256-GCM" label. */
function sealWithKeyBytes(keyBytes: number): string {
  const cek = new Uint8Array(keyBytes).fill(0x2b);
  const payloadNonce = new Uint8Array(12).fill(0x08);
  const wrapNonce = new Uint8Array(12).fill(0x09);
  const aadWrap = utf8ToBytes(`${ENVELOPE_SPEC}${NUL}${ENC_ALG}${NUL}${kidN}`);
  const aadBody = utf8ToBytes(
    canonicalJson({ spec: ENVELOPE_SPEC, enc_alg: ENC_ALG, recipients: [kidN] }),
  );
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(
    hexToBytes(envRecipient.public_key),
    new Uint8Array(32).fill(0x0e),
  );
  const kek = hkdf(sha384, sharedSecret, utf8ToBytes("sje-kek/0.1.0"), aadWrap, 32);
  return JSON.stringify({
    spec: ENVELOPE_SPEC,
    enc_alg: ENC_ALG,
    payload_nonce: bytesToHex(payloadNonce),
    payload: bytesToHex(gcm(cek, payloadNonce, aadBody).encrypt(plain)),
    recipients: [
      {
        kid: kidN,
        kem_ct: bytesToHex(cipherText),
        wrap_nonce: bytesToHex(wrapNonce),
        wrapped_cek: bytesToHex(gcm(kek, wrapNonce, aadWrap).encrypt(cek)),
      },
    ],
  });
}
{
  const control = JSON.parse(sealWithKeyBytes(32)) as Parameters<typeof openEnvelope>[0];
  const opened = openEnvelope(control, kidN, northlineKem.secretKey);
  if (new TextDecoder().decode(opened) !== envPlaintext) {
    throw new Error("vector self-check failed: hand-derived envelope does not open");
  }
}

const N = { kid: kidN, seed_hex: northSeedHex };
const S = { kid: kidS, seed_hex: summitSeedHex };
const F = { kid: kidN, seed_hex: northSeedHex, onetime_seed_hex: otSeedHex };

const envAccept: EnvCase[] = [
  { name: "golden-compact", why: "the golden 0.1.0 envelope as compact JSON", ...N, text: goldenText },
  {
    name: "members-reordered-and-indented",
    why: "member order and whitespace are not part of the shape",
    ...N,
    text: JSON.stringify(
      {
        recipients: envelope.recipients.map((r) => ({
          wrapped_cek: r.wrapped_cek,
          wrap_nonce: r.wrap_nonce,
          kem_ct: r.kem_ct,
          kid: r.kid,
        })),
        payload: envelope.payload,
        payload_nonce: envelope.payload_nonce,
        enc_alg: envelope.enc_alg,
        spec: envelope.spec,
      },
      null,
      2,
    ),
  },
  { name: "two-recipients-first", why: "first of two recipients opens", ...N, text: JSON.stringify(two) },
  { name: "two-recipients-second", why: "second of two recipients opens", ...S, text: JSON.stringify(two) },
  { name: "fs-golden-compact", why: "the golden 0.2.0 envelope as compact JSON", ...F, text: fsGoldenText },
];

const shape = (name: string, why: string, who: Omit<EnvCase, "name" | "why" | "text">, text: string) => ({
  name,
  why,
  stage: "shape" as const,
  ...who,
  text,
});
const crypto_ = (name: string, why: string, who: Omit<EnvCase, "name" | "why" | "text">, text: string) => ({
  name,
  why,
  stage: "crypto" as const,
  ...who,
  text,
});
const up = (h: string) => h.toUpperCase();

const envReject = [
  // ---- shape: would otherwise decrypt ----
  shape("extra-member", "an unknown top-level member; the tags do not cover it", N,
    edit(envelope, (e) => { e.note = "trust me"; })),
  shape("extra-recipient-member", "an unknown member on a recipient entry", N,
    edit(envelope, (e) => { e.recipients[0]!.hint = "x"; })),
  shape("payload-uppercase-hex", "hex must be lowercase: one wire form per envelope", N,
    edit(envelope, (e) => { e.payload = up(e.payload as string); })),
  shape("kem-ct-uppercase-hex", "hex must be lowercase", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = up(e.recipients[0]!.kem_ct as string); })),
  shape("wrapped-cek-uppercase-hex", "hex must be lowercase", N,
    edit(envelope, (e) => { e.recipients[0]!.wrapped_cek = up(e.recipients[0]!.wrapped_cek as string); })),
  shape("duplicate-member-payload", "a repeated member name: a last-wins reader opens the second payload and never reads the first", N,
    goldenText.replace('"payload":', '"payload":"00","payload":')),
  shape("duplicate-member-recipient-kid", "a repeated member name inside a recipient entry", N,
    goldenText.replace('"kid":', '"kid":"0000000000000000","kid":')),
  shape("byte-order-mark", "a UTF-8 byte-order mark before the envelope", N, BOM + goldenText),
  shape("trailing-content", "a second JSON value after the envelope", N, goldenText + " {}"),
  shape("content-key-16-bytes", "a 16-byte content key (AES-128-GCM under the AES-256-GCM label); the wrapped key is not 48 bytes", N,
    sealWithKeyBytes(16)),
  shape("content-key-24-bytes", "a 24-byte content key (AES-192-GCM under the AES-256-GCM label)", N,
    sealWithKeyBytes(24)),
  shape("same-recipient-twice", "the same kid in two recipient entries (the AAD binds [kid, kid], so it opens unless refused)", N,
    JSON.stringify(twice)),
  // ---- shape: malformed outright ----
  shape("missing-enc-alg", "a required member is absent", N,
    edit(envelope, (e) => { delete e.enc_alg; })),
  shape("alg-of-the-other-spec", "enc_alg must be the one that belongs to spec", N,
    edit(envelope, (e) => { e.enc_alg = FS_ENC_ALG; })),
  shape("unknown-spec", "an envelope version this specification does not define", N,
    edit(envelope, (e) => { e.spec = "sje-envelope/0.3.0"; })),
  shape("payload-nonce-13-bytes", "nonces are exactly 12 bytes", N,
    edit(envelope, (e) => { e.payload_nonce = (e.payload_nonce as string) + "00"; })),
  shape("wrap-nonce-11-bytes", "nonces are exactly 12 bytes", N,
    edit(envelope, (e) => { e.recipients[0]!.wrap_nonce = (e.recipients[0]!.wrap_nonce as string).slice(2); })),
  shape("kem-ct-one-byte-short", "an ML-KEM-1024 ciphertext is exactly 1568 bytes", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = (e.recipients[0]!.kem_ct as string).slice(2); })),
  shape("payload-shorter-than-a-tag", "the payload carries at least its 16-byte tag", N,
    edit(envelope, (e) => { e.payload = "00".repeat(15); })),
  shape("payload-odd-length-hex", "hex is whole bytes", N,
    edit(envelope, (e) => { e.payload = (e.payload as string) + "0"; })),
  shape("payload-nonce-null", "null is not a string", N,
    edit(envelope, (e) => { e.payload_nonce = null; })),
  shape("kid-not-hex", "kid is 8 bytes of lowercase hex", { kid: "northline-key-01", seed_hex: northSeedHex },
    edit(envelope, (e) => { e.recipients[0]!.kid = "northline-key-01"; })),
  shape("recipients-empty", "at least one recipient", N,
    edit(envelope, (e) => { e.recipients = []; })),
  shape("recipients-seventeen", "at most 16 recipients", N,
    edit(envelope, (e) => {
      const r = e.recipients[0]!;
      e.recipients = Array.from({ length: 17 }, (_, i) => ({ ...r, kid: i.toString(16).padStart(16, "0") }));
    })),
  shape("recipient-as-array", "a recipient entry written positionally, as an array", N,
    edit(envelope, (e) => {
      const r = e.recipients[0]!;
      (e as Record<string, unknown>).recipients = [[r.kid, r.kem_ct, r.wrap_nonce, r.wrapped_cek]];
    })),
  shape("envelope-as-array", "the envelope itself written as an array", N,
    JSON.stringify([envelope.spec, envelope.enc_alg, envelope.payload_nonce, envelope.payload, envelope.recipients])),
  shape("fs-prekey-id-with-nul", "prekey_id is 1-64 of [A-Za-z0-9._-]; it is concatenated into the key-derivation label", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = `northline-ot-1${NUL}x`; })),
  shape("fs-prekey-id-too-long", "prekey_id is at most 64 characters", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = "p".repeat(65); })),
  shape("fs-recipient-without-prekey-id", "a 0.2.0 recipient must name its one-time prekey", F,
    edit(fsEnvelope, (e) => { delete e.recipients[0]!.prekey_id; })),
  shape("static-recipient-in-fs-envelope", "0.1.0 recipient members under a 0.2.0 spec", F,
    edit(fsEnvelope, (e) => { e.recipients = structuredClone(envelope.recipients) as Record<string, unknown>[]; })),
  // ---- crypto: shape-valid, must not open ----
  crypto_("payload-bit-flipped", "one payload bit changed", N,
    edit(envelope, (e) => { e.payload = flip(e.payload as string); })),
  crypto_("payload-nonce-altered", "a different payload nonce", N,
    edit(envelope, (e) => { e.payload_nonce = flip(e.payload_nonce as string); })),
  crypto_("wrapped-cek-bit-flipped", "one bit of the wrapped content key changed", N,
    edit(envelope, (e) => { e.recipients[0]!.wrapped_cek = flip(e.recipients[0]!.wrapped_cek as string); })),
  crypto_("kem-ct-bit-flipped", "one bit of the ML-KEM ciphertext changed (implicit rejection, then the wrap tag fails)", N,
    edit(envelope, (e) => { e.recipients[0]!.kem_ct = flip(e.recipients[0]!.kem_ct as string); })),
  crypto_("two-recipients-reordered", "the payload AAD binds the ORDERED recipient set", N,
    edit(two, (e) => { e.recipients.reverse(); })),
  crypto_("two-recipients-one-dropped", "the payload AAD binds the WHOLE recipient set", N,
    edit(two, (e) => { e.recipients = [e.recipients[0]!]; })),
  crypto_("two-recipients-one-dropped-other-side", "the remaining recipient cannot open either", S,
    edit(two, (e) => { e.recipients = [e.recipients[1]!]; })),
  crypto_("two-recipients-keys-swapped", "each wrapped key is bound to its own kid", N,
    edit(two, (e) => {
      const [a, b] = [e.recipients[0]!, e.recipients[1]!];
      [a.wrapped_cek, b.wrapped_cek] = [b.wrapped_cek, a.wrapped_cek];
    })),
  crypto_("recipient-relabelled", "an entry sealed for one kid, relabelled with another's kid", S,
    edit(envelope, (e) => { e.recipients[0]!.kid = kidS; })),
  crypto_("fs-prekey-id-relabelled", "prekey_id is bound into the key derivation and the payload AAD", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.prekey_id = "northline-ot-2"; })),
  crypto_("fs-onetime-ct-bit-flipped", "one bit of the one-time ciphertext changed", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.kem_ct_onetime = flip(e.recipients[0]!.kem_ct_onetime as string); })),
  crypto_("fs-static-ct-bit-flipped", "one bit of the static ciphertext changed", F,
    edit(fsEnvelope, (e) => { e.recipients[0]!.kem_ct_static = flip(e.recipients[0]!.kem_ct_static as string); })),
  crypto_("fs-payload-bit-flipped", "one payload bit changed", F,
    edit(fsEnvelope, (e) => { e.payload = flip(e.payload as string); })),
];

const envelopeCases = {
  note:
    "Envelope accept/reject cases for both envelope specs. `text` is the envelope's JSON text " +
    "exactly as on the wire; `kid`/`seed_hex` (and `onetime_seed_hex` for 0.2.0) say who opens it. " +
    "accept: MUST pass the shape check and open to plaintext_utf8. reject with stage \"shape\": MUST " +
    "be refused by the shape check alone, before any key is used. reject with stage \"crypto\": MUST " +
    "pass the shape check and MUST fail to open. See docs/ENVELOPE-DRAFT.md (Wire shape).",
  plaintext_utf8: envPlaintext,
  accept: envAccept,
  reject: envReject,
};
// Written with every non-ASCII character escaped, so the byte-order mark in one case is
// visible in a diff instead of an invisible character in the file.
writeFileSync(
  `${here}/signatures/envelope-cases.json`,
  JSON.stringify(envelopeCases, null, 2).replace(
    /[^\n -~]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ) + "\n",
);
console.log(`envelope cases written (${envAccept.length} accept, ${envReject.length} reject)`);

/* ---------- verification cases: directories, bundles, recipients, travelers, ITAR ---------- */
// The golden vectors prove both implementations ACCEPT the same signed documents. These
// prove they REFUSE the same ones, for the same reason — including the cases the golden
// vectors could not see: a document signed with ANOTHER enrolled org's real key, a
// revoked or expired signer, an award that binds nothing determinate, and directories
// the root really signed but that are not well-formed.
//
// Every case states what MUST happen (`want`). The generator checks the TypeScript
// implementation against it before writing, so a wrong implementation fails generation
// instead of being baked into the vector; the Rust runner then checks the same file.
const eq = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function must(label: string, actual: unknown, want: unknown): void {
  if (!eq(actual, want)) {
    throw new Error(
      `case ${label}: implementation says ${JSON.stringify(actual)}, the case requires ${JSON.stringify(want)}`,
    );
  }
}
const rootHex = bytesToHex(rootKp.publicKey);
const otherRoot = keypairFromSeed(fill(0x77));
const AT = Date.parse("2027-01-01T00:00:00.000Z");
/** Sign `body` as a directory with the real root — whatever its shape. */
const rootSigned = (body: unknown): Record<string, unknown> => ({
  ...(body as Record<string, unknown>),
  sig: signDirectory(body as Directory, rootKp.secretKey),
});
const signedDir = (mutate: (d: Directory) => void = () => {}): Directory => {
  const d = structuredClone(directory);
  mutate(d);
  return rootSigned(d) as unknown as Directory;
};
const entryOf = (d: Directory, org: string) => d.entries.find((e) => e.org_id === org)!;

// Named directories the traveler / ITAR / recipient cases refer to.
const NEW_KEM = kemKeypairFromSeed(new Uint8Array(64).fill(0x54)); // northline's rotated-to key
const rotated = (newFirst: boolean, newFrom = "2026-06-01T00:00:00.000Z", newKid = "northline-2027") =>
  signedDir((d) => {
    const old = entryOf(d, "org_northline");
    const next: DirectoryEntry = {
      ...structuredClone(old),
      kid: newKid,
      valid_from: newFrom,
      enc_public_key: bytesToHex(NEW_KEM.publicKey),
    };
    d.entries = d.entries.filter((e) => e !== old);
    d.entries.push(...(newFirst ? [next, old] : [old, next]));
  });
const directories: Record<string, Directory> = {
  main: directoryVector.directory as Directory,
  "northline-revoked": signedDir((d) => { entryOf(d, "org_northline").status = "revoked"; }),
  "northline-expired-2026-07": signedDir((d) => { entryOf(d, "org_northline").valid_until = "2026-07-01T00:00:00.000Z"; }),
  "northline-from-2028": signedDir((d) => { entryOf(d, "org_northline").valid_from = "2028-01-01T00:00:00.000Z"; }),
  "huron-revoked": signedDir((d) => { entryOf(d, "org_huron").status = "revoked"; }),
  "huron-itar-on-a-second-entry": signedDir((d) => {
    const h = entryOf(d, "org_huron");
    h.capabilities = {};
    d.entries.push({ ...structuredClone(h), kid: "huron-2027", public_key: bytesToHex(summitKp.publicKey), capabilities: { itar: true } });
  }),
  "northline-no-encryption-key": signedDir((d) => {
    const n = entryOf(d, "org_northline");
    delete n.enc_alg;
    delete n.enc_public_key;
  }),
  "rotation-new-listed-last": rotated(false),
  "rotation-new-listed-first": rotated(true),
  "rotation-same-start": rotated(true, "2026-01-01T00:00:00.000Z"),
  "rotation-same-start-lesser-kid": rotated(false, "2026-01-01T00:00:00.000Z", "northline-2025"),
};

// ---- directory cases: shape, then trust ----
type DirCase = { name: string; why: string; text: string; root?: string; at_ms: number; shape_ok: boolean; verifies: boolean };
const small = (): Directory => {
  const d = structuredClone(directory);
  const n = structuredClone(entryOf(d, "org_northline"));
  delete n.enc_alg;
  delete n.enc_public_key;
  d.entries = [n];
  return d;
};
/** A directory the root really signed whose body breaks the shape. */
const malformed = (name: string, why: string, mutate: (d: Record<string, any>) => void): DirCase => {
  const d = small() as unknown as Record<string, any>;
  mutate(d);
  return { name, why, text: JSON.stringify(rootSigned(d)), at_ms: AT, shape_ok: false, verifies: false };
};
const smallSigned = JSON.stringify(rootSigned(small()));
const empty = JSON.stringify(rootSigned({ ...small(), entries: [] }));
const dirCases: DirCase[] = [
  { name: "valid", why: "well-formed, in its window, signed by the trusted root", text: smallSigned, at_ms: AT, shape_ok: true, verifies: true },
  { name: "valid-with-no-entries", why: "an empty directory is well-formed", text: empty, at_ms: AT, shape_ok: true, verifies: true },
  { name: "valid-three-entries-with-encryption-keys", why: "the directory the other vectors use", text: JSON.stringify(directories.main), at_ms: AT, shape_ok: true, verifies: true },
  { name: "signed-by-another-root", why: "well-formed, but not signed by the root this verifier trusts", text: smallSigned, root: bytesToHex(otherRoot.publicKey), at_ms: AT, shape_ok: true, verifies: false },
  { name: "before-issued-at", why: "evaluated before the directory's own window opens", text: smallSigned, at_ms: Date.parse("2025-06-01T00:00:00.000Z"), shape_ok: true, verifies: false },
  { name: "at-valid-until", why: "the window is half-open: valid_until itself is outside", text: smallSigned, at_ms: Date.parse("2030-01-01T00:00:00.000Z"), shape_ok: true, verifies: false },
  { name: "altered-after-signing", why: "a capability added without re-signing", text: JSON.stringify({ ...rootSigned(small()), entries: [{ ...small().entries[0]!, capabilities: { itar: true } }] }), at_ms: AT, shape_ok: true, verifies: false },
  // Root-signed, yet not well-formed: the signature is genuine and MUST NOT be enough.
  malformed("entries-contains-null", "an entry that is not an object", (d) => { d.entries = [null, ...d.entries]; }),
  malformed("capability-itar-as-string", "itar: \"false\" is not a boolean (a truthiness test would grant ITAR)", (d) => { d.entries[0].capabilities = { itar: "false" }; }),
  malformed("capability-unknown-member", "an unknown capability", (d) => { d.entries[0].capabilities = { itar: true, ear: true }; }),
  malformed("capabilities-as-array", "capabilities must be an object", (d) => { d.entries[0].capabilities = [true]; }),
  malformed("duplicate-kid", "one kid on two entries: which org signed is ambiguous", (d) => { d.entries.push({ ...d.entries[0], org_id: "org_summitfab" }); }),
  malformed("unknown-top-level-member", "an unknown member on the directory", (d) => { d.comment = "x"; }),
  malformed("unknown-entry-member", "an unknown member on an entry", (d) => { d.entries[0].name = "Northline Equipment"; }),
  malformed("missing-entry-member", "an entry without a status", (d) => { delete d.entries[0].status; }),
  malformed("public-key-uppercase-hex", "hex must be lowercase", (d) => { d.entries[0].public_key = d.entries[0].public_key.toUpperCase(); }),
  malformed("public-key-wrong-length", "an ML-DSA-87 key is exactly 2592 bytes", (d) => { d.entries[0].public_key = d.entries[0].public_key.slice(2); }),
  malformed("alg-not-ml-dsa-87", "the one signature algorithm this version defines", (d) => { d.entries[0].alg = "ML-DSA-65"; }),
  malformed("status-unknown", "status is active or revoked", (d) => { d.entries[0].status = "suspended"; }),
  malformed("entry-window-inverted", "valid_from must be before valid_until", (d) => { d.entries[0].valid_from = d.entries[0].valid_until; }),
  malformed("entry-valid-until-as-array", "a datetime written as a one-element array", (d) => { d.entries[0].valid_until = [d.entries[0].valid_until]; }),
  malformed("issued-at-with-offset", "datetimes are canonical UTC (Z), no offsets", (d) => { d.issued_at = "2026-01-01T00:00:00.000+00:00"; }),
  malformed("enc-alg-without-key", "enc_alg and enc_public_key come together or not at all", (d) => { d.entries[0].enc_alg = "ML-KEM-1024"; }),
  malformed("enc-key-wrong-length", "an ML-KEM-1024 key is exactly 1568 bytes", (d) => { d.entries[0].enc_alg = "ML-KEM-1024"; d.entries[0].enc_public_key = "ab".repeat(1567); }),
  malformed("enc-alg-unknown", "the one encapsulation algorithm this version defines", (d) => { d.entries[0].enc_alg = "ML-KEM-768"; d.entries[0].enc_public_key = bytesToHex(northlineKem.publicKey); }),
  malformed("org-id-uppercase", "org_id has the same form as in a traveler", (d) => { d.entries[0].org_id = "ORG_NORTHLINE"; }),
  malformed("kid-with-space", "a kid is 1-64 of [A-Za-z0-9._-]", (d) => { d.entries[0].kid = "northline 2026"; }),
  malformed("root-kid-empty", "root_kid is 1-64 of [A-Za-z0-9._-]", (d) => { d.root_kid = ""; }),
  malformed("entries-as-object", "entries must be an array", (d) => { d.entries = { "0": d.entries[0] }; }),
  malformed("unsupported-spec", "a directory version this specification does not define", (d) => { d.spec = "sje-directory/0.2.0"; }),
  { name: "sig-uppercase-hex", why: "the signature bytes are right but the hex is uppercase", text: smallSigned.replace(/"sig":"([0-9a-f]+)"/, (_m, h: string) => `"sig":"${h.toUpperCase()}"`), at_ms: AT, shape_ok: false, verifies: false },
  { name: "sig-missing", why: "an unsigned directory", text: JSON.stringify(small()), at_ms: AT, shape_ok: false, verifies: false },
  { name: "repeated-member", why: "a repeated member name: a last-wins reader sees the valid directory and never reads the first status", text: smallSigned.replace('"status":"active"', '"status":"revoked","status":"active"'), at_ms: AT, shape_ok: false, verifies: false },
  { name: "byte-order-mark", why: "a UTF-8 byte-order mark before the directory", text: String.fromCharCode(0xfeff) + smallSigned, at_ms: AT, shape_ok: false, verifies: false },
  { name: "as-array", why: "a directory written positionally, as an array", text: JSON.stringify(Object.values(rootSigned(small()))), at_ms: AT, shape_ok: false, verifies: false },
];
for (const c of dirCases) {
  let shapeOk = true;
  let verifies = false;
  try {
    verifies = verifyDirectory(parseDirectoryJson(c.text), c.root ?? rootHex, new Date(c.at_ms));
  } catch {
    shapeOk = false;
  }
  must(`directory/${c.name}`, { shape_ok: shapeOk, verifies }, { shape_ok: c.shape_ok, verifies: c.verifies });
}

// ---- prekey bundle cases ----
type BundleCase = { name: string; why: string; text: string; directory: string; root?: string; at_ms: number; shape_ok: boolean; verifies: boolean };
const BUNDLE_AT = Date.parse("2026-06-01T00:00:00.000Z");
const bundleBody = (): PrekeyBundle => {
  const { sig: _omit, ...body } = structuredClone(prekeyBundle);
  void _omit;
  return body as PrekeyBundle;
};
const signedBundle = (mutate: (b: Record<string, any>) => void, secretKey = northlineKp.secretKey): string => {
  const b = bundleBody() as unknown as Record<string, any>;
  mutate(b);
  return JSON.stringify({ ...b, sig: signPrekeyBundle(b as unknown as PrekeyBundle, secretKey) });
};
const bundleText = JSON.stringify(prekeyBundle);
const bundleCases: BundleCase[] = [
  { name: "valid", why: "signed by the org it names, in window", text: bundleText, directory: "main", at_ms: BUNDLE_AT, shape_ok: true, verifies: true },
  { name: "valid-with-no-prekeys", why: "an exhausted bundle is well-formed", text: signedBundle((b) => { b.prekeys = []; }), directory: "main", at_ms: BUNDLE_AT, shape_ok: true, verifies: true },
  { name: "signed-by-another-org-real-key", why: "names org_northline but is signed by org_summitfab's enrolled key: the signer's org is not the bundle's org", text: signedBundle((b) => { b.kid = "summit-2026"; }, summitKp.secretKey), directory: "main", at_ms: BUNDLE_AT, shape_ok: true, verifies: false },
  { name: "prekey-swapped-after-signing", why: "a prekey replaced without re-signing", text: JSON.stringify({ ...prekeyBundle, prekeys: [{ ...prekeyBundle.prekeys[0]!, public_key: bytesToHex(NEW_KEM.publicKey) }, prekeyBundle.prekeys[1]!] }), directory: "main", at_ms: BUNDLE_AT, shape_ok: true, verifies: false },
  { name: "after-valid-until", why: "evaluated outside the bundle's own window", text: bundleText, directory: "main", at_ms: Date.parse("2027-06-01T00:00:00.000Z"), shape_ok: true, verifies: false },
  { name: "signer-revoked", why: "the signing key is revoked in the directory", text: bundleText, directory: "northline-revoked", at_ms: BUNDLE_AT, shape_ok: true, verifies: false },
  { name: "untrusted-directory", why: "the directory is not signed by the trusted root", text: bundleText, directory: "main", root: bytesToHex(otherRoot.publicKey), at_ms: BUNDLE_AT, shape_ok: true, verifies: false },
  // Signed by the org, yet not well-formed.
  { name: "prekey-id-with-separator", why: "prekey_id is 1-64 of [A-Za-z0-9._-]; it is concatenated into a key-derivation label", text: signedBundle((b) => { b.prekeys[0].prekey_id = `ot${String.fromCharCode(0)}1`; }), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
  { name: "prekey-id-repeated", why: "two prekeys with one id", text: signedBundle((b) => { b.prekeys[1].prekey_id = b.prekeys[0].prekey_id; }), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
  { name: "prekey-key-wrong-length", why: "an ML-KEM-1024 key is exactly 1568 bytes", text: signedBundle((b) => { b.prekeys[0].public_key = b.prekeys[0].public_key.slice(2); }), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
  { name: "unknown-member", why: "an unknown member on the bundle", text: signedBundle((b) => { b.note = "x"; }), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
  { name: "prekey-as-array", why: "a prekey written positionally", text: signedBundle((b) => { b.prekeys[0] = [b.prekeys[0].prekey_id, b.prekeys[0].public_key]; }), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
  { name: "repeated-member", why: "a repeated member name", text: bundleText.replace('"org_id":', '"org_id":"org_summitfab","org_id":'), directory: "main", at_ms: BUNDLE_AT, shape_ok: false, verifies: false },
];
for (const c of bundleCases) {
  let shapeOk = true;
  let verifies = false;
  try {
    const b = parsePrekeyBundleJson(c.text);
    verifies = verifyPrekeyBundle(b, directories[c.directory]!, c.root ?? rootHex, new Date(c.at_ms)) !== undefined;
  } catch {
    shapeOk = false;
  }
  must(`bundle/${c.name}`, { shape_ok: shapeOk, verifies }, { shape_ok: c.shape_ok, verifies: c.verifies });
}

// ---- recipient resolution: which key to ENCRYPT to ----
const oldKey = { kid: envRecipient.kid, public_key: envRecipient.public_key };
const NEW_PUB = bytesToHex(NEW_KEM.publicKey);
const newKey = { kid: bytesToHex(sha384(NEW_KEM.publicKey)).slice(0, 16), public_key: NEW_PUB };
type RecipientCase = { name: string; why: string; directory: string; org_id: string; at_ms: number; want: { kid: string; public_key: string } | null };
const recipientCases: RecipientCase[] = [
  { name: "single-entry", why: "the org's one usable entry", directory: "main", org_id: "org_northline", at_ms: AT, want: oldKey },
  { name: "rotation-new-listed-last", why: "two usable entries: the most recently started wins", directory: "rotation-new-listed-last", org_id: "org_northline", at_ms: AT, want: newKey },
  { name: "rotation-new-listed-first", why: "...whatever order the root listed them in", directory: "rotation-new-listed-first", org_id: "org_northline", at_ms: AT, want: newKey },
  { name: "rotation-before-the-new-key-starts", why: "the new entry is not usable yet", directory: "rotation-new-listed-first", org_id: "org_northline", at_ms: Date.parse("2026-03-01T00:00:00.000Z"), want: oldKey },
  { name: "same-start-greater-kid", why: "equal start: the greater kid wins (northline-2027 > northline-2026)", directory: "rotation-same-start", org_id: "org_northline", at_ms: AT, want: newKey },
  { name: "same-start-lesser-kid", why: "equal start: the greater kid wins (northline-2026 > northline-2025)", directory: "rotation-same-start-lesser-kid", org_id: "org_northline", at_ms: AT, want: oldKey },
  { name: "revoked", why: "a revoked entry is never a recipient", directory: "northline-revoked", org_id: "org_northline", at_ms: AT, want: null },
  { name: "expired", why: "an expired entry is never a recipient", directory: "northline-expired-2026-07", org_id: "org_northline", at_ms: AT, want: null },
  { name: "no-encryption-key", why: "an org that publishes no encryption key cannot be sealed to", directory: "northline-no-encryption-key", org_id: "org_northline", at_ms: AT, want: null },
  { name: "unknown-org", why: "an org the directory does not list", directory: "main", org_id: "org_nobody", at_ms: AT, want: null },
];
for (const c of recipientCases) {
  must(`recipient/${c.name}`, recipientByOrg(directories[c.directory]!, c.org_id, new Date(c.at_ms)) ?? null, c.want);
}

writeFileSync(
  `${here}/signatures/directory-cases.json`,
  JSON.stringify(
    {
      note:
        "Directory, prekey-bundle and recipient-resolution cases. directory_cases / bundle_cases: `text` is the " +
        "JSON text as on the wire; `shape_ok` says whether it is well-formed (checked without any key), `verifies` " +
        "whether it is then trusted at at_ms under `root` (default root_public_key_hex) - a document that is not " +
        "well-formed MUST NOT verify even when its signature is genuine. recipient_cases: the (kid, public_key) to " +
        "encrypt to for org_id in the named directory at at_ms, or null. See docs/SPEC.md (Key directory).",
      root_public_key_hex: rootHex,
      directories,
      directory_cases: dirCases,
      bundle_cases: bundleCases,
      recipient_cases: recipientCases,
    },
    null,
    2,
  ).replace(/[^\n -~]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) + "\n",
);
console.log(`directory cases written (${dirCases.length} directory, ${bundleCases.length} bundle, ${recipientCases.length} recipient)`);

// ---- traveler cases: authorship, award, quote signatures ----
type WantCheck = { ok: true; kid: string; org_id: string } | { ok: false; reason: string };
type WantReport = {
  authorship: WantCheck[];
  award: WantCheck | null;
  quotes: { quote_id: string; check: WantCheck | null }[];
  verified: boolean;
};
type TravelerCase = { name: string; why: string; traveler: string; directory: string; root?: string; at_ms: number; want: WantReport };
const okBy = (kid: string, org_id: string): WantCheck => ({ ok: true, kid, org_id });
const no = (reason: string): WantCheck => ({ ok: false, reason });
const NORTH = okBy("northline-2026", "org_northline");
const R = {
  directory: "directory does not verify against the trust root",
  traveler: "not a valid traveler",
  noOrg: "author names no org_id to bind the signature to",
  noEntry: "no active in-window directory entry for kid",
  wrongOrg: "signer org does not match author org",
  bad: "signature does not verify",
  unsigned: "award is present but not signed by the buyer",
  noQuoteHash: "signed award does not bind a quote_hash",
  quoteAbsent: "awarded quote is not present to verify its priced content",
  quoteChanged: "awarded quote content does not match the buyer-signed quote_hash",
  quoteStale: "awarded quote is not bound to this revision",
  unpriced: "awarded quote has no price for the awarded quantity",
};
const slim = (c: SigCheck | undefined): WantCheck | null =>
  c === undefined ? null : c.ok ? { ok: true, kid: c.kid, org_id: c.org_id! } : { ok: false, reason: c.reason! };
const tcase = (name: string, why: string, t: unknown, want: WantReport, over: Partial<TravelerCase> = {}): TravelerCase => ({
  name,
  why,
  traveler: JSON.stringify(t),
  directory: "main",
  at_ms: AT,
  want,
  ...over,
});
const authoredOnly = (authorship: WantCheck[], verified: boolean): WantReport => ({ authorship, award: null, quotes: [], verified });
const AWARD_QUOTES = [{ quote_id: awardedQuote.quote_id, check: null }];
const awardWant = (award: WantCheck, authorship: WantCheck[] = [NORTH]): WantReport => ({
  authorship,
  award,
  quotes: AWARD_QUOTES,
  verified: authorship.some((c) => c.ok) && award.ok,
});
/** Re-sign a traveler's authorship and award as the buyer after editing it. */
const resign = (t: Traveler, awardKey = northlineKp.secretKey, awardKid = "northline-2026"): Traveler => {
  const out = structuredClone(t);
  delete out.signatures;
  if (out.award) delete out.award.sig;
  out.signatures = [signTraveler(out, "northline-2026", northlineKp.secretKey)];
  if (out.award) out.award.sig = signAward(out, awardKid, awardKey);
  return out;
};
const editAward = (f: (t: Traveler) => void, sign = true): Traveler => {
  const t = structuredClone(awardTraveler);
  f(t);
  return sign ? resign(t) : t;
};

// A traveler carrying three quotes: properly signed, signed by the wrong org, unsigned.
const threeQuotes: Traveler = (() => {
  const t = structuredClone(signedTraveler);
  const h = travelerHash(t);
  const mk = (id: string, org: string, name: string): Quote => ({
    quote_id: id,
    seller: { org_id: org, name },
    traveler_hash_quoted: h,
    created_at: "2026-02-01T00:00:00.000Z",
    valid_until: "2027-06-01T00:00:00.000Z",
    lead_time_days: 14,
    pricing: { currency: "USD", lines: [{ qty: t.part.qty.target, unit: 1500 }] },
  });
  const a = mk("qot_verify0001", "org_huron", "Huron Precision");
  a.sig = signQuote(a, "huron-2026", huronKp.secretKey);
  const b = mk("qot_verify0002", "org_huron", "Huron Precision");
  b.sig = signQuote(b, "summit-2026", summitKp.secretKey); // names huron, signed by summit's real key
  const c = mk("qot_verify0003", "org_summitfab", "Summit Fabrication");
  const d = mk("qot_verify0004", "org_summitfab", "Summit Fabrication");
  d.sig = signQuote(d, "summit-2026", summitKp.secretKey);
  d.lead_time_days = 2; // altered after signing
  t.quotes = [a, b, c, d];
  return t;
})();

const reissued: Traveler = (() => {
  // An enrolled bidder re-issues the buyer's traveler under ITS OWN org_id, keeping the
  // buyer's display name, and signs with its own (real, enrolled) key.
  const t = structuredClone(signedTraveler);
  delete t.signatures;
  t.buyer = { ...t.buyer, org_id: "org_summitfab" };
  t.signatures = [signTraveler(t, "summit-2026", summitKp.secretKey)];
  return t;
})();

const travelerCases: TravelerCase[] = [
  tcase("authored", "signed by the buyer the traveler names", signedTraveler, authoredOnly([NORTH], true)),
  tcase("unsigned", "no signature: nothing is established", { ...signedTraveler, signatures: undefined }, authoredOnly([], false)),
  tcase("signed-by-another-org-real-key", "the buyer's exact body, signed with ANOTHER enrolled org's real key: a valid signature by the wrong org",
    { ...signedTraveler, signatures: [signTraveler(signedTraveler, "summit-2026", summitKp.secretKey)] },
    authoredOnly([no(R.wrongOrg)], false)),
  tcase("buyer-org-relabelled", "buyer.org_id changed to another org, the original signature kept",
    { ...signedTraveler, buyer: { ...signedTraveler.buyer, org_id: "org_summitfab" } },
    authoredOnly([no(R.wrongOrg)], false)),
  tcase("reissued-under-another-org", "VERIFIES - as org_summitfab. Verification establishes WHICH org signed, never that it is the org a reader expects: a caller MUST compare org_id with the buyer it is dealing with",
    reissued, authoredOnly([okBy("summit-2026", "org_summitfab")], true)),
  tcase("body-altered", "the part changed after signing",
    { ...signedTraveler, part: { ...signedTraveler.part, notes: "altered" } }, authoredOnly([no(R.bad)], false)),
  tcase("revision-bumped", "the revision changed after signing",
    { ...signedTraveler, revision: signedTraveler.revision + 1 }, authoredOnly([no(R.bad)], false)),
  tcase("unknown-kid", "a kid the directory does not list",
    { ...signedTraveler, signatures: [{ ...signedTraveler.signatures![0]!, kid: "nobody-2026" }] }, authoredOnly([no(R.noEntry)], false)),
  tcase("buyer-names-no-org", "a signature with no org to bind it to",
    (() => { const t = structuredClone(signedTraveler); delete t.buyer.org_id; return t; })(), authoredOnly([no(R.noOrg)], false)),
  tcase("signer-revoked", "the buyer's key is revoked in the directory", signedTraveler, authoredOnly([no(R.noEntry)], false), { directory: "northline-revoked" }),
  tcase("signer-expired", "the buyer's entry expired before at_ms (the directory itself is still valid)", signedTraveler, authoredOnly([no(R.noEntry)], false), { directory: "northline-expired-2026-07" }),
  tcase("signer-in-window-earlier", "the same directory, evaluated while the entry was valid", signedTraveler, authoredOnly([NORTH], true), { directory: "northline-expired-2026-07", at_ms: Date.parse("2026-03-01T00:00:00.000Z") }),
  tcase("signer-not-yet-valid", "the buyer's entry starts after at_ms", signedTraveler, authoredOnly([no(R.noEntry)], false), { directory: "northline-from-2028" }),
  tcase("untrusted-directory", "the directory is not signed by the trusted root: nothing in it is believed", signedTraveler, authoredOnly([no(R.directory)], false), { root: bytesToHex(otherRoot.publicKey) }),
  tcase("not-a-valid-traveler", "a signature declaring another algorithm makes the document itself invalid",
    { ...signedTraveler, signatures: [{ ...signedTraveler.signatures![0]!, alg: "ML-DSA-65" }] }, authoredOnly([no(R.traveler)], false)),
  tcase("two-signatures-one-valid", "one signature by the wrong org, one by the buyer: authorship holds",
    { ...signedTraveler, signatures: [signTraveler(signedTraveler, "summit-2026", summitKp.secretKey), signedTraveler.signatures![0]!] },
    authoredOnly([no(R.wrongOrg), NORTH], true)),
  {
    ...tcase("quote-signatures", "four quotes: signed by its seller; naming one org but signed by another's real key; unsigned; altered after signing", threeQuotes, {
      authorship: [NORTH],
      award: null,
      quotes: [
        { quote_id: "qot_verify0001", check: okBy("huron-2026", "org_huron") },
        { quote_id: "qot_verify0002", check: no(R.wrongOrg) },
        { quote_id: "qot_verify0003", check: null },
        { quote_id: "qot_verify0004", check: no(R.bad) },
      ],
      verified: true,
    }),
  },
  // ---- awards ----
  tcase("award-verified", "the buyer signed this award and it binds the awarded quote", awardTraveler, awardWant(NORTH)),
  tcase("award-unsigned", "an award with no signature is a failure, not an absence",
    editAward((t) => { delete t.award!.sig; }, false), awardWant(no(R.unsigned))),
  tcase("award-forged-by-a-bidder-real-key", "the award body signed with an enrolled BIDDER's real key (kid summit-2026): a valid signature, not the buyer's",
    resign(awardTraveler, summitKp.secretKey, "summit-2026"), awardWant(no(R.wrongOrg))),
  tcase("award-ship-to-redirected", "ship_to changed after the buyer signed",
    editAward((t) => { t.ship_to = { ...t.ship_to!, line1: "1 Elsewhere Road" }; }, false), awardWant(no(R.bad))),
  tcase("award-quantity-changed", "award.qty changed after the buyer signed",
    editAward((t) => { t.award!.qty = 500; }, false), awardWant(no(R.bad))),
  tcase("award-moved-to-another-revision", "the revision changed: neither signature covers it",
    editAward((t) => { t.revision += 1; }, false), awardWant(no(R.bad), [no(R.bad)])),
  tcase("award-without-quote-hash", "the buyer signed an award that commits to no quote content",
    editAward((t) => { delete t.award!.quote_hash; }), awardWant(no(R.noQuoteHash))),
  tcase("awarded-quote-removed", "the awarded quote stripped from the traveler: its price cannot be checked",
    editAward((t) => { t.quotes = []; }, false), { ...awardWant(no(R.quoteAbsent)), quotes: [] }),
  tcase("awarded-quote-price-swapped", "the awarded (unsigned) quote's unit price changed after the award was signed",
    editAward((t) => { t.quotes![0]!.pricing.lines = t.quotes![0]!.pricing.lines.map((l) => ({ ...l, unit: l.unit + 1 })); }, false),
    awardWant(no(R.quoteChanged))),
  tcase("awarded-quote-for-another-revision", "buyer-signed, but the awarded quote was made against a different revision of the part",
    editAward((t) => {
      t.quotes![0]!.traveler_hash_quoted = `sha384:${"0".repeat(96)}`;
      t.award!.quote_hash = quoteContentHash(t.quotes![0]!);
    }), awardWant(no(R.quoteStale))),
  tcase("awarded-quantity-unpriced", "buyer-signed, but the awarded quote has no price line for the awarded quantity",
    editAward((t) => { t.award!.qty = 1_000_000; }), awardWant(no(R.unpriced))),
  tcase("award-signer-revoked", "the buyer's key is revoked", awardTraveler, awardWant(no(R.noEntry), [no(R.noEntry)]), { directory: "northline-revoked" }),
  tcase("award-untrusted-directory", "the directory is not trusted", awardTraveler,
    { authorship: [no(R.directory)], award: no(R.directory), quotes: [], verified: false }, { root: bytesToHex(otherRoot.publicKey) }),
];
for (const c of travelerCases) {
  const t = JSON.parse(c.traveler) as Traveler;
  const r = verificationReport(t, directories[c.directory]!, c.root ?? rootHex, new Date(c.at_ms));
  must(
    `traveler/${c.name}`,
    {
      authorship: r.authorship.map(slim),
      award: slim(r.award),
      quotes: r.quotes.map((q) => ({ quote_id: q.quote_id, check: slim(q.check) })),
      verified: r.verified,
    },
    c.want,
  );
}

// ---- ITAR gate ----
type ItarCase = { name: string; why: string; traveler: string; quote: string; directory: string; root?: string; at_ms: number; want: string | null };
const ITAR_AT = Date.parse("2026-06-01T00:00:00.000Z");
const itarTraveler: Traveler = { ...structuredClone(l0), itar: true };
const plainTraveler: Traveler = { ...structuredClone(l0), itar: false };
const unsignedHuron: Quote = (() => { const { sig: _omit, ...q } = signedQuote; void _omit; return q; })();
const bySummitNamingHuron: Quote = { ...unsignedHuron, sig: signQuote(unsignedHuron, "summit-2026", summitKp.secretKey) };
const summitQuote: Quote = (() => {
  const q: Quote = { ...unsignedHuron, quote_id: "qot_itar000002", seller: { org_id: "org_summitfab", name: "Summit Fabrication", itar: true } };
  return { ...q, sig: signQuote(q, "summit-2026", summitKp.secretKey) };
})();
const noOrgQuote: Quote = { ...unsignedHuron, seller: { name: "Huron Precision", itar: true } };
const huronSecondKey: Quote = { ...unsignedHuron, sig: signQuote(unsignedHuron, "huron-2027", summitKp.secretKey) };
const I = {
  notSigned: "ITAR traveler: quote is not signed by the seller it names",
  notAttested: "ITAR traveler: seller is not attested for ITAR in the directory",
  noOrg: "ITAR traveler: seller has no org_id to attest against the directory",
  directory: "ITAR traveler: key directory does not verify against the trust root",
  traveler: "ITAR gate: not a valid traveler",
  quote: "ITAR gate: not a valid quote",
};
const icase = (name: string, why: string, t: unknown, q: unknown, want: string | null, over: Partial<ItarCase> = {}): ItarCase => ({
  name, why, traveler: JSON.stringify(t), quote: JSON.stringify(q), directory: "main", at_ms: ITAR_AT, want, ...over,
});
const itarCases: ItarCase[] = [
  icase("signed-by-an-attested-seller", "the quote is signed by the seller it names, and the directory attests that seller for ITAR", itarTraveler, signedQuote, null),
  icase("unsigned-quote-naming-an-attested-org", "seller.org_id is a field anyone can type: unsigned, it proves nothing", itarTraveler, unsignedHuron, I.notSigned),
  icase("signed-by-another-org-naming-an-attested-org", "names the attested org, signed with another enrolled org's real key", itarTraveler, bySummitNamingHuron, I.notSigned),
  icase("signed-by-an-unattested-seller", "properly signed, by a seller the directory does not attest for ITAR", itarTraveler, summitQuote, I.notAttested),
  icase("seller-names-no-org", "nothing to attest", itarTraveler, noOrgQuote, I.noOrg),
  icase("not-an-itar-traveler", "a non-ITAR traveler imposes no gate, even on an unsigned quote", plainTraveler, unsignedHuron, null),
  icase("untrusted-directory", "an attestation from a directory the root did not sign is worth nothing", itarTraveler, signedQuote, I.directory, { root: bytesToHex(otherRoot.publicKey) }),
  icase("attested-seller-revoked", "the seller's entry is revoked: its signature no longer resolves", itarTraveler, signedQuote, I.notSigned, { directory: "huron-revoked" }),
  icase("attestation-on-another-entry-of-the-org", "the org holds ITAR on a different usable entry than the key that signed (key rotation): the capability is the org's", itarTraveler, huronSecondKey, null, { directory: "huron-itar-on-a-second-entry" }),
  icase("traveler-fragment", "a fragment that says itar:true but is not a traveler is refused, not read as 'not ITAR'... or as ITAR", { itar: true }, signedQuote, I.traveler),
  icase("traveler-itar-not-boolean", "itar: 1 is not a traveler", { ...itarTraveler, itar: 1 }, signedQuote, I.traveler),
  icase("not-a-valid-quote", "a quote with a negative price is not a quote", itarTraveler, { ...signedQuote, lead_time_days: -1 }, I.quote),
];
for (const c of itarCases) {
  must(
    `itar/${c.name}`,
    itarAttestationBlocker(JSON.parse(c.traveler) as Traveler, JSON.parse(c.quote) as Quote, directories[c.directory]!, c.root ?? rootHex, new Date(c.at_ms)),
    c.want,
  );
}

writeFileSync(
  `${here}/signatures/verify-cases.json`,
  JSON.stringify(
    {
      note:
        "Signature-verification cases. traveler_cases: verify `traveler` (JSON text) against the named directory of " +
        "directory-cases.json at at_ms under `root` (default root_public_key_hex) and produce exactly `want`: one check " +
        "per buyer signature, the award check (null: no award), one check per quote (null: unsigned), and `verified` " +
        "(a valid buyer signature and, if there is an award, a valid award). A passing check carries the signing kid " +
        "and the org the directory binds it to; a refused check carries the REASON, which is normative - an " +
        "implementation that refuses for a different reason has a different rule. itar_cases: the ITAR gate's answer " +
        "for (traveler, quote): null (allowed) or the reason it is refused.",
      root_public_key_hex: rootHex,
      directories: "directory-cases.json#/directories",
      traveler_cases: travelerCases,
      itar_cases: itarCases,
    },
    null,
    2,
  ) + "\n",
);
console.log(`verify cases written (${travelerCases.length} traveler, ${itarCases.length} itar)`);
