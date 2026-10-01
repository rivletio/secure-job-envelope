/** RFC 8785-ish canonical JSON: object keys sorted by Unicode code point,
 *  compact output, no undefined.
 *
 *  The serializer is explicit — it never round-trips through a rebuilt object —
 *  because JavaScript enumerates integer-like keys ("2", "10") in numeric order
 *  regardless of insertion order, which would silently reorder them against the
 *  sort every other language uses. (Caught by conformance vector `key-order-digits`.)
 *
 *  Keys are sorted by code point (not UTF-16 code unit) so the ordering matches
 *  the Rust core's byte-wise (UTF-8) key sort for astral-plane keys too; for the
 *  ASCII field names of the spec the two orders coincide, so no fielded hash
 *  changes. Strings (values and keys) containing a lone surrogate are refused:
 *  Rust's serde_json cannot even parse them, so hashing one in TypeScript would
 *  be a silent cross-implementation divergence.
 */

function canonicalNumber(value: number): string {
  // Numbers must land byte-identical across implementations AND survive a
  // JSON round-trip in every language. The format therefore admits only:
  // finite values, |x| <= 2^53-1 (exact in an f64 and in JS), and
  // non-integers of magnitude >= 1e-5 (below that, Rust's ryu switches to
  // exponential notation while JS stays fixed — the renderings diverge).
  // Mirrored exactly in the Rust core; refused rather than hashed
  // ambiguously. (The Rust crate enables serde_json's `float_roundtrip` so its
  // float *parse* also matches ECMAScript's, not just its render.)
  if (!Number.isFinite(value)) {
    throw new Error("non-finite number is not canonical");
  }
  const abs = Math.abs(value);
  if (abs > 9007199254740991) {
    throw new Error("number exceeds 2^53-1 and is not canonical in sje/0.1.0");
  }
  if (!Number.isInteger(value) && abs < 1e-5) {
    throw new Error(
      "non-integer number below 1e-5 is outside the canonical fixed-notation range of sje/0.1.0",
    );
  }
  const rendered = JSON.stringify(value);
  if (rendered.includes("e") || rendered.includes("E")) {
    throw new Error("number outside the canonical fixed-notation range of sje/0.1.0");
  }
  return rendered;
}

// A lone surrogate — a high surrogate not followed by a low, or a low not
// preceded by a high. Such a string is not well-formed UTF-16 and has no UTF-8
// encoding, so serde_json refuses it at parse; TypeScript must refuse it too.
// Exported so the parser can refuse a lone surrogate in ANY string (not only the
// hashed ones), matching serde's parse-time rejection across the whole document.
export const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function canonicalString(value: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new Error("string contains a lone surrogate and is not canonical");
  }
  return JSON.stringify(value);
}

/** Compare two strings by Unicode code point (== UTF-8 byte order), matching the
 *  Rust core's key sort. Differs from JavaScript's default UTF-16 comparison only
 *  for astral-plane characters. */
function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const na = ia.next();
    const nb = ib.next();
    if (na.done && nb.done) return 0;
    if (na.done) return -1;
    if (nb.done) return 1;
    const ca = na.value.codePointAt(0)!;
    const cb = nb.value.codePointAt(0)!;
    if (ca !== cb) return ca - cb;
  }
}

// Defense-in-depth bound on nesting. The hashed body is fixed-shape and small,
// and JSON.parse already caps input depth, but canonicalJson is exported, so a
// hand-built deeply-nested object cannot be allowed to blow the stack.
const MAX_CANONICAL_DEPTH = 128;

function writeCanonical(value: unknown, depth = 0): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new Error("canonical JSON nesting exceeds the maximum depth");
  }
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return canonicalNumber(value);
    case "string":
      return canonicalString(value);
    case "object": {
      if (Array.isArray(value)) {
        // JSON.stringify semantics: undefined array members serialize as null.
        return `[${value.map((v) => (v === undefined ? "null" : writeCanonical(v, depth + 1))).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(obj).sort(compareCodePoints)) {
        const v = obj[key];
        if (v === undefined) continue;
        parts.push(`${canonicalString(key)}:${writeCanonical(v, depth + 1)}`);
      }
      return `{${parts.join(",")}}`;
    }
    default:
      throw new Error(`value of type ${typeof value} is not canonical`);
  }
}

export function canonicalJson(value: unknown): string {
  return writeCanonical(value);
}
