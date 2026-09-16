/** RFC 8785-ish: sorted keys, compact JSON, no undefined. ASCII-safe for 0.0.1.
 *  Numbers follow JSON.stringify (JS NumberToJSON): integer-valued floats emit
 *  without a trailing `.0`. Non-finite numbers are refused — they must not hash.
 */
export function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new Error("non-finite number is not canonical");
      }
      // Numbers must land byte-identical across implementations AND survive a
      // JSON round-trip in every language. 0.0.1 therefore admits only:
      // finite values, |x| <= 2^53-1 (exact in an f64 and in JS), and
      // non-integers of magnitude >= 1e-5 (below that, Rust's ryu switches to
      // exponential notation while JS stays fixed — the renderings diverge).
      // Mirrored exactly in the Rust core; refused rather than hashed
      // ambiguously.
      const abs = Math.abs(value);
      if (abs > 9007199254740991) {
        throw new Error("number exceeds 2^53-1 and is not canonical in rivlet-packet/0.0.1");
      }
      if (!Number.isInteger(value) && abs < 1e-5) {
        throw new Error(
          "non-integer number below 1e-5 is outside the canonical fixed-notation range of rivlet-packet/0.0.1",
        );
      }
      const rendered = JSON.stringify(value);
      if (rendered.includes("e") || rendered.includes("E")) {
        throw new Error(
          "number outside the canonical fixed-notation range of rivlet-packet/0.0.1",
        );
      }
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(sortKeys);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key];
    if (v === undefined) continue;
    out[key] = sortKeys(v);
  }
  return out;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}
