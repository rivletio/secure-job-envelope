/** RFC 8785-ish canonical JSON: keys sorted lexicographically, compact
 *  output, no undefined. ASCII field names in 0.0.1.
 *
 *  The serializer is explicit — it never round-trips through a rebuilt
 *  object — because JavaScript enumerates integer-like keys ("2", "10") in
 *  numeric order regardless of insertion order, which would silently
 *  reorder them against the lexicographic sort every other language uses.
 *  (Caught by conformance vector `key-order-digits`.)
 */

function canonicalNumber(value: number): string {
  // Numbers must land byte-identical across implementations AND survive a
  // JSON round-trip in every language. 0.0.1 therefore admits only:
  // finite values, |x| <= 2^53-1 (exact in an f64 and in JS), and
  // non-integers of magnitude >= 1e-5 (below that, Rust's ryu switches to
  // exponential notation while JS stays fixed — the renderings diverge).
  // Mirrored exactly in the Rust core; refused rather than hashed
  // ambiguously.
  if (!Number.isFinite(value)) {
    throw new Error("non-finite number is not canonical");
  }
  const abs = Math.abs(value);
  if (abs > 9007199254740991) {
    throw new Error("number exceeds 2^53-1 and is not canonical in sje/0.0.1");
  }
  if (!Number.isInteger(value) && abs < 1e-5) {
    throw new Error(
      "non-integer number below 1e-5 is outside the canonical fixed-notation range of sje/0.0.1",
    );
  }
  const rendered = JSON.stringify(value);
  if (rendered.includes("e") || rendered.includes("E")) {
    throw new Error("number outside the canonical fixed-notation range of sje/0.0.1");
  }
  return rendered;
}

function writeCanonical(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return canonicalNumber(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        // JSON.stringify semantics: undefined array members serialize as null.
        return `[${value.map((v) => (v === undefined ? "null" : writeCanonical(v))).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(obj).sort()) {
        const v = obj[key];
        if (v === undefined) continue;
        parts.push(`${JSON.stringify(key)}:${writeCanonical(v)}`);
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
