/** The text boundary: JSON *bytes* → a JavaScript value, refused exactly where the
 *  Rust core's serde_json parse refuses.
 *
 *  `JSON.parse` is more permissive than a strict parser in ways that matter the moment
 *  two implementations must judge the same wire document:
 *
 *    - **Duplicate member names.** `JSON.parse` keeps the last and discards the rest
 *      without ever *looking* at them — so a shadowed value (`{"a":1e309,"a":1}`, a lone
 *      surrogate, a 200-deep value) sails past every check that runs on the resolved
 *      object, while serde lexes it and refuses the document. A typed serde struct also
 *      refuses a repeated field outright. Here a repeated member name is refused at any
 *      depth; the Rust core does the same (including inside free-form blobs), so the two
 *      agree by refusing rather than by sharing a tie-break.
 *    - **Byte-order mark.** `TextDecoder` strips a leading BOM by default and
 *      `Blob.text()` always does; serde refuses it. Decoding here keeps the BOM so it can
 *      be refused.
 *    - **Size.** The 512 KiB cap is on the UTF-8 *bytes of the wire text* — what the Rust
 *      core measures — not on UTF-16 code units of a re-serialization (a CJK document is
 *      three bytes per unit) and not on a pretty-printed copy.
 *    - **Invalid UTF-8** is refused, not replaced with U+FFFD.
 *
 *  Everything that crosses a company boundary as text — a traveler inside a sealed
 *  envelope's archive, a `.json` file opened on the desk, a JSON string handed to an MCP
 *  tool, a conformance vector — goes through here, so the two implementations are
 *  comparing the same thing. (A value that is already a JavaScript object cannot contain
 *  a duplicate member; that path is bounded by its compact serialization instead.)
 */

/** serde_json's recursion limit: a container that is the 128th or deeper is refused. */
export const MAX_JSON_DEPTH = 128;

/** Decode UTF-8 strictly: invalid sequences throw, and a leading BOM is preserved (so
 *  the caller can refuse it) rather than silently dropped. */
export function decodeUtf8Strict(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

/** Length of `text` in UTF-8 bytes. */
export function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** True iff `text` is larger than `maxBytes` of UTF-8. Every UTF-16 code unit encodes
 *  to at least one byte, so a string longer than the limit in code units is over
 *  without encoding it. */
export function exceedsUtf8Bytes(text: string, maxBytes: number): boolean {
  return text.length > maxBytes || utf8ByteLength(text) > maxBytes;
}

/** The first member name that repeats within one JSON object, at any depth — or
 *  `undefined` if there is none. One pass, no recursion.
 *
 *  Names are compared after JSON unescaping (`"a"` and `"\u0061"` are the same member),
 *  as serde does. On malformed text this returns `undefined` and leaves the syntax error
 *  to `JSON.parse`; for well-formed JSON the tokenization is exact (structural
 *  characters are only ever tracked outside string literals).
 *
 *  Throws when nesting reaches serde_json's recursion limit, which also bounds the
 *  scanner's own memory on a hostile deeply-nested input. (`maxDepth` is for a caller
 *  scanning text that WRAPS a document — a protocol message around a traveler — and so
 *  legitimately nests a few levels deeper than a document may.) */
export function findDuplicateMember(text: string, maxDepth: number = MAX_JSON_DEPTH): string | undefined {
  // One frame per open container: the member names seen so far for an object, `null`
  // for an array.
  const stack: (Set<string> | null)[] = [];
  let expectName = false;
  const n = text.length;
  for (let i = 0; i < n; i++) {
    switch (text.charCodeAt(i)) {
      case 0x7b: // {
      case 0x5b: {
        // [
        if (stack.length + 1 >= maxDepth) {
          throw new Error("JSON nesting exceeds the maximum depth");
        }
        const isObject = text.charCodeAt(i) === 0x7b;
        stack.push(isObject ? new Set() : null);
        expectName = isObject;
        break;
      }
      case 0x7d: // }
      case 0x5d: // ]
        stack.pop();
        expectName = false;
        break;
      case 0x2c: // ,
        expectName = stack.length > 0 && stack[stack.length - 1] !== null;
        break;
      case 0x22: {
        // " — scan to the closing quote, honouring backslash escapes.
        let j = i + 1;
        while (j < n) {
          const d = text.charCodeAt(j);
          if (d === 0x5c) j += 2;
          else if (d === 0x22) break;
          else j++;
        }
        if (j >= n) return undefined; // unterminated string: JSON.parse will report it
        if (expectName) {
          const names = stack[stack.length - 1];
          let name: string;
          try {
            name = JSON.parse(text.slice(i, j + 1)) as string;
          } catch {
            return undefined; // malformed escape: JSON.parse will report it
          }
          if (names) {
            if (names.has(name)) return name;
            names.add(name);
          }
          expectName = false;
        }
        i = j;
        break;
      }
      default:
        break; // whitespace, ':', numbers, literals — nothing to track
    }
  }
  return undefined;
}

/** A short, single-line, printable rendering of attacker-controlled text for an error
 *  message (a duplicated member name is chosen by whoever wrote the document). */
export function quoteForMessage(s: string): string {
  const shown = s.length > 40 ? `${s.slice(0, 40)}...` : s;
  // JSON.stringify escapes quotes, backslashes and C0 controls; additionally mask DEL,
  // C1 controls, line/paragraph separators and bidi controls so the message stays on
  // one line and cannot reorder what surrounds it.
  return JSON.stringify(shown).replace(
    /[\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,
    "?",
  );
}

/** Parse JSON text the way the Rust core would accept it, or throw.
 *
 *  `input` is the wire form: bytes (preferred — the size cap and the BOM check are then
 *  exact) or a string. Refuses: more than `maxBytes` of UTF-8, invalid UTF-8, a leading
 *  byte-order mark, a repeated member name at any depth, nesting past the recursion
 *  limit, and anything `JSON.parse` rejects. */
export function parseStrictJson(
  input: string | Uint8Array,
  opts: { maxBytes: number; label: string },
): unknown {
  const { maxBytes, label } = opts;
  const over = () => new Error(`${label} exceeds ${Math.floor(maxBytes / 1024)} KiB`);
  let text: string;
  if (typeof input === "string") {
    if (exceedsUtf8Bytes(input, maxBytes)) throw over();
    text = input;
  } else {
    if (input.length > maxBytes) throw over();
    try {
      text = decodeUtf8Strict(input);
    } catch {
      throw new Error(`${label} is not valid UTF-8`);
    }
  }
  if (text.charCodeAt(0) === 0xfeff) {
    throw new Error(`${label} must not start with a byte-order mark`);
  }
  const dup = findDuplicateMember(text);
  if (dup !== undefined) {
    throw new Error(`${label} has a duplicate member name ${quoteForMessage(dup)}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}
