/** Mutation catalog, part 4 of 4: BYTE mutations — edits to the encoded document.
 *
 *  The last stage: whatever the earlier stages built is now a byte string, and these
 *  touch it without knowing its structure — a byte-order mark in front, padding to
 *  the size cap, a second document behind, a flipped bit. (Bytes that must land at a
 *  particular place in the text — inside a string, between two tokens — are placed by
 *  the wire stage instead; see `utf8-invalid` in mutations-wire.ts.)
 */
import { MAX_TRAVELER_JSON_BYTES } from "../src/lib/traveler/types.ts";
import type { ByteMutation } from "./mutations.ts";
import { concatBytes } from "./wire.ts";

const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));
const of = (...bytes: number[]): Uint8Array => Uint8Array.from(bytes);
const BOM = of(0xef, 0xbb, 0xbf);
const insert = (bytes: Uint8Array, at: number, extra: Uint8Array): Uint8Array =>
  concatBytes([bytes.subarray(0, at), extra, bytes.subarray(at)]);

/** Re-encode UTF-8 bytes as UTF-16 (invalid sequences become U+FFFD first). */
function utf16(bytes: Uint8Array, littleEndian: boolean): Uint8Array {
  const text = new TextDecoder().decode(bytes);
  const out = new Uint8Array(text.length * 2);
  const view = new DataView(out.buffer);
  for (let i = 0; i < text.length; i++) view.setUint16(i * 2, text.charCodeAt(i), littleEndian);
  return out;
}

export const BYTE_MUTATIONS: ByteMutation[] = [
  {
    name: "bom-prefix",
    why: "a byte-order mark before the document: TextDecoder and Blob.text() strip it silently, a strict parser refuses (K7)",
    weight: 8,
    apply: (bytes, ctx) => {
      const [label, mark] = ctx.rng.pick<[string, Uint8Array]>([
        ["utf-8", BOM],
        ["utf-8", BOM],
        ["utf-8", BOM],
        ["utf-8-twice", concatBytes([BOM, BOM])],
        ["utf-8-then-newline", concatBytes([BOM, ascii("\n")])],
        ["space-then-utf-8", concatBytes([ascii(" "), BOM])],
        ["utf-16le-mark", of(0xff, 0xfe)],
        ["utf-16be-mark", of(0xfe, 0xff)],
        ["utf-32le-mark", of(0xff, 0xfe, 0x00, 0x00)],
      ]);
      ctx.note(label);
      return concatBytes([mark, bytes]);
    },
  },
  {
    name: "pad-small",
    why: "a few bytes of legal whitespace around the document (the trailing newline every editor adds): nothing may change",
    weight: 8,
    apply: (bytes, ctx) => {
      const [label, lead, trail] = ctx.rng.pick<[string, string, string]>([
        ["trailing-lf", "", "\n"],
        ["trailing-crlf", "", "\r\n"],
        ["trailing-spaces", "", "        "],
        ["leading-space", " ", ""],
        ["leading-blank-lines", "\n\n", ""],
        ["both", "\t", "\r\n\r\n"],
      ]);
      ctx.note(label);
      return concatBytes([ascii(lead), bytes, ascii(trail)]);
    },
  },
  {
    name: "pad-to-cap",
    why: "whitespace until the document is exactly at, one under or one over 512 KiB: the cap is on the bytes as sent, not on a re-serialization (K8)",
    weight: 4,
    liveOnly: true,
    apply: (bytes, ctx) => {
      const cap = MAX_TRAVELER_JSON_BYTES;
      const [label, target] = ctx.rng.pick<[string, number]>([
        ["cap-1", cap - 1],
        ["cap", cap],
        ["cap", cap],
        ["cap+1", cap + 1],
        ["cap+1", cap + 1],
        ["over", cap + ctx.rng.int(2, 100_000)],
      ]);
      const count = target - bytes.length;
      if (count <= 0) return bytes;
      const [wsName, ws] = ctx.rng.pick<[string, number]>([
        ["spaces", 0x20],
        ["newlines", 0x0a],
        ["tabs", 0x09],
        ["carriage-returns", 0x0d],
      ]);
      // "interior" is just inside the outermost brackets, where whitespace is legal.
      const where = ctx.rng.pick(["leading", "trailing", "interior-front", "interior-back", "both-ends"] as const);
      ctx.note(`${label} ${where} ${wsName}`);
      const pad = new Uint8Array(count).fill(ws);
      if (where === "both-ends") {
        const half = count >> 1;
        return concatBytes([pad.subarray(0, half), bytes, pad.subarray(half)]);
      }
      const at = { leading: 0, trailing: bytes.length, "interior-front": 1, "interior-back": bytes.length - 1 }[where];
      return insert(bytes, Math.max(0, at), pad);
    },
  },
  {
    name: "second-value",
    why: "a second JSON value after the first ({…}{…}, NDJSON, {…}null): a parser that stops at the first value has accepted a prefix",
    weight: 4,
    apply: (bytes, ctx) => {
      const [label, between, second] = ctx.rng.pick<[string, string, Uint8Array]>([
        ["same-again", "", bytes],
        ["same-again-on-next-line", "\n", bytes],
        ["same-again-after-comma", ",", bytes],
        ["empty-object", "", ascii("{}")],
        ["empty-array", " ", ascii("[]")],
        ["null", "", ascii("null")],
        ["number", " ", ascii("1")],
        ["string", "", ascii('""')],
      ]);
      ctx.note(label);
      return concatBytes([bytes, ascii(between), second]);
    },
  },
  {
    name: "trailing-garbage",
    why: "anything but whitespace after the document (a word, a NUL, a BOM, Ctrl-Z, a stray bracket): refused, not ignored",
    weight: 4,
    apply: (bytes, ctx) => {
      const [label, tail] = ctx.rng.pick<[string, Uint8Array]>([
        ["word", ascii(" garbage")],
        ["semicolon", ascii(";")],
        ["close-brace", ascii("}")],
        ["close-bracket", ascii("]")],
        ["comma", ascii(",")],
        ["comment", ascii(" // end")],
        ["nul", of(0x00)],
        ["bom", BOM],
        ["form-feed", of(0x0c)],
        ["ctrl-z", of(0x1a)],
        ["0xff", of(0xff)],
        ["nbsp", of(0xc2, 0xa0)],
      ]);
      ctx.note(label);
      return concatBytes([bytes, tail]);
    },
  },
  {
    name: "leading-garbage",
    why: "bytes before the document that some readers skip (an XSSI guard, a record separator, a variable assignment)",
    weight: 3,
    apply: (bytes, ctx) => {
      const [label, head] = ctx.rng.pick<[string, Uint8Array]>([
        ["word", ascii("garbage ")],
        ["xssi-guard", ascii(")]}',\n")],
        ["record-separator", of(0x1e)],
        ["nul", of(0x00)],
        ["form-feed", of(0x0c)],
        ["assignment", ascii("traveler = ")],
        ["open-paren", ascii("(")],
        ["nbsp", of(0xc2, 0xa0)],
      ]);
      ctx.note(label);
      return concatBytes([head, bytes]);
    },
  },
  {
    name: "empty-input",
    why: "no document at all: zero bytes, only whitespace, only a BOM, only NULs — a refusal, not a crash",
    weight: 1,
    apply: (_bytes, ctx) => {
      const [label, input] = ctx.rng.pick<[string, Uint8Array]>([
        ["zero-bytes", of()],
        ["space", ascii(" ")],
        ["newline", ascii("\n")],
        ["whitespace", ascii("\t\r\n ")],
        ["bom-only", BOM],
        ["nul-only", of(0x00)],
        ["nuls", new Uint8Array(16)],
      ]);
      ctx.note(label);
      return input;
    },
  },
  {
    name: "nul-bytes",
    why: "NUL bytes in and around the text: valid UTF-8, never valid JSON outside an escape, and a C-string reader stops at one",
    weight: 3,
    apply: (bytes, ctx) => {
      const where = ctx.rng.pick(["front", "back", "after-open", "at-random", "replacing-a-space"] as const);
      ctx.note(where);
      if (where === "replacing-a-space") {
        const out = Uint8Array.from(bytes);
        const at = out.indexOf(0x20, ctx.rng.int(0, Math.max(0, out.length - 1)));
        if (at >= 0) out[at] = 0;
        return out;
      }
      const at = { front: 0, back: bytes.length, "after-open": 1, "at-random": ctx.rng.int(0, bytes.length) }[where];
      return insert(bytes, Math.min(at, bytes.length), of(0x00));
    },
  },
  {
    name: "utf16-transcode",
    why: "the same document in UTF-16, with or without its byte-order mark: the wire encoding is UTF-8 and nothing else",
    weight: 1,
    apply: (bytes, ctx) => {
      const little = ctx.rng.bool();
      const marked = ctx.rng.bool();
      ctx.note(`${little ? "le" : "be"}${marked ? " with mark" : ""}`);
      const body = utf16(bytes.subarray(0, 64 * 1024), little);
      return marked ? concatBytes([little ? of(0xff, 0xfe) : of(0xfe, 0xff), body]) : body;
    },
  },
  {
    name: "truncate",
    why: "the document cut short — mid-string, mid-number, mid-character, or just its closing brace: never a partial accept",
    weight: 4,
    apply: (bytes, ctx) => {
      if (bytes.length < 2) return bytes;
      const how = ctx.rng.pick(["last-byte", "first-byte", "anywhere", "anywhere"] as const);
      const at = how === "last-byte" ? bytes.length - 1 : how === "first-byte" ? 1 : ctx.rng.int(1, bytes.length - 1);
      ctx.note(how === "anywhere" ? `at ${at} of ${bytes.length}` : how);
      return how === "first-byte" ? bytes.slice(at) : bytes.slice(0, at);
    },
  },
  {
    name: "byte-flip",
    why: "one to three bytes changed at random (a bit flip, or any value): whatever it lands on, the two verdicts must match",
    weight: 6,
    apply: (bytes, ctx) => {
      if (!bytes.length) return bytes;
      const out = Uint8Array.from(bytes);
      const n = ctx.rng.int(1, 3);
      for (let i = 0; i < n; i++) {
        const at = ctx.rng.int(0, out.length - 1);
        out[at] = ctx.rng.bool() ? out[at]! ^ (1 << ctx.rng.int(0, 7)) : ctx.rng.int(0, 255);
      }
      ctx.note(`${n} byte${n > 1 ? "s" : ""}`);
      return out;
    },
  },
  {
    name: "byte-delete",
    why: "a short run of bytes removed at random: a missing quote, comma, digit or continuation byte",
    weight: 4,
    apply: (bytes, ctx) => {
      if (bytes.length < 2) return bytes;
      const n = ctx.rng.int(1, 3);
      const at = ctx.rng.int(0, bytes.length - n);
      ctx.note(`${n} at ${at}`);
      return concatBytes([bytes.subarray(0, at), bytes.subarray(at + n)]);
    },
  },
  {
    name: "byte-insert",
    why: "one random byte inserted at random: a stray quote, bracket, control or non-UTF-8 byte",
    weight: 4,
    apply: (bytes, ctx) => {
      const at = ctx.rng.int(0, bytes.length);
      const byte = ctx.rng.bool() ? ctx.rng.pick(Array.from(ascii('"\\{}[],:0-.eE+ \n\t/u'))) : ctx.rng.int(0, 255);
      ctx.note(`0x${byte.toString(16).padStart(2, "0")} at ${at}`);
      return insert(bytes, at, of(byte));
    },
  },
  {
    name: "chunk-repeat",
    why: "a random slice of the document repeated in place: by luck a duplicated member, a doubled element or a broken token",
    weight: 3,
    apply: (bytes, ctx) => {
      if (bytes.length < 4) return bytes;
      const from = ctx.rng.int(0, bytes.length - 2);
      const to = Math.min(bytes.length, from + ctx.rng.int(1, 200));
      ctx.note(`${from}..${to}`);
      return insert(bytes, to, bytes.subarray(from, to));
    },
  },
];
