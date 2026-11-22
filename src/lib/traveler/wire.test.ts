import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseTraveler, parseTravelerJson } from "./conformance.ts";
import { MAX_TRAVELER_JSON_BYTES } from "./types.ts";
import {
  MAX_JSON_DEPTH,
  decodeUtf8Strict,
  exceedsUtf8Bytes,
  findDuplicateMember,
  parseStrictJson,
  utf8ByteLength,
} from "./wire.ts";

const BASE = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_wiretest01",
  revision: 1,
  created_at: "2026-09-16T12:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  itar: false,
};
const enc = (s: string) => new TextEncoder().encode(s);

describe("wire: the strict text boundary", () => {
  it("finds a repeated member name at any depth, and only a repeated NAME", () => {
    assert.equal(findDuplicateMember('{"a":1,"a":2}'), "a");
    assert.equal(findDuplicateMember('{"x":{"y":[{"k":1,"k":2}]}}'), "k");
    assert.equal(findDuplicateMember('[{"a":1},{"a":1}]'), undefined, "same name in sibling objects");
    assert.equal(findDuplicateMember('{"a":{"a":{"a":1}}}'), undefined, "same name at different depths");
    // a string VALUE equal to a member name is not a member
    assert.equal(findDuplicateMember('{"a":"a","b":["a","a"]}'), undefined);
    // structural characters and quotes inside strings are not structure
    assert.equal(findDuplicateMember('{"a":"}{\\",\\"a\\":1","b":"[{"}'), undefined);
    assert.equal(findDuplicateMember('{"a\\"b":1,"a\\"b":2}'), 'a"b');
    // names are compared after unescaping, as serde does
    assert.equal(findDuplicateMember('{"lot":"A","lo\\u0074":"B"}'), "lot");
    assert.equal(findDuplicateMember('{"\\ud83d\\ude00":1,"\u{1F600}":2}'), "\u{1F600}");
    assert.equal(findDuplicateMember('{"__proto__":1,"__proto__":2}'), "__proto__");
    assert.equal(findDuplicateMember("{}"), undefined);
    assert.equal(findDuplicateMember('{"a":1,"b":2, "c" : {"a":1,"b":2}}'), undefined);
  });

  it("leaves malformed text to JSON.parse instead of guessing", () => {
    assert.equal(findDuplicateMember('{"a":1,"a'), undefined, "unterminated string");
    assert.equal(findDuplicateMember("}}]]"), undefined);
    assert.throws(() => parseStrictJson('{"a":1,}', { maxBytes: 100, label: "doc" }), /doc is not JSON/);
  });

  it("refuses nesting at serde_json's recursion limit, in the scanner", () => {
    const nest = (d: number) => "[".repeat(d) + "]".repeat(d);
    assert.equal(findDuplicateMember(nest(MAX_JSON_DEPTH - 1)), undefined);
    assert.throws(() => findDuplicateMember(nest(MAX_JSON_DEPTH)), /nesting exceeds the maximum depth/);
    // 400,000 open brackets must be refused promptly, not walked into
    assert.throws(() => findDuplicateMember("[".repeat(400_000)), /nesting exceeds/);
  });

  it("measures size in UTF-8 bytes of the text as sent", () => {
    const cjk = "\u6f22".repeat(10); // 10 UTF-16 units, 30 UTF-8 bytes
    assert.equal(utf8ByteLength(cjk), 30);
    assert.equal(exceedsUtf8Bytes(cjk, 29), true);
    assert.equal(exceedsUtf8Bytes(cjk, 30), false);
    const text = JSON.stringify({ s: cjk });
    assert.doesNotThrow(() => parseStrictJson(text, { maxBytes: utf8ByteLength(text), label: "doc" }));
    assert.throws(
      () => parseStrictJson(text, { maxBytes: utf8ByteLength(text) - 1, label: "doc" }),
      /doc exceeds/,
    );
    // bytes in: the same rule, on the bytes
    assert.throws(() => parseStrictJson(enc(text), { maxBytes: 20, label: "doc" }), /doc exceeds/);
    // whitespace padding counts (the Rust core caps the raw text too)
    assert.throws(
      () => parseStrictJson(`{"a":1}${" ".repeat(100)}`, { maxBytes: 50, label: "doc" }),
      /doc exceeds/,
    );
  });

  it("refuses a byte-order mark and invalid UTF-8 rather than repairing them", () => {
    const ok = JSON.stringify({ a: 1 });
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...enc(ok)]);
    assert.equal(decodeUtf8Strict(bom).charCodeAt(0), 0xfeff, "the BOM is kept, not stripped");
    assert.throws(() => parseStrictJson(bom, { maxBytes: 100, label: "doc" }), /byte-order mark/);
    assert.throws(() => parseStrictJson(`\ufeff${ok}`, { maxBytes: 100, label: "doc" }), /byte-order mark/);
    assert.throws(
      () => parseStrictJson(new Uint8Array([0x7b, 0xff, 0x7d]), { maxBytes: 100, label: "doc" }),
      /not valid UTF-8/,
    );
  });

  it("an error message never carries attacker text raw", () => {
    const name = `evil\u001b[2K\r\u202e${"x".repeat(200)}`;
    const text = `{${JSON.stringify(name)}:1,${JSON.stringify(name)}:2}`;
    let message = "";
    try {
      parseStrictJson(text, { maxBytes: 10_000, label: "doc" });
    } catch (e) {
      message = (e as Error).message;
    }
    assert.match(message, /duplicate member name/);
    assert.ok(message.length < 140, "the echoed name is truncated");
    // eslint-disable-next-line no-control-regex
    assert.doesNotMatch(message, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/, "no control or bidi characters");
  });

  it("the traveler cap is 512 KiB of UTF-8 on BOTH entry points — not UTF-16 units", () => {
    // ~180k CJK characters across the long-text fields: well under 512 Ki UTF-16 code
    // units, but ~540 KiB of UTF-8. The old rule (UTF-16 units of the re-serialization)
    // accepted this; the Rust core, which caps the bytes, refused it.
    const big = structuredClone(BASE) as typeof BASE & { ops: { seq: number; code: string; notes: string }[] };
    big.ops = Array.from({ length: 64 }, (_, i) => ({ seq: i + 1, code: "op", notes: "\u6f22".repeat(2000) }));
    const withText = { ...big, part: { ...big.part, notes: "\u6f22".repeat(2000), finish: "\u6f22".repeat(2000) } };
    const more = {
      ...withText,
      quotes: Array.from({ length: 4 }, (_, q) => ({
        quote_id: `qot_wirebig00${q}`,
        seller: { name: "Summit Fabrication" },
        traveler_hash_quoted: `sha384:${"ab".repeat(48)}`,
        created_at: "2026-09-16T12:00:00.000Z",
        valid_until: "2039-01-01T00:00:00.000Z",
        lead_time_days: 21,
        pricing: { currency: "USD", lines: [{ qty: 50, unit: 1420 }] },
        exceptions: Array.from({ length: 16 }, (_, i) => ({ code: `E${i}`, proposal: "\u6f22".repeat(700) })),
      })),
    };
    const text = JSON.stringify(more);
    assert.ok(text.length < MAX_TRAVELER_JSON_BYTES, `UTF-16 units ${text.length} are under the cap`);
    assert.ok(utf8ByteLength(text) > MAX_TRAVELER_JSON_BYTES, `UTF-8 bytes ${utf8ByteLength(text)} are over it`);
    assert.throws(() => parseTravelerJson(text), /exceeds 512 KiB/);
    assert.throws(() => parseTravelerJson(enc(text)), /exceeds 512 KiB/);
    assert.throws(() => parseTraveler(more), /exceeds 512 KiB/);
  });

  it("an absurdly long array is refused before the schema ever walks it", () => {
    // 174,629 empty quotes serialize to just under 512 KiB, so the size cap does not
    // stop them. Validating them one by one (an issue object each, before the array's
    // own length cap applied) once cost ~1 GiB and two seconds per document. The
    // refusal must come from the cheap structural pre-check — its message, not zod's.
    const flood = { ...BASE, quotes: Array.from({ length: 174_629 }, () => ({})) };
    assert.ok(utf8ByteLength(JSON.stringify(flood)) <= MAX_TRAVELER_JSON_BYTES, "under the size cap");
    assert.throws(() => parseTraveler(flood), /^Error: Invalid traveler\. array is longer than any field allows$/);
    assert.throws(() => parseTravelerJson(JSON.stringify(flood)), /array is longer than any field allows/);
    // …and it refuses nothing a field could legitimately hold: the longest list that
    // fits a free-form blob's 8 KiB cap is shorter than the pre-check's limit.
    const longest = { ...BASE, as_built: { a: Array.from({ length: 4000 }, () => 1) } };
    assert.doesNotThrow(() => parseTraveler(longest));
    const tooLongForTheBlobAnyway = { ...BASE, as_built: { a: Array.from({ length: 4097 }, () => 1) } };
    assert.throws(() => parseTraveler(tooLongForTheBlobAnyway), /array is longer|exceeds 8 KiB/);
  });

  it("parseTravelerJson accepts what parseTraveler accepts, from text or bytes", () => {
    const text = JSON.stringify(BASE, null, 2);
    assert.deepEqual(parseTravelerJson(text), parseTraveler(BASE));
    assert.deepEqual(parseTravelerJson(enc(text)), parseTraveler(BASE));
    assert.throws(() => parseTravelerJson("not json"), /Invalid traveler\. traveler is not JSON/);
  });
});
