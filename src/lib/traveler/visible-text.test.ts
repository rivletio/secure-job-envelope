import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hasHiddenCharacters, visibleText } from "./visible-text.ts";

// Every character under test is built from its code point: this file must not itself
// contain an invisible, bidi or control character.
const cp = (n: number) => String.fromCodePoint(n);
const tag = (n: number) => `[U+${n.toString(16).toUpperCase().padStart(4, "0")}]`;

describe("visibleText", () => {
  it("makes a right-to-left override visible instead of letting it reorder the text", () => {
    // "Acme <RLO>orp lacitirC<PDF>" is DRAWN as "Acme Critical pro".
    const name = `Acme ${cp(0x202e)}orp lacitirC${cp(0x202c)}`;
    assert.equal(visibleText(name), "Acme [U+202E]orp lacitirC[U+202C]");
    assert.ok(hasHiddenCharacters(name));
  });

  it("replaces every bidi embedding, override and isolate", () => {
    for (const n of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
      assert.equal(visibleText(`a${cp(n)}b`), `a${tag(n)}b`, tag(n));
    }
    // The implicit directional marks reorder neighbouring punctuation too.
    for (const n of [0x200e, 0x200f, 0x061c]) {
      assert.equal(visibleText(`a${cp(n)}b`), `a${tag(n)}b`, tag(n));
    }
  });

  it("replaces zero-width characters, so two different names cannot look identical", () => {
    for (const n of [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x034f, 0x180e]) {
      const spoofed = `North${cp(n)}line`;
      assert.notEqual(spoofed, "Northline");
      assert.equal(visibleText(spoofed), `North${tag(n)}line`, tag(n));
    }
    // Letters that are drawn as nothing at all (Hangul fillers), tag characters and
    // variation selectors are caught by the same rule.
    for (const n of [0x115f, 0x1160, 0x3164, 0xffa0, 0xe0041, 0xe007f, 0xfe0f, 0xe0100]) {
      assert.equal(visibleText(`x${cp(n)}y`), `x${tag(n)}y`, tag(n));
    }
  });

  it("replaces line breaks and control characters", () => {
    assert.equal(
      visibleText("Trusted Buyer\nVERIFIED by the desk"),
      "Trusted Buyer[U+000A]VERIFIED by the desk",
    );
    for (const n of [0x0000, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x001b, 0x007f, 0x0085, 0x009f]) {
      assert.equal(visibleText(`a${cp(n)}b`), `a${tag(n)}b`, tag(n));
    }
    for (const n of [0x2028, 0x2029]) assert.equal(visibleText(`a${cp(n)}b`), `a${tag(n)}b`, tag(n));
  });

  it("shows a lone surrogate, and leaves a real astral character alone", () => {
    assert.equal(visibleText(`a${cp(0xd83d)}b`), "a[U+D83D]b");
    assert.equal(visibleText(`a${cp(0xde00)}b`), "a[U+DE00]b");
    const grin = cp(0x1f600);
    assert.equal(visibleText(`a${grin}b`), `a${grin}b`);
  });

  it("leaves ordinary text exactly as it is, in any script", () => {
    const hebrew = [0x05e9, 0x05dc, 0x05d5, 0x05dd].map(cp).join(""); // strong RTL letters
    for (const s of [
      "Northline Equipment",
      "org_summitfab",
      "recip-2026",
      "Café Müller GmbH & Co. KG",
      `${cp(0x65e5)}${cp(0x672c)}${cp(0x88fd)}${cp(0x4f5c)}${cp(0x6240)}`, // CJK
      hebrew,
      `a${cp(0x00a0)}b`, // a no-break space is drawn (as a space)
      "",
    ]) {
      assert.equal(visibleText(s), s);
      assert.ok(!hasHiddenCharacters(s));
    }
  });

  it("is idempotent, and its output is free of every character on the audited list", () => {
    // An explicit list of ranges, written independently of the Unicode-property
    // pattern the implementation uses: C0/C1 controls, bidi embeddings/overrides/
    // isolates, zero-width characters and marks, line/paragraph separators, BOM.
    const listed: Array<[number, number]> = [
      [0x0000, 0x001f],
      [0x007f, 0x009f],
      [0x061c, 0x061c],
      [0x200b, 0x200f],
      [0x2028, 0x202e],
      [0x2060, 0x2060],
      [0x2066, 0x2069],
      [0xfeff, 0xfeff],
    ];
    let all = "";
    for (const [from, to] of listed) for (let n = from; n <= to; n++) all += `<${cp(n)}>`;
    const shown = visibleText(all);
    assert.equal(visibleText(shown), shown, "idempotent");
    for (const [from, to] of listed) {
      for (let n = from; n <= to; n++) {
        assert.ok(!shown.includes(cp(n)), `${tag(n)} must not survive`);
        assert.ok(shown.includes(`<${tag(n)}>`), `${tag(n)} must be shown as a placeholder`);
      }
    }
  });
});
