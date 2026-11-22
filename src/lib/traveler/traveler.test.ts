import assert from "node:assert/strict";
import { describe, it } from "node:test";
import JSZip from "jszip";
import { canonicalJson } from "./canonical.ts";
import { boundQuotes, levelOf, parseTraveler } from "./conformance.ts";
import { GOLDEN_QUOTEABLE, seedTravelers } from "./fixtures.ts";
import { cannotAward, cannotQuote, isQuoteExpired } from "./guards.ts";
import { GOLDEN_HASH, hashQuoteable, sha384Hex, travelerHash, quoteableBody } from "./hash.ts";
import { quoteSchema } from "./schema.ts";
import type { Traveler, Quote } from "./types.ts";
import { importTravelerFile, travelerToZip } from "./zip.ts";

function validQuote(over: Partial<Quote> & { traveler_hash_quoted: string }): Quote {
  return {
    quote_id: "qot_testquote01",
    seller: { name: "Huron Precision", org_id: "org_huron", itar: true },
    created_at: "2026-09-09T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    lead_time_days: 12,
    pricing: { currency: "USD", lines: [{ qty: 50, unit: 29 }] },
    ...over,
  };
}

describe("rivlet traveler 0.0.1", () => {
  it("hashes the golden quoteable body", () => {
    const hash = hashQuoteable(GOLDEN_QUOTEABLE);
    assert.match(hash, /^sha384:[0-9a-f]{96}$/);
    assert.equal(hash, GOLDEN_HASH);
  });

  it("canonical JSON sorts keys and matches JS number encoding", () => {
    assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(canonicalJson({ t: 10.0 }), '{"t":10}');
    assert.equal(canonicalJson({ t: 9.53 }), '{"t":9.53}');
    assert.equal(canonicalJson({ t: -0 }), '{"t":0}');
  });

  it("refuses non-finite numbers in canonical JSON", () => {
    assert.throws(() => canonicalJson({ n: Infinity }), /non-finite number is not canonical/);
    assert.throws(() => canonicalJson({ n: -Infinity }), /non-finite number is not canonical/);
    assert.throws(() => canonicalJson({ n: NaN }), /non-finite number is not canonical/);
  });

  it("closed field set: extra buyer keys do not change the hash", () => {
    const [bracket] = seedTravelers();
    const tainted = {
      ...bracket,
      buyer: { ...bracket.buyer, extra: "should-not-hash" },
    } as Traveler;
    assert.equal(travelerHash(tainted), travelerHash(bracket));
    assert.equal("extra" in quoteableBody(tainted).buyer, false);
  });

  it("drops empty strings and arrays from the quoteable body (Rust parity)", () => {
    const withEmpties = parseTraveler({
      spec: "sje/0.1.0",
      traveler_id: "tvl_emptydrop1",
      revision: 1,
      created_at: "2026-09-08T15:12:00.000Z",
      buyer: { name: "Northline Equipment", certs: [] },
      part: {
        family: "CNC bracket",
        part_number: "NL-BRK-4410",
        material: { spec: "6061-T6" },
        qty: { target: 50, breaks: [] },
        processes: [],
      },
      itar: false,
    });
    const canon = canonicalJson(quoteableBody(withEmpties));
    assert.equal(canon.includes("certs"), false);
    assert.equal(canon.includes("processes"), false);
    assert.equal(canon.includes("breaks"), false);
  });

  it("contact is hashed when present", () => {
    const a = hashQuoteable({
      ...GOLDEN_QUOTEABLE,
      buyer: { name: "Northline Equipment", contact: "buyer@northline.example" },
    });
    const b = hashQuoteable(GOLDEN_QUOTEABLE);
    assert.notEqual(a, b);
  });

  it("seeds L0 L1 L2 travelers with bound quotes", () => {
    const travelers = seedTravelers();
    const codes = travelers.map((p) => levelOf(p).code).sort();
    assert.deepEqual(codes, ["L0", "L1", "L1", "L2"]);
    for (const p of travelers) {
      parseTraveler(JSON.parse(JSON.stringify(p)));
      for (const q of boundQuotes(p)) {
        assert.equal(q.traveler_hash_quoted, travelerHash(p));
        assert.equal(quoteSchema.safeParse(q).success, true);
      }
    }
  });

  it("rejects negative unit prices and non-ISO currency", () => {
    // Asserting only `success === false` let this test pass on a fixture that was itself
    // invalid: the hash here was 64 hex digits, HASH_RE wants 96, so every quote below
    // was refused for its hash and none of the three rules was ever exercised. Each case
    // now names every issue the schema raises, as [path, code, message].
    const hash = "sha384:" + "a".repeat(96);
    const issues = (pricing: Quote["pricing"]) => {
      const r = quoteSchema.safeParse(validQuote({ traveler_hash_quoted: hash, pricing }));
      return r.success ? "accepted" : r.error.issues.map((i) => [i.path.join("."), i.code, i.message]);
    };
    // The fixture is valid: whatever is refused below is refused for the one thing changed.
    assert.equal(issues({ currency: "USD", lines: [{ qty: 1, unit: 5 }] }), "accepted");
    assert.deepEqual(issues({ currency: "USD", lines: [{ qty: 1, unit: -5 }] }), [
      ["pricing.lines.0.unit", "too_small", "Too small: expected number to be >=0"],
    ]);
    assert.deepEqual(issues({ currency: "usd", lines: [{ qty: 1, unit: 5 }] }), [
      ["pricing.currency", "invalid_format", "Invalid string: must match pattern /^[A-Z]{3}$/"],
    ]);
    assert.deepEqual(issues({ currency: "USD", lines: [{ qty: 1, unit: Infinity }] }), [
      ["pricing.lines.0.unit", "invalid_type", "Invalid input: expected number, received Infinity"],
    ]);
    // The hash rule this fixture used to trip, pinned on its own.
    const shortHash = quoteSchema.safeParse(validQuote({ traveler_hash_quoted: "sha384:" + "a".repeat(64) }));
    assert.deepEqual(
      shortHash.success ? "accepted" : shortHash.error.issues.map((i) => [i.path.join("."), i.code]),
      [["traveler_hash_quoted", "invalid_format"]],
    );
  });

  it("refuses ITAR quotes from non-ITAR sellers", () => {
    const [bracket] = seedTravelers();
    const traveler = { ...bracket, itar: true };
    const quote = validQuote({
      traveler_hash_quoted: travelerHash(traveler),
      seller: { name: "Red River Machine", org_id: "org_redriver", itar: false },
    });
    assert.equal(cannotQuote(traveler, quote), "ITAR traveler cannot be quoted by a seller that has not self-declared ITAR.");
    // Refused for the ITAR rule and for nothing else: the same traveler with the same
    // quote from an ITAR seller parses, so the seller's flag is the only defect.
    assert.doesNotThrow(() =>
      parseTraveler({ ...traveler, quotes: [{ ...quote, seller: { ...quote.seller, itar: true } }] }),
    );
    assert.throws(
      () => parseTraveler({ ...traveler, quotes: [quote] }),
      /^Error: Invalid traveler\. quotes\.0\.seller\.itar: ITAR traveler cannot carry a quote from a non-ITAR seller$/,
    );
  });

  it("refuses award of an expired quote or a qty with no price line", () => {
    const travelers = seedTravelers();
    const bracket = travelers.find((p) => p.traveler_id === "tvl_nlbrk4410")!;
    const quote = boundQuotes(bracket)[0]!;
    const expired: Quote = { ...quote, valid_until: "2026-09-01T00:00:00.000Z" };
    assert.equal(isQuoteExpired(expired, new Date("2026-09-14T00:00:00.000Z")), true);
    assert.match(cannotAward(bracket, expired, new Date("2026-09-14T00:00:00.000Z")) ?? "", /expired/);
    // Far-future validity + a fixed evaluation instant so this asserts the
    // price-line path specifically, not expiry (which is checked first) — and so
    // the test never depends on the wall clock.
    const noLine: Quote = {
      ...quote,
      valid_until: "2099-01-01T00:00:00.000Z",
      pricing: { ...quote.pricing, lines: [{ qty: 7, unit: 99 }] },
    };
    assert.match(
      cannotAward(bracket, noLine, new Date("2026-09-14T00:00:00.000Z")) ?? "",
      /no unit price/,
    );
  });

  it("round-trips a zip and rejects path tricks and META mismatch", async () => {
    const traveler = seedTravelers()[0]!;
    const blob = await travelerToZip(traveler);
    const file = new File([blob], `${traveler.traveler_id}.traveler.zip`, { type: "application/zip" });
    const back = await importTravelerFile(file);
    assert.equal(back.traveler_id, traveler.traveler_id);
    assert.equal(travelerHash(back), travelerHash(traveler));

    // What this archive is refused FOR is the directory entry JSZip writes next to a
    // member named "../traveler.json" — not the traversal in the name. (JSZip cannot
    // write such a name without that entry, so this case never reached the name check;
    // with no reason pinned it passed all the same.) The stored-name guard is exercised
    // on its own, on hand-built archives, in zip.test.ts.
    const evil = new JSZip();
    evil.file("../traveler.json", JSON.stringify(traveler));
    const evilBlob = await evil.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([evilBlob], "evil.zip", { type: "application/zip" })),
      /^Error: Archive directories are not allowed$/,
    );

    const tamper = new JSZip();
    const mutated = { ...traveler, part: { ...traveler.part, notes: "tampered" } };
    tamper.file("traveler.json", JSON.stringify(mutated, null, 2));
    tamper.file(
      "META.json",
      JSON.stringify({ traveler_id: traveler.traveler_id, traveler_hash: travelerHash(traveler) }),
    );
    const tamperBlob = await tamper.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([tamperBlob], "tamper.zip", { type: "application/zip" })),
      /traveler_hash does not match/,
    );

    const noMeta = new JSZip();
    noMeta.file("traveler.json", JSON.stringify(traveler));
    const noMetaBlob = await noMeta.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([noMetaBlob], "nometa.zip", { type: "application/zip" })),
      /missing META.json/,
    );

    const extra = new JSZip();
    extra.file("traveler.json", JSON.stringify(traveler));
    extra.file("META.json", JSON.stringify({ traveler_id: traveler.traveler_id, traveler_hash: travelerHash(traveler) }));
    extra.file("payload.bin", "nope");
    const extraBlob = await extra.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([extraBlob], "extra.zip", { type: "application/zip" })),
      /Unexpected archive member/,
    );

    const badCanon = new JSZip();
    const badCanonJson = JSON.stringify(traveler, null, 2);
    badCanon.file("traveler.json", badCanonJson);
    badCanon.file(
      "META.json",
      // A valid full-bytes digest so we reach the canonical-member check (the
      // digest is now mandatory and would otherwise fire first).
      JSON.stringify({
        traveler_id: traveler.traveler_id,
        traveler_hash: travelerHash(traveler),
        traveler_json_sha384: sha384Hex(badCanonJson),
      }),
    );
    badCanon.file("quoteable.canonical.json", '{"tampered":true}');
    const badCanonBlob = await badCanon.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([badCanonBlob], "badcanon.zip", { type: "application/zip" })),
      /quoteable\.canonical\.json does not match/,
    );
  });

  it("refuses tampering of non-quoteable fields (award/ship_to) — full-bytes digest is required", async () => {
    // award/ship_to/ops are NOT in the quoteable body, so traveler_hash alone does
    // not cover them. Only the mandatory traveler_json_sha384 over the whole
    // traveler.json does. Injecting an award leaves traveler_hash unchanged.
    const traveler = seedTravelers()[0]!;
    const honestJson = JSON.stringify(traveler, null, 2);
    const tampered = {
      ...traveler,
      award: { quote_id: "qot_injected1", awarded_at: "2027-01-01T00:00:00.000Z", qty: 1 },
    };
    const tamperedJson = JSON.stringify(tampered, null, 2);
    assert.equal(
      travelerHash(parseTraveler(tampered)),
      travelerHash(traveler),
      "an injected award does not change traveler_hash",
    );

    // (a) META carries the HONEST full-bytes digest, but traveler.json is tampered → refused.
    const staleDigest = new JSZip();
    staleDigest.file("traveler.json", tamperedJson);
    staleDigest.file(
      "META.json",
      JSON.stringify({
        traveler_id: traveler.traveler_id,
        traveler_hash: travelerHash(traveler),
        traveler_json_sha384: sha384Hex(honestJson),
      }),
    );
    await assert.rejects(
      importTravelerFile(
        new File([await staleDigest.generateAsync({ type: "blob" })], "a.zip", { type: "application/zip" }),
      ),
      /traveler_json_sha384/,
    );

    // (b) META omits the digest entirely → refused (it is required, no longer optional).
    const noDigest = new JSZip();
    noDigest.file("traveler.json", tamperedJson);
    noDigest.file(
      "META.json",
      JSON.stringify({ traveler_id: traveler.traveler_id, traveler_hash: travelerHash(traveler) }),
    );
    await assert.rejects(
      importTravelerFile(
        new File([await noDigest.generateAsync({ type: "blob" })], "b.zip", { type: "application/zip" }),
      ),
      /traveler_json_sha384 is required/,
    );
  });

  it("refuses a zip whose member inflates past the decompressed cap (zip-bomb)", async () => {
    // A tiny compressed archive whose traveler.json inflates far past the
    // 512 KiB member cap must be refused mid-decompression, not fully inflated.
    const bomb = new JSZip();
    bomb.file("traveler.json", "a".repeat(2 * 1024 * 1024), { compression: "DEFLATE" });
    bomb.file(
      "META.json",
      JSON.stringify({ traveler_id: "tvl_zipbomb001", traveler_hash: "sha384:x" }),
    );
    const blob = await bomb.generateAsync({ type: "blob", compression: "DEFLATE" });
    assert.ok(blob.size < 64 * 1024, `bomb should compress small, got ${blob.size} bytes`);
    await assert.rejects(
      importTravelerFile(new File([blob], "bomb.zip", { type: "application/zip" })),
      /exceeds \d+ bytes uncompressed/,
    );
  });

  it("opsFromProcesses ignores prototype-chain keys (no phantom op)", async () => {
    const { opsFromProcesses } = await import("./network.ts");
    const ops = opsFromProcesses(["__proto__", "constructor", "toString", "cnc_mill"]);
    assert.ok(ops.every((o) => typeof o.code === "string" && o.code.length > 0));
    assert.ok(ops.some((o) => o.code === "MILL"));
  });

  it("accepts optional award commercial terms (caveat 5)", () => {
    const base = seedTravelers().find((t) => t.award);
    assert.ok(base?.award, "a seed traveler is awarded");
    const withTerms = parseTraveler({
      ...base,
      award: {
        ...base!.award!,
        terms: { governing_law: "US-DE", warranty: "12 months", payment_terms: "Net 30" },
      },
    });
    assert.equal(withTerms.award?.terms?.payment_terms, "Net 30");
    assert.equal(levelOf(withTerms).code, "L2");
  });

  it("surfaces the first schema path on invalid travelers", () => {
    // The whole message: the path of the FIRST issue (this document has many — every
    // required member but `spec` is missing) and that issue's text.
    assert.throws(
      () => parseTraveler({ spec: "nope" }),
      /^Error: Invalid traveler\. spec: Invalid input: expected "sje\/0\.1\.0"$/,
    );
    assert.throws(
      () => parseTraveler({ spec: "sje/0.1.0" }),
      /^Error: Invalid traveler\. traveler_id: Invalid input: expected string, received undefined$/,
    );
  });
});

it("canonical JSON refuses numbers outside the 0.0.1 fixed-notation range (Rust parity)", () => {
  // Each refusal is pinned to the rule that fires. (1e21 is refused for its magnitude,
  // before its rendering is ever looked at.)
  assert.throws(() => canonicalJson({ t: 1e21 }), /number exceeds 2\^53-1/);
  assert.throws(() => canonicalJson({ t: 1e-7 }), /non-integer number below 1e-5/);
  assert.throws(() => canonicalJson({ t: 0.000001 }), /non-integer number below 1e-5/); // ryu renders 1e-6
  assert.throws(() => canonicalJson({ t: 9007199254740992 }), /number exceeds 2\^53-1/); // > 2^53-1
  assert.equal(canonicalJson({ t: 0.00001 }), '{"t":0.00001}');
  assert.equal(canonicalJson({ t: 9007199254740991 }), '{"t":9007199254740991}');
  assert.equal(canonicalJson({ t: 9.53 }), '{"t":9.53}');
});
