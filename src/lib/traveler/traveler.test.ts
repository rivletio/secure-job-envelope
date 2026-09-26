import assert from "node:assert/strict";
import { describe, it } from "node:test";
import JSZip from "jszip";
import { canonicalJson } from "./canonical.ts";
import { boundQuotes, levelOf, parseTraveler } from "./conformance.ts";
import { GOLDEN_QUOTEABLE, seedTravelers } from "./fixtures.ts";
import { cannotAward, cannotQuote, isQuoteExpired } from "./guards.ts";
import { GOLDEN_HASH, hashQuoteable, travelerHash, quoteableBody } from "./hash.ts";
import { quoteSchema } from "./schema.ts";
import type { Traveler, Quote } from "./types.ts";
import { importTravelerFile, travelerToZip } from "./zip.ts";

function validQuote(over: Partial<Quote> & { traveler_hash_quoted: string }): Quote {
  return {
    quote_id: "qte_testquote01",
    seller: { name: "Huron Precision", org_id: "org_huron", itar: true },
    created_at: "2026-09-09T00:00:00.000Z",
    valid_until: "2026-09-30T00:00:00.000Z",
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
    assert.throws(() => canonicalJson({ n: Infinity }));
    assert.throws(() => canonicalJson({ n: NaN }));
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
      spec: "sje/0.0.1",
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
    const hash = "sha384:" + "a".repeat(64);
    assert.equal(
      quoteSchema.safeParse(validQuote({ traveler_hash_quoted: hash, pricing: { currency: "USD", lines: [{ qty: 1, unit: -5 }] } }))
        .success,
      false,
    );
    assert.equal(
      quoteSchema.safeParse(validQuote({ traveler_hash_quoted: hash, pricing: { currency: "usd", lines: [{ qty: 1, unit: 5 }] } }))
        .success,
      false,
    );
    assert.equal(
      quoteSchema.safeParse(validQuote({ traveler_hash_quoted: hash, pricing: { currency: "USD", lines: [{ qty: 1, unit: Infinity }] } }))
        .success,
      false,
    );
  });

  it("refuses ITAR quotes from non-ITAR sellers", () => {
    const [bracket] = seedTravelers();
    const traveler = { ...bracket, itar: true };
    const quote = validQuote({
      traveler_hash_quoted: travelerHash(traveler),
      seller: { name: "Red River Machine", org_id: "org_redriver", itar: false },
    });
    assert.equal(cannotQuote(traveler, quote), "ITAR traveler cannot be quoted by a seller that is not ITAR-registered.");
    assert.throws(() => parseTraveler({ ...traveler, quotes: [quote] }));
  });

  it("refuses award of an expired quote or a qty with no price line", () => {
    const travelers = seedTravelers();
    const bracket = travelers.find((p) => p.traveler_id === "tvl_nlbrk4410")!;
    const quote = boundQuotes(bracket)[0]!;
    const expired: Quote = { ...quote, valid_until: "2026-09-01T00:00:00.000Z" };
    assert.equal(isQuoteExpired(expired, new Date("2026-09-14T00:00:00.000Z")), true);
    assert.match(cannotAward(bracket, expired, new Date("2026-09-14T00:00:00.000Z")) ?? "", /expired/);
    const noLine: Quote = {
      ...quote,
      pricing: { ...quote.pricing, lines: [{ qty: 7, unit: 99 }] },
    };
    assert.match(cannotAward(bracket, noLine) ?? "", /no unit price/);
  });

  it("round-trips a zip and rejects path tricks and META mismatch", async () => {
    const traveler = seedTravelers()[0]!;
    const blob = await travelerToZip(traveler);
    const file = new File([blob], `${traveler.traveler_id}.traveler.zip`, { type: "application/zip" });
    const back = await importTravelerFile(file);
    assert.equal(back.traveler_id, traveler.traveler_id);
    assert.equal(travelerHash(back), travelerHash(traveler));

    const evil = new JSZip();
    evil.file("../traveler.json", JSON.stringify(traveler));
    const evilBlob = await evil.generateAsync({ type: "blob" });
    await assert.rejects(
      importTravelerFile(new File([evilBlob], "evil.zip", { type: "application/zip" })),
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
  });

  it("surfaces the first schema path on invalid travelers", () => {
    assert.match(
      (() => {
        try {
          parseTraveler({ spec: "nope" });
        } catch (e) {
          return e instanceof Error ? e.message : "";
        }
        return "";
      })(),
      /Invalid traveler/,
    );
  });
});

it("canonical JSON refuses numbers outside the 0.0.1 fixed-notation range (Rust parity)", () => {
  assert.throws(() => canonicalJson({ t: 1e21 }));
  assert.throws(() => canonicalJson({ t: 1e-7 }));
  assert.throws(() => canonicalJson({ t: 0.000001 })); // ryu renders 1e-6
  assert.throws(() => canonicalJson({ t: 9007199254740992 })); // > 2^53-1
  assert.equal(canonicalJson({ t: 0.00001 }), '{"t":0.00001}');
  assert.equal(canonicalJson({ t: 9007199254740991 }), '{"t":9007199254740991}');
  assert.equal(canonicalJson({ t: 9.53 }), '{"t":9.53}');
});
