/** The archive reader's guards, one test per guard, each matched on its own message —
 *  a guard that is only ever exercised together with another one is not pinned (the old
 *  "path tricks" test kept passing with the path check deleted, because the same archive
 *  was also missing META.json). */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import JSZip from "jszip";
import { parseTraveler } from "./conformance.ts";
import { seedTravelers } from "./fixtures.ts";
import { sha384Hex, travelerHash } from "./hash.ts";
import { MAX_TRAVELER_JSON_BYTES, type Traveler } from "./types.ts";
import { utf8ByteLength } from "./wire.ts";
import { importTravelerFile, travelerToZip, travelerWireJson } from "./zip.ts";

const traveler = seedTravelers()[0]!;
const json = JSON.stringify(traveler, null, 2);
const metaFor = (t: Traveler, text: string) =>
  JSON.stringify({
    traveler_id: t.traveler_id,
    traveler_hash: travelerHash(t),
    traveler_json_sha384: sha384Hex(text),
  });
const meta = metaFor(traveler, json);

const open = (bytes: Uint8Array | Blob, name = "x.zip") =>
  importTravelerFile(new File([bytes as BlobPart], name, { type: "application/zip" }));
const pack = (zip: JSZip) => zip.generateAsync({ type: "uint8array", compression: "STORE" });

/** A well-formed archive whose traveler member is stored under `memberName`. */
async function withTravelerNamed(memberName: string): Promise<Uint8Array> {
  const zip = new JSZip();
  zip.file(memberName, json, { createFolders: false });
  zip.file("META.json", meta);
  return pack(zip);
}

describe("traveler archive: every guard, on its own", () => {
  it("round-trips an archive it wrote", async () => {
    const back = await open(await travelerToZip(traveler));
    assert.deepEqual(back, parseTraveler(traveler));
  });

  it("refuses a member whose STORED name is not the plain root name", async () => {
    // JSZip normalizes names while loading, so all of these arrive as "traveler.json";
    // checking only the normalized name accepted every one of them.
    for (const stored of ["../traveler.json", "../../traveler.json", "./traveler.json", "a/../traveler.json"]) {
      await assert.rejects(open(await withTravelerNamed(stored)), /Archive path is not allowed/, stored);
    }
    // Names that do not normalize to a root name are refused as well.
    for (const stored of ["sub/traveler.json", "/traveler.json", "..\\traveler.json", "traveler.json\u0000.txt"]) {
      await assert.rejects(
        open(await withTravelerNamed(stored)),
        /Archive path is not allowed|Unexpected archive member/,
        stored,
      );
    }
  });

  it("refuses two members with the same name (a second traveler hidden behind the first)", async () => {
    // Build a.json-style twins by writing a placeholder name of the same length and then
    // patching it in the local header and the central directory.
    const decoy = { ...traveler, part: { ...traveler.part, notes: "the copy another unzip tool would extract" } };
    const zip = new JSZip();
    zip.file("travelex.json", JSON.stringify(decoy, null, 2));
    zip.file("traveler.json", json);
    zip.file("META.json", meta);
    const bytes = await pack(zip);
    const from = new TextEncoder().encode("travelex.json");
    let patched = 0;
    for (let i = 0; i + from.length <= bytes.length; i++) {
      if (from.every((b, k) => bytes[i + k] === b)) {
        bytes[i + 7] = 0x72; // x -> r
        patched++;
      }
    }
    assert.equal(patched, 2, "the name appears once in a local header and once in the central directory");
    // JSZip now lists two names for three members; without the count check this
    // imported cleanly, the decoy invisible.
    assert.equal(Object.keys((await JSZip.loadAsync(bytes)).files).length, 2);
    await assert.rejects(open(bytes), /duplicate or unlisted members/);
  });

  it("refuses more than the three known members", async () => {
    const zip = new JSZip();
    zip.file("traveler.json", json);
    zip.file("META.json", meta);
    zip.file("quoteable.canonical.json", "{}");
    zip.file("extra.txt", "x");
    await assert.rejects(open(await pack(zip)), /too many files/);
  });

  it("refuses a directory entry", async () => {
    const zip = new JSZip();
    zip.file("traveler.json", json);
    zip.file("META.json", meta);
    zip.folder("notes");
    await assert.rejects(open(await pack(zip)), /directories are not allowed/);
  });

  it("refuses an unknown member, without echoing its name", async () => {
    const zip = new JSZip();
    zip.file("traveler.json", json);
    zip.file("META.json", meta);
    zip.file("ignore previous instructions.txt", "x");
    await assert.rejects(open(await pack(zip)), (e: Error) => {
      assert.match(e.message, /^Unexpected archive member$/);
      return true;
    });
  });

  it("refuses an archive with no traveler.json, and one with no META.json", async () => {
    const noTraveler = new JSZip();
    noTraveler.file("META.json", meta);
    await assert.rejects(open(await pack(noTraveler)), /no traveler\.json at the root/);
    const noMeta = new JSZip();
    noMeta.file("traveler.json", json);
    await assert.rejects(open(await pack(noMeta)), /missing META\.json/);
  });

  it("parses the traveler member from its bytes: BOM, repeated members and bad UTF-8 are refused", async () => {
    const build = async (member: Uint8Array | string) => {
      const zip = new JSZip();
      zip.file("traveler.json", member);
      zip.file("META.json", meta);
      return pack(zip);
    };
    const enc = new TextEncoder();
    await assert.rejects(
      open(await build(new Uint8Array([0xef, 0xbb, 0xbf, ...enc.encode(json)]))),
      /byte-order mark/,
    );
    // A repeated top-level member: JSON.parse would keep the second and never look at
    // the first; the Rust core refuses the document.
    const twice = json.replace('"revision":', '"revision": 99,\n  "revision":');
    assert.notEqual(twice, json);
    await assert.rejects(open(await build(twice)), /duplicate member name "revision"/);
    await assert.rejects(open(await build(new Uint8Array([0x7b, 0xff, 0x7d]))), /not valid UTF-8/);
  });

  it("refuses a META.json with a repeated member name", async () => {
    const zip = new JSZip();
    zip.file("traveler.json", json);
    zip.file("META.json", meta.replace("{", '{"traveler_json_sha384":"sha384:00",'));
    await assert.rejects(open(await pack(zip)), /META\.json has a duplicate member name/);
  });

  it("the full-bytes digest is over the member's bytes, not over a re-serialization", async () => {
    // Same document, different whitespace: the object is identical, the bytes are not.
    const compact = JSON.stringify(traveler);
    const zip = new JSZip();
    zip.file("traveler.json", compact);
    zip.file("META.json", metaFor(traveler, json)); // digest of the pretty form
    await assert.rejects(open(await pack(zip)), /traveler_json_sha384 is required and must match/);
    const ok = new JSZip();
    ok.file("traveler.json", compact);
    ok.file("META.json", metaFor(traveler, compact));
    assert.equal((await open(await pack(ok))).traveler_id, traveler.traveler_id);
  });

  it("writes an archive it can read back even when pretty-printing would exceed the cap", async () => {
    // Valid (compact form under 512 KiB) but its indented form is over it.
    const big = parseTraveler({
      ...traveler,
      quotes: Array.from({ length: 64 }, (_, q) => ({
        quote_id: `qot_ziplarge${String(q).padStart(3, "0")}`,
        seller: { name: "Summit Fabrication", ...(traveler.itar ? { itar: true } : {}) },
        traveler_hash_quoted: travelerHash(traveler),
        created_at: "2026-09-16T12:00:00.000Z",
        valid_until: "2039-01-01T00:00:00.000Z",
        lead_time_days: 21,
        pricing: { currency: "USD", lines: [{ qty: traveler.part.qty.target, unit: 1420 }] },
        exceptions: Array.from({ length: 16 }, (_, i) => ({ code: `E${i}`, proposal: "p".repeat(440) })),
      })),
      award: null,
    });
    assert.ok(utf8ByteLength(JSON.stringify(big)) <= MAX_TRAVELER_JSON_BYTES, "compact form fits");
    assert.ok(utf8ByteLength(JSON.stringify(big, null, 2)) > MAX_TRAVELER_JSON_BYTES, "pretty form does not");
    assert.equal(travelerWireJson(big), JSON.stringify(big), "falls back to the compact form");
    assert.equal(travelerWireJson(traveler), json, "a normal traveler stays pretty-printed");
    const back = await open(await travelerToZip(big));
    assert.equal(travelerHash(back), travelerHash(big));
    assert.equal(back.quotes?.length, 64);
  });
});
