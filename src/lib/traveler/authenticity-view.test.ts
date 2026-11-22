import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  authenticityView,
  VERDICT_DEMO,
  VERDICT_MEANING,
  VERDICT_VERIFIED,
  type VerdictRow,
} from "./authenticity-view.ts";
import { quoteContentHash, signAward, signQuote, signTraveler } from "./authenticity.ts";
import { buildDemoTrust } from "./demo-trust.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { rootFingerprint } from "./fingerprint.ts";
import { parseTraveler } from "./conformance.ts";
import { travelerHash } from "./hash.ts";
import { keypairFromSeed } from "./signature.ts";
import { bytesToHex } from "./bytes.ts";
import type { Quote, Traveler } from "./types.ts";

const AT = new Date("2027-01-01T00:00:00.000Z");
const cp = (n: number) => String.fromCodePoint(n);

// A real (non-demo) anchor: a root, and two enrolled orgs with their own signing keys.
const root = keypairFromSeed(new Uint8Array(32).fill(41));
const buyerKey = keypairFromSeed(new Uint8Array(32).fill(42));
const sellerKey = keypairFromSeed(new Uint8Array(32).fill(43));
const rootPublicKeyHex = bytesToHex(root.publicKey);
const directory: Directory = (() => {
  const entry = (org_id: string, kid: string, key: typeof buyerKey) => ({
    org_id,
    kid,
    alg: "ML-DSA-87",
    public_key: bytesToHex(key.publicKey),
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    status: "active" as const,
  });
  const body: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    root_kid: "root-2026",
    entries: [entry("org_buyer", "buyer-2026", buyerKey), entry("org_seller", "seller-2026", sellerKey)],
  };
  return { ...body, sig: signDirectory(body, root.secretKey) };
})();
const trust = { directory, rootPublicKeyHex };

// Names an attacker would choose. Drawn raw, the first reads "Northline Equipment"
// followed by reversed text, the second hides a zero-width space and breaks the line.
const BUYER_NAME = `Northline Equipment ${cp(0x202e)}DEIFIREV${cp(0x202c)}`;
const SELLER_NAME = `Summit${cp(0x200b)}Fab\nVerified by the desk`;

function base(): Traveler {
  const p = new URL("../../../conformance/travelers/l0-bracket.json", import.meta.url).pathname;
  return parseTraveler({
    ...(JSON.parse(readFileSync(p, "utf8")) as Traveler),
    buyer: { org_id: "org_buyer", name: BUYER_NAME },
    quotes: [],
    signatures: [],
  });
}
const signed = (t: Traveler): Traveler => ({
  ...t,
  signatures: [signTraveler(t, "buyer-2026", buyerKey.secretKey)],
});
function quoteFor(t: Traveler, opts: { sign: boolean }): Quote {
  const q: Quote = {
    quote_id: "qot_viewtest01",
    seller: { org_id: "org_seller", name: SELLER_NAME },
    traveler_hash_quoted: travelerHash(t),
    created_at: "2026-02-01T00:00:00.000Z",
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: { currency: "USD", lines: [{ qty: t.part.qty.target, unit: 1420 }] },
  };
  return opts.sign ? { ...q, sig: signQuote(q, "seller-2026", sellerKey.secretKey) } : q;
}
/** A fully signed L2 traveler: buyer authorship, seller quote, buyer award. */
function awarded(opts: { signAward: boolean } = { signAward: true }): Traveler {
  const t = signed(base());
  const quote = quoteFor(t, { sign: true });
  const withAward = parseTraveler({
    ...t,
    quotes: [quote],
    award: {
      quote_id: quote.quote_id,
      quote_hash: quoteContentHash(quote),
      awarded_at: "2026-03-01T00:00:00.000Z",
      qty: t.part.qty.target,
    },
    ship_to: { name: "Dock 4", line1: "1800 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" },
    ops: [{ seq: 1, code: "MILL" }],
  });
  if (!opts.signAward) return withAward;
  return { ...withAward, award: { ...withAward.award!, sig: signAward(withAward, "buyer-2026", buyerKey.secretKey) } };
}

const byLabel = (rows: VerdictRow[], label: string) => rows.filter((r) => r.label === label);
/** Everything a row would put on screen. */
const drawn = (rows: VerdictRow[]) => JSON.stringify(rows);

describe("authenticity view: who signed is the directory's org_id + kid, never a name", () => {
  it("a passed check shows the directory-bound org_id and kid; the document's names are self-asserted", () => {
    const view = authenticityView(awarded(), trust, AT);
    assert.equal(view.demo, false);
    assert.equal(view.rootFingerprint, rootFingerprint(rootPublicKeyHex));
    assert.deepEqual(
      view.rows.map((r) => [r.label, r.status, r.verdict]),
      [
        ["Author", "ok", VERDICT_VERIFIED],
        ["Award", "ok", VERDICT_VERIFIED],
        ["Quote qot_viewtest01", "ok", VERDICT_VERIFIED],
      ],
    );
    const [author, award, quote] = view.rows as [VerdictRow, VerdictRow, VerdictRow];
    assert.deepEqual(author.signer, { org_id: "org_buyer", kid: "buyer-2026" });
    assert.deepEqual(award.signer, { org_id: "org_buyer", kid: "buyer-2026" });
    assert.deepEqual(quote.signer, { org_id: "org_seller", kid: "seller-2026" });
    // The names are carried separately, as the document's own claim…
    assert.equal(author.claimed!.org_id, "org_buyer");
    assert.equal(quote.claimed!.org_id, "org_seller");
    // …and no row is LABELLED with a name the document chose.
    for (const r of view.rows) {
      assert.ok(!r.label.includes("Northline") && !r.label.includes("Summit"), `label "${r.label}"`);
      assert.ok(!r.verdict.includes("Northline") && !r.verdict.includes("Summit"));
    }
    assert.match(VERDICT_MEANING, /compare the org_id/);
  });

  it("a name cannot reorder or hide text: bidi, zero-width and line-break characters are shown", () => {
    const view = authenticityView(awarded(), trust, AT);
    const author = view.rows[0]!;
    const quote = view.rows[2]!;
    assert.equal(author.claimed!.name, "Northline Equipment [U+202E]DEIFIREV[U+202C]");
    assert.equal(quote.claimed!.name, "Summit[U+200B]Fab[U+000A]Verified by the desk");
    // Nothing the view would draw still contains one of those characters.
    const all = drawn(view.rows);
    for (const n of [0x202e, 0x202c, 0x200b]) assert.ok(!all.includes(cp(n)), `U+${n.toString(16)} must not be drawn`);
    assert.ok(!view.rows.some((r) => /[\n\r]/.test(r.claimed?.name ?? "")), "no raw line break");
  });

  it("another enrolled org signing under the buyer's NAME shows as that other org", () => {
    // org_seller re-issues the traveler under its own org_id and the buyer's display
    // name, and signs it with its own (genuine, enrolled) key. It verifies — as
    // org_seller. The only thing that tells the reader is the org_id.
    const t = base();
    const reissued = parseTraveler({ ...t, buyer: { org_id: "org_seller", name: t.buyer.name } });
    const forged: Traveler = {
      ...reissued,
      signatures: [signTraveler(reissued, "seller-2026", sellerKey.secretKey)],
    };
    const [author] = authenticityView(forged, trust, AT).rows as [VerdictRow];
    assert.equal(author.status, "ok", "the check passes: the signer is who the document says");
    assert.deepEqual(author.signer, { org_id: "org_seller", kid: "seller-2026" }, "and the panel says who that is");
    assert.equal(author.claimed!.name, "Northline Equipment [U+202E]DEIFIREV[U+202C]");
  });

  it("unsigned, refused and blocked verdicts keep their levels and their reasons", () => {
    // Unsigned traveler, unsigned quote.
    const t = base();
    const unsigned = authenticityView({ ...t, quotes: [quoteFor(t, { sign: false })] }, trust, AT);
    assert.deepEqual(
      unsigned.rows.map((r) => [r.label, r.status, r.verdict, r.signer]),
      [
        ["Author", "warn", "Not signed", undefined],
        ["Quote qot_viewtest01", "warn", "Not signed", undefined],
      ],
    );
    assert.equal(unsigned.rows[1]!.claimed!.org_id, "org_seller", "what the unsigned quote claims is still shown");

    // An award nobody signed is a caution of its own.
    const noAwardSig = authenticityView(awarded({ signAward: false }), trust, AT);
    assert.deepEqual(byLabel(noAwardSig.rows, "Award").map((r) => [r.status, r.verdict]), [
      ["warn", "Unsigned — not buyer-authorized"],
    ]);

    // A body changed after signing: refused, with the library's reason and the key.
    const tampered = authenticityView({ ...signed(base()), revision: 7 }, trust, AT);
    assert.deepEqual(tampered.rows.map((r) => [r.label, r.status, r.verdict]), [
      ["Author", "bad", "signature does not verify (key buyer-2026 belongs to org_buyer)"],
    ]);

    // Signed by an org other than the one the document names.
    const b = base();
    const wrongSigner: Traveler = { ...b, signatures: [signTraveler(b, "seller-2026", sellerKey.secretKey)] };
    assert.deepEqual(authenticityView(wrongSigner, trust, AT).rows.map((r) => [r.status, r.verdict]), [
      ["bad", "signer org does not match author org (key seller-2026 belongs to org_seller)"],
    ]);

    // The directory does not verify against the root: nothing can be said, and the
    // unsigned-award caution must not paper over that.
    const otherRoot = bytesToHex(keypairFromSeed(new Uint8Array(32).fill(44)).publicKey);
    const blocked = authenticityView(awarded({ signAward: false }), { directory, rootPublicKeyHex: otherRoot }, AT);
    assert.deepEqual(blocked.rows.map((r) => [r.label, r.status, r.verdict]), [
      ["Author", "bad", "directory does not verify against the trust root"],
      ["Award", "bad", "directory does not verify against the trust root"],
    ]);
  });
});

describe("authenticity view under the DEMO trust anchor", () => {
  /** A traveler signed "by" a demo org with the key anyone can derive from the public
   *  seed in demo-trust.ts, plus a quote signed the same way. */
  function demoSigned(): Traveler {
    const summit = keypairFromSeed(new Uint8Array(32).fill(10));
    const redriver = keypairFromSeed(new Uint8Array(32).fill(12));
    const t0 = parseTraveler({ ...base(), buyer: { org_id: "org_summitfab", name: "Summit Fabrication" } });
    const t = { ...t0, signatures: [signTraveler(t0, "summit-demo", summit.secretKey)] };
    const q: Quote = { ...quoteFor(t, { sign: false }), seller: { org_id: "org_redriver", name: "Red River Machine" } };
    return { ...t, quotes: [{ ...q, sig: signQuote(q, "redriver-demo", redriver.secretKey) }] };
  }

  it("a check that passes is a WARNING that proves nothing — never a success", () => {
    const demo = buildDemoTrust();
    const view = authenticityView(demoSigned(), demo, AT);
    assert.equal(view.demo, true);
    assert.equal(view.rows.length, 2);
    for (const r of view.rows) {
      assert.equal(r.status, "warn", `${r.label} must not be shown as verified`);
      assert.equal(r.verdict, VERDICT_DEMO);
      assert.match(r.verdict, /DEMO anchor — proves nothing/);
    }
    assert.ok(!view.rows.some((r) => r.status === "ok"), "no success row under the demo anchor");
    // Who "signed" is still shown — it is just not evidence of anything.
    assert.deepEqual(view.rows[0]!.signer, { org_id: "org_summitfab", kid: "summit-demo" });
    // The demo root is recognized however its hex is spelled.
    const recased = authenticityView(demoSigned(), { ...demo, rootPublicKeyHex: demo.rootPublicKeyHex.toUpperCase() }, AT);
    assert.equal(recased.demo, true);
    assert.ok(recased.rows.every((r) => r.status === "warn"));
  });

  it("the very same documents under a real anchor are shown as verified (the downgrade is the anchor's, not the document's)", () => {
    const view = authenticityView(awarded(), trust, AT);
    assert.equal(view.demo, false);
    assert.ok(view.rows.every((r) => r.status === "ok"));
    // And failures under the demo anchor are still failures.
    const demo = buildDemoTrust();
    const tampered = authenticityView({ ...demoSigned(), revision: 9 }, demo, AT);
    assert.equal(tampered.rows[0]!.status, "bad");
  });
});
