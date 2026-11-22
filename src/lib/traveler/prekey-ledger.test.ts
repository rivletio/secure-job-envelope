import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  MAX_LEDGER_MARKS_PER_ORG,
  MAX_LEDGER_ORGS,
  forwardSecrecyOutlook,
  prekeyMark,
  recordPrekeyUse,
  sanitizePrekeyLedger,
  staticReasonText,
  usedPrekeyIds,
  type PrekeyLedger,
} from "./prekey-ledger.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "./prekeys.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "./directory.ts";
import { kemKeypairFromSeed } from "./envelope.ts";
import { keypairFromSeed } from "./signature.ts";
import { sealTraveler } from "./transport.ts";
import { parseTraveler } from "./conformance.ts";
import { bytesToHex } from "./bytes.ts";
import type { Traveler } from "./types.ts";

const AT = new Date("2027-01-01T00:00:00.000Z");
const root = keypairFromSeed(new Uint8Array(32).fill(31));
const rootPublicKeyHex = bytesToHex(root.publicKey);
const signerA = keypairFromSeed(new Uint8Array(32).fill(32));
const signerB = keypairFromSeed(new Uint8Array(32).fill(33));

/** A distinct, real ML-KEM-1024 public key per `n` (deterministic). */
function kemPub(n: number): string {
  const seed = new Uint8Array(64);
  seed[0] = n & 0xff;
  seed[1] = (n >> 8) & 0xff;
  seed[63] = 0x5a;
  return bytesToHex(kemKeypairFromSeed(seed).publicKey);
}

const directory: Directory = (() => {
  const entry = (org_id: string, kid: string, signer: typeof signerA, enc: number) => ({
    org_id,
    kid,
    alg: "ML-DSA-87",
    public_key: bytesToHex(signer.publicKey),
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    status: "active" as const,
    enc_alg: "ML-KEM-1024",
    enc_public_key: kemPub(enc),
  });
  const body: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    root_kid: "root-2026",
    entries: [entry("org_alpha", "alpha-2026", signerA, 9001), entry("org_beta", "beta-2026", signerB, 9002)],
  };
  return { ...body, sig: signDirectory(body, root.secretKey) };
})();

/** A bundle for `org`, signed by its directory key, listing the given (label, key#) pairs. */
function bundleOf(
  org: "org_alpha" | "org_beta",
  prekeys: Array<[label: string, key: number]>,
  issued_at = "2026-01-01T00:00:00.000Z",
): PrekeyBundle {
  const b: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: org,
    kid: org === "org_alpha" ? "alpha-2026" : "beta-2026",
    enc_alg: "ML-KEM-1024",
    issued_at,
    valid_until: "2030-01-01T00:00:00.000Z",
    prekeys: prekeys.map(([prekey_id, key]) => ({ prekey_id, public_key: kemPub(key) })),
  };
  b.sig = signPrekeyBundle(b, (org === "org_alpha" ? signerA : signerB).secretKey);
  return b;
}

function sampleTraveler(): Traveler {
  const p = new URL("../../../conformance/travelers/l0-bracket.json", import.meta.url).pathname;
  return parseTraveler(JSON.parse(readFileSync(p, "utf8")));
}

describe("prekey ledger (sender-side memory of spent one-time prekeys)", () => {
  it("records a spent prekey and reports it as used for that bundle", () => {
    const bundle = bundleOf("org_alpha", [["pk1", 1], ["pk2", 2], ["pk3", 3]]);
    const empty: PrekeyLedger = {};
    assert.deepEqual(usedPrekeyIds(empty, bundle), []);
    const one = recordPrekeyUse(empty, bundle, "pk2");
    assert.deepEqual(empty, {}, "the input ledger is not modified");
    assert.deepEqual(usedPrekeyIds(one, bundle), ["pk2"]);
    assert.deepEqual(one, { org_alpha: [prekeyMark(kemPub(2))] });
    assert.match(one.org_alpha![0]!, /^[0-9a-f]{16}$/);
    // Recording the same prekey again changes nothing.
    assert.equal(recordPrekeyUse(one, bundle, "pk2"), one);
    const two = recordPrekeyUse(one, bundle, "pk1");
    assert.deepEqual(usedPrekeyIds(two, bundle).sort(), ["pk1", "pk2"]);
    // A prekey that was never offered cannot be recorded.
    assert.throws(() => recordPrekeyUse(two, bundle, "pk9"), /not in the bundle/);
  });

  it("a NEW bundle of fresh keys from the same org starts fresh — even if it reuses the old labels", () => {
    const first = bundleOf("org_alpha", [["pk1", 1], ["pk2", 2]]);
    let ledger = recordPrekeyUse({}, first, "pk1");
    ledger = recordPrekeyUse(ledger, first, "pk2");
    assert.deepEqual(usedPrekeyIds(ledger, first).sort(), ["pk1", "pk2"], "the first bundle is spent");

    // The recipient mints new one-time keys and publishes them under the SAME labels.
    const second = bundleOf("org_alpha", [["pk1", 11], ["pk2", 12]], "2026-06-01T00:00:00.000Z");
    assert.deepEqual(usedPrekeyIds(ledger, second), [], "nothing in the new bundle is marked spent");
    assert.deepEqual(
      forwardSecrecyOutlook({ ledger, bundle: second, directory, rootPublicKeyHex, recipientOrg: "org_alpha", at: AT }),
      { forwardSecret: true, unused: 2, total: 2 },
    );
  });

  it("a prekey this sender already sealed to stays spent when a new bundle re-lists it, or an old bundle is loaded again", () => {
    const first = bundleOf("org_alpha", [["pk1", 1], ["pk2", 2]]);
    const ledger = recordPrekeyUse({}, first, "pk1");
    // A top-up bundle: the old unconsumed keys (re-labelled) plus new ones.
    const topUp = bundleOf("org_alpha", [["a", 1], ["b", 2], ["c", 21]], "2026-06-01T00:00:00.000Z");
    assert.deepEqual(usedPrekeyIds(ledger, topUp), ["a"], "key #1 is spent whatever it is called now");
    // Using the new bundle, then going back to the first one: its spent prekey is still spent.
    const later = recordPrekeyUse(ledger, topUp, "c");
    assert.deepEqual(usedPrekeyIds(later, first), ["pk1"]);
  });

  it("keeps each org's memory separate", () => {
    const alpha = bundleOf("org_alpha", [["pk1", 1], ["pk2", 2]]);
    const beta = bundleOf("org_beta", [["pk1", 41], ["pk2", 42]]);
    const ledger = recordPrekeyUse({}, alpha, "pk1");
    assert.deepEqual(usedPrekeyIds(ledger, beta), []);
    const both = recordPrekeyUse(ledger, beta, "pk2");
    assert.deepEqual(usedPrekeyIds(both, alpha), ["pk1"]);
    assert.deepEqual(usedPrekeyIds(both, beta), ["pk2"]);
    assert.deepEqual(Object.keys(both), ["org_alpha", "org_beta"]);
  });

  it("is bounded: at most 512 marks per org and 128 orgs", () => {
    const bundle = bundleOf("org_alpha", [["pk1", 1]]);
    const full: PrekeyLedger = {
      org_alpha: Array.from({ length: MAX_LEDGER_MARKS_PER_ORG }, (_, i) => i.toString(16).padStart(16, "0")),
    };
    const next = recordPrekeyUse(full, bundle, "pk1");
    assert.equal(next.org_alpha!.length, MAX_LEDGER_MARKS_PER_ORG);
    assert.equal(next.org_alpha!.at(-1), prekeyMark(kemPub(1)), "the newest mark is kept");
    assert.ok(!next.org_alpha!.includes("0".repeat(16)), "the oldest mark is the one forgotten");

    const crowded: PrekeyLedger = Object.fromEntries(
      Array.from({ length: MAX_LEDGER_ORGS }, (_, i) => [`org_n${i}`, ["0".repeat(16)]]),
    );
    const grown = recordPrekeyUse(crowded, bundle, "pk1");
    assert.equal(Object.keys(grown).length, MAX_LEDGER_ORGS);
    assert.ok(Object.hasOwn(grown, "org_alpha"));
    assert.ok(!Object.hasOwn(grown, "org_n0"), "the org sealed to longest ago is the one forgotten");
  });

  it("sanitizePrekeyLedger keeps only what has the ledger's shape", () => {
    const mark = "0123456789abcdef";
    assert.deepEqual(sanitizePrekeyLedger(undefined), {});
    assert.deepEqual(sanitizePrekeyLedger(null), {});
    assert.deepEqual(sanitizePrekeyLedger("x"), {});
    assert.deepEqual(sanitizePrekeyLedger([[mark]]), {});
    assert.deepEqual(
      sanitizePrekeyLedger({
        org_ok: [mark, mark, "fedcba9876543210"], // duplicates collapse
        org_mixed: [mark, 7, null, "NOTHEX0123456789", "abc", { m: mark }],
        org_empty: [],
        org_notalist: mark,
        "Not An Org": [mark],
        constructor: [mark], // a legal org_id, and an inherited member name: own entries only
      }),
      { org_ok: [mark, "fedcba9876543210"], org_mixed: [mark], constructor: [mark] },
    );
    // What it returns survives a JSON round trip unchanged (it is what gets persisted).
    const ledger = recordPrekeyUse({}, bundleOf("org_alpha", [["pk1", 1]]), "pk1");
    assert.deepEqual(sanitizePrekeyLedger(JSON.parse(JSON.stringify(ledger))), ledger);
    // An org named like an inherited member is looked up as an own entry, never the prototype's.
    assert.deepEqual(usedPrekeyIds({}, { ...bundleOf("org_alpha", [["pk1", 1]]), org_id: "constructor" }), []);
  });

  it("forwardSecrecyOutlook says what a seal would do, and why it would fall back", () => {
    const bundle = bundleOf("org_alpha", [["pk1", 1], ["pk2", 2]]);
    const outlook = (ledger: PrekeyLedger, b: PrekeyBundle | undefined, recipientOrg = "org_alpha", at = AT) =>
      forwardSecrecyOutlook({ ledger, bundle: b, directory, rootPublicKeyHex, recipientOrg, at });

    assert.deepEqual(outlook({}, bundle), { forwardSecret: true, unused: 2, total: 2 });
    const one = recordPrekeyUse({}, bundle, "pk1");
    assert.deepEqual(outlook(one, bundle), { forwardSecret: true, unused: 1, total: 2 });
    const both = recordPrekeyUse(one, bundle, "pk2");
    assert.deepEqual(outlook(both, bundle), { forwardSecret: false, reason: "prekeys-exhausted", total: 2 });

    assert.deepEqual(outlook({}, undefined), { forwardSecret: false, reason: "no-bundle", total: 0 });
    const badSig: PrekeyBundle = { ...bundle, sig: (bundle.sig![0] === "a" ? "b" : "a") + bundle.sig!.slice(1) };
    assert.deepEqual(outlook({}, badSig), { forwardSecret: false, reason: "bundle-not-verified", total: 0 });
    // Another org's bundle is not this recipient's.
    assert.deepEqual(outlook({}, bundle, "org_beta"), { forwardSecret: false, reason: "bundle-not-verified", total: 0 });
    // Outside the bundle's window.
    assert.deepEqual(outlook({}, bundle, "org_alpha", new Date("2031-01-01T00:00:00.000Z")), {
      forwardSecret: false,
      reason: "bundle-not-verified",
      total: 0,
    });
    // Not a bundle at all (corrupted storage): no throw.
    assert.deepEqual(outlook({}, { prekeys: 3 } as unknown as PrekeyBundle), {
      forwardSecret: false,
      reason: "bundle-not-verified",
      total: 0,
    });
    for (const r of ["no-bundle", "bundle-not-verified", "prekeys-exhausted", "prekey-unavailable"] as const) {
      assert.match(staticReasonText(r, "org_alpha"), /org_alpha/);
    }
  });

  it("drives sealTraveler: with the ledger, N seals spend N distinct prekeys and the next one falls back — across a reload", async () => {
    const N = 4;
    const bundle = bundleOf("org_alpha", Array.from({ length: N }, (_, i) => [`pk${i}`, 100 + i]));
    let ledger: PrekeyLedger = {};
    const spent: string[] = [];
    for (let i = 0; i < N; i++) {
      const r = await sealTraveler(sampleTraveler(), {
        directory,
        rootPublicKeyHex,
        recipientOrg: "org_alpha",
        prekeyBundle: bundle,
        excludePrekeyIds: usedPrekeyIds(ledger, bundle),
        at: AT,
      });
      assert.equal(r.forwardSecret, true);
      spent.push(r.prekeyId!);
      ledger = recordPrekeyUse(ledger, bundle, r.prekeyId!);
      // The desk persists the ledger; a reload reads it back.
      ledger = sanitizePrekeyLedger(JSON.parse(JSON.stringify(ledger)));
    }
    assert.equal(new Set(spent).size, N, "no prekey was sealed to twice");
    const next = await sealTraveler(sampleTraveler(), {
      directory,
      rootPublicKeyHex,
      recipientOrg: "org_alpha",
      prekeyBundle: bundle,
      excludePrekeyIds: usedPrekeyIds(ledger, bundle),
      at: AT,
    });
    assert.equal(next.forwardSecret, false);
    assert.equal(next.staticReason, "prekeys-exhausted");
  });
});
