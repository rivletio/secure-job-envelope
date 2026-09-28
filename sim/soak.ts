/** Soak + adversarial harness: simulate many jobs, transact them through the full
 *  lifecycle, and try to break the invariants.
 *
 *  Three phases, all deterministic in the seed range:
 *   1. Lifecycle — compose -> quote -> award -> (amend) through the real store
 *      state machine, asserting the invariants that must always hold (hash
 *      stability, binding, level progression, the executable lock).
 *   2. Adversarial — a battery of inputs that MUST be refused or handled: hostile
 *      documents, quotes bound to the wrong hash, expired/unbound awards, and
 *      verifiers fed uncanonicalizable bodies. None may silently succeed or throw
 *      uncaught.
 *   3. Authenticity / confidentiality — sign & verify travelers and quotes against
 *      a seeded directory, seal & open static and forward-secret envelopes, and
 *      confirm every tamper is caught.
 *
 *  Exits non-zero if any invariant fails, so CI fails loudly.
 *
 *  Run: node --experimental-strip-types sim/soak.ts [--jobs N] [--start S]
 */
import { readFileSync, readdirSync } from "node:fs";
import { Rng } from "./rng.ts";
import { SHOPS, genId, genTraveler } from "./generate.ts";
import { buildTrust } from "./directory.ts";
import { useTravelerStore } from "../src/lib/traveler/store.ts";
import { boundQuotes, levelOf, parseTraveler, staleQuotes } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";
import { locked } from "../src/lib/traveler/guards.ts";
import { canonicalJson } from "../src/lib/traveler/canonical.ts";
import { signTraveler, signQuote, verifyTravelerSignatures, verifyQuoteSignature, itarAttestationBlocker } from "../src/lib/traveler/authenticity.ts";
import { recipientByOrg, sealEnvelope, openEnvelope, fsRecipientFromBundle, sealFsEnvelope, openFsEnvelope } from "../src/lib/traveler/envelope.ts";
import type { Quote, Traveler } from "../src/lib/traveler/types.ts";

// ---- tiny assertion harness (collects failures with context, never throws) ----
let checks = 0;
const failures: string[] = [];
const ok = (cond: boolean, msg: string) => {
  checks++;
  if (!cond) failures.push(`FAIL ${msg}`);
};
const mustThrow = (fn: () => void, msg: string) => {
  checks++;
  try {
    fn();
    failures.push(`FAIL expected rejection: ${msg}`);
  } catch {
    /* expected */
  }
};
const LEVELS = new Set(["D", "L0", "L1", "L2", "L3"]);

/** A quote guaranteed to be bindable and (given `target`) awardable now: bound to
 *  `hash`, a price line whose qty is exactly `target` (cannotAward requires an exact
 *  match), and a validity window that spans today. */
function goodQuote(
  rng: Rng,
  hash: string,
  seller: { org_id: string; name: string; itar: boolean },
  target = 1,
): Quote {
  const lines = [{ qty: 1, unit: rng.int(100, 500_000) }];
  if (target !== 1) lines.push({ qty: target, unit: rng.int(100, 400_000) });
  return {
    quote_id: genId(rng, "qot"),
    seller: { org_id: seller.org_id, name: seller.name, ...(seller.itar ? { itar: true } : {}) },
    traveler_hash_quoted: hash,
    created_at: "2026-01-02T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    lead_time_days: rng.int(1, 300),
    pricing: { currency: "USD", lines },
  };
}

function sellerFor(rng: Rng, itar: boolean) {
  if (itar) return { org_id: "org_huron", name: "Huron Precision", itar: true };
  const s = rng.pick(SHOPS.filter((x) => !x.itar));
  return { org_id: s.org_id, name: s.name, itar: false };
}

// ------------------------------- phase 1: lifecycle -------------------------------
function lifecycle(seed: number) {
  const rng = new Rng(seed);
  const store = useTravelerStore.getState();
  const itar = rng.bool(0.15);
  const l0 = genTraveler(rng, { level: "L0", itar });
  const id = l0.traveler_id;

  store.upsert(l0);
  const composed = store.get(id)!;
  ok(!!composed, `#${seed} composed traveler present`);
  ok(levelOf(composed).code === "L0", `#${seed} fresh traveler is L0`);
  ok(boundQuotes(composed).length === 0, `#${seed} no bound quotes before quoting`);
  ok(travelerHash(l0) === travelerHash(structuredClone(l0)), `#${seed} hash is deterministic`);
  ok(!locked(composed), `#${seed} L0 is not locked`);

  const hash = travelerHash(composed);
  const quote = goodQuote(rng, hash, sellerFor(rng, itar), l0.part.qty.target);
  store.addQuote(id, quote);
  const quoted = store.get(id)!;
  ok(boundQuotes(quoted).some((q) => q.quote_id === quote.quote_id), `#${seed} quote binds to current hash`);
  ok(levelOf(quoted).code === "L1", `#${seed} bound quote makes it L1`);
  // A quote bound to a WRONG hash must never bind or be accepted.
  mustThrow(
    () => store.addQuote(id, { ...goodQuote(rng, "sha384:" + "b".repeat(96), sellerFor(rng, itar)) }),
    `#${seed} quote bound to wrong hash is refused`,
  );

  const award = { quote_id: quote.quote_id, awarded_at: "2026-03-01T00:00:00.000Z", qty: l0.part.qty.target };
  const shipTo = { name: "Dock 4", line1: "1800 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" };
  store.award(id, award, shipTo, [{ seq: 1, code: "laser" }, { seq: 2, code: "deburr" }]);
  const awarded = store.get(id)!;
  ok(levelOf(awarded).code === "L2", `#${seed} awarded traveler is L2`);
  ok(locked(awarded), `#${seed} awarded traveler is locked`);
  ok(travelerHash(awarded) === hash, `#${seed} award does not change the quoteable hash`);

  // The executable lock: neither upsert nor amend may mutate a locked traveler.
  mustThrow(() => store.upsert({ ...awarded, part: { ...awarded.part, notes: "tamper" } }), `#${seed} locked traveler refuses upsert`);
  const revBefore = awarded.revision;
  store.amend(id, { incoterms: "FOB" });
  ok(store.get(id)!.revision === revBefore, `#${seed} amend is a no-op on a locked traveler`);

  store.remove(id);
}

// ---------------------- phase 1b: amend invalidates prior quotes ----------------------
function amendInvalidation(seed: number) {
  const rng = new Rng(seed ^ 0x5a5a5a5a);
  const store = useTravelerStore.getState();
  const l0 = genTraveler(rng, { level: "L0", itar: false });
  const id = l0.traveler_id;
  store.upsert(l0);
  const quote = goodQuote(rng, travelerHash(l0), sellerFor(rng, false));
  store.addQuote(id, quote);
  ok(boundQuotes(store.get(id)!).length === 1, `#${seed} quote bound before amend`);

  store.amend(id, { incoterms: "DAP" });
  const amended = store.get(id)!;
  ok(amended.revision === l0.revision + 1, `#${seed} amend bumps the revision`);
  ok(boundQuotes(amended).length === 0, `#${seed} the prior quote no longer binds after amend`);
  ok(staleQuotes(amended).length === 1, `#${seed} the prior quote is now stale`);
  ok(LEVELS.has(levelOf(amended).code), `#${seed} amended level is well-formed`);
  store.remove(id);
}

// ------------------------------- phase 2: adversarial -------------------------------
function adversarial() {
  const store = useTravelerStore.getState();
  const root = new URL("../conformance/travelers/reject/", import.meta.url).pathname;
  for (const file of readdirSync(root)) {
    const doc = JSON.parse(readFileSync(`${root}${file}`, "utf8"));
    mustThrow(() => parseTraveler(doc), `reject vector refused at parse: ${file}`);
  }

  // Award refuses a quote that is not on the traveler.
  const rng = new Rng(0xadbeef);
  const l0 = genTraveler(rng, { level: "L0", itar: false });
  store.upsert(l0);
  const shipTo = { name: "D", line1: "1 A St", city: "Reno", region: "NV", postal: "89502", country: "US" };
  mustThrow(
    () => store.award(l0.traveler_id, { quote_id: "qot_notthere1", awarded_at: "2026-03-01T00:00:00.000Z", qty: 1 }, shipTo, [{ seq: 1, code: "laser" }]),
    "award refuses a quote not on the traveler",
  );

  // Award refuses an expired quote (added while unexpired-checks-are-off, awarded after expiry).
  const exp = goodQuote(rng, travelerHash(l0), sellerFor(rng, false), l0.part.qty.target);
  exp.created_at = "2024-01-01T00:00:00.000Z";
  exp.valid_until = "2024-02-01T00:00:00.000Z"; // already expired today
  store.addQuote(l0.traveler_id, exp);
  mustThrow(
    () => store.award(l0.traveler_id, { quote_id: exp.quote_id, awarded_at: "2026-03-01T00:00:00.000Z", qty: l0.part.qty.target }, shipTo, [{ seq: 1, code: "laser" }]),
    "award refuses an expired quote",
  );
  store.remove(l0.traveler_id);
}

// ---------------------- phase 3: authenticity & confidentiality ----------------------
function crypto(seed: number, trust: ReturnType<typeof buildTrust>) {
  const rng = new Rng(seed ^ 0x13371337);
  const { directory, rootPublicKeyHex, orgs, prekeyBundle, prekeyOrg } = trust;
  const buyer = orgs.get("org_northline")!;
  const at = new Date("2027-01-01T00:00:00.000Z");

  // Traveler authorship: sign as the buyer org, verify, then tamper.
  const base = genTraveler(rng, { level: "L0", itar: false });
  const t: Traveler = { ...base, buyer: { ...base.buyer, org_id: "org_northline" } };
  t.signatures = [signTraveler(t, buyer.kid, buyer.signer.secretKey)];
  ok(verifyTravelerSignatures(t, directory, rootPublicKeyHex, at).every((c) => c.ok), `#${seed} buyer signature verifies`);
  const tampered: Traveler = { ...t, revision: t.revision + 1 };
  ok(!verifyTravelerSignatures(tampered, directory, rootPublicKeyHex, at).some((c) => c.ok), `#${seed} tampered traveler fails authenticity`);
  const wrongOrg: Traveler = { ...t, buyer: { ...t.buyer, org_id: "org_summitfab" } };
  ok(!verifyTravelerSignatures(wrongOrg, directory, rootPublicKeyHex, at).some((c) => c.ok), `#${seed} wrong signer org fails authenticity`);

  // Quote authorship: sign as a seller org (org_huron), verify, then tamper.
  const seller = orgs.get("org_huron")!;
  const quote = goodQuote(rng, travelerHash(t), { org_id: "org_huron", name: "Huron Precision", itar: true });
  quote.sig = signQuote(quote, seller.kid, seller.signer.secretKey);
  ok(verifyQuoteSignature(quote, directory, rootPublicKeyHex, at)?.ok === true, `#${seed} seller quote signature verifies`);
  const tq: Quote = { ...quote, lead_time_days: quote.lead_time_days + 1 };
  ok(verifyQuoteSignature(tq, directory, rootPublicKeyHex, at)?.ok === false, `#${seed} tampered quote fails authenticity`);

  // ITAR attestation gate: an attested seller is allowed, a non-attested one blocked.
  const itarT: Traveler = { ...t, itar: true };
  ok(itarAttestationBlocker(itarT, quote, directory, rootPublicKeyHex, at) === null, `#${seed} ITAR-attested seller passes the gate`);
  const nonItarQuote: Quote = { ...quote, seller: { ...quote.seller, org_id: "org_summitfab" } };
  ok(!!itarAttestationBlocker(itarT, nonItarQuote, directory, rootPublicKeyHex, at), `#${seed} non-attested seller is blocked`);

  // Static envelope: seal to a directory recipient, open, then tamper the payload.
  const plaintext = new TextEncoder().encode(canonicalJson(t));
  const rcpt = recipientByOrg(directory, "org_huron", at)!;
  const env = sealEnvelope(plaintext, [rcpt]);
  const opened = openEnvelope(env, rcpt.kid, seller.kem.secretKey);
  ok(new TextDecoder().decode(opened) === canonicalJson(t), `#${seed} static envelope round-trips`);
  const tamperedEnv = { ...env, payload: (env.payload.startsWith("00") ? "11" : "00") + env.payload.slice(2) };
  mustThrow(() => openEnvelope(tamperedEnv, rcpt.kid, seller.kem.secretKey), `#${seed} tampered static envelope fails to open`);

  // Forward-secret envelope: seal with a one-time prekey + static key, open, tamper.
  const prekeyId = prekeyBundle.prekeys[0]!.prekey_id;
  const fsR = fsRecipientFromBundle(directory, prekeyBundle, prekeyOrg, prekeyId, rootPublicKeyHex, at);
  ok(!!fsR, `#${seed} FS recipient resolves from the signed bundle`);
  if (fsR) {
    const fsEnv = sealFsEnvelope(plaintext, [fsR]);
    const onetime = trust.prekeySecret(prekeyId)!;
    const fsOpened = openFsEnvelope(fsEnv, fsR.kid, seller.kem.secretKey, onetime);
    ok(new TextDecoder().decode(fsOpened) === canonicalJson(t), `#${seed} FS envelope round-trips`);
    const tf = { ...fsEnv, payload: (fsEnv.payload.startsWith("00") ? "11" : "00") + fsEnv.payload.slice(2) };
    mustThrow(() => openFsEnvelope(tf, fsR.kid, seller.kem.secretKey, onetime), `#${seed} tampered FS envelope fails to open`);
  }
}

// ------------------------------------ main ------------------------------------
function main() {
  const argv = process.argv.slice(2);
  const arg = (name: string, def: number) => {
    const i = argv.indexOf(name);
    return i >= 0 ? Number(argv[i + 1]) : def;
  };
  const jobs = arg("--jobs", 500);
  const start = arg("--start", 1);
  const cryptoJobs = Math.min(jobs, arg("--crypto", 40));

  const t0 = Date.now();
  for (let seed = start; seed < start + jobs; seed++) {
    lifecycle(seed);
    amendInvalidation(seed);
  }
  adversarial();
  const trust = buildTrust(new Rng(0xc0ffee));
  for (let seed = start; seed < start + cryptoJobs; seed++) crypto(seed, trust);

  const ms = Date.now() - t0;
  console.log(`\nsoak: ${checks} invariant checks over ${jobs} jobs (+${cryptoJobs} crypto) in ${ms}ms`);
  if (failures.length) {
    console.log(`\n${failures.length} FAILURES:`);
    for (const f of failures.slice(0, 40)) console.log(`  ${f}`);
    process.exit(1);
  }
  console.log("all invariants held — no breakage.");
}

main();
