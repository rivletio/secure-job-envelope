import "./style.css";
import { $, Out, Steps, sleep, short, registerSW } from "./ui.ts";
import { keypairFromSeed } from "../../src/lib/traveler/signature.ts";
import { createIdentity, unlock } from "../../src/lib/traveler/keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../../src/lib/traveler/directory.ts";
import {
  signPrekeyBundle,
  PREKEY_BUNDLE_SPEC,
  type PrekeyBundle,
} from "../../src/lib/traveler/prekeys.ts";
import { sealTraveler, openTraveler } from "../../src/lib/traveler/transport.ts";
import type { FsEnvelope } from "../../src/lib/traveler/envelope.ts";
import { parseTraveler } from "../../src/lib/traveler/conformance.ts";
import { bytesToHex } from "../../src/lib/traveler/bytes.ts";

registerSW();

const out = new Out($("#out"));
const runBtn = $("#run") as HTMLButtonElement;
const steps = new Steps($("#steps"), [
  { t: "Identities", d: "two desks mint ML-KEM keystores" },
  { t: "Directory", d: "publish a signed directory + prekey bundle" },
  { t: "Seal", d: "encrypt the traveler to the seller" },
  { t: "Ciphertext", d: "nothing about the job leaks in the clear" },
  { t: "Open", d: "the seller decrypts it" },
  { t: "Attacks", d: "tamper, wrong key, prekey-burn, downgrade" },
]);

const PASS_B = "buyer desk passphrase";
const PASS_S = "seller desk passphrase";
const W = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2030-01-01T00:00:00.000Z" };
const must = (cond: boolean, msg: string) => {
  if (!cond) throw new Error(msg);
};
const flip = (hex: string) => (hex[0] === "a" ? "b" : "a") + hex.slice(1);

const traveler = parseTraveler({
  spec: "sje/0.1.0",
  traveler_id: "tvl_webdemo01",
  revision: 1,
  created_at: "2026-10-01T00:00:00.000Z",
  buyer: { org_id: "org_northline", name: "Northline Equipment", city: "Reno", region: "NV" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6", form: "plate", thickness_mm: 6.35 },
    qty: { target: 250, breaks: [100, 250, 500] },
    processes: ["laser", "cnc-mill", "deburr"],
  },
  need_by: "2026-12-01",
  incoterms: "FOB",
  itar: false,
});

async function rejects(fn: () => Promise<unknown>, label: string) {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  out.line(threw ? `    refused: ${label} ✓` : `    NOT refused: ${label}`, threw ? "ok" : "no");
  if (!threw) throw new Error(`expected rejection: ${label}`);
}

async function run() {
  runBtn.disabled = true;
  runBtn.textContent = "Running…";
  steps.reset();
  out.clear();

  // 1 — identities (ML-KEM keygen + scrypt; the slow part)
  steps.on(0);
  out.line("[1] Two desks mint post-quantum identities (ML-KEM + scrypt)…", "hl");
  await sleep(30);
  const root = keypairFromSeed(new Uint8Array(32).fill(1));
  const rootHex = bytesToHex(root.publicKey);
  const buyer = await createIdentity({ passphrase: PASS_B, orgId: "org_northline" });
  const seller = await createIdentity({ passphrase: PASS_S, orgId: "org_summitfab" });
  out.line(
    `    buyer kid ${buyer.directoryEntry.kid} · seller kid ${seller.directoryEntry.kid}`,
    "k",
  );
  out.line(`    trust root ${short(rootHex, 22)} (verify out of band)`, "k");
  steps.done(0);
  await sleep(300);

  // 2 — signed directory + the seller's prekey bundle
  steps.on(1);
  out.line("[2] Publish a signed directory and the seller's prekey bundle", "hl");
  const bSign = keypairFromSeed(new Uint8Array(32).fill(2));
  const sSign = keypairFromSeed(new Uint8Array(32).fill(3));
  const dirBody: Directory = {
    spec: DIRECTORY_SPEC,
    ...W,
    root_kid: "root-2026",
    entries: [
      {
        org_id: "org_northline",
        kid: "northline-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(bSign.publicKey),
        valid_from: W.issued_at,
        valid_until: W.valid_until,
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: buyer.directoryEntry.enc_public_key,
      },
      {
        org_id: "org_summitfab",
        kid: "summit-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(sSign.publicKey),
        valid_from: W.issued_at,
        valid_until: W.valid_until,
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: seller.directoryEntry.enc_public_key,
      },
    ],
  };
  const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };
  const sellerDesk = await unlock(seller.keystore, PASS_S);
  const { prekeys } = sellerDesk.addPrekeys(2);
  const bundle: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: "org_summitfab",
    kid: "summit-2026",
    enc_alg: "ML-KEM-1024",
    ...W,
    prekeys,
  };
  bundle.sig = signPrekeyBundle(bundle, sSign.secretKey);
  out.line(`    2 orgs · seller published ${prekeys.length} one-time prekeys`, "k");
  steps.done(1);
  await sleep(300);

  // 3 — seal forward-secret
  steps.on(2);
  out.line("[3] Buyer seals the traveler to the seller (forward-secret)", "hl");
  const { envelope, forwardSecret } = await sealTraveler(traveler, {
    directory,
    rootPublicKeyHex: rootHex,
    recipientOrg: "org_summitfab",
    prekeyBundle: bundle,
    prekeyId: prekeys[0]!.prekey_id,
  });
  must(forwardSecret, "expected forward secrecy");
  out.line(`    ${envelope.spec} · forward_secret=${forwardSecret}`, "ok");
  steps.done(2);
  await sleep(300);

  // 4 — ciphertext proof
  steps.on(3);
  out.line("[4] The .sje is ciphertext — nothing about the job leaks", "hl");
  const wire = JSON.stringify(envelope);
  must(
    !wire.includes(traveler.traveler_id) &&
      !wire.includes(traveler.buyer.name) &&
      !wire.includes(traveler.part.part_number),
    "plaintext leaked into the envelope",
  );
  out.line("    no traveler_id / buyer / part_number in the clear ✓", "ok");
  out.line(`    payload ${envelope.payload.slice(0, 68)}…`, "k");
  steps.done(3);
  await sleep(300);

  // 5 — open
  steps.on(4);
  out.line("[5] Seller unlocks its keystore and opens the envelope", "hl");
  const opened = await openTraveler(envelope, sellerDesk);
  must(opened.traveler_id === traveler.traveler_id, "round-trip mismatch");
  out.line(`    decrypted ${opened.part.family} · ${opened.part.part_number} ✓`, "ok");
  steps.done(4);
  await sleep(300);

  // 6 — attacks
  steps.on(5);
  out.line("[6] Attacks the transport refuses", "hl");
  await rejects(
    () => openTraveler({ ...envelope, payload: flip(envelope.payload) } as FsEnvelope, sellerDesk),
    "a one-byte ciphertext flip",
  );
  const buyerDesk = await unlock(buyer.keystore, PASS_B);
  await rejects(() => openTraveler(envelope, buyerDesk), "the wrong desk's keystore");
  const otherId = prekeys[1]!.prekey_id;
  const sealOther = () =>
    sealTraveler(traveler, {
      directory,
      rootPublicKeyHex: rootHex,
      recipientOrg: "org_summitfab",
      prekeyBundle: bundle,
      prekeyId: otherId,
    });
  const legit = (await sealOther()).envelope as FsEnvelope;
  await rejects(
    () => openTraveler({ ...legit, payload: flip(legit.payload) } as FsEnvelope, sellerDesk),
    "a forged envelope naming a real prekey",
  );
  const reopened = await openTraveler((await sealOther()).envelope, sellerDesk);
  must(reopened.traveler_id === traveler.traveler_id, "the prekey was wrongly burned");
  out.line("    …and the prekey survived — a genuine envelope to it still opens ✓", "ok");
  await rejects(
    () =>
      sealTraveler(traveler, {
        directory,
        rootPublicKeyHex: rootHex,
        recipientOrg: "org_summitfab",
        requireForwardSecret: true,
      }),
    "a silent downgrade (requireForwardSecret)",
  );
  steps.done(5);

  out.line("");
  out.line("Done — real post-quantum crypto, in your browser; every attack refused.", "ok");
  runBtn.disabled = false;
  runBtn.textContent = "Run again";
}

runBtn.addEventListener("click", () => {
  run().catch((e) => {
    out.line(`error: ${e instanceof Error ? e.message : String(e)}`, "no");
    runBtn.disabled = false;
    runBtn.textContent = "Run again";
  });
});
