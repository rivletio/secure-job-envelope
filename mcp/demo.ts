/** SJE agent-to-agent demo — two companies, two MCP desks, one ENCRYPTED job.
 *
 *  Northline Equipment (buyer) and Summit Fabrication (seller) each run
 *  their OWN sje MCP server (separate processes, stdio — no shared
 *  database, no shared memory). The only thing that crosses the company
 *  boundary is a sealed `.sje` envelope (ML-KEM-1024 + AES-256-GCM,
 *  post-quantum), addressed to the recipient's key from a signed directory.
 *
 *  What each party holds, and where it comes from:
 *
 *  - Each desk's OPERATOR pins the trust root in the server's environment
 *    (SJE_TRUST_ROOT) and points it at the signed directory (SJE_DIRECTORY_FILE).
 *    Neither is ever a tool argument: an agent cannot be talked into another root.
 *  - Each desk mints its decryption identity ON ITS OWN SERVER (`sje_identity`). The
 *    passphrase-encrypted keystore is written on the desk and never appears in a tool
 *    call; only the public directory entry leaves.
 *  - Each org's ML-DSA SIGNING key lives off the desk (here: in this script, playing
 *    the two companies' signing workstations). The MCP server holds no signing key.
 *
 *  The demo proves the exchange is confidential, integrity-protected and AUTHENTIC:
 *  the transit artifact carries none of the traveler's plaintext; a single flipped
 *  byte is refused on open by AEAD; a desk reports who signed what it opened; a body
 *  the seller rewrote is refused when the buyer says which body it meant; and an award
 *  that is not verified as the buyer's is refused until it is.
 *
 *  The root pinned here is the public DEMO root — the desks say so on every result.
 *
 *  Run: npm run demo
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signAward, signTraveler } from "../src/lib/traveler/authenticity.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import {
  signDirectory,
  DIRECTORY_SPEC,
  type Directory,
  type DirectoryEntry,
} from "../src/lib/traveler/directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";
import type { Traveler } from "../src/lib/traveler/types.ts";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };
type Json = Record<string, any>;

function payload(res: ToolResult): Json {
  const text = res.content?.[0]?.text ?? "{}";
  return JSON.parse(text) as Json;
}
/** Call a tool that must succeed. */
async function tool(desk: Client, name: string, args: Json): Promise<Json> {
  const res = (await desk.callTool({ name, arguments: args })) as ToolResult;
  assert.ok(!res.isError, `${name} failed: ${res.content?.[0]?.text}`);
  return payload(res);
}
/** Call a tool that must be refused; returns the refusal. */
async function refusal(desk: Client, name: string, args: Json): Promise<Json> {
  const res = (await desk.callTool({ name, arguments: args })) as ToolResult;
  assert.ok(res.isError, `${name} must be refused`);
  return payload(res);
}

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);
const dollars = (cents: number) => `$${(cents / 100).toFixed(2)}`;

/* ---- What the OPERATORS set up: a pinned root, a directory file, a keystore path ---- */
// Demo-only passphrase (>= 12 chars). A real operator supplies a real secret, in the
// server's environment — never through a tool call.
const PASS = "demo-keystore-passphrase";
const workdir = mkdtempSync(join(tmpdir(), "sje-demo-"));
const directoryFile = join(workdir, "directory.json");

// The DEMO trust root (the same seed as src/lib/traveler/demo-trust.ts). Its secret key
// is public — which is why both desks flag every verdict under it.
const root = keypairFromSeed(new Uint8Array(32).fill(1));
const rootPublicKeyHex = bytesToHex(root.publicKey);

// Each org's ML-DSA signing key. These never go near an MCP server.
const BUYER_ORG = "org_northline";
const SELLER_ORG = "org_summitfab";
const BUYER_KID = "northline-2026";
const SELLER_KID = "summit-2026";
const buyerSigner = keypairFromSeed(new Uint8Array(32).fill(2));
const sellerSigner = keypairFromSeed(new Uint8Array(32).fill(3));
const WINDOW = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2030-01-01T00:00:00.000Z" };

async function desk(company: string, keystoreName: string): Promise<Client> {
  // The operator's settings, and nothing else that starts with SJE_.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("SJE_")) env[k] = v;
  }
  const client = new Client({ name: `${company}-agent`, version: "0.1.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: ["--experimental-strip-types", "mcp/server.ts"],
      env: {
        ...env,
        SJE_COMPANY: company,
        // Where this desk's keystore will be minted, and the passphrase that protects
        // it at rest. Both stay on the desk.
        SJE_KEYSTORE: join(workdir, keystoreName),
        SJE_KEYSTORE_PASSPHRASE: PASS,
        // The trust root this desk's operator pinned, and the directory it publishes.
        SJE_TRUST_ROOT: rootPublicKeyHex,
        SJE_DIRECTORY_FILE: directoryFile,
      },
      stderr: "ignore",
    }),
  );
  return client;
}

/** Seal `traveler` from one desk to a recipient org, asserting the transit
 *  artifact is genuine ciphertext (no plaintext field values leak). */
async function sealTo(from: Client, traveler: Json, recipientOrg: string, extra: Json = {}) {
  const sealed = await tool(from, "sje_seal", { traveler, recipient_org: recipientOrg, ...extra });
  const wire = JSON.stringify(sealed.sje);
  const part = traveler.part as { part_number?: string } | undefined;
  const who = traveler.buyer as { name?: string } | undefined;
  assert.ok(!wire.includes(String(traveler.traveler_id)), "traveler_id must not travel in the clear");
  if (part?.part_number) assert.ok(!wire.includes(part.part_number), "part number must not travel in the clear");
  if (who?.name) assert.ok(!wire.includes(who.name), "buyer name must not travel in the clear");
  assert.equal(sealed.recipient_org, recipientOrg);
  assert.equal(sealed.directory_source, "operator", "the recipient's key came from the operator's directory");
  return sealed;
}

const buyer = await desk("northline", "northline.keystore.json");
const seller = await desk("summit-fab", "summit.keystore.json");

try {
  console.log("=== SJE demo: two desks, one ENCRYPTED, AUTHENTICATED job ===");

  step(0, "Each desk mints its identity ON ITS SERVER; the directory's operator enrolls both");
  const buyerId = await tool(buyer, "sje_identity", { org_id: BUYER_ORG });
  const sellerId = await tool(seller, "sje_identity", { org_id: SELLER_ORG, prekeys: 2 });
  assert.deepEqual(Object.keys(buyerId), ["directory_entry"], "public material only: no keystore, no passphrase");
  assert.deepEqual(Object.keys(sellerId).sort(), ["directory_entry", "prekeys"]);
  const again = await refusal(seller, "sje_identity", { org_id: SELLER_ORG });
  assert.match(String(again.error), /never overwrites/);
  note("keystores written on each desk (mode 0600); only public keys came back");
  note(`a second mint is refused: ${String(again.error).replace(/^sje_identity: refused\. /, "").slice(0, 76)}…`);

  // The directory operator (holder of the root key) binds each org to its signing key
  // and to the encryption key its desk just minted, signs the directory, publishes it.
  const entry = (org_id: string, kid: string, signer: Uint8Array, id: Json): DirectoryEntry => ({
    org_id,
    kid,
    alg: "ML-DSA-87",
    public_key: bytesToHex(signer),
    valid_from: WINDOW.issued_at,
    valid_until: WINDOW.valid_until,
    status: "active",
    enc_alg: "ML-KEM-1024",
    enc_public_key: id.directory_entry.enc_public_key as string,
  });
  const dirBody: Directory = {
    spec: DIRECTORY_SPEC,
    ...WINDOW,
    root_kid: "root-demo",
    entries: [
      entry(BUYER_ORG, BUYER_KID, buyerSigner.publicKey, buyerId),
      entry(SELLER_ORG, SELLER_KID, sellerSigner.publicKey, sellerId),
    ],
  };
  const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };
  writeFileSync(directoryFile, JSON.stringify(directory));
  // Summit publishes its one-time prekeys in a bundle signed with ITS org key.
  const bundleBody: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: SELLER_ORG,
    kid: SELLER_KID,
    enc_alg: "ML-KEM-1024",
    ...WINDOW,
    prekeys: sellerId.prekeys as PrekeyBundle["prekeys"],
  };
  const sellerBundle: PrekeyBundle = {
    ...bundleBody,
    sig: signPrekeyBundle(bundleBody, sellerSigner.secretKey),
  };
  note("directory signed by the root and published; each desk re-reads it on its next call");

  step(1, "BUYER composes a traveler (CNC bracket, 250 pcs)");
  const composed = await tool(buyer, "sje_compose", {
    buyer: {
      org_id: BUYER_ORG,
      name: "Northline Equipment",
      city: "Reno",
      region: "NV",
      contact: "buyer@northline.example",
    },
    part: {
      family: "CNC bracket",
      part_number: "NL-BRK-4410",
      description: "Mounting bracket, brushed, deburred",
      drawing_rev: "C",
      material: { spec: "6061-T6", form: "plate", thickness_mm: 6.35 },
      qty: { target: 250, breaks: [100, 250, 500] },
      processes: ["laser", "cnc-mill", "deburr"],
      finish: "brushed",
    },
    need_by: "2026-10-30",
    incoterms: "FOB",
    itar: false,
  });
  // The buyer keeps this hash. It is how the buyer's desk — which keeps no copy of
  // anything — will later tell "the body I wrote" from "a body someone sent back".
  const hash0 = composed.traveler_hash as string;
  note(`level ${composed.level} · ${hash0.slice(0, 22)}… — the buyer keeps this hash`);
  assert.equal(composed.level, "L0");

  step(2, "BUYER signs the RFQ with its org key (off the desk) and seals it to the seller, forward-secret");
  const rfq = parseTraveler(composed.traveler);
  const signedRfq: Traveler = {
    ...rfq,
    signatures: [signTraveler(rfq, BUYER_KID, buyerSigner.secretKey)],
  };
  const sealed1 = await sealTo(buyer, signedRfq, SELLER_ORG, {
    prekey_bundle: sellerBundle,
    require_forward_secret: true,
    expected_traveler_hash: hash0,
  });
  assert.equal(sealed1.forward_secret, true);
  assert.equal(sealed1.demo_anchor, true);
  note(`${sealed1.spec} · to ${sealed1.recipient_org} key ${sealed1.recipient_kid} · forward_secret=${sealed1.forward_secret}`);
  note(`trust root ${sealed1.trust_root_fingerprint} — DEMO ANCHOR: ${String(sealed1.demo_anchor_warning).slice(0, 58)}…`);

  step(3, "TRANSIT: a single flipped byte is refused by the seller's desk (AEAD)");
  const env1 = sealed1.sje as { payload: string };
  const tamperedEnv = {
    ...(sealed1.sje as object),
    payload: (env1.payload[0] === "a" ? "b" : "a") + env1.payload.slice(1),
  };
  const tampered = await refusal(seller, "sje_open", { sje: tamperedEnv });
  note(`refused: ${String(tampered.error).slice(0, 72)}…`);

  step(4, "SELLER opens the genuine envelope — full defensive import, and WHO SIGNED IT");
  const opened = await tool(seller, "sje_open", { sje: sealed1.sje, expected_buyer_org: BUYER_ORG });
  assert.equal(opened.traveler_hash, hash0, "hash survives the encrypted boundary");
  assert.equal(opened.authenticity.status, "verified");
  assert.equal(opened.authenticity.verified_buyer_org, BUYER_ORG);
  assert.equal(opened.authenticity.demo_anchor, true, "…under the demo root, and the desk says so");
  assert.equal(opened.forward_secret, true);
  note(
    `${String(opened.traveler_hash).slice(0, 22)}… · authenticity: ${opened.authenticity.status}, signed by ${opened.authenticity.verified_buyer_org} (key ${opened.authenticity.authorship[0].kid})`,
  );
  // The one-time prekey was spent when the traveler was admitted: it opens once.
  await refusal(seller, "sje_open", { sje: sealed1.sje });
  note("its one-time prekey is now spent: the same envelope cannot be opened again");

  step(5, "SELLER quotes — binding hash computed from the traveler in hand");
  const quoted = await tool(seller, "sje_quote", {
    traveler: opened.traveler,
    expected_traveler_hash: hash0,
    seller: {
      org_id: SELLER_ORG,
      name: "Summit Fabrication",
      city: "Sparks",
      region: "NV",
      certs: ["ISO 9001"],
    },
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: {
      currency: "USD",
      nre: 35000,
      lines: [
        { qty: 100, unit: 1850 },
        { qty: 250, unit: 1420 },
        { qty: 500, unit: 1175 },
      ],
    },
  });
  assert.equal(quoted.level, "L1");
  note(`quote ${quoted.quote_id} bound · level ${quoted.level}`);

  step(6, "SELLER seals and returns; BUYER opens it as THE BODY IT WROTE, and evaluates the whole cost");
  const sealed2 = await sealTo(seller, quoted.traveler as Json, BUYER_ORG);
  assert.equal(sealed2.forward_secret, false);
  note(`${sealed2.spec} · forward_secret=false because ${sealed2.not_forward_secret_because}`);
  const back = await tool(buyer, "sje_open", { sje: sealed2.sje, expected_traveler_hash: hash0 });
  const evald = await tool(buyer, "sje_evaluate", { traveler: back.traveler, expected_traveler_hash: hash0 });
  const row = (evald.evaluation as Json[])[0]!;
  assert.equal(row.bound_to_current_revision, true);
  assert.equal(row.award_blocker, null);
  assert.equal(row.total_at_target.total, 250 * 1420 + 35000);
  note(
    `bound quote ${row.quote_id}: ${dollars(row.total_at_target.unit)}/pc x ${row.total_at_target.qty} + NRE ${dollars(row.total_at_target.nre)} = ${dollars(row.total_at_target.total)} ${row.currency}, ${row.lead_time_days}d lead, blocker: ${row.award_blocker ?? "none"}`,
  );

  step(7, "A DISHONEST seller rewrites the part and quotes THAT — the buyer's desk refuses to award it");
  const rewritten = structuredClone(opened.traveler) as Json;
  rewritten.part.material = { spec: "A36" }; // cheaper steel
  rewritten.part.qty = { target: 2500 }; // ten times the pieces
  delete rewritten.signatures; // the buyer's signature would no longer verify
  const swapped = await tool(seller, "sje_quote", {
    traveler: rewritten,
    seller: { org_id: SELLER_ORG, name: "Summit Fabrication" },
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: { currency: "USD", lines: [{ qty: 2500, unit: 1420 }] },
  });
  assert.equal(swapped.level, "L1", "the binding is honest: it binds the seller's body");
  assert.equal(swapped.traveler_id, composed.traveler_id, "same traveler_id, same revision");
  const notMine = await refusal(buyer, "sje_award", {
    traveler: swapped.traveler,
    expected_traveler_hash: hash0,
    quote_id: swapped.quote_id,
    qty: 2500,
    ops: [{ seq: 1, code: "laser" }],
    ship_to: { name: "Dock 4", line1: "1800 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" },
  });
  assert.match(String(notMine.error), /not the document expected/);
  assert.equal(notMine.expected_traveler_hash, hash0);
  note(
    `refused: not the document expected — its hash is ${String(notMine.traveler_hash).slice(0, 22)}…, the buyer's is ${hash0.slice(0, 22)}…`,
  );

  step(8, "BUYER awards the genuine quote — ops traveler + ship-to; traveler locks at L2");
  const awarded = await tool(buyer, "sje_award", {
    traveler: back.traveler,
    expected_traveler_hash: hash0,
    quote_id: quoted.quote_id,
    qty: 250,
    ops: [
      { seq: 1, code: "laser" },
      { seq: 2, code: "cnc-mill" },
      { seq: 3, code: "deburr" },
    ],
    ship_to: {
      name: "Northline Equipment — Dock 4",
      line1: "1800 Industrial Way",
      city: "Reno",
      region: "NV",
      postal: "89502",
      country: "US",
    },
  });
  assert.equal(awarded.level, "L2");
  assert.equal(awarded.locked, true);
  assert.equal(awarded.award_signed, false);
  note(
    `level ${awarded.level} · locked — award commits to quote ${awarded.award_commits_to.quote_id} at ${dollars(awarded.award_commits_to.total)} (not yet signed)`,
  );

  step(9, "BUYER seals the award UNSIGNED — the SELLER's desk refuses an award it cannot verify");
  const sealed3 = await sealTo(buyer, awarded.traveler as Json, SELLER_ORG);
  const unverified = await refusal(seller, "sje_open", { sje: sealed3.sje });
  assert.match(String(unverified.error), /refused by default/);
  assert.equal(unverified.traveler, undefined, "a refused document is not released");
  assert.equal(unverified.authenticity.award.reason, "award is present but not signed by the buyer");
  note(`refused: ${String((unverified.acknowledge as string[])[0]).slice(0, 78)}…`);

  step(10, "BUYER signs the award with its org key; SELLER opens it: the award is the buyer's");
  const awardedDoc = parseTraveler(awarded.traveler);
  const signedAward: Traveler = {
    ...awardedDoc,
    award: { ...awardedDoc.award!, sig: signAward(awardedDoc, BUYER_KID, buyerSigner.secretKey) },
  };
  const sealed4 = await sealTo(buyer, signedAward, SELLER_ORG);
  const final = await tool(seller, "sje_open", {
    sje: sealed4.sje,
    expected_traveler_hash: hash0,
    expected_buyer_org: BUYER_ORG,
  });
  assert.equal(final.level, "L2");
  assert.equal(final.awarded_quote, quoted.quote_id);
  assert.equal(final.traveler_hash, quoted.traveler_hash, "quoteable body unchanged through award");
  assert.equal(final.authenticity.status, "verified");
  assert.equal(final.authenticity.award.ok, true);
  assert.equal(final.authenticity.award.org_id, BUYER_ORG);
  assert.equal(final.unverified, undefined, "nothing was accepted without proof");
  note(
    `seller sees L2, award on ${final.awarded_quote} verified as ${final.authenticity.award.org_id}'s, body hash ${String(final.traveler_hash).slice(0, 22)}… unchanged`,
  );

  step(11, "Amend-after-lock is refused on either desk");
  const locked = await refusal(buyer, "sje_amend", {
    traveler: awarded.traveler,
    patch: { need_by: "2027-01-01" },
  });
  note(`refused: ${String(locked.error).replace(/^sje_amend: refused\. /, "").slice(0, 84)}…`);

  console.log(
    "\n=== DONE — RFQ → quote → award, two agents, two desks, zero shared state; every hop ENCRYPTED; a flipped byte refused; signatures verified against the operator-pinned root; a rewritten part refused; an unverified award refused; L2 locked. ===",
  );
} finally {
  await buyer.close();
  await seller.close();
  rmSync(workdir, { recursive: true, force: true });
}
