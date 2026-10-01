/** SJE agent-to-agent demo — two companies, two MCP desks, one ENCRYPTED job.
 *
 *  Northline Equipment (buyer) and Summit Fabrication (seller) each run
 *  their OWN sje MCP server (separate processes, stdio — no shared
 *  database, no shared memory). The only thing that crosses the company
 *  boundary is a sealed `.sje` envelope (ML-KEM-1024 + AES-256-GCM,
 *  post-quantum), addressed to the recipient's key from a signed directory.
 *
 *  The demo proves the exchange is confidential and integrity-protected:
 *  the transit artifact carries none of the traveler's plaintext, and a
 *  single flipped byte is refused on open by AEAD. Each desk decrypts with
 *  its own passphrase-encrypted keystore (loaded from an env passphrase),
 *  then runs the full defensive import and reports the same content hash.
 *
 *  Note on scope: the envelope gives the recipient CONFIDENTIALITY and
 *  INTEGRITY, not proof of SENDER identity — traveler/sender signatures are a
 *  later milestone. Sealing uses only public keys; opening uses the keystore
 *  secret, which never leaves the desk.
 *
 *  Run: npm run demo
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createIdentity } from "../src/lib/traveler/keystore.ts";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };

function payload(res: ToolResult): Record<string, unknown> {
  const text = res.content?.[0]?.text ?? "{}";
  return JSON.parse(text) as Record<string, unknown>;
}

async function desk(company: string, keystorePath: string, passphrase: string): Promise<Client> {
  const client = new Client({ name: `${company}-agent`, version: "0.1.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: ["--experimental-strip-types", "mcp/server.ts"],
      // The desk unlocks its decryption keystore from these two env vars. The
      // passphrase stays on the desk; the keystore file is encrypted at rest.
      env: {
        ...process.env,
        SJE_COMPANY: company,
        SJE_KEYSTORE: keystorePath,
        SJE_KEYSTORE_PASSPHRASE: passphrase,
      },
      stderr: "ignore",
    }),
  );
  return client;
}

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);

/* ---- Trust setup: a root, two keystores, one signed directory ---- */
// Demo-only passphrase (>= 12 chars). Real desks use a human-entered secret.
const PASS = "demo-keystore-passphrase";
const workdir = mkdtempSync(join(tmpdir(), "sje-demo-"));
const buyerKeystorePath = join(workdir, "northline.keystore.json");
const sellerKeystorePath = join(workdir, "summit.keystore.json");

const root = keypairFromSeed(new Uint8Array(32).fill(1));
const rootPublicKeyHex = bytesToHex(root.publicKey);

const buyerId = await createIdentity({ passphrase: PASS, orgId: "org_northline" });
const sellerId = await createIdentity({ passphrase: PASS, orgId: "org_summitfab" });
writeFileSync(buyerKeystorePath, JSON.stringify(buyerId.keystore));
writeFileSync(sellerKeystorePath, JSON.stringify(sellerId.keystore));

// A signed directory carrying both orgs' ENCRYPTION keys. The signing public
// keys are placeholders — this version seals/opens with ML-KEM and does not yet
// verify traveler signatures; the directory is used to resolve (and verify,
// against the root) the recipient's encryption key before sealing.
const buyerSigner = keypairFromSeed(new Uint8Array(32).fill(2));
const sellerSigner = keypairFromSeed(new Uint8Array(32).fill(3));
const dirBody: Directory = {
  spec: DIRECTORY_SPEC,
  issued_at: "2026-01-01T00:00:00.000Z",
  valid_until: "2030-01-01T00:00:00.000Z",
  root_kid: "root-2026",
  entries: [
    {
      org_id: "org_northline",
      kid: "northline-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(buyerSigner.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      enc_alg: "ML-KEM-1024",
      enc_public_key: buyerId.directoryEntry.enc_public_key,
    },
    {
      org_id: "org_summitfab",
      kid: "summit-2026",
      alg: "ML-DSA-87",
      public_key: bytesToHex(sellerSigner.publicKey),
      valid_from: "2026-01-01T00:00:00.000Z",
      valid_until: "2030-01-01T00:00:00.000Z",
      status: "active",
      enc_alg: "ML-KEM-1024",
      enc_public_key: sellerId.directoryEntry.enc_public_key,
    },
  ],
};
const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };

/** Seal `traveler` from one desk to a recipient org, asserting the transit
 *  artifact is genuine ciphertext (no plaintext field values leak). */
async function sealTo(from: Client, traveler: Record<string, unknown>, recipientOrg: string) {
  const sealed = payload(
    (await from.callTool({
      name: "sje_seal",
      arguments: { traveler, directory, root_public_key_hex: rootPublicKeyHex, recipient_org: recipientOrg },
    })) as ToolResult,
  );
  const wire = JSON.stringify(sealed.sje);
  const part = traveler.part as { part_number?: string } | undefined;
  const buyer = traveler.buyer as { name?: string } | undefined;
  assert.ok(!wire.includes(String(traveler.traveler_id)), "traveler_id must not travel in the clear");
  if (part?.part_number) assert.ok(!wire.includes(part.part_number), "part number must not travel in the clear");
  if (buyer?.name) assert.ok(!wire.includes(buyer.name), "buyer name must not travel in the clear");
  return sealed;
}

const buyer = await desk("northline", buyerKeystorePath, PASS);
const seller = await desk("summit-fab", sellerKeystorePath, PASS);

try {
  console.log("=== SJE demo: two desks, one ENCRYPTED job (sje-envelope/0.1.0) ===");
  note(`trust root: ${rootPublicKeyHex.slice(0, 22)}… (verify this out-of-band)`);

  step(1, "BUYER composes a traveler (CNC bracket, 250 pcs)");
  const composed = payload(
    (await buyer.callTool({
      name: "sje_compose",
      arguments: {
        buyer: {
          org_id: "org_northline",
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
      },
    })) as ToolResult,
  );
  const hash0 = composed.traveler_hash as string;
  note(`level ${composed.level} · ${hash0.slice(0, 22)}…`);
  assert.equal(composed.level, "L0");

  step(2, "BUYER seals it to the seller — the only artifact that crosses company lines, now ciphertext");
  const sealed1 = await sealTo(buyer, composed.traveler as Record<string, unknown>, "org_summitfab");
  note(
    `${sealed1.spec} · forward_secret=${sealed1.forward_secret} · ${sealed1.recipients} recipient — no plaintext leaks`,
  );
  assert.equal(sealed1.forward_secret, false, "static path in this version (no prekey bundle)");

  step(3, "TRANSIT: a single flipped byte is refused by the seller's desk (AEAD)");
  const env1 = sealed1.sje as { payload: string };
  const tamperedEnv = { ...(sealed1.sje as object), payload: (env1.payload[0] === "a" ? "b" : "a") + env1.payload.slice(1) };
  const tamperedRes = (await seller.callTool({
    name: "sje_open",
    arguments: { sje: tamperedEnv },
  })) as ToolResult;
  assert.ok(tamperedRes.isError, "tampered envelope must be refused");
  note(`refused: ${String(payload(tamperedRes).error).slice(0, 72)}…`);

  step(4, "SELLER decrypts the genuine envelope with its keystore — full defensive import");
  const opened = payload(
    (await seller.callTool({ name: "sje_open", arguments: { sje: sealed1.sje } })) as ToolResult,
  );
  assert.equal(opened.traveler_hash, hash0, "hash survives the encrypted boundary");
  note(`decrypted & verified ${String(opened.traveler_hash).slice(0, 22)}… — same body the buyer sealed`);

  step(5, "SELLER quotes — binding hash computed from the traveler in hand");
  const quoted = payload(
    (await seller.callTool({
      name: "sje_quote",
      arguments: {
        traveler: opened.traveler,
        seller: {
          org_id: "org_summitfab",
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
      },
    })) as ToolResult,
  );
  assert.equal(quoted.level, "L1");
  note(`quote ${quoted.quote_id} bound · level ${quoted.level}`);

  step(6, "SELLER seals and returns (encrypted to the buyer); BUYER decrypts and evaluates");
  const sealed2 = await sealTo(seller, quoted.traveler as Record<string, unknown>, "org_northline");
  const back = payload(
    (await buyer.callTool({ name: "sje_open", arguments: { sje: sealed2.sje } })) as ToolResult,
  );
  const evald = payload(
    (await buyer.callTool({
      name: "sje_evaluate",
      arguments: { traveler: back.traveler },
    })) as ToolResult,
  );
  const evalRow = (evald.evaluation as Array<Record<string, unknown>>)[0];
  note(
    `bound quote from ${evalRow.seller}: $${(Number(evalRow.unit_at_target) / 100).toFixed(2)}/pc at target, ${evalRow.lead_time_days}d lead, blocker: ${evalRow.award_blocker ?? "none"}`,
  );
  assert.equal(evalRow.award_blocker, null);

  step(7, "BUYER awards — ops traveler + ship-to; traveler locks at L2");
  const awarded = payload(
    (await buyer.callTool({
      name: "sje_award",
      arguments: {
        traveler: back.traveler,
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
      },
    })) as ToolResult,
  );
  assert.equal(awarded.level, "L2");
  assert.equal(awarded.locked, true);
  note(`level ${awarded.level} · locked — award bound to quote ${awarded.awarded_quote}`);

  step(8, "BUYER seals the executable traveler (encrypted); SELLER decrypts the final state");
  const sealed3 = await sealTo(buyer, awarded.traveler as Record<string, unknown>, "org_summitfab");
  const final = payload(
    (await seller.callTool({ name: "sje_open", arguments: { sje: sealed3.sje } })) as ToolResult,
  );
  assert.equal(final.level, "L2");
  assert.equal(final.awarded_quote, quoted.quote_id);
  assert.equal(final.traveler_hash, quoted.traveler_hash, "quoteable body unchanged through award");
  note(
    `seller sees L2, award on ${final.awarded_quote}, body hash ${String(final.traveler_hash).slice(0, 22)}… unchanged`,
  );

  step(9, "Amend-after-lock is refused on either desk");
  const amendRes = (await buyer.callTool({
    name: "sje_amend",
    arguments: { traveler: awarded.traveler, patch: { need_by: "2027-01-01" } },
  })) as ToolResult;
  assert.ok(amendRes.isError, "locked traveler must refuse amendment");
  note(`refused: ${payload(amendRes).error}`);

  console.log(
    "\n=== DONE — RFQ → quote → award, two agents, two desks, zero shared state; every hop ENCRYPTED (ciphertext on the wire); a flipped byte refused; L2 locked. ===",
  );
} finally {
  await buyer.close();
  await seller.close();
  rmSync(workdir, { recursive: true, force: true });
}
