/** SJE agent-to-agent demo — two companies, two MCP desks, one sealed job.
 *
 *  Northline Equipment (buyer) and Summit Fabrication (seller) each run
 *  their OWN sje MCP server (separate processes, stdio — no shared
 *  database, no shared memory). The only thing that crosses the company
 *  boundary is the sealed archive, exactly as the protocol intends.
 *
 *  The demo narrates every exchange, proves the hash lineage at each hop,
 *  and demonstrates the defense: a tampered archive is refused on open.
 *
 *  Run: npm run demo
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import assert from "node:assert/strict";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };

function payload(res: ToolResult): Record<string, unknown> {
  const text = res.content?.[0]?.text ?? "{}";
  return JSON.parse(text) as Record<string, unknown>;
}

async function desk(company: string): Promise<Client> {
  const client = new Client({ name: `${company}-agent`, version: "0.0.1" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: ["--experimental-strip-types", "mcp/server.ts"],
      env: { ...process.env, SJE_COMPANY: company },
      stderr: "ignore",
    }),
  );
  return client;
}

const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const note = (s: string) => console.log(`    ${s}`);

const buyer = await desk("northline");
const seller = await desk("summit-fab");

console.log("=== SJE demo: two desks, one sealed job (sje/0.0.1) ===");

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

step(2, "BUYER seals it — the only artifact that will cross company lines");
const sealed1 = payload(
  (await buyer.callTool({
    name: "sje_seal",
    arguments: { traveler: composed.traveler },
  })) as ToolResult,
);
note(`${sealed1.filename} (${sealed1.bytes} bytes)`);

step(3, "TRANSIT: a tampered copy is refused by the seller's desk");
const zipB64 = sealed1.zip_base64 as string;
const tampered = Buffer.from(zipB64, "base64");
tampered[Math.floor(tampered.length / 2)] ^= 0xff;
const tamperedRes = (await seller.callTool({
  name: "sje_open",
  arguments: { zip_base64: tampered.toString("base64") },
})) as ToolResult;
assert.ok(tamperedRes.isError, "tampered archive must be refused");
note(`refused: ${String(payload(tamperedRes).error).slice(0, 60)}…`);

step(4, "SELLER opens the genuine archive — full defensive import");
const opened = payload(
  (await seller.callTool({ name: "sje_open", arguments: { zip_base64: zipB64 } })) as ToolResult,
);
assert.equal(opened.traveler_hash, hash0, "hash survives the company boundary");
note(`verified ${String(opened.traveler_hash).slice(0, 22)}… — same body the buyer sealed`);

step(5, "SELLER quotes — binding hash computed from the traveler in hand");
const quoted = payload(
  (await seller.callTool({
    name: "sje_quote",
    arguments: {
      traveler: opened.traveler,
      seller: { org_id: "org_summitfab", name: "Summit Fabrication", city: "Sparks", region: "NV", certs: ["ISO 9001"] },
      valid_until: "2039-01-01T00:00:00.000Z",
      lead_time_days: 21,
      pricing: {
        currency: "USD",
        nre: 350,
        lines: [
          { qty: 100, unit: 18.5 },
          { qty: 250, unit: 14.2 },
          { qty: 500, unit: 11.75 },
        ],
      },
    },
  })) as ToolResult,
);
assert.equal(quoted.level, "L1");
note(`quote ${quoted.quote_id} bound · level ${quoted.level}`);

step(6, "SELLER seals and returns; BUYER opens and evaluates");
const sealed2 = payload(
  (await seller.callTool({ name: "sje_seal", arguments: { traveler: quoted.traveler } })) as ToolResult,
);
const back = payload(
  (await buyer.callTool({
    name: "sje_open",
    arguments: { zip_base64: sealed2.zip_base64 },
  })) as ToolResult,
);
const evald = payload(
  (await buyer.callTool({ name: "sje_evaluate", arguments: { traveler: back.traveler } })) as ToolResult,
);
const evalRow = (evald.evaluation as Array<Record<string, unknown>>)[0];
note(
  `bound quote from ${evalRow.seller}: $${evalRow.unit_at_target}/pc at target, ${evalRow.lead_time_days}d lead, blocker: ${evalRow.award_blocker ?? "none"}`,
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

step(8, "BUYER seals the executable traveler; SELLER verifies the final state");
const sealed3 = payload(
  (await buyer.callTool({ name: "sje_seal", arguments: { traveler: awarded.traveler } })) as ToolResult,
);
const final = payload(
  (await seller.callTool({
    name: "sje_open",
    arguments: { zip_base64: sealed3.zip_base64 },
  })) as ToolResult,
);
assert.equal(final.level, "L2");
assert.equal(final.awarded_quote, quoted.quote_id);
assert.equal(final.traveler_hash, quoted.traveler_hash, "quoteable body unchanged through award");
note(`seller sees L2, award on ${final.awarded_quote}, body hash ${String(final.traveler_hash).slice(0, 22)}… unchanged`);

step(9, "Amend-after-lock is refused on either desk");
const amendRes = (await buyer.callTool({
  name: "sje_amend",
  arguments: { traveler: awarded.traveler, patch: { need_by: "2027-01-01" } },
})) as ToolResult;
assert.ok(amendRes.isError, "locked traveler must refuse amendment");
note(`refused: ${payload(amendRes).error}`);

console.log(
  "\n=== DONE — RFQ → quote → award, two agents, two desks, zero shared state; every hop hash-verified; tamper refused; L2 locked. ===",
);
await buyer.close();
await seller.close();
