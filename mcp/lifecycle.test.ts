/** The MCP tools take their lifecycle rules from the same guards as the desk, so two
 *  fixes there must hold over MCP as well:
 *   - a seller can re-quote after an amend (the one-quote rule counts only quotes bound
 *     to the current revision);
 *   - "locked" is the conformance level (L2+), nothing else — the report's `locked`
 *     flag and the amend refusal can no longer disagree with the reported level.
 */
import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "./server.ts";
import { amendMerge, parseTraveler } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";
import type { Quote, Traveler } from "../src/lib/traveler/types.ts";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };
type Report = {
  error?: string;
  traveler: Traveler;
  level: string;
  locked: boolean;
  revision: number;
  quote_id: string;
  bound_quotes: string[];
  stale_quotes: string[];
};

let client: Client;
let server: ReturnType<typeof buildServer>;

before(async () => {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  server = buildServer();
  await server.connect(st);
  client = new Client({ name: "lifecycle-test", version: "0.0.1" });
  await client.connect(ct);
});

after(async () => {
  await client.close();
  await server.close();
});

const call = async (name: string, args: Record<string, unknown>) => {
  const r = (await client.callTool({ name, arguments: args })) as ToolResult;
  return { isError: r.isError ?? false, ...(JSON.parse(r.content[0]!.text) as Report) };
};

const conformance = (file: string): Traveler =>
  parseTraveler(JSON.parse(readFileSync(new URL(`../conformance/travelers/${file}`, import.meta.url), "utf8")));

const SELLER = { org_id: "org_huron", name: "Huron Precision" };
const QUOTE_ARGS = {
  seller: SELLER,
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: { currency: "USD", lines: [{ qty: 250, unit: 1420 }] },
};
const SHIP = { name: "Dock 4", line1: "1800 Industrial Way", city: "Reno", region: "NV", postal: "89502", country: "US" };

describe("sje mcp lifecycle", () => {
  it("a seller can re-quote after sje_amend; the stale quote stays on the traveler", async () => {
    const l0 = conformance("l0-bracket.json");
    const quoted = await call("sje_quote", { traveler: l0, ...QUOTE_ARGS });
    assert.equal(quoted.isError, false, quoted.error);
    const amended = await call("sje_amend", { traveler: quoted.traveler, patch: { need_by: "2026-12-01" } });
    assert.equal(amended.isError, false, amended.error);
    assert.deepEqual(amended.stale_quotes, [quoted.quote_id]);

    const requoted = await call("sje_quote", {
      traveler: amended.traveler,
      ...QUOTE_ARGS,
      pricing: { currency: "USD", lines: [{ qty: 250, unit: 1500 }] },
    });
    assert.equal(requoted.isError, false, `same seller, new revision: ${requoted.error}`);
    assert.equal(requoted.level, "L1");
    assert.deepEqual(requoted.bound_quotes, [requoted.quote_id]);
    assert.deepEqual(requoted.stale_quotes, [quoted.quote_id]);

    // The rule itself still stands: one quote per seller on a given revision.
    const again = await call("sje_quote", { traveler: requoted.traveler, ...QUOTE_ARGS });
    assert.equal(again.isError, true);
    assert.match(again.error!, /already has a quote on this revision/);
  });

  it("reports locked exactly when the level is L2 or above", async () => {
    for (const file of ["l0-bracket.json", "l1-quoted.json", "l2-awarded.json"]) {
      const rep = await call("sje_validate", { traveler: conformance(file) });
      assert.equal(rep.locked, rep.level === "L2" || rep.level === "L3", `${file}: ${rep.level}`);
    }
    const l3 = await call("sje_validate", { traveler: { ...conformance("l2-awarded.json"), as_built: { lot: "A1" } } });
    assert.deepEqual([l3.level, l3.locked], ["L3", true]);
  });

  it("an award naming a stale quote is not a lock: the report says so and amend/quote go through", async () => {
    // Revision 2 of a traveler whose award still names a quote priced against
    // revision 1, with ops and a ship-to present — what a counterparty can hand back.
    const rev1 = conformance("l0-bracket.json");
    const stale: Quote = {
      quote_id: "qot_stale00001",
      seller: SELLER,
      traveler_hash_quoted: travelerHash(rev1),
      created_at: "2026-09-16T12:00:00.000Z",
      valid_until: "2039-01-01T00:00:00.000Z",
      lead_time_days: 21,
      pricing: { currency: "USD", lines: [{ qty: 250, unit: 1420 }] },
    };
    const rev2 = amendMerge({ ...rev1, quotes: [stale] }, { need_by: "2026-12-01" });
    const voidAward = parseTraveler({
      ...rev2,
      award: { quote_id: stale.quote_id, awarded_at: "2026-10-01T00:00:00.000Z", qty: 250 },
      ops: [{ seq: 1, code: "MILL" }],
      ship_to: SHIP,
    });

    const rep = await call("sje_validate", { traveler: voidAward });
    // It used to answer level L0 *and* locked: true.
    assert.deepEqual([rep.level, rep.locked], ["L0", false]);

    const amended = await call("sje_amend", { traveler: voidAward, patch: { incoterms: "EXW" } });
    assert.equal(amended.isError, false, `was refused as "locked at L2" while reporting L0: ${amended.error}`);
    assert.equal(amended.revision, voidAward.revision + 1);
    assert.equal(amended.traveler.award ?? null, null, "the void award is dropped by the amend");

    const quoted = await call("sje_quote", { traveler: voidAward, ...QUOTE_ARGS, seller: { org_id: "org_cascade", name: "Cascade" } });
    assert.equal(quoted.isError, false, `was refused as executable: ${quoted.error}`);
    assert.deepEqual([quoted.level, quoted.locked], ["L1", false]);

    // A real L2 is still locked, for both.
    const l2 = conformance("l2-awarded.json");
    assert.equal((await call("sje_amend", { traveler: l2, patch: { incoterms: "EXW" } })).isError, true);
    const refused = await call("sje_quote", { traveler: l2, ...QUOTE_ARGS, seller: { org_id: "org_cascade", name: "Cascade" } });
    assert.equal(refused.isError, true);
    assert.match(refused.error!, /Executable travelers cannot take new quotes/);
  });
});
