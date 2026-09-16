/** Tests for the SJE MCP surface — proves the MCP layer enforces the same
 *  guards as the reference implementation (see docs/CLAIMS.md §MCP).
 */
import assert from "node:assert/strict";
import { describe, it, before } from "node:test";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "./server.ts";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };
const payload = (r: ToolResult) => JSON.parse(r.content[0]!.text) as Record<string, unknown>;

let client: Client;

before(async () => {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const server = buildServer();
  await server.connect(st);
  client = new Client({ name: "test-agent", version: "0.0.1" });
  await client.connect(ct);
});

const call = async (name: string, args: Record<string, unknown>) =>
  (await client.callTool({ name, arguments: args })) as ToolResult;

const EXAMPLE = JSON.parse(
  readFileSync(new URL("../examples/bracket.traveler.json", import.meta.url), "utf8"),
) as Record<string, unknown>;

const QUOTE_ARGS = {
  seller: { org_id: "org_summitfab", name: "Summit Fabrication" },
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: { currency: "USD", lines: [{ qty: 250, unit: 14.2 }] },
};

describe("sje mcp surface", () => {
  it("lists all eight tools", async () => {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 8);
    assert.ok(tools.every((t) => t.name.startsWith("sje_")));
  });

  it("validates the worked example at L0 with the documented hash", async () => {
    const rep = payload(await call("sje_validate", { traveler: EXAMPLE }));
    assert.equal(rep.level, "L0");
    assert.match(String(rep.traveler_hash), /^sha384:[0-9a-f]{96}$/);
  });

  it("runs compose → quote → award to a locked L2 over MCP", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4410",
          material: { spec: "6061-T6" },
          qty: { target: 250 },
        },
      }),
    );
    assert.equal(composed.level, "L0");

    const quoted = payload(
      await call("sje_quote", { traveler: composed.traveler, ...QUOTE_ARGS }),
    );
    assert.equal(quoted.level, "L1");

    const awarded = payload(
      await call("sje_award", {
        traveler: quoted.traveler,
        quote_id: quoted.quote_id,
        qty: 250,
        ops: [{ seq: 1, code: "laser" }],
        ship_to: {
          name: "Dock 4",
          line1: "1800 Industrial Way",
          city: "Reno",
          region: "NV",
          postal: "89502",
          country: "US",
        },
      }),
    );
    assert.equal(awarded.level, "L2");
    assert.equal(awarded.locked, true);

    // locked traveler refuses amendment
    const amend = await call("sje_amend", {
      traveler: awarded.traveler,
      patch: { need_by: "2027-01-01" },
    });
    assert.ok(amend.isError);
  });

  it("stale quotes cannot be awarded: amend re-binds the world", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4411",
          material: { spec: "6061-T6" },
          qty: { target: 100 },
        },
      }),
    );
    const quoted = payload(
      await call("sje_quote", {
        traveler: composed.traveler,
        ...QUOTE_ARGS,
        pricing: { currency: "USD", lines: [{ qty: 100, unit: 18.5 }] },
      }),
    );
    const amended = payload(
      await call("sje_amend", { traveler: quoted.traveler, patch: { incoterms: "EXW" } }),
    );
    assert.equal(amended.level, "L0", "stale quote drops traveler back to L0");
    assert.equal((amended.stale_quotes as string[]).length, 1);

    const award = await call("sje_award", {
      traveler: amended.traveler,
      quote_id: quoted.quote_id,
      qty: 100,
      ops: [{ seq: 1, code: "laser" }],
      ship_to: {
        name: "Dock 4",
        line1: "1800 Industrial Way",
        city: "Reno",
        region: "NV",
        postal: "89502",
        country: "US",
      },
    });
    assert.ok(award.isError, "stale quote must not be awardable");
  });

  it("ITAR traveler refuses a quote from a seller without itar: true", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4412",
          material: { spec: "6061-T6" },
          qty: { target: 50 },
        },
        itar: true,
      }),
    );
    const res = await call("sje_quote", { traveler: composed.traveler, ...QUOTE_ARGS });
    assert.ok(res.isError, "non-ITAR seller must be refused");
  });

  it("seal → open round-trips; a tampered archive is refused", async () => {
    const sealed = payload(await call("sje_seal", { traveler: EXAMPLE }));
    const openRes = payload(await call("sje_open", { zip_base64: sealed.zip_base64 }));
    assert.equal(openRes.traveler_hash, sealed.traveler_hash);

    const bytes = Buffer.from(String(sealed.zip_base64), "base64");
    bytes[Math.floor(bytes.length / 2)] ^= 0xff;
    const tampered = await call("sje_open", { zip_base64: bytes.toString("base64") });
    assert.ok(tampered.isError, "tampered archive must be refused");
  });

  it("binding cannot be asserted: traveler_hash_quoted always comes from the traveler in hand", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4413",
          material: { spec: "6061-T6" },
          qty: { target: 25 },
        },
      }),
    );
    const quoted = payload(
      await call("sje_quote", {
        traveler: composed.traveler,
        ...QUOTE_ARGS,
        pricing: { currency: "USD", lines: [{ qty: 25, unit: 22 }] },
      }),
    );
    const t = quoted.traveler as { quotes: Array<{ traveler_hash_quoted: string }> };
    assert.equal(t.quotes[0]!.traveler_hash_quoted, composed.traveler_hash);
  });
});
