/** SJE MCP server — exposes the Secure Job Envelope reference
 *  implementation as Model Context Protocol tools, so agents on either
 *  side of a job (buyer or seller) can compose, validate, quote, award,
 *  seal, and open travelers.
 *
 *  Design rules:
 *  - STATELESS. The traveler file is the state; every tool takes and
 *    returns explicit traveler JSON or sealed archives. No database —
 *    that is the protocol's thesis.
 *  - The MCP layer adds no second truth: every check is the reference
 *    implementation's own (schema, guards, hash binding, defensive zip
 *    import). Tool inputs are described with plain JSON Schema; real
 *    validation happens in src/lib/traveler.
 *  - Quote binding (`traveler_hash_quoted`) is COMPUTED server-side from
 *    the traveler the seller is looking at — an agent cannot assert a
 *    binding it does not have.
 *
 *  Run: node --experimental-strip-types mcp/server.ts   (stdio transport)
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { travelerHash } from "../src/lib/traveler/hash.ts";
import {
  awardedQuote,
  boundQuotes,
  levelOf,
  parseTraveler,
  staleQuotes,
} from "../src/lib/traveler/conformance.ts";
import { cannotAward, cannotQuote, isQuoteExpired, locked } from "../src/lib/traveler/guards.ts";
import { isoNow, newQuoteId, newTravelerId } from "../src/lib/traveler/ids.ts";
import { importTravelerFile, travelerToZip } from "../src/lib/traveler/zip.ts";
import { TRAVELER_SPEC } from "../src/lib/traveler/types.ts";
import type { Award, Op, Quote, ShipTo, Traveler } from "../src/lib/traveler/types.ts";

const COMPANY = process.env.SJE_COMPANY ?? "unnamed-desk";

/* ---------------- helpers ---------------- */

function asTraveler(input: unknown): Traveler {
  const doc = typeof input === "string" ? (JSON.parse(input) as unknown) : input;
  return parseTraveler(doc);
}

function report(traveler: Traveler) {
  const lvl = levelOf(traveler);
  return {
    traveler_id: traveler.traveler_id,
    revision: traveler.revision,
    traveler_hash: travelerHash(traveler),
    level: lvl.code,
    level_name: lvl.name,
    missing: lvl.missing,
    locked: locked(traveler),
    quotes: (traveler.quotes ?? []).length,
    bound_quotes: boundQuotes(traveler).map((q) => q.quote_id),
    stale_quotes: staleQuotes(traveler).map((q) => q.quote_id),
    expired_quotes: (traveler.quotes ?? [])
      .filter((q) => isQuoteExpired(q))
      .map((q) => q.quote_id),
    awarded_quote: awardedQuote(traveler)?.quote_id ?? null,
  };
}

function ok(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

function fail(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
  };
}

const obj = (properties: Record<string, unknown>, required: string[] = []) => ({
  type: "object" as const,
  properties,
  required,
});
const TRAVELER_ARG = {
  description: "A traveler document (object, or JSON string)",
  anyOf: [{ type: "object" }, { type: "string" }],
};

/* ---------------- tool definitions ---------------- */

const TOOLS = [
  {
    name: "sje_validate",
    description:
      "Validate a traveler against the SJE schema and report its content hash, conformance level (D/L0/L1/L2), quote binding status, and lock state. The validation-service primitive.",
    inputSchema: obj({ traveler: TRAVELER_ARG }, ["traveler"]),
  },
  {
    name: "sje_compose",
    description:
      "Compose a new traveler (buyer side): one part family with material and target quantity. Returns the traveler with a fresh traveler_id, its hash, and its level.",
    inputSchema: obj(
      {
        buyer: obj({}, []),
        part: obj({}, []),
        need_by: { type: "string", description: "YYYY-MM-DD" },
        incoterms: { type: "string" },
        itar: { type: "boolean" },
      },
      ["buyer", "part"],
    ),
  },
  {
    name: "sje_amend",
    description:
      "Amend a traveler's quoteable body (buyer side). Bumps revision and stale-marks every existing quote (their binding hash no longer matches). Refused when the traveler is locked (L2).",
    inputSchema: obj({ traveler: TRAVELER_ARG, patch: obj({}, []) }, ["traveler", "patch"]),
  },
  {
    name: "sje_quote",
    description:
      "Attach a structured quote to a traveler (seller side). traveler_hash_quoted is computed here from the traveler being quoted — the binding cannot be asserted, only earned. Enforces schema, ITAR consistency, and one-quote-per-seller.",
    inputSchema: obj(
      {
        traveler: TRAVELER_ARG,
        seller: obj({}, []),
        valid_until: { type: "string", description: "ISO datetime" },
        lead_time_days: { type: "number" },
        pricing: obj({}, []),
        exceptions: { type: "array" },
      },
      ["traveler", "seller", "valid_until", "lead_time_days", "pricing"],
    ),
  },
  {
    name: "sje_evaluate",
    description:
      "Evaluate a traveler's quotes (buyer side): which are bound to the current revision, which are stale, which have expired, and whether each bound quote prices the target quantity.",
    inputSchema: obj({ traveler: TRAVELER_ARG }, ["traveler"]),
  },
  {
    name: "sje_award",
    description:
      "Award a bound, unexpired quote (buyer side) with an ops traveler and ship-to. Locks the traveler at L2 Executable. Refuses stale or expired quotes.",
    inputSchema: obj(
      {
        traveler: TRAVELER_ARG,
        quote_id: { type: "string" },
        qty: { type: "number" },
        ops: { type: "array", description: "[{seq, code, notes?}]" },
        ship_to: obj({}, []),
      },
      ["traveler", "quote_id", "qty", "ops", "ship_to"],
    ),
  },
  {
    name: "sje_seal",
    description:
      "Seal a traveler into its archive ({traveler_id}.traveler.zip with META.json digests and canonical body) and return it base64-encoded — the artifact one company sends another.",
    inputSchema: obj({ traveler: TRAVELER_ARG }, ["traveler"]),
  },
  {
    name: "sje_open",
    description:
      "Open a received sealed archive (base64). Runs the full defensive import: member allowlist, size caps, path-traversal refusal, META digest cross-checks, canonical-body cross-check, schema validation. Tampered archives are refused.",
    inputSchema: obj(
      {
        zip_base64: { type: "string" },
        filename: { type: "string", description: "defaults to received.traveler.zip" },
      },
      ["zip_base64"],
    ),
  },
] as const;

/* ---------------- handlers ---------------- */

type Args = Record<string, unknown>;

async function handle(name: string, args: Args) {
  switch (name) {
    case "sje_validate": {
      const t = asTraveler(args.traveler);
      return ok(report(t));
    }

    case "sje_compose": {
      const draft = {
        spec: TRAVELER_SPEC,
        traveler_id: newTravelerId(),
        revision: 1,
        created_at: isoNow(),
        buyer: args.buyer,
        part: args.part,
        need_by: (args.need_by as string | undefined) ?? null,
        incoterms: (args.incoterms as string | undefined) ?? null,
        itar: Boolean(args.itar ?? false),
      };
      const t = parseTraveler(draft);
      return ok({ traveler: t, ...report(t) });
    }

    case "sje_amend": {
      const t = asTraveler(args.traveler);
      if (locked(t)) return fail("Traveler is locked at L2; amend refused.");
      const patch = args.patch as Partial<Traveler>;
      const next = parseTraveler({
        ...t,
        ...patch,
        spec: t.spec,
        traveler_id: t.traveler_id,
        created_at: t.created_at,
        revision: t.revision + 1,
        quotes: t.quotes,
        award: null,
      });
      return ok({ traveler: next, ...report(next) });
    }

    case "sje_quote": {
      const t = asTraveler(args.traveler);
      const quote: Quote = {
        quote_id: newQuoteId(),
        seller: args.seller as Quote["seller"],
        // Binding is computed from the traveler in hand — never taken from input.
        traveler_hash_quoted: travelerHash(t),
        created_at: isoNow(),
        valid_until: String(args.valid_until),
        lead_time_days: Number(args.lead_time_days),
        pricing: args.pricing as Quote["pricing"],
        ...(args.exceptions ? { exceptions: args.exceptions as Quote["exceptions"] } : {}),
      };
      const err = cannotQuote(t, quote);
      if (err) return fail(err);
      const rest = (t.quotes ?? []).filter((q) => q.quote_id !== quote.quote_id);
      const next = parseTraveler({ ...t, quotes: [...rest, quote] });
      return ok({ traveler: next, quote_id: quote.quote_id, ...report(next) });
    }

    case "sje_evaluate": {
      const t = asTraveler(args.traveler);
      const bound = boundQuotes(t);
      return ok({
        ...report(t),
        evaluation: bound.map((q) => ({
          quote_id: q.quote_id,
          seller: q.seller.name,
          lead_time_days: q.lead_time_days,
          valid_until: q.valid_until,
          expired: isQuoteExpired(q),
          currency: q.pricing.currency,
          unit_at_target: q.pricing.lines.find((l) => l.qty === t.part.qty.target)?.unit ?? null,
          nre: q.pricing.nre ?? 0,
          award_blocker: cannotAward(t, q),
        })),
      });
    }

    case "sje_award": {
      const t = asTraveler(args.traveler);
      const quote = (t.quotes ?? []).find((q) => q.quote_id === args.quote_id);
      if (!quote) return fail("Award references a quote that is not on the traveler.");
      const err = cannotAward(t, quote);
      if (err) return fail(err);
      const ops = args.ops as Op[];
      const shipTo = args.ship_to as ShipTo;
      if (!Array.isArray(ops) || ops.length === 0) return fail("List at least one op.");
      const award: Award = {
        quote_id: quote.quote_id,
        awarded_at: isoNow(),
        qty: Number(args.qty),
      };
      const next = parseTraveler({ ...t, award, ship_to: shipTo, ops });
      const lvl = levelOf(next);
      if (lvl.code !== "L2") return fail(`Award did not reach L2 (${lvl.code}): ${lvl.missing.join(", ")}`);
      return ok({ traveler: next, ...report(next) });
    }

    case "sje_seal": {
      const t = asTraveler(args.traveler);
      const blob = await travelerToZip(t);
      const bytes = Buffer.from(await blob.arrayBuffer());
      return ok({
        filename: `${t.traveler_id}.traveler.zip`,
        bytes: bytes.length,
        traveler_hash: travelerHash(t),
        zip_base64: bytes.toString("base64"),
      });
    }

    case "sje_open": {
      const bytes = Buffer.from(String(args.zip_base64), "base64");
      const name = typeof args.filename === "string" ? args.filename : "received.traveler.zip";
      const file = new File([bytes], name, { type: "application/zip" });
      const t = await importTravelerFile(file);
      return ok({ traveler: t, ...report(t) });
    }

    default:
      return fail(`Unknown tool: ${name}`);
  }
}

/* ---------------- server ---------------- */

export function buildServer(): Server {
  const server = new Server(
    { name: `sje-desk (${COMPANY})`, version: "0.0.1" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: TOOLS.map((t) => ({ ...t })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    try {
      return await handle(req.params.name, (req.params.arguments ?? {}) as Args);
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e));
    }
  });
  return server;
}

const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const server = buildServer();
  await server.connect(new StdioServerTransport());
  console.error(`[sje] ${COMPANY} desk on stdio — ${TRAVELER_SPEC}`);
}
