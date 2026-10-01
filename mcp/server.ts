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
  parseQuote,
  parseTraveler,
  staleQuotes,
} from "../src/lib/traveler/conformance.ts";
import { cannotAward, cannotQuote, isQuoteExpired, locked } from "../src/lib/traveler/guards.ts";
import { isoNow, newQuoteId, newTravelerId } from "../src/lib/traveler/ids.ts";
import { sealTraveler, openTraveler, parseSjeEnvelope } from "../src/lib/traveler/transport.ts";
import { createIdentity, unlock, type Keystore, type Unlocked } from "../src/lib/traveler/keystore.ts";
import { MAX_ARCHIVE_BYTES, MAX_TRAVELER_JSON_BYTES, TRAVELER_SPEC } from "../src/lib/traveler/types.ts";
import type { Award, Op, ShipTo, Traveler } from "../src/lib/traveler/types.ts";
import type { Directory } from "../src/lib/traveler/directory.ts";
import type { PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import { readFileSync, writeFileSync, renameSync, openSync, fsyncSync, closeSync } from "node:fs";

const COMPANY = process.env.SJE_COMPANY ?? "unnamed-desk";

/** Write the keystore atomically: a crash or ENOSPC mid-write must never truncate
 *  the live file (that would brick the desk's identity). Write a temp file, fsync it,
 *  then rename over the target (atomic within a filesystem). */
function atomicWriteFile(path: string, data: string): void {
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "w");
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/** This desk's decryption identity, loaded lazily from the passphrase-encrypted
 *  keystore file (SJE_KEYSTORE) and unlocked with SJE_KEYSTORE_PASSPHRASE. Only
 *  `sje_open` needs it — sealing uses the recipient's public key, never a secret.
 *  Cached for the process; a failed unlock clears the cache so config can be fixed
 *  and retried. */
let cachedKeystore: Promise<Unlocked> | undefined;
function serverKeystore(): Promise<Unlocked> {
  if (cachedKeystore) return cachedKeystore;
  const path = process.env.SJE_KEYSTORE;
  const passphrase = process.env.SJE_KEYSTORE_PASSPHRASE;
  if (!path || !passphrase) {
    return Promise.reject(
      new Error("sje_open needs SJE_KEYSTORE (keystore file path) and SJE_KEYSTORE_PASSPHRASE"),
    );
  }
  const p = (async () => {
    let blob: Keystore;
    try {
      blob = JSON.parse(readFileSync(path, "utf8")) as Keystore;
    } catch (e) {
      // Don't surface the on-disk path or parser internals to the tool caller;
      // log the detail server-side and return a uniform, path-free message.
      console.error("[sje] keystore read/parse failed:", e);
      throw new Error("keystore unavailable (could not read SJE_KEYSTORE)");
    }
    return unlock(blob, passphrase); // throws the uniform UNLOCK_FAIL (no path leak)
  })();
  p.catch(() => {
    if (cachedKeystore === p) cachedKeystore = undefined;
  });
  cachedKeystore = p;
  return p;
}

/* ---------------- helpers ---------------- */

function asTraveler(input: unknown): Traveler {
  // Early-out cap for the string form. Object input (already JSON-parsed by the MCP
  // SDK) is bounded instead by parseTraveler's per-field schema limits (numeric
  // ceilings, string/array caps — docs/CLAIMS.md C12), which are the authoritative
  // bound; there is no unbounded path here.
  if (typeof input === "string" && input.length > MAX_TRAVELER_JSON_BYTES) {
    throw new Error("traveler JSON exceeds 512 KiB");
  }
  let doc: unknown = input;
  if (typeof input === "string") {
    try {
      doc = JSON.parse(input) as unknown;
    } catch {
      // Normalize a raw V8 SyntaxError to a generic message (don't echo parser internals).
      throw new Error("traveler is not valid JSON");
    }
  }
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
        terms: obj({}, []),
      },
      ["traveler", "quote_id", "qty", "ops", "ship_to"],
    ),
  },
  {
    name: "sje_identity",
    description:
      "Generate an ML-KEM encryption identity. Returns a passphrase-encrypted keystore blob (save it to the file SJE_KEYSTORE points at) and the public directory-entry fields to publish. Optionally mints N one-time prekeys for forward secrecy. The passphrase is sensitive — it protects the keystore at rest.",
    inputSchema: obj(
      {
        passphrase: { type: "string" },
        org_id: { type: "string" },
        prekeys: { type: "number", description: "optional count of one-time prekeys to mint" },
      },
      ["passphrase"],
    ),
  },
  {
    name: "sje_seal",
    description:
      "Encrypt a traveler to a directory-attested recipient and return the `.sje` envelope — the ONLY artifact sent between companies (ML-KEM-1024 + AES-256-GCM, post-quantum). Needs the signed directory and the trust-root public key (both public) to resolve the recipient's encryption key; no secret key is needed to seal. Supply the recipient's signed prekey_bundle to get a forward-secret envelope (reported via forward_secret); set require_forward_secret to refuse sending without it.",
    inputSchema: obj(
      {
        traveler: TRAVELER_ARG,
        directory: { type: "object", description: "the signed key directory" },
        root_public_key_hex: { type: "string", description: "the trust-root public key (hex)" },
        recipient_org: { type: "string", description: "org_id of the recipient" },
        prekey_bundle: { type: "object", description: "the recipient's signed one-time prekey bundle (enables forward secrecy)" },
        require_forward_secret: { type: "boolean", description: "throw instead of falling back to the static envelope" },
      },
      ["traveler", "directory", "root_public_key_hex", "recipient_org"],
    ),
  },
  {
    name: "sje_open",
    description:
      "Decrypt a received `.sje` envelope with this desk's keystore (SJE_KEYSTORE + SJE_KEYSTORE_PASSPHRASE) and run the full defensive import. An envelope not addressed to this desk, tampered, or corrupt is refused.",
    inputSchema: obj(
      { sje: { description: "an SJE envelope (object or JSON string)", anyOf: [{ type: "object" }, { type: "string" }] } },
      ["sje"],
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
        ship_to: t.ship_to,
        ops: t.ops,
        as_built: t.as_built ?? null,
      });
      return ok({ traveler: next, ...report(next) });
    }

    case "sje_quote": {
      const t = asTraveler(args.traveler);
      // Validate the assembled quote up front — a malformed seller/pricing gets
      // a clean schema error here rather than a raw TypeError inside the guard.
      const quote = parseQuote({
        quote_id: newQuoteId(),
        seller: args.seller,
        // Binding is computed from the traveler in hand — never taken from input.
        traveler_hash_quoted: travelerHash(t),
        created_at: isoNow(),
        valid_until: String(args.valid_until),
        lead_time_days: Number(args.lead_time_days),
        pricing: args.pricing,
        ...(args.exceptions ? { exceptions: args.exceptions } : {}),
      });
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
        ...(args.terms ? { terms: args.terms as Award["terms"] } : {}),
      };
      const next = parseTraveler({ ...t, award, ship_to: shipTo, ops });
      const lvl = levelOf(next);
      if (lvl.code !== "L2") return fail(`Award did not reach L2 (${lvl.code}): ${lvl.missing.join(", ")}`);
      return ok({ traveler: next, ...report(next) });
    }

    case "sje_identity": {
      // Mint an ML-KEM identity. The keystore is encrypted at rest under the
      // passphrase; only the public directory-entry fields are meant to be
      // published. Optional one-time prekeys enable forward-secret envelopes.
      const passphrase = String(args.passphrase ?? "");
      const orgId =
        args.org_id === undefined || args.org_id === null ? undefined : String(args.org_id);
      const created = await createIdentity({ passphrase, ...(orgId ? { orgId } : {}) });
      const n = Math.floor(Number(args.prekeys ?? 0));
      if (Number.isFinite(n) && n > 0) {
        const u = await unlock(created.keystore, passphrase);
        const { keystore, prekeys } = u.addPrekeys(Math.min(n, 1024));
        u.lock();
        return ok({ keystore, directory_entry: created.directoryEntry, prekeys });
      }
      return ok({ keystore: created.keystore, directory_entry: created.directoryEntry });
    }

    case "sje_seal": {
      // Encrypt to a directory-attested recipient. Needs only public inputs (the
      // signed directory + trust-root public key); no secret key seals. The
      // returned envelope is the ONLY artifact that crosses company lines.
      const t = asTraveler(args.traveler);
      if (!args.directory || typeof args.directory !== "object") {
        return fail("sje_seal needs the signed key directory.");
      }
      const rootHex = String(args.root_public_key_hex ?? "");
      const recipientOrg = String(args.recipient_org ?? "");
      if (!rootHex) return fail("sje_seal needs root_public_key_hex (the trust-root public key).");
      if (!recipientOrg) return fail("sje_seal needs recipient_org.");
      const { envelope, forwardSecret } = await sealTraveler(t, {
        directory: args.directory as Directory,
        rootPublicKeyHex: rootHex,
        recipientOrg,
        ...(args.prekey_bundle ? { prekeyBundle: args.prekey_bundle as PrekeyBundle } : {}),
        ...(args.require_forward_secret ? { requireForwardSecret: true } : {}),
      });
      return ok({
        sje: envelope,
        spec: envelope.spec,
        forward_secret: forwardSecret,
        recipients: envelope.recipients.length,
        traveler_hash: travelerHash(t),
      });
    }

    case "sje_open": {
      // The one input that crosses the trust boundary. Cap the raw size before any
      // decode/decrypt: the envelope wraps a hex payload (~2x the archive bytes)
      // plus per-recipient KEM material, so bound to 2x the archive limit + slack.
      const raw = typeof args.sje === "string" ? args.sje : JSON.stringify(args.sje ?? {});
      if (raw.length > 2 * MAX_ARCHIVE_BYTES + 64 * 1024) {
        return fail("Sealed envelope exceeds size limit.");
      }
      let keystore: Unlocked;
      try {
        keystore = await serverKeystore();
      } catch (e) {
        return fail(e instanceof Error ? e.message : "keystore unavailable");
      }
      let envelope;
      try {
        envelope = parseSjeEnvelope(args.sje);
      } catch {
        return fail("Input is not a recognized SJE envelope.");
      }
      // On the forward-secret path, persist the consumed-prekey deletion back to the
      // keystore file so a restart cannot resurrect a spent one-time prekey.
      const keystorePath = process.env.SJE_KEYSTORE;
      let t: Traveler;
      try {
        t = await openTraveler(envelope, keystore, {
          persistKeystore: keystorePath
            ? (ks) => {
                try {
                  atomicWriteFile(keystorePath, JSON.stringify(ks));
                } catch (e) {
                  // Surface the disk fault server-side and fail the open rather than
                  // silently proceeding with an unpersisted prekey consumption.
                  console.error("[sje] keystore persist failed:", e);
                  throw e;
                }
              }
            : undefined,
        });
      } catch {
        // Uniform failure — do not reveal whether it was the wrong recipient, a
        // tampered envelope, or a malformed payload (no decryption oracle).
        return fail("Could not open envelope (wrong recipient, tampered, or not addressed to this desk).");
      }
      return ok({ traveler: t, ...report(t) });
    }

    default:
      return fail(`Unknown tool: ${name}`);
  }
}

/* ---------------- server ---------------- */

export function buildServer(): Server {
  const server = new Server(
    { name: `sje-desk (${COMPANY})`, version: "0.1.0" },
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
