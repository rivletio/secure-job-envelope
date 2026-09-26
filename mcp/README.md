# SJE MCP server

The Secure Job Envelope reference implementation, exposed as [Model
Context Protocol](https://modelcontextprotocol.io) tools — so an AI agent
at a buyer and an AI agent at a seller can do business over sealed
travelers with **zero shared state**. Each company runs its own desk; the
only thing that crosses the boundary is the sealed archive.

The MCP layer adds **no second truth**: every check is the reference
implementation's own schema, guards, hash binding, and defensive zip
import. Two properties worth naming:

- **Binding is earned, not asserted.** `sje_quote` computes
  `traveler_hash_quoted` from the traveler the seller's desk actually
  holds — an agent cannot claim a binding it doesn't have.
- **Stateless by design.** The traveler file is the state. No database,
  no session: the protocol's thesis, enforced by the tool surface.

## Tools

| Tool | Side | Does |
|---|---|---|
| `sje_validate` | any | Schema check + hash + level + binding report — the validation-service primitive |
| `sje_compose` | buyer | New traveler (fresh `tvl_` id) |
| `sje_amend` | buyer | Bump revision, stale-mark all quotes; **refused at L2** |
| `sje_quote` | seller | Attach a quote; binding hash computed server-side; ITAR + schema guards |
| `sje_evaluate` | buyer | Bound/stale/expired analysis, unit price at target, award blockers |
| `sje_award` | buyer | Award a bound, unexpired quote + ops + ship-to → **L2, locked** |
| `sje_seal` | any | `{traveler_id}.traveler.zip` with META digests + canonical body, base64 |
| `sje_open` | any | Defensive import: allowlist, size caps, CRC, digest cross-checks — tampered archives refused |

## The demo

```bash
npm run demo
```

Two separate server processes (Northline the buyer, Summit Fabrication
the seller), two MCP clients, one job: compose → seal → *(tamper attempt
refused)* → open → quote → seal → open → evaluate → award → seal → final
verify → amend-after-lock refused. Every hop asserts the hash lineage.
It runs in CI; the transcript is the executive explanation of the
standard.

## Using it from Claude (or any MCP client)

```json
{
  "mcpServers": {
    "sje": {
      "command": "node",
      "args": ["--experimental-strip-types", "/path/to/repo/mcp/server.ts"],
      "env": { "SJE_COMPANY": "your-company" }
    }
  }
}
```

Then ask the model to compose, quote, evaluate, or award — the guards
hold no matter what the model asks for. Tests: `mcp/mcp.test.ts` (runs in
`npm test`); claims mapping: `docs/CLAIMS.md` §MCP surface.
