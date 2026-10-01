# SJE MCP server

The Secure Job Envelope reference implementation, exposed as [Model
Context Protocol](https://modelcontextprotocol.io) tools — so an AI agent
at a buyer and an AI agent at a seller can do business over **encrypted**
travelers with **zero shared state**. Each company runs its own desk; the
only thing that crosses the boundary is an encrypted `.sje` envelope
(ML-KEM-1024 + AES-256-GCM).

The MCP layer adds **no second truth**: every check is the reference
implementation's own schema, guards, hash binding, and defensive zip
import. Two properties worth naming:

- **Binding is earned, not asserted.** `sje_quote` computes
  `traveler_hash_quoted` server-side from the traveler in hand, so it cannot be
  asserted through the tool input (test M2).
- **Stateless by design.** The traveler file is the state. No database,
  no session — the one exception is the desk's passphrase-encrypted decryption
  keystore (`SJE_KEYSTORE` + `SJE_KEYSTORE_PASSPHRASE`), loaded to open received
  envelopes. The protocol's thesis, enforced by the tool surface.

## Tools

| Tool | Side | Does |
|---|---|---|
| `sje_validate` | any | Schema check + hash + level + binding report — the validation-service primitive |
| `sje_compose` | buyer | New traveler (fresh `tvl_` id) |
| `sje_amend` | buyer | Bump revision, stale-mark all quotes; **refused at L2** |
| `sje_quote` | seller | Attach a quote; binding hash computed server-side; ITAR + schema guards |
| `sje_evaluate` | buyer | Bound/stale/expired analysis, unit price at target, award blockers |
| `sje_award` | buyer | Award a bound, unexpired quote + ops + ship-to → **L2, locked** |
| `sje_identity` | any | Mint an ML-KEM identity: a passphrase-encrypted keystore blob + the public directory entry to publish (+ optional one-time prekeys) |
| `sje_seal` | any | Encrypt a traveler to a directory-attested recipient → the `.sje` envelope (ML-KEM-1024 + AES-256-GCM); a `prekey_bundle` enables forward secrecy, reported via `forward_secret` |
| `sje_open` | any | Decrypt a received `.sje` with this desk's keystore (`SJE_KEYSTORE` + `SJE_KEYSTORE_PASSPHRASE`), then the full defensive import — wrong-recipient / tampered / corrupt refused |

## The demo

```bash
npm run demo
```

Two separate server processes (Northline the buyer, Summit Fabrication
the seller), each loading its own passphrase-encrypted keystore, two MCP
clients, one job: compose → **seal (encrypted)** → *(a flipped byte refused
by AEAD)* → **decrypt** → quote → seal → decrypt → evaluate → award → seal →
final verify → amend-after-lock refused. Every hop is ciphertext on the wire
and asserts the hash lineage. It runs in CI; the transcript is the executive
explanation of the standard.

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
apply to every tool call regardless of the prompt (tests M1–M3). Tests:
`mcp/mcp.test.ts` (runs in `npm test`); claims mapping: `docs/CLAIMS.md`
§MCP surface.
