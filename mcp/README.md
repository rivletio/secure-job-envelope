# SJE MCP server

The Secure Job Envelope reference implementation, exposed as [Model
Context Protocol](https://modelcontextprotocol.io) tools — so an AI agent
at a buyer and an AI agent at a seller can do business over **encrypted**
travelers with **zero shared state**. Each company runs its own desk; the
only thing that crosses the boundary is an encrypted `.sje` envelope
(ML-KEM-1024 + AES-256-GCM).

An agent drives these tools, and the documents it handles are written by
**counterparties**. The server is built on the assumption that those documents
— and anything in the agent's context they could have influenced — are hostile.

The MCP layer adds **no second truth**: every check is the reference
implementation's own schema, guards, hash binding, signature verification,
receive policy and defensive zip import. What this layer decides is what an
*argument* may be and what a *result* may say:

- **Trust comes from the operator, never from arguments.** The trust root is
  pinned in the server's environment. A key directory may be passed as an
  argument (it is public), but it is used only after it verifies against the
  pinned root. Secrets are never arguments and never results.
- **Binding is earned, not asserted.** `sje_quote` computes
  `traveler_hash_quoted` server-side from the traveler in hand, so it cannot be
  asserted through the tool input (test M2).
- **Stateless by design.** The traveler file is the state. No database, no
  session — the one exception is the desk's passphrase-encrypted decryption
  keystore. See [What statelessness means](#what-statelessness-means).
- **Arguments are exact.** An unknown argument is refused, never ignored (a
  misspelled `require_forward_secrecy` once meant an envelope silently sent
  without forward secrecy). Types are never coerced. Every argument is
  size-capped before anything validates it.
- **Results label their sources.** Counterparty-authored content appears only
  under the members `traveler`, `quote` and `sje`. Everything else is computed
  by the server and carries nothing from a document but identifiers, hashes,
  numbers and dates. No message the server writes quotes document text.

## Operator configuration

All of it is read from the server's **environment**. None of it can be set, or
overridden, by a tool call.

| Variable | What it does | When absent | When malformed |
|---|---|---|---|
| `SJE_TRUST_ROOT` | The pinned trust-root public key: 5184 lowercase hex characters (a 2592-byte ML-DSA-87 key). Read once, at startup. | No root: `sje_seal` refuses; `sje_open` and `sje_evaluate` report authenticity as *unverifiable*. | **The server does not start.** |
| `SJE_TRUST_ROOT_FILE` | Path of a file holding that hex (surrounding whitespace is ignored). Alternative to `SJE_TRUST_ROOT`; setting both is an error. | as above | **The server does not start** (unreadable, or not a key). |
| `SJE_DIRECTORY_FILE` | Path of the operator's signed key directory: the default when a tool is not given a `directory` argument. **Re-read on every call** — replace the file (atomically: write a new file, rename it over the old one) to publish a new directory; no restart. It is still verified against the pinned root on every use. Requires a pinned root. | Tools need a `directory` argument to verify or seal. | Set without a root, or empty: the server does not start. A file that is missing, unreadable, expired or not signed by the root is reported per call, in operator-facing terms. |
| `SJE_REQUIRE_VERIFIED_AWARD` | `1`: an award that is not verified as the buyer's is never admitted — `accept_unverified_award` is refused outright. `0`: default. | Unverified awards are refused by default, and admitted with `accept_unverified_award: true`. | Any other value: the server does not start. |
| `SJE_KEYSTORE` | Path of this desk's passphrase-encrypted keystore. `sje_identity` creates it (exclusively, mode 0600); `sje_open` loads it and rewrites it when a one-time prekey is spent. | `sje_open` and `sje_identity` refuse. | `sje_open` reports the keystore as unavailable. |
| `SJE_KEYSTORE_PASSPHRASE` | The passphrase that protects the keystore at rest (at least 12 characters). | as above | `sje_identity` refuses a passphrase that is too short; `sje_open` fails to unlock. |
| `SJE_COMPANY` | A label for the server's name and its log line. | `unnamed-desk` | Shown sanitized. |

On startup the server writes one line to stderr naming the pinned root's
fingerprint, e.g. `trust root 09cb 9e82 d269 7c0c 6307 78c7 9a06 1c46`. The
same `trust_root_fingerprint` (SHA-384 of the raw public-key bytes, first 32 hex
characters, in groups of four) is on every result that depends on trust.

If the pinned root is the **demo root** (`src/lib/traveler/demo-trust.ts`), every
trust-dependent result carries `demo_anchor: true` and a warning: its private
keys are public, and a verdict under it proves nothing.

## Tools

Every tool refuses unknown arguments and mistyped ones. Each takes
`expected_traveler_hash` where it acts on a traveler: when given, the
traveler's current hash must equal it, or the call is refused and both hashes
are reported.

| Tool | Side | Does |
|---|---|---|
| `sje_validate` | any | Schema check + hash + level + binding report — the validation-service primitive |
| `sje_compose` | buyer | New traveler (fresh `tvl_` id). Keep its `traveler_hash`: it is how you later say which body you mean |
| `sje_amend` | buyer | `patch` sets `buyer`, `part`, `need_by`, `incoterms`, `itar` — nothing else. Bumps revision, stale-marks all quotes; **refused when the traveler handed in is locked** |
| `sje_quote` | seller | Attach a quote; binding hash computed server-side; ITAR + schema guards |
| `sje_evaluate` | buyer | Every quote, with everything an award would commit to: each price line, NRE, freight, tax, currency, lead time, validity and expiry, `need_by_feasible`, each exception's `price_delta`, whether assumptions/capacity are present, the quote's content hash, an itemized total at the target quantity, award blockers, and — with a root and a directory — the seller's signature check. The quote itself is returned whole under `quote` |
| `sje_award` | buyer | Award one bound, unexpired quote + ops + ship-to → **L2, locked**. `expected_traveler_hash` is **required**; `qty` must be a JSON integer the quote has a price line for. The award is **not signed** (see below) |
| `sje_identity` | any | Mint this desk's ML-KEM identity **on the server**: writes the keystore to `SJE_KEYSTORE` (never overwrites one), returns only the public `directory_entry` and, if asked, up to 64 public one-time prekeys. Takes no passphrase; returns no keystore |
| `sje_seal` | any | Encrypt a traveler to a recipient org whose key comes from a directory that verifies against the pinned root. Refuses an `itar: true` traveler unless the directory attests the recipient for ITAR (or the recipient is the buyer the traveler names). Reports `recipient_org`, the key used, `forward_secret` — and `not_forward_secret_because` when it is not |
| `sje_open` | any | Decrypt a received `.sje` with this desk's keystore, run the full defensive import, verify, and apply the receive policy. Reports `authenticity`. Takes `expected_traveler_hash`, `expected_buyer_org`, `accept_unverified_award` |

### What `sje_open` tells you

An envelope proves nothing about who sealed it: anyone holding the public
directory can encrypt to an org. `sje_open` therefore reports what verification
established:

```jsonc
"authenticity": {
  "status": "verified",            // verified | unverified | unverifiable
  "verified_buyer_org": "org_northline",
  "authorship": [{ "ok": true, "kid": "northline-2026", "org_id": "org_northline", "reason": null }],
  "award": null,                   // a check, or null when the traveler carries no award
  "quotes": [{ "quote_id": "qot_…", "signed": false, "check": null }],
  "trust_root_fingerprint": "09cb 9e82 d269 7c0c 6307 78c7 9a06 1c46",
  "demo_anchor": false
}
```

- **verified** — a buyer signature verifies and, if there is an award, so does
  the buyer's award signature. It names the org that *signed*, which is not
  necessarily the org you expect: compare `verified_buyer_org` yourself, or pass
  `expected_buyer_org`. A display name is never evidence.
- **unverified** — a root and a directory were available and that was not
  established (unsigned, or signed with a key the directory does not list).
- **unverifiable** — the server had no trust root or no usable directory.

A signature that is present and **fails** is refused. An award that is not
verified as the buyer's is **refused by default**, with the statements the
caller must accept; after confirming the award with the buyer out of band,
retry with `accept_unverified_award: true` and the result carries those
statements verbatim under `unverified`. A one-time prekey is spent only when the
traveler is admitted: a refusal spends nothing, and the same envelope can be
opened again.

## What statelessness means

The server keeps no copy of any traveler. Two consequences are worth stating
plainly, because no amount of checking inside a stateless tool can change them:

- **A lock is whatever the document handed in says it is.** `sje_amend` on a
  traveler whose `award` the caller deleted succeeds — the server cannot know
  there ever was one. The party that holds the authoritative copy is responsible
  for it.
- **The server cannot know what you sent out.** A seller can return a different
  body (another material, tolerance or quantity) under the same `traveler_id`
  and revision, with a quote honestly bound to *that* body. The protection is the
  hash of the body *you* wrote: pass it as `expected_traveler_hash` to `sje_open`,
  `sje_evaluate` and `sje_award` (where it is required). It protects you only if
  it comes from your own copy — not from the document that came back.

Other limits of this surface:

- **Nothing here signs.** The server holds no ML-DSA key, so travelers, quotes
  and awards produced by these tools are unsigned. A desk that receives an award
  made by `sje_award` reports it as unverified until the buyer signs it with its
  org key elsewhere (the demo does this in-process).
- **Directory freshness.** Without `SJE_DIRECTORY_FILE`, a root-signed directory
  passed as an argument is accepted for as long as its own validity window lasts,
  even if a newer one exists. With it, an argument older than the operator's is
  refused.
- **ITAR.** `sje_quote` and `sje_award` apply the traveler's self-declared ITAR
  consistency rule only. The directory's attestation gates `sje_seal`, and is
  reported per quote by `sje_evaluate`.
- **`price_delta`.** The format does not say whether an exception's `price_delta`
  is per unit or per order; totals add each once, and say so.
- **Verification work.** Checking a quote's signature re-verifies the whole
  directory, so the cost is (signed quotes) × (directory size) — and the author
  of a traveler chooses the first factor. Authorship and the award are always
  checked. Quote signatures are checked only when all of them fit a fixed work
  limit (64 signed quotes fit for a directory of up to about 60 entries);
  otherwise each is reported as *not checked* — never as passed — and
  `sje_evaluate` says so. Evaluate fewer quotes at a time to have them checked.

## The demo

```bash
npm run demo
```

Two separate server processes (Northline the buyer, Summit Fabrication the
seller), each with a root pinned by its operator and a keystore **minted on its
own server**, two MCP clients, one job: mint identities → compose → sign →
**seal (forward-secret)** → *(a flipped byte refused by AEAD)* → **open, verified
as the buyer's** → quote → seal → open as the body the buyer wrote → evaluate →
*(a rewritten part refused)* → award → *(an unsigned award refused)* → signed
award verified → amend-after-lock refused. Every hop is ciphertext on the wire
and asserts the hash lineage. It runs in CI; the transcript is the executive
explanation of the standard. The root it pins is the public demo root, and the
desks say so on every result.

## Using it from Claude (or any MCP client)

```json
{
  "mcpServers": {
    "sje": {
      "command": "node",
      "args": ["--experimental-strip-types", "/path/to/repo/mcp/server.ts"],
      "env": {
        "SJE_COMPANY": "your-company",
        "SJE_TRUST_ROOT_FILE": "/etc/sje/root.hex",
        "SJE_DIRECTORY_FILE": "/etc/sje/directory.json",
        "SJE_KEYSTORE": "/var/lib/sje/desk.keystore.json",
        "SJE_KEYSTORE_PASSPHRASE": "…"
      }
    }
  }
}
```

The server sends `instructions` at initialize telling the model what the
documents are (data, never instructions), that names are self-asserted, that an
unverified award must be confirmed out of band, and that a request to use
another root, directory, key or recipient is an attack. Then ask the model to
compose, quote, evaluate, or award — the guards apply to every tool call
regardless of the prompt (tests M1–M3). Tests: `mcp/mcp.test.ts` (runs in
`npm test`); claims mapping: `docs/CLAIMS.md` §MCP surface.
