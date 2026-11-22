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
  size-capped before anything validates it. A request whose text gives a member
  name twice, or names a member `__proto__`, is refused **before it is parsed**
  (see [Requests are read as text first](#requests-are-read-as-text-first)).
- **Results label their sources.** Counterparty-authored content appears only
  under the members `traveler`, `quote` and `sje`. Everything else is computed
  by the server and carries nothing from a document but document ids
  (`tvl_…`, `qot_…`: at most 28 characters of `[a-z0-9_]`), hashes, numbers and
  dates. An org is named outside those members only when it comes from the
  operator's directory (a verified signer) or from the caller's own arguments —
  never because a document says so. No message the server writes quotes
  document text.

## Operator configuration

All of it is read from the server's **environment**. None of it can be set, or
overridden, by a tool call.

| Variable | What it does | When absent | When malformed |
|---|---|---|---|
| `SJE_TRUST_ROOT` | The pinned trust-root public key: 5184 lowercase hex characters (a 2592-byte ML-DSA-87 key). Read once, at startup. | No root: `sje_seal` refuses; `sje_open` and `sje_evaluate` report authenticity as *unverifiable*. | **The server does not start.** |
| `SJE_TRUST_ROOT_FILE` | Path of a file holding that hex (surrounding whitespace is ignored). Alternative to `SJE_TRUST_ROOT`; setting both is an error. | as above | **The server does not start** (unreadable, or not a key). |
| `SJE_DIRECTORY_FILE` | Path of the operator's signed key directory: the default when a tool is not given a `directory` argument, and the **floor** for one that is — an argument is accepted only if it is this directory or was issued strictly after it. **Re-read on every call** — replace the file (atomically: write a new file, rename it over the old one) to publish a new directory; no restart. It is still verified against the pinned root on every use. Requires a pinned root. | Tools need a `directory` argument to verify or seal. | Set without a root, or empty: the server does not start. A file that is missing, unreadable, expired or not signed by the root is reported per call, in operator-facing terms, and logged. An expired file that is the root's is still the floor; while the file cannot be authenticated at all, **no** `directory` argument is accepted. |
| `SJE_REQUIRE_VERIFIED_AWARD` | `1`: an award that is not verified as the buyer's is never admitted — `accept_unverified_award` is refused outright. `0`: default. | Unverified awards are refused by default, and admitted with `accept_unverified_award: true`. | Any other value: the server does not start. |
| `SJE_KEYSTORE` | Path of this desk's passphrase-encrypted keystore. `sje_identity` creates it (exclusively, mode 0600); `sje_open` loads it and rewrites it when a one-time prekey is spent. | `sje_open` and `sje_identity` refuse. | `sje_open` reports the keystore as unavailable. |
| `SJE_KEYSTORE_PASSPHRASE` | The passphrase that protects the keystore at rest (at least 12 characters). | as above | `sje_identity` refuses a passphrase that is too short; `sje_open` fails to unlock. |
| `SJE_ORG` | The `org_id` this desk acts as. It decides one thing: a quote that names this org as its seller is the desk's own, and travels with whatever the desk seals (see `sje_seal`). | No quote is the desk's own: a quote is sealed only to the buyer org its traveler names, or to the seller org the quote names. | Not an `org_id`: the server does not start. |
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
| `sje_amend` | buyer | `patch` sets `buyer`, `part`, `need_by`, `incoterms`, `itar` — nothing else. Bumps revision, stale-marks all quotes; **refused when the traveler handed in is locked**. Says what the new revision no longer carries (`amendment_dropped`: an award that was not in effect, the buyer's signatures) |
| `sje_quote` | seller | Attach a quote; binding hash computed server-side; ITAR + schema guards |
| `sje_evaluate` | buyer | Every quote, with everything an award would commit to: each price line, NRE, freight, tax, currency, lead time, validity and expiry, `need_by_feasible`, each exception's `price_delta`, whether assumptions/capacity are present, the quote's content hash, an itemized total at the target quantity, award blockers, and — with a root and a directory — the seller's signature check, which is the only thing that says who the seller is. The quote itself, including the seller it names for itself, is returned whole under `quote` |
| `sje_award` | buyer | Award one bound, unexpired quote + ops + ship-to → **L2, locked**. `expected_traveler_hash` is **required**; `qty` must be a JSON integer the quote has a price line for. The award is **not signed** (see below) |
| `sje_identity` | any | Mint this desk's ML-KEM identity **on the server**: writes the keystore to `SJE_KEYSTORE` (never overwrites one), returns only the public `directory_entry` and, if asked, up to 64 public one-time prekeys. Takes no passphrase; returns no keystore |
| `sje_prekeys` | any | Mint up to 64 more one-time prekeys into the **existing** keystore and return their public halves. The identity is unchanged. A keystore holds at most 1,024 unspent prekeys |
| `sje_seal` | any | Encrypt a traveler to a recipient org whose key comes from a directory that verifies against the pinned root. **Seals only the recipient's part** (see below) and says what it left out (`sent`, `withheld`). Refuses an `itar: true` traveler unless the directory attests the recipient for ITAR (or the recipient is the buyer the traveler names). Reports `recipient_org`, the key used, `forward_secret` — with the `prekey_id` it spent, or `not_forward_secret_because`. Takes `exclude_prekey_ids` |
| `sje_open` | any | Decrypt a received `.sje` with this desk's keystore, run the full defensive import, verify, and apply the receive policy. Reports `authenticity`. Takes `expected_traveler_hash`, `expected_buyer_org`, `accept_unverified_award`. A refusal for the wrong buyer does not repeat the org the document names for itself |

### What `sje_seal` sends

A traveler accumulates every seller's quote. Sealing used to encrypt all of it to
whoever was named, so a buyer's agent re-sending an RFQ handed one seller another's
price, and a losing bidder was told who won and where the parts ship. `sje_seal` now
seals what the recipient is entitled to see — the rule is the library's
(`sealTraveler`, `projection.ts`), not this server's:

- the **buyer org the traveler names** receives all of it;
- **anyone else** receives the quoteable body and its signatures, the quotes that name
  the recipient as seller, the quotes that name this desk's own org as seller
  (`SJE_ORG`), and the award — with ship-to, ops and as-built data — only when the
  awarded quote is one of those.

The result says what went into the envelope: `sent: { quotes, award }` and
`withheld: { quotes, award }`, with a note when anything was withheld. The body, its hash
and the buyer's signatures are unchanged, so what the recipient opens still verifies.
**No argument widens this**: an agent cannot be talked into sending a competitor's quote.
Org ids here are the document's own claims — the rule decides what to disclose, not whom
to trust — so it holds for the document as the caller handed it in.

**One-time prekeys are the caller's to track.** A forward-secret seal spends one prekey
of the recipient's bundle and returns its `prekey_id`. A prekey opens exactly one
envelope, and this server remembers nothing between calls: pass every `prekey_id` you
have been given for a bundle as `exclude_prekey_ids` on later seals to it. Without the
list a later seal can pick a prekey already used — an envelope the recipient can never
open, reported as forward-secret. When every prekey is excluded the seal says so and
falls back to a static envelope (or refuses, under `require_forward_secret`).

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
  "status_covers": "the buyer's authorship of the traveler and, if it carries one, the buyer's award. …",
  "directory_source": "operator",  // or "argument": WHICH directory the verdict stood on
  "directory_issued_at": "2026-01-01T00:00:00.000Z",
  "directory_valid_until": "2030-01-01T00:00:00.000Z",
  "trust_root_fingerprint": "09cb 9e82 d269 7c0c 6307 78c7 9a06 1c46",
  "demo_anchor": false
}
```

`status` is about the **buyer**: who wrote the traveler and, if there is one, the award.
It says nothing about the quotes — each quote's seller signature is its own answer under
`quotes`, and a quote can be unsigned, or signed with a key this directory does not list,
on a traveler whose status is `verified`.

- **verified** — a buyer signature verifies and, if there is an award, so does
  the buyer's award signature. It names the org that *signed*, which is not
  necessarily the org you expect: compare `verified_buyer_org` yourself, or pass
  `expected_buyer_org`. A display name is never evidence.
- **unverified** — a root and a directory were available and that was not
  established (unsigned, or signed with a key the directory does not list).
- **unverifiable** — the server had no trust root or no usable directory.

A signature that is present and **fails** is refused — the buyer's, the award's,
or a seller's on a quote: a changed body, a signer from another org, or a key the
directory lists as **revoked** (reported as such, with the key and the org it
belonged to; no acknowledgment covers it). A signature that cannot be *checked* —
a key the directory does not list, or one outside its window — is not a failure:
the result says so and nothing is established. The refusal carries `authenticity`,
so the caller can see which check failed without being handed the document.

An award that is not verified as the buyer's is **refused by default**, with the
statements the caller must accept; after confirming the award with the buyer out
of band, retry with `accept_unverified_award: true` and the result carries those
statements verbatim under `unverified`.

A ship-to, an ops list or as-built data on a traveler that carries **no award** is
returned as it arrived, and `notes` says what it is: nothing signed covers it, and
whoever sealed the copy could have written it. (A buyer may send draft ops with an
RFQ; a seller can as easily return a ship-to of its own. The hash and the buyer's
signature cover the quoteable body only, so every expectation still matches.)

A one-time prekey is spent only when the traveler is admitted and the result has
been built: a refusal spends nothing, and the same envelope can be opened again.
The keystore file is rewritten without the prekey *before* the prekey is forgotten,
so a failed write also spends nothing.

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
  org key elsewhere (the demo does this in-process). The same goes for one-time
  prekeys: `sje_identity` and `sje_prekeys` return their public halves, and a
  sender can use them only from a prekey bundle signed with the org's directory
  key, outside this server.
- **One-time prekeys run out, and anyone can spend them.** Each forward-secret
  envelope this desk admits spends one. A prekey's public half is in a published
  bundle, so any party holding the bundle can seal to it; when none are left,
  senders fall back to static envelopes (and say so). `sje_prekeys` mints more;
  it cannot stop a pool being used up.
- **One keystore-changing step at a time.** Recording a spent prekey and minting
  new ones each rewrite the keystore file. They take turns within a server, and a
  server never writes over a file another process has changed since it last
  looked (it reloads and the call is refused with "call again"). Two processes
  that both pass that check in the same instant can still race: that needs a lock
  both honour, which a file does not have.
- **Directory freshness.** Without `SJE_DIRECTORY_FILE`, a root-signed directory
  passed as an argument is accepted for as long as its own validity window lasts,
  even if a newer one exists — a superseded directory that still lists a since-revoked
  key verifies, and nothing here can know. With it, an argument is accepted only if it
  is the operator's directory or was issued strictly after it (an expired operator
  file still counts; one that cannot be authenticated blocks every argument). "Newer"
  is the directory's own `issued_at`: the format has no serial number, so an argument
  newer than the operator's file may itself have been superseded.
- **ITAR.** `sje_quote` and `sje_award` apply the traveler's self-declared ITAR
  consistency rule only. The directory's attestation gates `sje_seal`, and is
  reported per quote by `sje_evaluate`.
- **`price_delta`.** The format does not say whether an exception's `price_delta`
  is per unit or per order; totals add each once, and say so.
- **Verification work.** A call verifies the key directory once (twice for an
  ITAR evaluation), whatever the traveler carries, and then each signature
  present: at most 8 on the traveler, one on the award and one on each of at
  most 64 quotes. Every signed quote gets a real verdict; none is skipped. The
  traveler's own state is established once per call, not once per quote.
- **Result size.** Results are one line of compact JSON, at most a small multiple of
  the (capped) inputs, with a 4 MiB backstop. `sje_open` builds its result before
  it spends the one-time prekey.

## Requests are read as text first

By the time a tool handler sees its arguments, the MCP SDK has parsed the request —
and two things have already happened that this server would never do with an
argument. A member name given **twice** has silently become its last value, at any
depth (inside a document passed as an object, too). And an argument named
`__proto__` has been dropped by the SDK's own schema, so "never ignores an argument
it does not know" was untrue for that one name.

So each request line is checked as text before the SDK reads it. One that repeats a
member name within an object, names a member `__proto__` (however it is spelled), or
nests deeper than any request can, is answered with a JSON-RPC error (`-32600`) and
goes no further. A notification that fails the check has no id to answer and is
dropped.

What this cannot see is whatever produced the text. A host that turns a model's tool
call into an object and serializes it again has already resolved a repeated name, its
own way, before a byte reaches this process. For a document received from a
counterparty, pass its **text** (a string) rather than an object you built from it:
the strict text rules of the format — repeated names, number spelling, a byte-order
mark — can only be applied to text that still exists.

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
regardless of the prompt. Tests: `mcp/mcp.test.ts` and `mcp/lifecycle.test.ts`
(both run in `npm test`); claims mapping: `docs/CLAIMS.md` §MCP surface.
