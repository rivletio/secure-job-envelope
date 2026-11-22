# SJE guide — a practical manual

A hands-on walkthrough of the Secure Job Envelope: what it is, how a job moves
through it, and how to drive it from each of the four surfaces (the TypeScript
library, the Rust CLI, the MCP server, and the browser desk). Every walkthrough
below maps to a **runnable example** you can execute right now.

New to the project? Read the [README](../README.md) first for the one-paragraph
pitch, then come back here to actually use it. To find your way around the codebase,
see [ARCHITECTURE.md](ARCHITECTURE.md). For the exact wire formats see
[SPEC.md](SPEC.md) and [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md); for the security
posture, [SECURITY.md](../SECURITY.md) and the proof map in [CLAIMS.md](CLAIMS.md).

---

## 1. Install and verify

```bash
npm install
npm test          # TypeScript suite (parsing, guards, keystore, transport, MCP)
npm run build     # the browser desk builds
npm run demo      # two MCP desks exchange one ENCRYPTED job end to end
```

The three worked examples run standalone and each exits non-zero if an invariant
fails, so they double as living documentation **and** smoke tests:

```bash
npm run example:lifecycle    # compose → quote → amend → re-quote → award
npm run example:signatures   # sign a traveler, verify, refuse tamper / wrong org
npm run example:exchange      # encrypt to a recipient, open, refuse the attacks
```

The independent Rust core builds and verifies the same vectors:

```bash
cd crates/secure-job-envelope && cargo test
```

### The four surfaces

| Surface | What it is | Use it to |
|---|---|---|
| **Library** (`src/lib/traveler`) | the TypeScript reference implementation | build on SJE in code; everything else calls this |
| **Rust CLI** (`crates/secure-job-envelope`) | an independent second implementation + `envelope` CLI | verify a file's hash/level with no Node in the loop |
| **MCP server** (`mcp/`) | the library exposed as Model Context Protocol tools | let AI agents on each side compose, quote, award, seal, open |
| **Browser desk** (`src/routes`) | a local workbench (`npm run dev`) | compose/quote/award by hand; manage keys; seal & send |

---

## 2. Mental model

A **traveler** is one manufacturing job for one part family, moving between a
buyer and a seller. It carries a *quoteable body* (buyer, part, material,
quantity, need-by, Incoterms, ITAR flag) plus *lifecycle fields* added as the job
progresses (quotes, the award, the ops traveler, ship-to, as-built).

Two ideas make the file usable as a system of record without a shared database:

- **Content addressing.** `traveler_hash` is a SHA-384 over the *canonical*
  quoteable body. Both implementations compute it byte-for-byte identically, so a
  hash means the same thing to both parties.
- **The conformance ladder.** A traveler advances through levels as it gains the
  ingredients each one needs:

  | Level | Name | It has |
  |---|---|---|
  | D | Draft | not yet quoteable |
  | L0 | Quoteable | material + quantity known |
  | L1 | Awardable | at least one quote bound to the current hash |
  | L2 | Executable | an awarded quote + ops + ship-to (then it **locks**) |
  | L3 | As-built | as-built data recorded on the executed traveler |

SJE adds three security properties on top, each demonstrated by one example below:

1. **Integrity + binding** — a quote binds to the exact revision it priced.
2. **Authenticity** — ML-DSA-87 authorship signatures verified against a signed
   key directory.
3. **Confidentiality** — a post-quantum encrypted `.sje` envelope on the wire.

---

## 3. Walkthrough A — the lifecycle

```bash
npm run example:lifecycle
```

[`examples/lifecycle.ts`](../examples/lifecycle.ts) drives the real store state
machine (the same code the desk uses). It shows the two guarantees that matter:

- **Binding.** The seller quotes against `traveler_hash`. When the buyer amends
  the spec, the hash moves and the quote is **stale-marked** — it no longer
  counts, so a price can never silently apply to a spec it did not cover. A
  different shop then quotes the new hash.
- **The lock.** Awarding a bound quote (with ops and ship-to) reaches **L2**, and
  the traveler becomes immutable — `amend` on it is a no-op. The quoteable hash is
  unchanged by the award, so the hash the seller quoted still verifies at delivery.

The same flow by hand on the desk: `npm run dev`, compose on **New traveler**,
switch the role toggle to **Seller** to attach a quote, then **Award** as the
buyer. Over MCP it is `sje_compose` → `sje_quote` → `sje_amend` → `sje_award`;
the binding hash is always computed server-side, so a quote binding cannot be
asserted through the tool input, only earned.

---

## 4. Walkthrough B — authenticity (sign & verify)

```bash
npm run example:signatures
```

[`examples/signed-traveler.ts`](../examples/signed-traveler.ts) publishes a signed
key directory binding `org_northline` (the buyer) and `org_summitfab` (a competing
bidder) to signing keys, has the buyer sign the quoteable body **and the award**
(ML-DSA-87), and then verifies both:

- a genuine signature **verifies** and reports the author org;
- a one-field tamper no longer verifies;
- a signature whose key's org does not match the body's author org is **refused**
  (authorship must bind to an org — a missing `org_id` is a hard failure);
- the buyer's **award signature** (award decision + ship-to) verifies, while a
  redirected ship-to and a losing bidder's forged award — the latter sealed to the
  winner with the bidder's *own* key — are both **refused**: a non-buyer cannot
  produce the buyer's award signature. This closes the business-email-compromise
  gap — anyone holding a recipient's public key can seal an envelope to them, so an
  award or ship-to that the buyer did not sign is not trusted;
- the award also **binds the awarded quote's priced content** (via `quote_hash`), so a
  swapped unit price on the awarded quote — even an unsigned one — is **refused**.

Signing lives in the library / CLI / server. The browser desk only ever
*verifies* — it must never hold ML-DSA signing keys (see
[SECURITY.md](../SECURITY.md)). In 0.1 the buyer signs the quoteable body and,
separately, the award (award decision + ship-to); the desk **verifies both on
receive** — the **Authenticity** panel on a traveler checks them against the trust
anchor loaded in **Keys**.

Verifying is not the same as accepting. What a receiver *does* with the verdicts is
the **receive policy** (`src/lib/traveler/import-policy.ts`), shared by the desk and
the MCP server:

- a signature that is present and **fails** is refused — the buyer's, the award's, or
  a seller's on a quote; a changed body, a signer from another org, or a key the
  directory lists as **revoked**;
- a signature that cannot be **checked** (no trust anchor, a key the directory does not
  list or one outside its window) establishes nothing: the traveler is admitted as
  unverified and says so;
- an **award** that is not verified as the buyer's is taken only after the reader
  acknowledges what is unproven (on the desk), or is refused by default (over MCP);
- over a copy already held: an older revision, the same revision with different
  content, or a different buyer is refused; quotes are added, never dropped; an award
  verified as the buyer's cannot be replaced, and an unverified one yields to it;
- a ship-to or ops list that arrives **without** an award is a draft nobody signed: it
  is never merged into a held copy, and on a new traveler it is said to be one.

---

## 5. Walkthrough C — confidentiality (encrypt & send)

```bash
npm run example:exchange
```

[`examples/encrypted-exchange.ts`](../examples/encrypted-exchange.ts) runs a full
post-quantum exchange between two desks: it mints two identities, publishes a
signed directory and the seller's one-time prekey bundle, seals the traveler into
a **forward-secret `.sje`** envelope, opens it, and then shows the attacks the
transport refuses (a ciphertext byte-flip, the wrong keystore, a forged envelope
that must not burn a real prekey, and a refused silent downgrade).

Three parts cooperate:

- **Keystore** (`src/lib/traveler/keystore.ts`) — a passphrase-encrypted vault
  (scrypt + AES-256-GCM) holding the ML-KEM *decryption* secret. It is decrypted
  in memory only while unlocked. Sealing needs only public keys, so it works
  locked; opening needs an unlock.
- **Directory + prekey bundle** — public, signed material that resolves a
  recipient org to an attested ML-KEM key (and, for forward secrecy, one-time
  prekeys).
- **Transport** (`src/lib/traveler/transport.ts`) — `sealTraveler` verifies the
  directory against the trust root, then encrypts; `openTraveler` decrypts with
  the unlocked keystore and runs the same hardened archive import. Forward secrecy
  is preferred when a bundle exists and **reported** (`forwardSecret`); the
  fallback to the static envelope is explicit, and `requireForwardSecret` refuses
  to downgrade.

`sealTraveler` also decides **what** is sent and **to whom**, so that no caller has to
remember to:

- **Each recipient is sealed its part of the traveler.** The buyer org the traveler
  names receives all of it. Anyone else receives the quoteable body (same hash, same
  buyer signature), the quotes that are its own or the sender's (`senderOrg`), and the
  award — with ship-to, ops and as-built data — only if the awarded quote is one of
  those. What was left out is reported (`withheld`). A seller is never sent another
  seller's price by default; sending the whole traveler to a non-buyer has to be
  asked for by name (`disclose: "everything"`).
- **A traveler marked ITAR** is sealed only to an org the directory attests for ITAR,
  or back to the buyer org it names; anything else is refused (`SealRefused`). This is
  a consistency rule over a self-declared flag and a directory attestation — it is not
  export control.

### On the browser desk

1. Open **Keys**. Create an identity (passphrase) — it is stored encrypted; the
   public directory entry shown is what you publish so others can seal to you.
2. Load a **trust anchor** (`{ root_public_key_hex, directory, bundles? }`),
   obtained out of band. Confirm the root public key out of band — a swapped root
   lets an attacker forge a directory.
3. On a traveler, **Seal & send** to a directory-attested recipient. Before anything
   is sealed the dialog says what that recipient will **not** be sent — other sellers'
   quotes, and the award unless its quote won — and whether the envelope will be
   forward-secret. Sending the whole traveler instead is a tick you give per envelope.
   A traveler marked ITAR cannot be sealed to an org your directory does not attest
   for ITAR. The download is an encrypted `.sje` with a random filename (it never
   embeds the traveler id). The plaintext `.zip`/JSON exports remain, relabeled
   "local copy" — they are the whole traveler, every quote included.
4. To receive, **unlock** your identity, then **Open .traveler / .sje** — the desk
   decrypts and runs the defensive import.

### Over MCP

Everything that decides whom the desk trusts is set by its **operator**, in the
server's environment. None of it is a tool argument, so nothing an agent reads can
change it:

```bash
SJE_TRUST_ROOT_FILE=/etc/sje/root.hex          # the pinned trust root (or SJE_TRUST_ROOT)
SJE_DIRECTORY_FILE=/etc/sje/directory.json    # the signed directory; re-read on every call
SJE_ORG=org_me                                 # the org this desk acts as
SJE_KEYSTORE=/var/lib/sje/desk.keystore.json   # where the desk's keystore lives
SJE_KEYSTORE_PASSPHRASE=…  npm run mcp
```

The tools then need only public inputs:

```bash
# mint this desk's identity ON THE SERVER: the keystore is written to SJE_KEYSTORE
# (never overwritten); only the public directory entry and prekeys come back
sje_identity { "org_id": "org_me", "prekeys": 8 }
sje_prekeys  { "count": 8 }                    # later: more one-time prekeys, same identity

# seal: the recipient's key comes from a directory the pinned root signed; only the
# recipient's part of the traveler is sealed, and the result says what was left out
sje_seal { "traveler": {…}, "recipient_org": "org_them", "prekey_bundle": {…},
           "exclude_prekey_ids": ["…every prekey_id earlier seals to this bundle returned…"] }

# open: say which document and which buyer you expect; the result says what was verified
sje_open { "sje": {…}, "expected_traveler_hash": "sha384:…", "expected_buyer_org": "org_them" }
```

A passphrase is never an argument and a keystore is never a result. An award that is
not verified as the buyer's is refused unless the caller passes
`accept_unverified_award: true` after confirming it out of band; a signature that is
present and fails — including one made with a key the directory lists as revoked — is
refused whatever is passed. The server signs nothing: a directory entry, a prekey
bundle and an award are signed with the org's ML-DSA key outside it.
[`mcp/README.md`](../mcp/README.md) has every setting, every tool and the limits;
`npm run demo` is a scripted two-desk version of exactly this.

---

## 6. Formats at a glance

- **Traveler JSON** — the quoteable body + lifecycle fields; see the
  [examples](../examples) and [SPEC.md](SPEC.md) for the field set and the
  canonical-JSON / hashing rules.
- **Archive** `{traveler_id}.traveler.zip` — `traveler.json`, a `META.json`
  integrity manifest (required), and an optional canonical body; SHA-384
  cross-checks, allowlisted members, size caps. This is the *payload* of an
  envelope when sent, and a local copy otherwise.
- **Envelope** `.sje` — `sje-envelope/0.1.0` (static) or `0.2.0` (forward-secret);
  ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM. See [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md).
- **Directory + prekey bundle** — signed, public trust material; see the
  signatures section of [CLAIMS.md](CLAIMS.md) (PQ2, PQ8).

---

## 7. Security and boundaries

What is proven maps one-to-one to a passing CI test in [CLAIMS.md](CLAIMS.md), and
both implementations are held to identical verdicts by shared vectors, a
differential fuzzer, and a soak harness. State the limits plainly (full detail in
[SECURITY.md](../SECURITY.md) and [TRUST.md](../TRUST.md)):

- Archive integrity is **unkeyed** (it catches corruption and naive tampering);
  adversarial authenticity is the ML-DSA signature, which in 0.1 signs the
  quoteable body, not the mutable lifecycle fields.
- The keystore protects a stolen blob **without** the passphrase, not script in
  the origin — an XSS on an *unlocked* desk can read the in-memory ML-KEM secret.
  The desk never holds **signing** keys.
- SJE is **not** a compliance system (not SOC 2 / FIPS / CNSA 2.0 / ITAR / DFARS /
  NIST 800-171). Controlled technical data does not belong on a shared browser
  desk; the control environment is the operator's.

---

## 8. Running the proofs

```bash
npm test            # TS: parsing, guards, archive, keystore, transport, MCP
cd crates/secure-job-envelope && cargo test   # Rust: unit + golden + shared vectors
npm run demo        # two MCP desks, one encrypted job (CI)
npm run soak        # hundreds of jobs; lifecycle + crypto + transport invariants
npm run differential # seeded TS↔Rust differential fuzz (0 divergence)
npm run corpus      # regenerate the committed cross-impl fuzz corpus
npm run example:lifecycle && npm run example:signatures && npm run example:exchange
```

## 9. Where to go next

- [ARCHITECTURE.md](ARCHITECTURE.md) — how the codebase is organized (one library,
  four surfaces) and how the site/desk are built and deployed.
- [SPEC.md](SPEC.md) — the frozen base format (canonical JSON, hash, ladder, archive).
- [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md) — the encrypted envelope and forward secrecy.
- [CLAIMS.md](CLAIMS.md) — every claim mapped to its proof.
- [DISCLOSURE.md](DISCLOSURE.md) — what a courier may see before both sides opt in.
- Roadmap (see the README): wiring authorship signatures into the live exchange,
  and a CLI for the encrypted transport.
