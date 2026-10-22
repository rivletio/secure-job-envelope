# SJE architecture — a developer's map

High-level orientation for anyone about to work on the code. It explains how the
pieces fit together and where things live, so you can find the right file fast.

- New to the project? Read the [README](../README.md) for the one-paragraph pitch.
- Want to *use* it? [GUIDE.md](GUIDE.md) is the hands-on manual with runnable
  walkthroughs across all four surfaces.
- Need the exact bytes? [SPEC.md](SPEC.md) (base format) and
  [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md) (encrypted envelope) are the wire truth.

This document is the layer in between: how the repository is organized, how a job
flows through it, and how the surfaces are held together.

---

## One library, four surfaces

There is a single source of truth — the TypeScript reference library in
`src/lib/traveler`. Everything else is a thin surface over it, plus one
deliberately independent Rust implementation that must agree with it byte for byte.

```
                      ┌───────────────────────────────┐
                      │   src/lib/traveler  (library)  │   ← the reference impl
                      │  canonical JSON · SHA-384 hash │     everything TS calls this
                      │  guards · signatures · envelope│
                      └───────────────────────────────┘
                        ▲        ▲          ▲        ▲
        ┌───────────────┘        │          │        └───────────────┐
        │                        │          │                        │
┌───────────────┐      ┌──────────────┐  ┌──────────────┐   ┌──────────────────┐
│ Browser desk  │      │  MCP server  │  │   examples/  │   │       sim/       │
│ src/routes +  │      │    mcp/      │  │  runnable    │   │ soak · fuzz ·    │
│ src/components│      │ agent tools  │  │  walkthroughs│   │ differential     │
└───────────────┘      └──────────────┘  └──────────────┘   └──────────────────┘

        ┌──────────────────────────────────────────────────────────────┐
        │  crates/secure-job-envelope  (independent Rust impl + CLI)     │
        │  no shared code — held to the TS impl by a golden vector       │
        └──────────────────────────────────────────────────────────────┘
```

| Surface | Where | What it is |
|---|---|---|
| **Library** | `src/lib/traveler` | the TypeScript reference implementation — the only place the format logic lives |
| **Browser desk** | `src/routes`, `src/components` | a local workbench (TanStack Start) that drives the full L0→L2 flow by hand |
| **MCP server** | `mcp/` | the library exposed as Model Context Protocol tools, so AI agents can compose/quote/award/seal/open |
| **Rust CLI** | `crates/secure-job-envelope` | an independent second implementation + `envelope hash\|level` CLI, with no Node in the loop |

The `examples/` scripts and the `sim/` harness are additional consumers of the
library (worked walkthroughs and the fuzz/soak/differential suites).

---

## The repository at a glance

| Path | Purpose |
|---|---|
| `src/lib/traveler/` | the reference library (data model, hashing, guards, crypto transport, keystore) |
| `src/routes/`, `src/components/` | the browser desk (UI over the library) |
| `src/lib/traveler/store.ts`, `keys-store.ts` | desk client state (zustand + localStorage) |
| `mcp/` | MCP server (`server.ts`), the two-desk agent demo (`demo.ts`), its tests |
| `crates/secure-job-envelope/` | the independent Rust implementation + CLI |
| `examples/` | worked traveler files + three runnable examples (lifecycle / signatures / exchange) |
| `sim/` | cross-impl soak, differential fuzzer, and corpus generator |
| `conformance/` | language-agnostic conformance vectors (both impls run the same files in CI) |
| `public/schemas/` | JSON Schema 2020-12 for traveler and quote |
| `site/` | the static demo PWAs (plain Vite) — the public GitHub Pages landing + two demos |
| `scripts/build-pages.mjs` | assembles the Pages publish directory from the site + desk builds |
| `docs/` | spec, guide, this map, claims register, envelope draft, diagrams |
| `spec/` | the BDD design spec (Gherkin) — intent, not yet executed in CI |

---

## The data model

A **traveler** is one manufacturing job for one part family. It carries a
*quoteable body* (buyer, part, material, quantity, need-by, Incoterms, ITAR flag)
plus *lifecycle fields* added as the job progresses (quotes, award, ops traveler,
ship-to, as-built). Two ideas make the file usable as a system of record without a
shared database:

1. **Content addressing.** `traveler_hash` is a **SHA-384** over the *canonical*
   quoteable body. Canonicalization is defined so both implementations produce the
   same bytes — ambiguous numbers (exponential notation) are *refused*, not hashed.
   A hash therefore means exactly the same thing to both parties.

2. **The conformance ladder.** A traveler advances as it gains the ingredients each
   level needs:

   | Level | Name | It has |
   |---|---|---|
   | D | Draft | not yet quoteable |
   | L0 | Quoteable | material + quantity known |
   | L1 | Awardable | ≥1 quote bound to the current hash |
   | L2 | Executable | an awarded quote + ops + ship-to (then it **locks**) |
   | L3 | As-built | as-built data recorded |

On top of that, SJE adds three security properties: **integrity + binding** (a
quote binds to the exact revision it priced), **authenticity** (ML-DSA-87 signatures
verified against a signed directory), and **confidentiality** (a post-quantum
encrypted `.sje` envelope on the wire).

---

## The library module map (`src/lib/traveler`)

The public entry is `index.ts` (a barrel re-export). The modules, grouped by job:

**Format core**
| Module | Responsibility |
|---|---|
| `types.ts` | the TypeScript types for a traveler, quote, award, directory, envelope |
| `schema.ts` | zod schemas / runtime validation of untrusted input |
| `canonical.ts` | canonical-JSON serialization (the exact bytes that get hashed) |
| `hash.ts` | `travelerHash` — SHA-384 over the canonical quoteable body |
| `conformance.ts` | the D→L3 ladder: what level a traveler is at, and why |
| `guards.ts` | invariants and defensive checks on state transitions |
| `datetime.ts`, `ids.ts`, `bytes.ts`, `format.ts` | strict datetimes, id minting, byte/base64 helpers, display formatting |

**Archive + crypto**
| Module | Responsibility |
|---|---|
| `zip.ts` | the `.traveler.zip` archive: build, and the hardened defensive import |
| `signature.ts` | ML-DSA-87 authorship signatures over the canonical body |
| `directory.ts` | the signed key directory (resolve an org → its attested keys) |
| `prekeys.ts` | one-time prekey bundles for forward secrecy |
| `envelope.ts` | the `.sje` envelope: ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM (static 0.1 and forward-secret 0.2) |
| `keystore.ts` | the passphrase-encrypted vault (scrypt + AES-256-GCM) holding the ML-KEM decryption secret |
| `transport.ts` | `sealTraveler` / `openTraveler` — verify the directory, then seal/open; the layer the desk and MCP call |
| `authenticity.ts` | ties signature + directory verification into a receive-side check |
| `disclosure.ts` | what a courier may see before both sides opt in (tested list) |

**Desk + demo support**
| Module | Responsibility |
|---|---|
| `store.ts` | desk traveler/lifecycle state (zustand `persist` → localStorage) |
| `keys-store.ts` | desk key/trust-anchor state (identity, loaded trust anchor) |
| `demo-trust.ts` | a self-contained demo trust anchor so the desk's seal flow works with one click |
| `fixtures.ts` | seeded demo travelers and quotes |
| `network.ts` | the demo shop directory used by the desk's role switch |

The dependency direction is one-way: format core → archive/crypto → surfaces.
The desk and MCP never re-implement format logic; they call `transport.ts`,
`hash.ts`, `conformance.ts`, etc.

---

## How a job moves

**Lifecycle (compose → award).** Buyer composes a traveler (L0). A seller attaches
a quote bound to the current `traveler_hash` (L1). If the buyer amends the spec the
hash moves and prior quotes are stale-marked — a price can never silently apply to a
spec it did not cover. Awarding a bound quote with ops + ship-to reaches L2 and the
traveler **locks**. The quoteable hash is unchanged by the award, so what the seller
quoted still verifies at delivery. Over MCP this is `sje_compose` → `sje_quote` →
`sje_amend` → `sje_award`; the binding hash is always computed server-side, so a
binding is earned, never asserted through tool input.

**Transport (seal → open).** `sealTraveler` verifies the directory against the trust
root, resolves the recipient org to an attested ML-KEM key, and encrypts the archive
bytes into a `.sje` — forward-secret when a verifying prekey bundle exists, with an
explicit, reported fallback to the static envelope (`requireForwardSecret` refuses to
downgrade). `openTraveler` decrypts with the unlocked keystore and runs the same
hardened archive import. Sealing needs only public keys; only opening needs an unlock.

---

## The Rust twin and cross-impl testing

The TypeScript and Rust implementations share no code — no wasm bridge. They are held
together by a **golden test vector**
(`crates/secure-job-envelope/tests/golden.json`): both must produce the same hash for
the same body, byte for byte. Three mechanisms keep them honest, all in CI:

- **Conformance vectors** (`conformance/`) — both impls reproduce the same files.
- **Differential fuzzer** (`sim/differential.ts`) — seeded documents fed to both; zero
  divergence required.
- **Soak + corpus** (`sim/soak.ts`, `sim/corpus.ts`) — many jobs exercising lifecycle,
  crypto, and transport invariants; the committed fuzz corpus must still be what the
  generator produces.

Every written security claim maps to one passing test in [CLAIMS.md](CLAIMS.md); if a
claim is not in that register with a test, treat it as unverified.

---

## Build, run, test

```bash
npm install
npm run dev          # the browser desk (SSR dev server)
npm test             # TS suite: hashing, guards, archive, keystore, transport, MCP
npm run typecheck    # tsc --noEmit
npm run lint         # eslint
npm run build        # the default (SSR) desk build
npm run demo         # two MCP desks exchange one ENCRYPTED job end to end

npm run example:lifecycle    # compose → quote → amend → award
npm run example:signatures   # sign, verify, refuse tamper / wrong org
npm run example:exchange     # encrypt, open, refuse the attacks

npm run soak         # hundreds of jobs; lifecycle + crypto + transport invariants
npm run differential # seeded TS↔Rust differential fuzz (0 divergence)
npm run corpus       # regenerate the committed cross-impl fuzz corpus

cd crates/secure-job-envelope && cargo test   # Rust: unit + golden + shared vectors
```

CI (`.github/workflows/ci.yml`) runs every enforced suite plus a cross-implementation
job. See the README's "What is tested, and where" for the full matrix.

---

## The website and the desk build (GitHub Pages)

The public site at **https://rivletio.github.io/secure-job-envelope/** is a static
bundle assembled from two separate builds and deployed by
`.github/workflows/pages.yml` on every push to `main` (and on manual dispatch).

1. **Demo site** — `npm run site:build` builds `site/` with plain Vite (no server) at
   base `/secure-job-envelope/` into `site/dist`. It is the landing page plus two demo
   PWAs (`lifecycle.html`, `exchange.html`) that import the real library and run the
   post-quantum crypto entirely in the browser.
2. **Desk SPA** — `npm run desk:build` runs `DESK_STATIC=1 vite build`, which switches
   the TanStack Start config (`vite.config.ts`) into SPA mode (no nitro server) and
   base `/secure-job-envelope/desk/`, emitting a prerendered `_shell.html` + assets
   into `dist/client`. The desk is fully client-rendered from localStorage.
3. **Assemble** — `node scripts/build-pages.mjs` composes `_pages/`: the demo site at
   the root, the desk under `/desk/`, and the desk shell copied to both `desk/index.html`
   and the site-root `404.html`. The 404 copy is the SPA deep-link fallback — GitHub
   Pages serves it for any miss while preserving the URL, so the client router resolves
   deep links like `/desk/t/<id>` on reload.

Local preview tip: for serving at `/` instead of the Pages base, build the site with
`SITE_BASE=/ npm run site:build`.

---

## Extending SJE

- **Add or change a traveler field.** Start in `types.ts` and `schema.ts`. If the field
  is part of the *quoteable body* it is **hash-affecting**: update `canonical.ts`, bump
  the conformance vectors and the golden vector, and mirror the change in the Rust impl
  (`crates/.../src/`) so the differential and golden tests stay green. If it is a
  lifecycle field, it is outside the hash — update `guards.ts`/`store.ts` and tests.
- **Touch the crypto or envelope.** `envelope.ts` + its Rust twin + the envelope
  vectors; keep the explicit, reported forward-secrecy fallback intact. Update
  [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md) and the relevant [CLAIMS.md](CLAIMS.md) rows.
- **Add a surface.** Call the library — do not re-implement format logic. The MCP server
  and desk are the models to copy.

A rule of thumb: anything that changes the bytes that get hashed is a spec change and
must land in both implementations plus the vectors. Everything else is a surface detail.

---

## Where to go next

- [GUIDE.md](GUIDE.md) — the hands-on manual (runnable walkthroughs, per surface).
- [SPEC.md](SPEC.md) — the frozen base format (canonical JSON, hash, ladder, archive).
- [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md) — the encrypted envelope and forward secrecy.
- [CLAIMS.md](CLAIMS.md) — every security claim mapped to its proof.
- [../SECURITY.md](../SECURITY.md) / [../TRUST.md](../TRUST.md) — threat model and the
  honest limits.
- [DISCLOSURE.md](DISCLOSURE.md) — what a courier may see before both sides opt in.
- [diagrams/](diagrams/) — living mermaid diagrams (use cases, spec tree, work map).
