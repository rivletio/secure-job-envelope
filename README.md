# Secure Job Envelope (SJE)

**A content-addressed job envelope for parts manufacturing.**
`application/vnd.sje+json` · spec `sje/0.0.1` · MIT

A **traveler** is the job object — one part family moving between a buyer and a
seller: part, material, quantity (with price breaks), need-by, ship-to, the
quotes it attracted, and the award. It is **not** a shop OS and **not** a
marketplace. Coordination happens through the *file*: shops exchange
`{traveler_id}.traveler.zip` archives over whatever channel they already use, and
every implementation that follows this spec computes the same
`sha384:…` hash for the same quoteable body — so a quote can bind to
*exactly* the revision it priced.

What the file shows, and what a courier may say before both sides opt in, is [docs/DISCLOSURE.md](docs/DISCLOSURE.md). That list is tested. The hash does not hide the file. Anyone who holds the traveler can read it.

This format is open source. [Claanker](https://github.com/rivletio/claanker) uses it. After both sides opt in, Claanker carries a sealed traveler, PO, job, bill of lading, or envelope and does not open it. See [docs/CLAANKER.md](docs/CLAANKER.md).

```
Buyer composes traveler  ──►  L0 Quoteable   (can price without guessing)
Sellers attach quotes  ──►  L1 Awardable   (quotes bound to traveler_hash)
Buyer awards + ops     ──►  L2 Executable  (locked; traveler + ship-to)
                            L3 As-built    (reserved in 0.0.1)
```

This repo contains:

| Path | What it is |
|---|---|
| `docs/PLAN.md` | Project plan: goals, milestones, current state (shalt manages the live copy in `.shalt/plan.md`) |
| `docs/CLAANKER.md` | How Claanker carries a sealed envelope and does not open it |
| `docs/diagrams/` | Living mermaid: use cases, spec tree, play pipeline, work map |
| `docs/SPEC.md` | The 0.0.1 spec: quoteable body, canonical JSON, hash, conformance ladder, archive layout |
| `public/schemas/` | JSON Schema 2020-12 for traveler and quote |
| `src/lib/traveler/` | Reference **TypeScript** implementation (canonicalization, hashing, guards, zip import/export) |
| `crates/secure-job-envelope/` | Independent **Rust** implementation + CLI (`sje hash|level`) |
| `src/` (the rest) | The **desk** — a browser workbench that demonstrates the full L0→L2 flow |
| `examples/` | A worked example traveler and how to verify it with both implementations |
| `conformance/` | Language-agnostic conformance vectors — both implementations run the same files in CI |
| `docs/CLAIMS.md` | The claims register: every written security claim mapped to the test that proves it |
| `docs/ENVELOPE-DRAFT.md` | 0.1 draft: post-quantum encrypted envelope (`.sje`) |
| `TRUST.md` | Honest SOC 2 TSC mapping: what this gives you, what it does not |
| `SECURITY.md` | Threat model and how to report issues |

Hashing is **SHA-384** — chosen for post-quantum collision margins (see
`SECURITY.md`), locked in before anything shipped so no deployed hash ever
has to migrate.

The TypeScript and Rust implementations are deliberately independent — no
shared code, no wasm bridge — and are held together by a **golden test
vector** (`crates/secure-job-envelope/tests/golden.json`): both must produce the
same hash for the same body, byte for byte. Numbers that would render
differently across languages (exponential notation) are **refused by both
sides** rather than hashed ambiguously; see the canonicalization rules in
[`docs/SPEC.md`](docs/SPEC.md).

**Every security claim is meant to be checkable.** [`docs/CLAIMS.md`](docs/CLAIMS.md)
maps each written claim to the test that proves it — and says plainly which
statements are still drafts with no proof yet. If a claim is not in that
register with a passing test, treat it as unverified.

## Quickstart — the desk

```bash
npm install
npm run dev        # browser workbench
npm test           # traveler test suite (golden hash, guards, zip round-trip)
npm run typecheck
```

The desk stores travelers in your browser's localStorage — it is a
demonstration surface for the format, not a hosted service. The Buyer/Seller
toggle is a *view*, not authentication (see `TRUST.md`).

## Quickstart — the Rust verifier

```bash
cd crates/secure-job-envelope
cargo test         # includes the shared golden vector
cargo run -- hash  ../../examples/bracket.traveler.json
cargo run -- level ../../examples/bracket.traveler.json
```

## What 0.0.1 deliberately does not do

Stated here so nobody discovers it the hard way:

- **The hash is integrity, not a signature.** Anyone can mint a quote
  claiming to be a named shop. Party authentication (signing) is the top
  candidate for 0.1.
- **No identity, tenancy, or access control.** `org_id` is self-asserted.
- **`itar: true` is a self-declaration** with a quote/award consistency
  check — not DDTC registration, not a Technology Control Plan. Do not put
  actual USML/EAR technical data in a browser demo (see `TRUST.md`).
- **Money is IEEE-754** with fixed-notation canonical bounds; a later spec
  should prefer integer minor units if travelers become the commercial record.
- An award is a structured decision, **not a purchase order** — 0.0.1 has no
  governing law, warranty, or payment terms.

## Why a file format

Every job shop already has systems — an ERP it rents, a desktop app it
fears, spreadsheets that hold it together. A coordination *platform* asks
everyone to move in. A coordination *format* meets every shop where it is:
any tool that can read and write a small, hashable JSON envelope can
participate, and the hash means nobody has to trust anyone's database but
their own. The platform can come later; the envelope has to come first.

## Governance

SJE is intended as a **vendor-neutral standard** — the name carries no
company, the spec and both reference implementations are MIT, and
conformance is defined by the public vector suite, not by anyone's
product. Rivlet, Inc. authors the spec today and operates a commercial
**validation and execution service** built on it (envelope.rivlet.io);
the standard is designed so that service has no privileged position —
anyone can implement, validate, and run jobs against the same vectors.

## License

MIT. See [LICENSE](LICENSE).
