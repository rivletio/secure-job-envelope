# Secure Job Envelope (SJE)

**A content-addressed job envelope for parts manufacturing.**
`application/vnd.sje+json` · spec `sje/0.1.0` · MIT

A **traveler** is the job object — one part family moving between a buyer and a
seller: part, material, quantity (with price breaks), need-by, ship-to, the
quotes it attracted, and the award. It is **not** a shop OS and **not** a
marketplace. Coordination happens through the *file*: shops seal a traveler into
an **encrypted `.sje` envelope** (post-quantum — ML-KEM-1024 + AES-256-GCM) and
send that over whatever channel they already use; the plaintext
`{traveler_id}.traveler.zip` stays a local copy, not the thing on the wire. Every
implementation that follows this spec computes the same `sha384:…` hash for the
same quoteable body — so a quote can bind to *exactly* the revision it priced.

What the file shows, and what a courier may say before both sides opt in, is [docs/DISCLOSURE.md](docs/DISCLOSURE.md). That list is tested. The hash does not hide the file. Anyone who holds the traveler can read it.

This format is open source. [Claanker](https://github.com/rivletio/claanker) uses it. After both sides opt in, Claanker carries a sealed traveler, PO, job, bill of lading, or envelope and does not open it. See [docs/CLAANKER.md](docs/CLAANKER.md).

```
Buyer composes traveler  ──►  L0 Quoteable   (can price without guessing)
Sellers attach quotes  ──►  L1 Awardable   (quotes bound to traveler_hash)
Buyer awards + ops     ──►  L2 Executable  (locked; traveler + ship-to)
                            L3 As-built    (as-built data recorded)
```

This repo contains:

| Path | What it is |
|---|---|
| `docs/PLAN.md` | Project plan: goals, milestones, current state (shalt manages the live copy in `.shalt/plan.md`) |
| `docs/CLAANKER.md` | How Claanker carries a sealed envelope and does not open it |
| `docs/diagrams/` | Living mermaid: use cases, spec tree, play pipeline, work map |
| `docs/SPEC.md` | The 0.1.0 spec: quoteable body, canonical JSON, hash, conformance ladder, archive layout |
| `public/schemas/` | JSON Schema 2020-12 for traveler and quote |
| `src/lib/traveler/` | Reference **TypeScript** implementation (canonicalization, hashing, guards, zip import/export, encrypted transport + passphrase keystore) |
| `crates/secure-job-envelope/` | Independent **Rust** implementation + CLI (`envelope hash|level`) |
| `src/` (the rest) | The **desk** — a browser workbench that demonstrates the full L0→L2 flow |
| `examples/` | A worked example traveler and how to verify it with both implementations |
| `mcp/` | **MCP server + two-desk agent demo** — buyer and seller agents transacting over sealed travelers (`npm run demo`) |
| `conformance/` | Language-agnostic conformance vectors — both implementations run the same files in CI |
| `docs/CLAIMS.md` | The claims register: every written security claim mapped to the test that proves it |
| `docs/ENVELOPE-DRAFT.md` | 0.1 draft: post-quantum encrypted envelope (`.sje`) |
| `TRUST.md` | Honest SOC 2 TSC mapping: what this gives you, what it does not |
| `SECURITY.md` | Threat model and how to report issues |

Hashing is **SHA-384** — selected for post-quantum collision margins (see
`SECURITY.md`), chosen before first release to avoid a later hash migration.

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
npm test           # TS suite: hashes, guards, zip, schema contract, MCP
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

## What is tested, and where

CI (`.github/workflows/ci.yml`) runs every enforced suite: the TypeScript
tests (`npm test` — the traveler suite, the shared conformance vectors, strict
datetimes, the published-schema contract, and the MCP surface), the two-desk MCP
demo (`npm run demo`), the Rust crate (`cargo test` inside
`crates/secure-job-envelope`, including the fuzz-corpus replay), and a
cross-implementation job (`crossimpl`) that runs the lifecycle soak
(`npm run soak`), the TypeScript↔Rust differential fuzzer (`npm run differential`),
and a check that the committed fuzz corpus is still what the generator produces.
The TypeScript and Rust implementations must reproduce the shared conformance
vectors byte for byte and agree on every document the differential feeds them,
and every statement in [`docs/CLAIMS.md`](docs/CLAIMS.md) maps to one of these.

The `spec/*.feature` files are the **BDD design spec** — 88 Gherkin scenarios
of intended desk behavior, managed by the `shalt` workflow. They document
intent and are **not yet executed in CI**; their behaviors are covered today by
the suites above. Run the implementation's Rust tests from inside
`crates/secure-job-envelope` (the repo root also carries a `shalt` scaffold, so
`cargo test` there exercises the BDD harness, not the implementation).

## What 0.1 resolves — and the edges that remain

0.1 addresses the five caveats 0.0.1 flagged, each proven across both
implementations — golden vectors for the crypto, and shared structural parity
plus the TypeScript↔Rust differential for integer money and award terms (see
`docs/CLAIMS.md`):

- **Party authentication — post-quantum signatures.** ML-DSA-87 (FIPS 204)
  authorship signatures over the canonical body, verified against a signed key
  directory: a signature whose key's org does not match the body's `org_id`
  fails verification. (The hash itself is still integrity, not a signature;
  authorship is the separate signature.)
- **Identity via the directory.** `org_id` is bound to a key in the signed
  directory. There is still no multi-tenant access-control layer — that sits
  above the format.
- **`itar` is directory-attested.** An ITAR traveler's seller must hold the
  directory's attested ITAR capability, not merely self-declare `seller.itar`.
  Still not DDTC registration or a Technology Control Plan — do not put actual
  USML/EAR technical data in a browser demo (see `TRUST.md`).
- **Money is integer minor units** of an ISO-4217 currency — exact, no IEEE-754.
- **An award can carry commercial terms** (governing law, warranty, payment) —
  closer to a purchase order, though still not a contract by itself.

Remaining honest edges: forward secrecy is opt-in — the transport prefers the 0.2
envelope (`sje-envelope/0.2.0`, single-use prekeys + a two-KEM combine) when a
verifying prekey bundle is present and **reports** the choice; the fallback to the
base 0.1 envelope is explicit, never silent (`requireForwardSecret` refuses to
downgrade), and realizing forward secrecy depends on the recipient deleting the
consumed one-time secret after opening. Key custody: the browser desk now holds its
ML-KEM **decryption** secret, but only in a passphrase-encrypted keystore (in memory
only while unlocked — an XSS on an unlocked desk can read it); it still never holds
**signing** keys. See `SECURITY.md`.

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

## Disclaimer

SJE is provided under the MIT License, "as is" and without warranty of any kind (see [LICENSE](LICENSE)). Nothing here — the spec, the implementations, the desk, or the security docs — is a warranty, guarantee, or assurance of security, correctness, or fitness for any purpose. Its security is best-effort and has not been independently audited. Selecting NIST/CNSA 2.0 algorithms is an engineering choice, not a certification: SJE is not SOC 2, FIPS, CNSA 2.0, ITAR, DFARS, or NIST 800-171 compliant, and using it does not make your system compliant. It is not legal or export-control advice — meeting your ITAR/EAR and CUI (DFARS 252.204-7012 / NIST 800-171) obligations is your responsibility, and controlled technical data does not belong on a shared browser desk. To the fullest extent permitted by law, Rivlet, Inc. accepts no liability arising from use of this software.
