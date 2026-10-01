# sim/ — soak + cross-implementation differential harness

Test infrastructure for hardening SJE by simulating many jobs, transacting them
through the full lifecycle, and adversarially trying to break the invariants and
the two-implementation parity. Everything here is deterministic in a seed, so any
failure reproduces exactly from the seed it printed. None of it is used at
runtime or for anything security-sensitive (production keys/IDs come from a
CSPRNG; `rng.ts` is mulberry32, for reproducibility only).

## What runs

| command | what it does |
|---|---|
| `npm run soak [-- --jobs N]` | Drives the real store state machine (compose → quote → award → amend) over N seeded jobs and asserts the invariants that must always hold: hash stability, quote binding, level progression, the executable lock, amend invalidation. Then an adversarial battery (hostile documents, wrong-hash/expired/unbound quotes) and a signature/envelope roundtrip + tamper phase against a seeded key directory. |
| `npm run differential [-- --seeds N]` | Generates N seeded travelers (most with one adversarial mutation) and asks **both** implementations for their verdict — parse / hash / level / bound — on the exact same bytes, via the TS reference in-process and the Rust `envelope check` CLI. Any disagreement is a break. Build the Rust CLI first: `cargo build --release --manifest-path crates/secure-job-envelope/Cargo.toml`. |
| `npm run corpus [-- N]` | Regenerates the committed cross-implementation fuzz corpus in `conformance/fuzz/` (documents + the TS reference verdict for each). The Rust core replays it in `cargo test` (`tests/fuzz_corpus.rs`) with no Node in the loop. |

All three run in CI (the `crossimpl` job in `.github/workflows/ci.yml`).

## Files

- `rng.ts` — seeded PRNG (mulberry32).
- `generate.ts` — seeded generators of *valid* travelers/quotes/orgs across the level ladder.
- `mutations.ts` — the adversarial mutation catalog (shared by the differential and the corpus).
- `verdict.ts` — the four-field verdict (parse/hash/level/bound), computed for TS and via the Rust CLI, plus the comparison.
- `directory.ts` — a seeded signed key directory + one-time prekey bundle for the soak's crypto phase.
- `differential.ts`, `soak.ts`, `corpus.ts` — the entry points above.

## How the parity work was found

The differential started by finding **585 divergent documents** between the two
implementations (the Rust core accepted hundreds of documents the zod schema
rejects, and hashed a different byte string for others). Each class was
root-caused and fixed — see `docs/CLAIMS.md` C12–C15 and the commit history — until
the differential was clean across thousands of documents. The harness stays so it
never regresses.
