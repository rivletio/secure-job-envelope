# conformance/fuzz — committed cross-implementation fuzz corpus

A frozen, deterministic slice of the TS↔Rust differential, so the Rust core can
replay it in `cargo test` with no Node in the loop.

- `travelers.jsonl` — one document per line (exact bytes), a spread of valid
  documents across the level ladder plus adversarial boundary cases.
- `expected.jsonl` — the TypeScript reference verdict for the same line:
  `{ accept, hash, level, bound }`.

`crates/secure-job-envelope/tests/fuzz_corpus.rs` recomputes each verdict in Rust
and asserts it matches the reference. Agreement here is agreement between two
independent codebases on parse / hash / level / bind.

Regenerate with `npm run corpus` (deterministic). CI fails if the committed files
drift from what the generator produces. Documents that cannot round-trip through a
file serde can read (lone surrogates) are excluded here and pinned by a reject
vector in `../travelers/reject/` instead.
