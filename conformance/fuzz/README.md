# conformance/fuzz — committed cross-implementation fuzz corpus

A frozen, deterministic selection of the TS↔Rust differential's cases, so each
implementation can replay it in its own test run with nothing else in the loop.

- `cases/<seed>.bin` — one case per file: the **exact bytes** handed to both
  implementations. Many are deliberately not JSON; some are not UTF-8, start with a
  byte-order mark, or end in CR, LF or NUL. They are `binary` in `.gitattributes`:
  never open-and-save one in an editor, never let a tool normalize it.
- `manifest.jsonl` — one line per case:
  `{ file, seed, mutations, bytes, sha384, expected: { accept, hash, level, bound } }`.
  `expected` is the TypeScript reference verdict; `sha384` and `bytes` pin the file's
  content so a silently altered case fails loudly instead of quietly testing
  something else; `mutations` names what was done to a valid traveler to get it
  (`[]` for an unmutated one), each as `name[variant]` from the catalog in `sim/`.

Replayed from the bytes by both sides, every test run:

- Rust: `crates/secure-job-envelope/tests/fuzz_corpus.rs` (`cargo test`) — through the
  library and again through the `envelope check` CLI.
- TypeScript: `sim/corpus.test.ts` (`npm test`) — through `parseTravelerJson(bytes)`.

Agreement of both with the one manifest is agreement between two independent
codebases on parse / hash / level / bind.

## What is in it

The corpus is coverage-driven: for every mutation in the fuzzer's catalog, the first
seeds (from 1,000,001) in which that mutation is the only one applied — one case for
a fixed field mutation, up to three different variants for a family — plus 24
unmutated travelers across the level ladder and 48 stacked cases. That includes the
wire-level classes an audit found the two implementations split on (a struct written
as an array, `__proto__` members, signature shapes, whitespace-like names, duplicate
identifiers, repeated member names, a byte-order mark, invalid UTF-8); the corpus
test asserts they are present and refused.

Two kinds of case are deliberately absent:

- **Half-megabyte cases.** The mutations that work at the 512 KiB size cap
  (`inflate-to-cap`, `pad-to-cap`) and any case over 12 KiB run in the live fuzzer
  only (`npm run differential`).
- **Open findings.** Only verdicts the two implementations *agree* on are frozen.
  A case they judge differently is a bug to fix, not a regression vector; the
  generator reports it and leaves it out, and it is tracked in `sim/findings/`.

## Regenerating

`npm run corpus` (deterministic; needs the Rust CLI built, because of the agreement
check). CI fails if the committed files differ from what the generator produces, and
`npm test` fails if a case is no longer what its seed generates — so a change to the
mutation catalog must be committed together with the regenerated corpus. Any case
reproduces from its seed alone: `npm run differential -- --start <seed> --seeds 1`.
