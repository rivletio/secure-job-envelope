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
| `npm run differential [-- --seeds N]` | Builds N seeded fuzz cases — a valid traveler, usually with one to three adversarial mutations stacked on it, rendered to exact wire **bytes** — and asks **both** implementations for their verdict (parse / hash / level / bound) on those bytes: the TS reference through `parseTravelerJson(bytes)`, the Rust core through the `envelope check` CLI. Any disagreement, crash, non-answer, hang or answer slower than 2 s is a finding; all seeds run, and findings are grouped by the mutation responsible. Build the Rust CLI first: `cargo build --release --manifest-path crates/secure-job-envelope/Cargo.toml`. |
| `npm run corpus` | Regenerates the committed cross-implementation fuzz corpus in `conformance/fuzz/` (one file of exact bytes per case + a manifest with the TS reference verdict). The Rust core replays it in `cargo test` (`tests/fuzz_corpus.rs`), the TS reference in `npm test` (`sim/corpus.test.ts`). Needs the Rust CLI too: only verdicts the two agree on are frozen. |

All three run in CI (the `crossimpl` job in `.github/workflows/ci.yml`).

## How a fuzz case is made

```
seed ─► valid traveler (JS value)      generate.ts
           │  object stage   mutations.ts (one field → one boundary value)
           │                 mutations-object.ts (families: any position, any signature site, …)
           ▼
        wire tree                       wire.ts — every token's spelling
           │  wire stage     mutations-wire.ts (what only the TEXT can hold)
           ▼
        bytes
           │  bytes stage    mutations-bytes.ts (BOM, padding to the cap, a flipped bit, …)
           ▼
        the case  ──►  parseTravelerJson(bytes)   and   envelope check <file with the same bytes>
```

`buildCase(seed)` (`case.ts`) is a pure function of the seed. A fifth of the cases
are left unmutated (hash / level / bound parity on well-formed input); the rest
stack one to three mutations drawn by weight from all three stages. Each mutation
has its own random stream, so the harness can drop one from a diverging stack and
re-judge the rest — that is how a finding is attributed to "the smallest subset of
the case's mutations that still reproduces" instead of to a three-part label.

Why three stages: the first fuzzer mutated a JS value, serialized it with
`JSON.stringify`, and handed TypeScript the *parsed value*. So it could only ever
write what `JSON.stringify` emits, and TypeScript never saw the text at all. Of the
eight classes in "Would it have caught them?" below, three exist only in the text;
the other five needed mutations that pick their own position and variant.

Every mutation carries a one-line `why`. A mutation that finds nothing to bite on
(a quote mutation on a traveler without quotes) leaves the document unchanged; the
harness notices and does not count it.

## Reading a report

```
differential: 20000 cases, seeds 1..20000
  ts   = this checkout (parseTravelerJson)
  rust = crates/secure-job-envelope/target/release/envelope
  4407 unmutated, 8030 with one mutation, 7563 stacked; 175 of 175 mutations exercised
  both accept 7522 · both refuse 12478 · findings 0
  slowest: ts 60.3 ms (seed 149: …) · rust 65.2 ms (seed 2559: …)
no findings — the implementations agree on every case, and neither crashed, hung or stalled.
```

That is this checkout. A run with findings ends differently — this is the first run of
the byte-level fuzzer, before the one root cause it found was fixed (see
[`findings/`](findings/README.md)):

```
  both accept 7610 · both refuse 12365 · findings 25

FINDINGS: 25 cases — 25 accept/refuse splits, 0 hash/level/bound splits, 0 ts crashes, 0 rust crashes, 0 hangs, 0 slow
by responsible mutation (the smallest subset of a case's mutations that still reproduces):
  blob-fill                   15 × ts accepts, rust refuses   seeds 1428, 3435, 3727, …
  blob-fill                    8 × ts refuses, rust accepts   seeds 4165, 4926, 7645, …
  blob-fill+chunk-repeat       1 × ts accepts, rust refuses   seeds 1034
  blob-fill+chunk-repeat       1 × ts refuses, rust accepts   seeds 7948
```

- Reproduce one case: `npm run differential -- --start 149 --seeds 1` (add `--save DIR` to get its bytes).
- Sweep one mutation over every seed's traveler: `--only blob-fill` (comma-separate to stack).
- Judge a saved file or a directory of them: `--replay sim/findings`.
- `--jobs J` sets the worker count (one Rust process is spawned per case — `envelope check`
  takes one document per invocation — so the range is split across processes); `--report FILE`
  writes everything as JSON, including per-mutation case counts.
- Exit status: 0 clean, 1 findings, 2 the harness itself could not run.

What counts as a finding, besides a verdict field that differs: a TypeScript
exception that is not a refusal (anything but a plain `Error`), a Rust exit without a
verdict (a panic, a non-zero status, no answer in 10 s), either side taking more than
2 s on one document, a worker that stops reporting progress for 30 s — it is
killed, the seed is recorded as `ts hung`, and the rest of its seeds run without it —
and an *unmutated* document that both sides refuse: the generator is then producing
travelers that are not valid, and a mutated case built on one is refused whatever its
mutation did. (That happened: one base document in a few hundred priced the same
quantity twice, which the format refuses.)

A finding that is not resolved yet lives in [`findings/`](findings/README.md) as
minimized bytes with both verdicts and a diagnosis. The fuzzer keeps reporting it until
it is fixed — it is never special-cased. There are none open.

## Would it have caught them? (mutation-testing the fuzzer)

An audit found eight classes of TS↔Rust split that the first fuzzer ran past. The
fuzzer is itself tested against them: run it against the last commits that still had
the bugs, and it must find each one. The old code is checked out next to the repo,
never into it:

```sh
OLD="$(mktemp -d)"
for c in a987ea8 be62aa7; do
  git worktree add --detach "$OLD/$c" "$c"
  (cd "$OLD/$c" && npm ci && cargo build --release --locked --manifest-path crates/secure-job-envelope/Cargo.toml)
done

# today's sim/ against yesterday's implementations: old Rust via --bin, old TypeScript via --ts-root
for c in a987ea8 be62aa7; do
  npm run differential -- --seeds 6000 --quiet \
    --ts-root "$OLD/$c" --bin "$OLD/$c/crates/secure-job-envelope/target/release/envelope"
done

for c in a987ea8 be62aa7; do git worktree remove --force "$OLD/$c"; done
```

`--ts-root DIR` loads `src/lib/traveler/conformance.ts` and `hash.ts` from that
checkout (with its own `node_modules`). Neither old tree has `parseTravelerJson`;
what their callers did with wire bytes was `parseTraveler(JSON.parse(new TextDecoder().decode(bytes)))`,
so that is what the harness runs for them (`loadTsImpl` in `verdict.ts`).

Result with this catalog, seeds 1..6000 at each old commit (K1–K4 at `a987ea8`,
672 findings in all; K6–K8 at `be62aa7`, 356 in all). `×` counts the cases
attributed to that mutation alone; the example seed is a case with no other mutation;
the last column is the same mutation in 20,000 seeds at the commit that introduced this fuzzer.

| class | mutation | × | example seed | at the old commit | at HEAD |
|---|---|---|---|---|---|
| K1 struct as positional array | `positional-struct` | 33 | 196 (`part.material` as an array) | TS refuses, Rust accepts | 0 findings in 480 cases |
| K2 `__proto__` in a blob | `proto-only-blob` | 10 | 185 | both accept; level TS `L2`, Rust `L3` | 0 in 277 |
| | `proto-name-blob` | 5 | 1750 | TS accepts (a 9,000-char `__proto__` member is dropped before the size check), Rust refuses | 0 in 510 |
| K3 `award.sig` shape | `sig-shape` | 9 | 817 (`award.sig.sig` in full-width letters) | TS refuses, Rust accepts | 0 in 327 |
| K4 name of only U+0085 | `ws-whole-name` | 8 | 4 (`part.part_number`) | both accept; level TS `L0`, Rust `D` | 0 in 365 |
| K5 duplicate identifiers | `dup-quote-id`, `dup-line-qty`, `dup-op-seq` | — | `--only <name> --seeds 400` | both accept every case (289 / 289 / 400): nothing to split on | both refuse every one of them; in the corpus as refusals |
| K6 repeated member name | `dup-member-typed` | 51 | 3 | TS accepts (last wins), Rust refuses | 0 in 477 |
| | `dup-member-escaped` | 39 | 211 | TS accepts, Rust refuses | 0 in 331 |
| | `dup-member-whole` | 46 | 1 (`itar` twice) | TS accepts, Rust refuses | 0 in 347 |
| | `dup-shadow-range` / `-surrogate` / `-deep` | 37 / 35 / 29 | 123 / 14 / 231 | TS accepts (never lexes the hidden value), Rust refuses | 0 in 309 / 288 / 279 |
| K7 BOM, invalid UTF-8 | `bom-prefix` | 39 | 222 | TS accepts (BOM stripped), Rust refuses | 0 in 416 |
| | `utf8-invalid` | 34 | 89 (a lone 0x80 in `incoterms`) | TS accepts (U+FFFD substituted), Rust refuses | 0 in 459 |
| K8 size-cap units | `inflate-to-cap` | 16 | 1276 (530,299 bytes of astral text) | TS accepts (it counted UTF-16 units), Rust refuses | 0 in 189 |
| | `pad-to-cap` | 14 | 686 (599,003 bytes, mostly trailing spaces) | TS accepts (it measured a re-serialization), Rust refuses | 0 in 190 |

Also in those runs: `dup-member-blob` alone finds nothing at `be62aa7` — both sides
kept the last value there, as the audit said. At `a987ea8` the Rust CLI exits non-zero
with no verdict on any input that is not UTF-8 (277 cases, reported as `rust crashed`),
and the old TypeScript takes over 2 s on a list of 170,000 or more elements (3 cases,
`ts slow`).
The finding written up in `findings/` (`blob-fill`, since fixed) is present at both old commits too.

## Files

- `rng.ts` — seeded PRNG (mulberry32), plus an independent stream per mutation slot.
- `generate.ts` — seeded generators of *valid* travelers/quotes/orgs across the level ladder.
- `wire.ts` — the wire tree: a JSON document as it is *spelled* (repeatable members, per-token spelling, raw bytes at a chosen place), its printer and its byte encoder.
- `mutations.ts`, `mutations-object.ts`, `mutations-wire.ts`, `mutations-bytes.ts` — the mutation catalog, one file per kind (see the diagram above). `spelling.ts` — the exact respellers (one number or string, many spellings) and the tables of edge-case literals the wire mutations draw from.
- `case.ts` — seed → case: draws the mutations, runs the three stages, records which ones bit.
- `verdict.ts` — the four-field verdict (parse/hash/level/bound) from bytes, for TS (this checkout or `--ts-root`) and via the Rust CLI; crash and timeout detection; the comparison.
- `differential.ts`, `soak.ts`, `corpus.ts` — the entry points above. `corpus.test.ts` — the TS replay of the corpus and the harness's own invariants (runs in `npm test`).
- `findings/` — findings: minimized reproducers and a diagnosis while one is open, the write-up once it is fixed.
- `directory.ts` — a seeded signed key directory + one-time prekey bundle for the soak's crypto phase.

## How the parity work was found

The differential started by finding **585 divergent documents** between the two
implementations (the Rust core accepted hundreds of documents the zod schema
rejects, and hashed a different byte string for others). Each class was
root-caused and fixed — see `docs/CLAIMS.md` C12–C15 and the commit history — until
the differential was clean across thousands of documents. An audit then found the
eight classes above in input the fuzzer could not generate; it was rebuilt around
bytes so that it can, and now has to prove it. The harness stays so parity never
regresses.
