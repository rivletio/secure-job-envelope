# Conformance vectors

Language-agnostic test vectors that define what a conforming
`jobseal/0.0.1` implementation must do. The TypeScript and Rust
reference implementations both run these exact files in CI; a third
implementation proves itself the same way.

| File | Contract |
|---|---|
| `canonical.json` → `valid[]` | For each `value`, produce exactly `canonical` (bytes) and `sha384` |
| `canonical.json` → `invalid[]` | Refuse to canonicalize `value` (do not hash, do not substitute) |
| `travelers/*.json` + `travelers/expected.json` | Parse each traveler; produce exactly `traveler_hash` and `level` |
| `travelers/reject/*.json` | Refuse the document at parse time |

Runners: `src/lib/traveler/vectors.test.ts` (TypeScript),
`crates/jobseal/tests/vectors.rs` (Rust).

`generate.ts` regenerates the expected values **from the TypeScript
implementation**; the Rust side never generates, only verifies — so
agreement is a genuine cross-check, not a copy. Regenerate only when the
spec changes, and expect the diff to be reviewed like a spec change,
because it is one.

One deliberate omission: integers above 2^53−1 are refused by both
implementations, but that rule is proven by language-local tests instead
of a shared vector — JavaScript's `JSON.parse` cannot represent such a
number faithfully, which is exactly why the rule exists.
