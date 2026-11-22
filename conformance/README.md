# Conformance vectors

Language-agnostic test vectors that define what a conforming
`sje/0.1.0` implementation must do. The TypeScript and Rust
reference implementations both run these exact files in CI; a third
implementation proves itself the same way.

| File | Contract |
|---|---|
| `canonical.json` → `valid[]` | For each `value`, produce exactly `canonical` (bytes) and `sha384` |
| `canonical.json` → `invalid[]` | Refuse to canonicalize `value` (do not hash, do not substitute) |
| `travelers/*.json` + `travelers/expected.json` | Parse each traveler; produce exactly `traveler_hash` and `level` |
| `travelers/reject/*.json` + `travelers/reject-reasons.json` | Refuse the document at parse time — **parsed from the file's bytes** (some vectors, e.g. a byte-order mark or a repeated member name, exist only in the text). `reject-reasons.json` pins, per vector and per implementation, a fragment the refusal must mention, so a vector cannot pass by being refused for some other defect |
| `signatures/envelope-cases.json` → `accept[]` | The envelope `text` passes the shape check and opens (as `kid`, with `seed_hex` / `onetime_seed_hex`) to `plaintext_utf8` |
| `signatures/envelope-cases.json` → `reject[]` | `stage: "shape"`: refused by the shape check alone, before any key is used. `stage: "crypto"`: passes the shape check and fails to open |
| `signatures/directory-cases.json` → `directory_cases[]`, `bundle_cases[]` | `shape_ok`: whether the JSON `text` is a well-formed directory / prekey bundle (checked with no key). `verifies`: whether it is then trusted at `at_ms`. A document that is not well-formed MUST NOT verify, even when its signature is genuine |
| `signatures/directory-cases.json` → `recipient_cases[]` | The `(kid, public_key)` to encrypt to for `org_id`, or `null` — independent of the order of the directory's entries |
| `signatures/verify-cases.json` → `traveler_cases[]` | Verify the traveler and produce exactly `want`: a check per buyer signature, the award check (`null`: no award), a check per quote (`null`: unsigned), and `verified`. A refused check carries its **reason**, which is normative (SPEC §Verification) |
| `signatures/verify-cases.json` → `itar_cases[]` | The ITAR gate's answer for `(traveler, quote)`: `null` (allowed) or the reason it is refused |

Runners: `src/lib/traveler/vectors.test.ts` (TypeScript),
`crates/secure-job-envelope/tests/vectors.rs` (Rust).

`generate.ts` regenerates the expected values **from the TypeScript
implementation**; the Rust side never generates, only verifies — so
agreement is a genuine cross-check, not a copy. Regenerate only when the
spec changes, and expect the diff to be reviewed like a spec change,
because it is one.

One deliberate omission: integers above 2^53−1 are refused by both
implementations, but that rule is proven by language-local tests instead
of a shared vector — JavaScript's `JSON.parse` cannot represent such a
number faithfully, which is exactly why the rule exists.
