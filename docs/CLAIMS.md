# Claims register

Every security-relevant claim this project makes in writing, mapped to the
test that proves it. A claim with no passing test does not belong in the
README, the spec, or a sales conversation. CI runs every proof on every
push (`.github/workflows/ci.yml`).

**Status meanings** — ✅ proven: enforced by a passing test in this repo,
in both implementations where the claim spans both. 📝 specified: written
design, honestly labeled draft; no implementation, therefore no proof yet.
⚠️ known gap: a divergence or limitation we state rather than hide.

## Content addressing & cross-implementation parity

| # | Claim (where written) | Proof | Status |
|---|---|---|---|
| C1 | Both implementations produce byte-identical canonical JSON and identical SHA-384 hashes for the same body (README, SPEC) | Shared vectors `conformance/canonical.json` run by `src/lib/traveler/vectors.test.ts` (TS) **and** `crates/jobseal/tests/vectors.rs` (Rust); golden vector `crates/jobseal/tests/golden.json` asserted in `traveler.test.ts` and `lib.rs::golden_hash_matches_ts` | ✅ |
| C2 | The hash covers a closed field set; extra keys never enter it (SPEC, SECURITY) | `traveler.test.ts` closed-field-set case; `lib.rs::contact_is_in_the_hash` (field present vs absent changes hash; unknown keys do not) | ✅ |
| C3 | Numbers outside the canonical range (non-finite, >2^53−1, non-integer <1e-5, exponential rendering) are refused, not hashed (SPEC §Canonical JSON) | `conformance/canonical.json` invalid vectors, both runners; `traveler.test.ts` fixed-notation parity case; `lib.rs::canonical_refuses_exponential_notation` | ✅ |
| C4 | Integer-valued floats, `-0`, and unicode strings canonicalize identically across languages (SPEC) | `canonical.json` vectors `integer`, `negative-zero`, `unicode-raw-utf8`; `lib.rs::integer_valued_float_matches_json_stringify` | ✅ |
| C5 | Integers above 2^53−1 are refused by both sides | Language-local tests both sides (`traveler.test.ts`, `lib.rs`) — **not** in the shared wire vectors, because JavaScript's `JSON.parse` cannot even represent such a vector faithfully (which is the point of the rule) | ✅ |
| C6 | Traveler hash and conformance level agree across implementations for real travelers (README) | `conformance/travelers/{l0,l1,l2}*.json` + `expected.json`, asserted by both runners | ✅ |
| C7 | Wrong spec string, malformed traveler_id, and ITAR seller mismatch are refused at parse by both sides (SPEC) | `conformance/travelers/reject/*`, both runners | ✅ |
| C8 | Object keys serialize in lexicographic order even when integer-like — JS numeric key enumeration must not leak into canonical bytes (SPEC §Canonical JSON) | Vector `key-order-digits`, both runners. *This vector caught a real bug in the TS reference serializer on its first run — the register exists precisely for this.* | ✅ |

## Quote binding & lifecycle

| # | Claim | Proof | Status |
|---|---|---|---|
| L1 | A quote binds only to the exact revision it priced; amending stale-marks every quote (SPEC, SECURITY) | `store.test.ts` "amend bumps revision and stale-marks"; `traveler.test.ts` binding cases; L1→L0 drop asserted | ✅ |
| L2 | Awarded (L2) travelers lock: further amendment is refused (SPEC, TRUST CC8) | `store.test.ts` "locks the traveler at L2" | ✅ |
| L3 | A stale quote cannot be awarded; expiry and priced-line-at-target are enforced at award (SPEC) | `store.test.ts` stale-award refusal; `traveler.test.ts` expiry + price-line guards | ✅ |
| L4 | An ITAR traveler cannot take a quote from a seller without `itar: true` (SPEC §Export control) | `traveler.test.ts` ITAR guard; `lib.rs::itar_traveler_rejects_non_itar_seller`; reject vector `itar-mismatch.json` both sides | ✅ |
| L5 | Every compose/quote/amend/award/import/export is appended to the audit log with a timestamp (TRUST CC7) | `store.test.ts` "audits every state change in order" | ✅ |

## Archive handling

| # | Claim | Proof | Status |
|---|---|---|---|
| A1 | Zip import refuses path traversal, non-allowlisted members, oversized entries, CRC mismatches, and META digest mismatches (SPEC §Archive, SECURITY) | `traveler.test.ts` zip round-trip + path-trick + META-mismatch negative cases | ✅ |

## Honest gaps and drafts

| # | Statement | Where | Status |
|---|---|---|---|
| G1 | The hash is integrity, **not** a signature; parties are unauthenticated in 0.0.1 | README, SPEC, SECURITY, TRUST | ⚠️ stated everywhere; PQ signatures (ML-DSA / SLH-DSA) are the 0.1 headline |
| G2 | Encrypted envelope (ML-KEM-768 + HKDF-SHA-384 + AES-256-GCM, CNSA 2.0-aligned) | `docs/ENVELOPE-DRAFT.md` | 📝 specified; becomes ✅ only with its own golden vectors in both languages (required by the draft itself) |
| G3 | TS parse (zod, strict bounds) is stricter than the Rust verifier's structural parse — e.g. Rust accepts an empty `material.spec` and reports level D where TS refuses the document | this file | ⚠️ acceptance sets converge in 0.1; shared vectors pin the surface both sides must agree on today |
| G4 | No forward secrecy with static recipient keys in the envelope draft | `docs/ENVELOPE-DRAFT.md` §Keys | ⚠️ stated, with mitigations (rotation, re-encryption) |
| G5 | Key sorting for non-ASCII keys can differ across languages (UTF-16 vs UTF-8 order); 0.0.1 field names are ASCII | SPEC §Canonical JSON | ⚠️ documented restriction |

## Running the proofs

```bash
npm test                                # TS: vectors + traveler suite + store state machine
cd crates/jobseal && cargo test   # Rust: unit + golden + the same shared vectors
node --experimental-strip-types conformance/generate.ts   # regenerate vectors (TS is generator, Rust is independent verifier)
```
