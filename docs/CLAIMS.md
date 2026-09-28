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
| C1 | Both implementations produce byte-identical canonical JSON and identical SHA-384 hashes for the same body (README, SPEC) | Shared vectors `conformance/canonical.json` run by `src/lib/traveler/vectors.test.ts` (TS) **and** `crates/secure-job-envelope/tests/vectors.rs` (Rust); golden vector `crates/secure-job-envelope/tests/golden.json` asserted in `traveler.test.ts` and `lib.rs::golden_hash_matches_ts` | ✅ |
| C2 | The hash covers a closed field set; extra keys never enter it (SPEC, SECURITY) | `traveler.test.ts` closed-field-set case; `lib.rs::contact_is_in_the_hash` (field present vs absent changes hash; unknown keys do not) | ✅ |
| C3 | Numbers outside the canonical range (non-finite, >2^53−1, non-integer <1e-5, exponential rendering) are refused, not hashed (SPEC §Canonical JSON) | `conformance/canonical.json` invalid vectors, both runners; `traveler.test.ts` fixed-notation parity case; `lib.rs::canonical_refuses_exponential_notation` | ✅ |
| C4 | Integer-valued floats, `-0`, and unicode strings canonicalize identically across languages (SPEC) | `canonical.json` vectors `integer`, `negative-zero`, `unicode-raw-utf8`; `lib.rs::integer_valued_float_matches_json_stringify` | ✅ |
| C5 | Integers above 2^53−1 are refused by both sides | Language-local tests both sides (`traveler.test.ts`, `lib.rs`) — **not** in the shared wire vectors, because JavaScript's `JSON.parse` cannot even represent such a vector faithfully (which is the point of the rule) | ✅ |
| C6 | Traveler hash and conformance level agree across implementations for real travelers (README) | `conformance/travelers/{l0,l1,l2}*.json` + `expected.json`, asserted by both runners | ✅ |
| C7 | Wrong spec string, malformed traveler_id, and ITAR seller mismatch are refused at parse by both sides (SPEC) | `conformance/travelers/reject/*`, both runners | ✅ |
| C8 | Object keys serialize in lexicographic order even when integer-like — JS numeric key enumeration must not leak into canonical bytes (SPEC §Canonical JSON) | Vector `key-order-digits`, both runners. *This vector caught a real bug in the TS reference serializer on its first run — the register exists precisely for this.* | ✅ |
| C9 | Every schema field is classified as clear-in-file, and the pre-reveal courier view omits names, contacts, prices, part numbers, and addresses ([DISCLOSURE.md](DISCLOSURE.md)) | `src/lib/traveler/disclosure.test.ts` | ✅ |
| C10 | Empty strings and empty arrays are dropped from the quoteable body identically on both sides (SPEC §quoteable body) — a traveler with `part.processes: []` (or empty `certs`/`breaks`) hashes the same as one that omits them, and TS == Rust | conformance `travelers/l0-empty-arrays.json` (both runners); `traveler.test.ts` "drops empty strings and arrays"; `lib.rs::empty_arrays_and_strings_drop_from_the_hash` | ✅ |
| C11 | The published JSON Schemas bound every numeric field inside the canonical range and accept the whole reference corpus (SPEC §Canonical JSON) | `src/lib/traveler/schema-contract.test.ts` — ajv validates the example, all conformance vectors, and every seed fixture, and rejects out-of-range integers and sub-1e-5 / >1e12 money | ✅ |

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
| A1 | Zip import allowlists members (`traveler.json`, `META.json`, `quoteable.canonical.json`), requires `META.json`, and refuses path traversal, non-allowlisted members (e.g. `NOTES.txt`), oversized entries, CRC mismatches, META id/digest mismatches, and a tampered `quoteable.canonical.json` (SPEC §Archive, SECURITY) | `traveler.test.ts` zip round-trip + path-trick + META-mismatch + canonical-member-mismatch negative cases | ✅ |

## MCP surface

| # | Claim | Proof | Status |
|---|---|---|---|
| M1 | The MCP tools enforce the same guards as the reference implementation — stale quotes unawardable, ITAR mismatch refused, L2 locks against amendment, and `amend` cannot inject `ops`/`ship_to`/`as_built` to escalate the level (mcp/README) | `mcp/mcp.test.ts` stale-award, ITAR, locked-amend, and amend-cannot-inject-fields cases over a real client/server pair (InMemory transport) | ✅ |
| M2 | Quote binding cannot be asserted through the MCP surface — `traveler_hash_quoted` is computed from the traveler the desk holds (mcp/README) | `mcp/mcp.test.ts` "binding cannot be asserted"; `sje_quote` handler takes no binding input by schema | ✅ |
| M3 | A tampered sealed archive is refused on open over MCP | `mcp/mcp.test.ts` tamper case; demo step 3 | ✅ |
| M4 | Two desks with zero shared state complete RFQ → quote → award with hash lineage verified at every hop | `npm run demo` (CI): two separate server processes, asserts on every exchange | ✅ |

## Post-quantum authenticity & confidentiality (0.1, CNSA 2.0 suite)

The 0.1 profile selects its algorithms from the **CNSA 2.0 Category 5** suite:
ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), AES-256-GCM, HKDF-SHA-384,
SHA-384. Algorithm selection is an engineering choice, **not a certification** —
see the Disclaimer in the README. Every primitive is implemented in **both**
languages and pinned by a golden vector the TypeScript reference generates and
the Rust crate independently verifies byte-for-byte — the same discipline as
the content-hash vectors above.

| # | Claim | Proof | Status |
|---|---|---|---|
| PQ1 | ML-DSA-87 authorship signatures over the domain-separated canonical body are byte-identical across implementations, deterministic, and verify each other's output; a tampered body or cross-role (wrong-domain) replay is refused | `conformance/signatures/traveler-sig.json` (both runners); `signature.test.ts`; `sign.rs` unit tests; `vectors.rs::signature_vector_matches_cross_language` | ✅ |
| PQ2 | A signed key directory (ML-DSA-87) binds `org_id`→key with a validity window, revocation status, and attested capabilities; both sides verify it against the trust root, and tampering a capability or using the wrong root key fails | `conformance/signatures/directory.json` (both runners); `directory.test.ts`; `sign.rs::verify_directory`; `vectors.rs::directory_vector_verifies_cross_language` | ✅ |
| PQ3 | A traveler's buyer signature is enforced against the directory: a signature whose kid's org ≠ `buyer.org_id` is refused, and one that names no org_id at all is refused (authorship must bind to an org) — enforced identically on **both** implementations | `conformance/signatures/signed-traveler.json` (both runners, incl. the no-org_id case); `authenticity.test.ts`; `sign.rs::verify_traveler_authorship`; `vectors.rs::signed_traveler_vector_verifies_cross_language` | ✅ |
| PQ4 | The encrypted envelope (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) seals byte-identically across implementations and each side decrypts the other's envelope; a tampered payload or an unknown recipient is refused; AAD binds `{spec, enc_alg, recipients}` (payload) and `{spec, enc_alg, kid}` (each wrap) | `conformance/signatures/envelope.json` (both runners); `envelope.test.ts`; `envelope.rs`; `vectors.rs::envelope_vector_roundtrips_cross_language` | ✅ |
| PQ5 | Directory freshness is fail-closed on **both** sides: a directory evaluated outside its own `[issued_at, valid_until)` window, or a signer entry outside its `[valid_from, valid_until)` window (or revoked, or wrong-alg), does not authenticate — bounding revocation rollback | `conformance/signatures/directory-expired-entry.json` (both runners); `directory.test.ts` (H3); `authenticity.test.ts` (H1); `vectors.rs::expired_entry_directory_enforces_window_cross_language`; `sign.rs::verify_directory` / `directory_entry_by_kid` | ✅ |
| PQ6 | A seller quote signature verifies against the directory, and ITAR is gated on the directory's attested capability (not self-declared `seller.itar`) — enforced identically on **both** implementations | `conformance/signatures/signed-quote.json` (both runners); `authenticity.test.ts`; `sign.rs::verify_quote_signature` / `itar_attestation_blocker`; `vectors.rs::signed_quote_vector_verifies_cross_language` | ✅ |
| PQ7 | Envelope recipients are resolved through the signed directory (an org's attested ML-KEM key), the recipient kid is derived from that key (`enc_kid`) identically on both sides, and the payload AAD authenticates the ordered recipient set (dropping/reordering a recipient fails open) | `conformance/signatures/envelope.json` recipient (both runners); `envelope.test.ts` (M3 resolution, L2 recipient-set); `vectors.rs` `enc_kid` parity assertion | ✅ |
| PQ8 | A signed one-time prekey bundle binds an org's one-time ML-KEM keys to its ML-DSA identity: both sides verify the bundle against the directory (kid → org, bundle validity window, ML-DSA signature over the canonical body), and a tampered prekey, out-of-window bundle, or wrong root fails closed | `conformance/signatures/prekey-bundle.json` (both runners); `prekeys.test.ts`; `sign.rs::verify_prekey_bundle`; `vectors.rs::prekey_bundle_vector_verifies_cross_language` | ✅ |
| PQ9 | The forward-secret envelope (`sje-envelope/0.2.0`) encapsulates to a one-time prekey **and** the static identity key, binding both shared secrets into the KEK (`HKDF(ss_onetime ‖ ss_static)`); both sides re-seal byte-identically and open with both keys, and a missing one-time secret, a reordered/dropped recipient, or a tampered payload all fail closed | `conformance/signatures/fs-envelope.json` (both runners); `envelope.test.ts` (FS suite); `envelope.rs::seal_fs_deterministic_fields` / `open_fs`; `vectors.rs::fs_envelope_vector_roundtrips_cross_language` | ✅ |

## Honest gaps and drafts

| # | Statement | Where | Status |
|---|---|---|---|
| G1 | Party authentication. 0.0.1 had none — the hash is integrity, not a signature, so any party could claim any `org_id`. 0.1 implements ML-DSA-87 authorship signatures bound to a signed key directory. | README, SPEC, SECURITY, TRUST | ✅ **resolved in 0.1** (PQ1–PQ6); the browser desk verifies only and never holds signing keys |
| G2 | Encrypted envelope (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM, algorithms from the CNSA 2.0 Cat 5 suite). 0.0.1 had no confidentiality. | PQ4, PQ7; `docs/ENVELOPE-DRAFT.md` | ✅ **resolved in 0.1** with the dual-language golden vectors the draft itself demanded |
| G3 | TS parse (zod, strict bounds) is stricter than the Rust verifier's structural parse — e.g. Rust accepts an empty `material.spec` and reports level D where TS refuses the document. (An *acceptance* difference; both sides **hash** identically — see C10 — and both now refuse to **bind** a quote whose `valid_until` is not after `created_at`.) | this file; `lib.rs::quote_valid_until_must_be_after_created_at_to_bind` | ⚠️ acceptance sets converge in 0.1; shared vectors pin the surface both sides must agree on today |
| G4 | Forward secrecy. The base 0.1 envelope encapsulates only to a recipient's **static** ML-KEM key (a later compromise exposes past envelopes). The 0.2 envelope adds single-use prekeys + a two-KEM combine that binds both shared secrets. | PQ8, PQ9; `docs/ENVELOPE-DRAFT.md` §"Forward secrecy" | ✅ **resolved in the 0.2 envelope** — with the operational caveat that realizing forward secrecy requires the recipient to delete the consumed one-time secret; the base 0.1 static envelope still has none |
| G5 | Key sorting for non-ASCII keys can differ across languages (UTF-16 vs UTF-8 order); field names are ASCII | SPEC §Canonical JSON | ⚠️ documented restriction |

## Running the proofs

```bash
npm test                                # TS: vectors + traveler suite + store state machine
cd crates/secure-job-envelope && cargo test   # Rust: unit + golden + the same shared vectors
node --experimental-strip-types conformance/generate.ts   # regenerate vectors (TS is generator, Rust is independent verifier)
```
