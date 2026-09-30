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
| C12 | The Rust core's structural validation mirrors the zod schema field for field — every numeric ceiling, UTF-16 string-length bound, array-count cap, regex, the 8 KiB blob limit, and unknown-key rejection (`deny_unknown_fields` ↔ zod `.strict()`) — so both implementations accept and reject exactly the same documents | `crates/secure-job-envelope/src/validate.rs`; shared reject vectors `conformance/travelers/reject/*` (both runners); the differential + corpus (C15) | ✅ |
| C13 | One strict, shared datetime definition (fixed-width `YYYY-MM-DDTHH:MM:SS(.f)?Z`, real leap-aware calendar): both sides accept/reject the same timestamps and compute the same instant for bind/expiry — a trailing offset, second 60, hour 24, or `2026-02-31` is refused on both | `src/lib/traveler/datetime.ts` + `datetime.test.ts`; `lib.rs::rfc3339_millis_is_strict_and_calendar_aware` / `iso_day_ok_is_calendar_strict`; reject vectors `created-at-*` (both runners) | ✅ |
| C14 | A string carrying a lone UTF-16 surrogate (no UTF-8 encoding) is refused at parse on both sides, and a hashed/limited string with leading or trailing whitespace is refused rather than silently trimmed — so the two implementations never hash different bytes for the "same" document | `conformance.ts` UTF-8-safety walk + `vectors.test.ts`; serde's parse-time refusal + `lib.rs::serde_rejects_lone_surrogate`; reject vectors `untrimmed-name.json`, `lone-surrogate-in-notes.json` (both runners) | ✅ |
| C15 | The two implementations are held to identical verdicts (parse / hash / level / bound) at scale: a seeded TS↔Rust differential fuzzer over thousands of mutated documents finds zero divergence, a committed fuzz corpus replays in `cargo test` with no Node in the loop, and a lifecycle soak asserts the invariants over hundreds of transacted jobs | `sim/differential.ts` (`npm run differential`); `conformance/fuzz/*` + `crates/secure-job-envelope/tests/fuzz_corpus.rs`; `sim/soak.ts` (`npm run soak`); all wired into CI (`crossimpl` job) | ✅ |

## Quote binding & lifecycle

| # | Claim | Proof | Status |
|---|---|---|---|
| L1 | A quote binds only to the exact revision it priced; amending stale-marks every quote (SPEC, SECURITY) | `store.test.ts` "amend bumps revision and stale-marks"; `traveler.test.ts` binding cases; L1→L0 drop asserted | ✅ |
| L2 | Awarded (L2) travelers lock: further amendment is refused (SPEC, TRUST CC8) | `store.test.ts` "locks the traveler at L2" | ✅ |
| L3 | A stale quote cannot be awarded; expiry and priced-line-at-target are enforced at award (SPEC) | `store.test.ts` stale-award refusal; `traveler.test.ts` expiry + price-line guards | ✅ |
| L4 | An ITAR traveler cannot take a quote from a seller without `itar: true` (SPEC §Export control) | `traveler.test.ts` ITAR guard; `lib.rs::itar_traveler_rejects_non_itar_seller`; reject vector `itar-mismatch.json` both sides | ✅ |
| L5 | Every compose/quote/amend/award/import is appended to the store's audit log with a timestamp; export is audited from the traveler route (UI). (TRUST CC7) | `store.test.ts` "audits every state change in order" (compose/quote/amend) and "audits award and import" (award/import); export audit is in `src/routes/t.$travelerId.tsx` (not unit-tested) | ✅ |

## Archive handling

| # | Claim | Proof | Status |
|---|---|---|---|
| A1 | Zip import allowlists members (`traveler.json`, `META.json`, `quoteable.canonical.json`), requires `META.json`, and refuses path traversal, non-allowlisted members (e.g. `NOTES.txt`), oversized/zip-bomb entries, META id/digest mismatches, and a tampered `quoteable.canonical.json`. Integrity rests on SHA-384 cross-checks, not CRC32 (CRC is deliberately skipped to avoid inflating a hostile archive before the guards run). (SPEC §Archive, SECURITY) | `traveler.test.ts` zip round-trip + path-trick + zip-bomb + META-mismatch + canonical-member-mismatch negative cases | ✅ |

## MCP surface

| # | Claim | Proof | Status |
|---|---|---|---|
| M1 | The MCP tools enforce the same guards as the reference implementation — stale quotes unawardable, ITAR mismatch refused, L2 locks against amendment, and `amend` cannot inject `ops`/`ship_to`/`as_built` to escalate the level (mcp/README) | `mcp/mcp.test.ts` stale-award, ITAR, locked-amend, and amend-cannot-inject-fields cases over a real client/server pair (InMemory transport) | ✅ |
| M2 | Quote binding cannot be asserted through the MCP surface — `traveler_hash_quoted` is computed from the traveler the desk holds (mcp/README) | `mcp/mcp.test.ts` "binding cannot be asserted"; `sje_quote` handler takes no binding input by schema | ✅ |
| M3 | Any byte-level tamper of a sealed archive is refused on open over MCP — including tampering of the non-quoteable lifecycle fields (award/ship_to/ops), because the full-bytes `traveler_json_sha384` digest is required. Adversarial re-sealing is out of scope (unkeyed integrity — see G7). | `mcp/mcp.test.ts` random-byte tamper case + injected-award tamper case; `traveler.test.ts` non-quoteable-field tamper cases; demo step 3 | ✅ |
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
| PQ10 | Signature verification is fail-closed on hostile input: a quote or traveler whose signature body cannot be canonicalized (e.g. an out-of-range number in an opaque `assumptions`/`capacity` blob) returns "not verified" rather than raising an uncaught exception — no verifier-reachable denial of service | `authenticity.test.ts` "fails closed (never throws) on a non-canonicalizable body (D3)"; try/catch in `authenticity.ts` `verifyQuoteSignature` / `verifyTravelerSignatures` | ✅ |

## Honest gaps and drafts

| # | Statement | Where | Status |
|---|---|---|---|
| G1 | Party authentication. 0.0.1 had none — the hash is integrity, not a signature, so any party could claim any `org_id`. 0.1 implements ML-DSA-87 authorship signatures bound to a signed key directory. | README, SPEC, SECURITY, TRUST | ✅ **resolved in 0.1** (PQ1–PQ6). Signature/directory verification lives in the reference library (exercised by the conformance vectors, unit tests, and the soak) — it is **not** wired into the browser desk UI, which never holds signing keys and never signs |
| G2 | Encrypted envelope (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM, algorithms from the CNSA 2.0 Cat 5 suite). 0.0.1 had no confidentiality. | PQ4, PQ7; `docs/ENVELOPE-DRAFT.md` | ✅ **resolved in 0.1** with the dual-language golden vectors the draft itself demanded |
| G3 | TS parse (zod) and the Rust structural parse now accept and reject the same documents. The former acceptance gap — Rust accepting documents zod refused (looser numeric ceilings, missing string/count bounds, unknown keys, lenient datetimes) — is closed by a full structural validator in the Rust core. | this file (C12–C14); `crates/secure-job-envelope/src/validate.rs`; the differential + committed corpus (C15) | ✅ **resolved in this pass** — a seeded TS↔Rust differential over thousands of documents finds zero accept/reject divergence, pinned by shared reject vectors and the committed corpus |
| G6 | The 512 KiB size limit is enforced on the raw input length in Rust vs the re-serialized (compact, UTF-16) length in zod, so a document padded with whitespace to just under the limit could differ at the exact boundary. A negligible edge (both cap ≈512 KiB; the differential feeds compact JSON), stated rather than hidden. | this file; `lib.rs::parse_traveler`; `schema.ts` superRefine | ⚠️ documented edge |
| G4 | Forward secrecy. The base 0.1 envelope encapsulates only to a recipient's **static** ML-KEM key (a later compromise exposes past envelopes). The 0.2 envelope adds single-use prekeys + a two-KEM combine that binds both shared secrets. | PQ8, PQ9; `docs/ENVELOPE-DRAFT.md` §"Forward secrecy" | ✅ **resolved in the 0.2 envelope** — with the operational caveat that realizing forward secrecy requires the recipient to delete the consumed one-time secret; the base 0.1 static envelope still has none |
| G5 | Key sorting for non-ASCII keys now uses Unicode code point order on both sides (== UTF-8 byte order), so astral-plane keys sort identically; field names remain ASCII regardless. | SPEC §Canonical JSON; C1 | ✅ **resolved** — `canonical.ts` code-point sort; vector `astral-key-order` (both runners) |
| G7 | Archive integrity is **unkeyed** SHA-384. The required `traveler_json_sha384` digest makes any byte-level tamper of a received archive refused (award/ship_to/ops included), but a party that re-seals an archive recomputes the digest. Adversarial authenticity is the ML-DSA authorship signature, which in 0.1 signs the **quoteable body only** — the lifecycle fields (award, ship_to, ops) are mutable workflow state, not signed. Signing them is a candidate for a later revision. | SPEC §Archive; SECURITY; `zip.ts` (digest now required); `types.ts` (Award/ShipTo/Op have no sig) | ⚠️ documented boundary |

## Running the proofs

```bash
npm test                                # TS: vectors + traveler suite + store state machine
cd crates/secure-job-envelope && cargo test   # Rust: unit + golden + shared vectors + fuzz corpus replay
node --experimental-strip-types conformance/generate.ts   # regenerate vectors (TS is generator, Rust is independent verifier)

# Cross-implementation hardening (the crossimpl CI job runs all three):
cargo build --release --manifest-path crates/secure-job-envelope/Cargo.toml  # the differential's other half
npm run soak                            # simulate + transact hundreds of jobs, assert lifecycle invariants
npm run differential                    # seeded TS<->Rust differential fuzz (parse/hash/level/bound)
npm run corpus                          # regenerate the committed cross-impl fuzz corpus (conformance/fuzz)
```
