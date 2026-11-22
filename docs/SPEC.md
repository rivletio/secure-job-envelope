# Secure Job Envelope (SJE) — spec 0.1.0

> This is the frozen base spec (canonical JSON, hash, conformance ladder, archive). 0.1 adds ML-DSA-87 authorship signatures, a signed key directory, directory-attested ITAR, integer-minor-unit money, and the encrypted envelope — see docs/CLAIMS.md and SECURITY.md.

Implementable draft. Media type `application/vnd.sje+json`.
Archive name `{traveler_id}.traveler.zip`. License Apache-2.0.

A traveler is the job object — one part family between a buyer and sellers —
not a shop OS and not a marketplace. Quotes bind to `traveler_hash_quoted`,
a SHA-384 of the canonical **quoteable body**.

## Identifiers

```
traveler_id / quote_id : ^[a-z]{3}_[a-z0-9]{6,24}$     (e.g. tvl_8kq2mfn3, qot_x91k2p)
hash                 : ^sha384:[0-9a-f]{96}$
currency             : ^[A-Z]{3}$    country: ^[A-Z]{2}$
created_at           : ISO-8601 UTC with trailing Z
```

Size caps: traveler JSON ≤ 512 KiB; archive ≤ 2 MiB; strings ≤ 2000 chars;
names ≤ 128 chars.

## The quoteable body (closed field set)

The hash covers **exactly** these fields — extra keys on in-memory objects
never enter the hash:

```
spec, traveler_id, revision, created_at, buyer, part,
need_by, incoterms, itar
```

`buyer` (Org) and `part` are themselves closed: absent optionals are
dropped, empty strings and empty arrays are dropped, `need_by`/`incoterms`
are `null` when absent, `itar` defaults to `false`. Quotes, award, ops, and
ship_to sit **outside** the hash so a traveler can climb L0→L2 without
invalidating quotes. Amending the quoteable body bumps `revision` and
stale-marks every existing quote.

**The hash is integrity of the buyer-authored body, not a signature, and
not non-repudiation.** 0.1 adds ML-DSA-87 authorship signatures over the
canonical body — and a separate buyer signature over the award (award decision
+ ship-to) — verified against a signed key directory (see SECURITY.md).

## Canonical JSON

RFC 8785-inspired, restricted for cross-language byte equality:

1. Object keys sorted **lexicographically by Unicode code point** (equivalently,
   by UTF-8 byte order); compact output
   (no whitespace). Implementations must emit in that order explicitly —
   in particular, JavaScript implementations must not serialize a rebuilt
   object, because JS enumerates integer-like keys ("2", "10") in numeric
   order regardless of insertion order. Conformance vector
   `key-order-digits` pins this.
2. `undefined` / absent members are omitted entirely.
3. Strings escape per standard JSON. **Field names are ASCII** by convention.
   Non-ASCII keys are sorted by Unicode code point on both implementations
   (the TypeScript reference sorts by code point explicitly, not by UTF-16 code
   unit, matching the Rust core's UTF-8 byte order), so astral-plane keys order
   identically across languages. Conformance vector `astral-key-order` pins this.
4. **Numbers are restricted to a range where every language renders the
   same bytes and round-trips exactly.** A number is canonical iff it is
   finite, `|x| <= 9007199254740991` (2^53−1), and — when not an integer —
   `|x| >= 1e-5` (or exactly 0). Conforming implementations **refuse**
   anything else rather than hash it ambiguously. Within the range:
   - integer-valued floats emit without a trailing `.0` (thickness `10.0`
     hashes as `10`),
   - `-0` emits as `0`,
   - non-integers emit their shortest round-trip decimal in fixed
     notation (both JS `Number::toString` and Rust's ryu agree here).

   Why the bounds: above 2^53−1 integers stop being exact in an IEEE-754
   double, so a JSON round-trip through JavaScript silently changes the
   value (and the hash); below 1e-5, ryu switches to exponential notation
   (`1e-6`) while JavaScript stays fixed (`0.000001`), so the renderings
   diverge. Non-finite numbers are refused outright. The published JSON
   Schemas bound every numeric field inside this range — integer fields
   within 2^53−1, the `money` / `priceDelta` `$defs` in `quote-0.1.0.json`
   as integer minor units (`0 … 1e12` / `±1e12`), and the sole non-integer
   field, `thickness_mm`, bounded `≥ 1e-4` so it always renders in canonical
   fixed notation. The canonicalizer is the final gate and refuses anything
   outside the range regardless.
5. **A value nests at most 127 containers deep** (objects or arrays inside one
   another, the outermost included; scalars do not count). A deeper value has no
   canonical form. This is the same limit parsing rule 9 puts on wire text, on
   purpose: a value canonicalizes only if its text could have been read by every
   conforming parser. (The two reference canonicalizers used to allow 129 while
   one parser stopped at 127 and the other had no limit, so a signed document
   nested 128 deep verified in one implementation and could not be read by the
   other.) Conformance vectors `nesting-127-*` and `nesting-128-*` pin both sides.

The hash is `"sha384:" + lowercase-hex(SHA-384(canonical_json_bytes))`.

**Why SHA-384:** the spec targets ≥128-bit collision resistance against a
quantum adversary. SHA-256's classical 128-bit collision bound degrades
under quantum collision search; SHA-384 keeps ≥128-bit collision and
≥192-bit (Grover) preimage margins post-quantum, at the cost of a longer
hash string. Chosen pre-release so no deployed hashes ever migrate.

Both reference implementations must reproduce the golden vector
(`crates/secure-job-envelope/tests/golden.json`) exactly.

### Parsing (wire bytes → document)

Serialization is only half of cross-language byte equality; the two parsers must
also **accept and reject the same wire documents**. These rules are easy to get
subtly wrong because the natural default differs between a zod schema and a serde
struct:

1. **Integer-valued floats are accepted into integer fields.** An integer field
   accepts an integer or an integer-valued float — `250.0` and `1.0` parse exactly
   as `250` and `1` — because `250.0 === 250` in JavaScript (so `JSON.parse`
   collapses it and zod `.int()` accepts it) and the canonicalizer already renders
   `10.0` as `10`. The Rust core, whose fields are `i64`, carries a lenient integer
   deserializer (`de.rs`) that accepts an integer-valued float while still refusing a
   fractional value (`250.5`) or one outside ±(2^53−1). A document with `{"qty":250.0}`
   therefore parses on both sides and hashes identically to `{"qty":250}`.

2. **An explicit `null` is allowed only on the explicitly-nullable fields.** The five
   fields `need_by`, `incoterms`, `ship_to`, `award`, and `as_built` accept an explicit
   `null` and treat it as absent (zod `.nullable()`; JSON Schema `["…","null"]`). Every
   other optional field accepts **absence** but **refuses an explicit `null`** — a
   `null` there is a malformed document, refused by both implementations rather than
   silently coerced to absent. (serde's `Option<T>` maps `null`→`None` by default, so
   the Rust core refuses it explicitly via `de.rs` to match zod `.optional()` and the
   published JSON Schema.) This closes a split where one implementation would accept a
   `null`-carrying document the other refused.

3. **A structured value is a JSON object, never an array.** The traveler itself and
   every structured value inside it (`buyer`, `part`, `material`, `qty`, each quote and
   its `seller` / `pricing` / price lines / exceptions, `award` and its `terms`,
   `ship_to`, each op, each signature) MUST be written as a JSON object. The same
   fields written positionally as an array — `"material": ["6061-T6"]` — are refused.
   (A serde-derived struct accepts the positional form by default; zod does not. Code
   that reads the raw JSON by key would otherwise see a different document from the
   typed one.)

4. **No member may be named `__proto__`,** at any depth, including inside the free-form
   blobs (`assumptions`, `capacity`, `as_built`). JavaScript object models cannot carry
   that name faithfully (a schema library may drop it silently), so an implementation
   that kept it and one that dropped it would canonicalize — and therefore sign and
   verify — different bytes for the same wire document.

5. **Identifiers are unique within their list.** Within one traveler no two quotes share
   a `quote_id` and no two ops share a `seq`; within one quote no two price lines share
   a `qty`. An award names its quote by id and a price by quantity, so a duplicate makes
   "the awarded quote" or "the unit price" ambiguous — and lets what a reader is shown
   differ from what an award commits to. A document with a duplicate is refused.

6. **A member name appears at most once in any object,** at any depth — in the typed
   fields and inside the free-form blobs alike. Names are compared after JSON
   unescaping (`"lot"` and `"lo\u0074"` are the same name). A document with a repeated
   member name is refused; it is never resolved first-wins or last-wins. (JavaScript's
   `JSON.parse` keeps the last and never examines the others, so a value hidden behind
   a duplicate — an out-of-range number, a second `award` — is invisible to every check
   that runs on the parsed object, while a strict parser reads it. Two readers would
   judge two different documents.)

7. **The wire text is UTF-8 with no byte-order mark.** A leading U+FEFF is refused, not
   stripped; an invalid UTF-8 sequence is refused, not replaced. (Many decoders strip a
   BOM or substitute U+FFFD by default; a reader that does has silently accepted bytes
   another reader refuses.)

8. **Size is measured on the wire.** Traveler text longer than 512 KiB — 524,288 bytes of
   UTF-8, whitespace included — is refused before it is parsed. An implementation that
   is handed an already-parsed value rather than text (an API argument, a store entry)
   applies the same limit to the UTF-8 length of the value's compact serialization, the
   shortest text it could have arrived as. The limit is in bytes, not in characters or
   UTF-16 code units.

9. **Containers nest at most 127 deep.** Counting the traveler itself, no object or
   array has more than 126 containers around it; a text in which a 128th nested
   container opens is refused. (Only a free-form blob can be that deep. Parsers differ
   here by default — one has a recursion limit, another has none — so the limit is a
   rule of the format, not a property of a library.)

10. **Every string is well-formed Unicode.** No string and no member name contains a
    lone surrogate (an escape `\uD800`–`\uDBFF` not followed by `\uDC00`–`\uDFFF`, or
    the reverse). Such text has no UTF-8 encoding; one parser refuses it, another
    substitutes U+FFFD or keeps an ill-formed string, and the two would then hash
    different bytes.

11. **Every number is a finite binary64 value,** including numbers inside the free-form
    blobs. A literal that rounds to infinity (`1e309`) is refused.

12. **A free-form blob has a canonical form of at most 8 KiB.** `as_built`, and a
    quote's `assumptions` and `capacity`, are objects whose members the format does not
    name. Two conditions make them something every implementation judges alike:
    - every number inside one, at any depth, is a canonical number (Canonical JSON
      rule 4) — so the blob has a canonical form; and
    - that canonical form is at most 8,192 bytes of UTF-8.

    The size is measured on the canonical form because it is the one serialization
    every implementation must already produce byte for byte. It is not the size of the
    text as sent (`1.0` and `1`, `"A"` and `"\u0041"` are the same blob), and it is not
    the size of an implementation's own re-serialization: the two reference
    implementations used to measure exactly that, and since one writes `1e15` in 16
    characters and the other in 18, a blob of a few hundred numbers was accepted by one
    and refused by the other. A quote's blobs are inside the quote's content hash, so a
    number with no canonical form used to make a quote that parsed and could never be
    hashed or awarded; it is now refused when the document is read.

An implementation MUST apply rules 6–8 to the bytes as received — a traveler read from
a file, from an archive member, or from a decrypted envelope is parsed from those bytes,
not from a value some earlier layer already parsed leniently.

All twelve rules are held across the two implementations by the conformance vectors
(`travelers/l0-intfloat.json`; `travelers/reject/*` — each reject vector's refusal
*reason* is pinned per implementation in `travelers/reject-reasons.json`, so a vector
cannot pass by being refused for some other defect; both runners parse every vector
from its bytes), the seeded differential, and the committed fuzz corpus.

## Conformance ladder

| Level | Name | Meaning |
|---|---|---|
| D | Draft | Missing something L0 needs |
| L0 | Quoteable | A seller can price without guessing material or qty |
| L1 | Awardable | ≥ 1 structured quote bound to the current buyer revision |
| L2 | Executable | Awarded, ops listed, ship-to present; traveler locks |
| L3 | As-built | A non-empty `as_built` object recorded on the executed traveler. Both implementations compute L3; the object's contents are not specified or covered by conformance vectors in 0.1 |

## Quotes

```
required: quote_id, seller, traveler_hash_quoted, created_at,
          valid_until, lead_time_days, pricing
pricing.required: currency, lines[]
lines[]: { qty >= 1, unit: integer minor units, 0 .. 1e12 }
```

A quote's `valid_until` MUST be later than its `created_at`, compared as instants; a
quote that is not is refused.

A quote is **bound** when `traveler_hash_quoted` equals the current traveler
hash. Guards a conforming desk enforces at bind/award time: quote expiry
(`valid_until`), one live quote per seller per revision (a quote that is not
bound to the current revision, or has expired, does not count), a priced line
at the quantity being awarded (the same rule verification applies to a signed
award), and ITAR consistency
(a seller with `itar !== true` cannot quote an `itar: true` traveler — a
consistency check, not compliance).

**Amounts.** `unit`, `nre`, `freight_estimate` and an exception's
`price_delta` are integers in the minor unit of `pricing.currency`. `unit` is
per part; `nre` and `freight_estimate` are for the order. **0.1 does not
define the basis of `price_delta`** (per part or for the order). Until a later
version does: a reader MUST show each `price_delta` as stated and MUST NOT
multiply it by a quantity, a reader that totals a quote MUST say how it counted
the deltas, and a seller that means a per-part change SHOULD put it in
`pricing.lines` instead.

## Archive (`{traveler_id}.traveler.zip`)

> When sent between parties, this archive is the **payload of an encrypted `.sje`
> envelope** (ML-KEM-1024 + AES-256-GCM; see [ENVELOPE-DRAFT.md](ENVELOPE-DRAFT.md)),
> not transmitted in the clear. On the desk it is also available as a plaintext
> local copy, labeled not-for-sending.

Allowlisted members only (max 3):

```
traveler.json                the traveler document (required, root only)
META.json                    integrity manifest (required, root only)
quoteable.canonical.json     canonical quoteable-body bytes (optional)
```

`META.json` carries at least `{ traveler_id, traveler_hash,
traveler_json_sha384 }` and normally also `{ spec, media_type, archive, itar,
export_control }`. Any other member — including `NOTES.txt` — is refused.

Import rules: refuse any member outside the allowlist; refuse a member whose
**stored** name is not exactly the plain root name — so `../traveler.json`,
`./traveler.json`, `a/../traveler.json`, and anything containing `/`, `\`, `..`
or a NUL are refused (the check is on the name as stored in the archive: a zip
library may hand back an already-normalized name, on which this check would
refuse nothing); refuse an archive holding two members with the same name, or
whose member count differs from the count its end-of-central-directory record
declares; refuse directory entries; cap compressed and uncompressed sizes.
`traveler.json` is parsed from its bytes under the §Parsing rules, and
`traveler_json_sha384` is the SHA-384 of exactly those bytes. Integrity is verified with SHA-384 cross-checks, not
CRC32 (CRC is deliberately skipped so a hostile archive is not fully
inflated before the guards run). `META.json` is **required** — its
`traveler_id` and `traveler_hash` must match the received `traveler.json`,
and `traveler_json_sha384` (a digest over the whole `traveler.json`) is
**required** and must match. Because `traveler_hash` covers only the quoteable
body, this full-bytes digest is what binds the non-quoteable lifecycle fields
(award, ship_to, ops, quotes, as_built); without it those could be altered
under an unchanged `traveler_hash`. When `quoteable.canonical.json` is present
it must equal your canonical rendering of the quoteable body. Re-canonicalize
and check `traveler_hash` yourself — treat the archive as the document.

These digests are **unkeyed** integrity: they detect corruption and naive
tampering, and guarantee the archive is internally consistent, but a party that
re-seals an archive recomputes them. Adversarial *authenticity* is the separate
ML-DSA signature layer: in 0.1 the buyer signs the quoteable body **and** the
award (the award decision + ship-to, bound to the traveler revision, and binding
the awarded quote's priced content via `quote_hash`), so a re-sealed archive that
forges the award, redirects the ship-to, or swaps the awarded quote's price is
refused by that signature even though its digest recomputes. `ops` and `as_built` remain
post-award workflow state not covered by a signature.

A reader works from the archive's central directory, as zip readers do. An archive with
a repeated member name is refused (above), because readers disagree on which copy wins.
Bytes that are present in the file but not listed in the central directory are not
examined; a streaming extractor that walks local headers instead can surface content
this reader never saw. Open archives with a conforming reader, not a general-purpose
unzip tool.

## Signatures, the key directory and verification (0.1, normative)

Everything in this section is held across the two reference implementations by
`conformance/signatures/directory-cases.json` and `verify-cases.json`: documents both
must accept, and documents both must refuse **for the stated reason**.

### What is signed

A signature is ML-DSA-87 (FIPS 204) over `domain ‖ 0x00 ‖ body`, where `domain` is an
ASCII tag and `body` is the UTF-8 canonical JSON (§Canonical JSON) of:

| Signature | `domain` | `body` |
|---|---|---|
| Buyer authorship (`signatures[]`) | `sje-sig/traveler/0.1.0` | the quoteable body — the `traveler_hash` preimage |
| Seller quote (`quotes[].sig`) | `sje-sig/quote/0.1.0` | the quote with its `sig` member removed |
| Buyer award (`award.sig`) | `sje-sig/award/0.1.0` | `{ spec, traveler_id, traveler_hash, award, ship_to }` — `award` with its `sig` removed, `ship_to` as on the traveler or `null` |
| Directory (`sig`) | `sje-sig/directory/0.1.0` | the directory with its `sig` removed |
| Prekey bundle (`sig`) | `sje-sig/prekeys/0.1.0` | the bundle with its `sig` removed |

A signature object is exactly `{ "alg": "ML-DSA-87", "kid", "sig" }`, `sig` in lowercase
hex. `award.quote_hash` is `sha384:` + hex of SHA-384 over the seller-quote body above —
the content of the awarded quote. The reference signers use the deterministic ML-DSA
variant; a verifier accepts either variant.

What is **not** signed: `ops`, `as_built`, the set of quotes a traveler carries, and —
before an award — `ship_to`.

### Key directory (`sje-directory/0.1.0`)

A directory binds `org_id` → keys and is signed by a trust root whose public key the
verifier holds out of band. A root's signature says the root signed these bytes; it does
not make them well-formed. A directory MUST be exactly this shape, or it does not verify
— **even when its signature is genuine**:

| Element | Rule |
|---|---|
| Text | UTF-8, no byte-order mark, at most 8 MiB; a member name appears at most once in any object |
| Directory | an object with exactly `spec`, `issued_at`, `valid_until`, `root_kid`, `entries`, `sig` |
| `spec` | `sje-directory/0.1.0` |
| `issued_at`, `valid_until` | canonical UTC datetimes (as in a traveler), `issued_at` before `valid_until`; the directory is usable for instants in `[issued_at, valid_until)` |
| `root_kid` | 1–64 characters of `A–Z a–z 0–9 . _ -` |
| `sig` | lowercase hex, 4627 bytes |
| `entries` | an array of at most 512 entries; no `kid` appears on two entries |
| Entry | an object with `org_id`, `kid`, `alg`, `public_key`, `valid_from`, `valid_until`, `status`, and optionally `capabilities`, `enc_alg`, `enc_public_key` — nothing else |
| `org_id` | as in a traveler (`^[a-z][a-z0-9_]{1,63}$`) |
| `kid` | 1–64 characters of `A–Z a–z 0–9 . _ -` |
| `alg`, `public_key` | `ML-DSA-87`; lowercase hex, 2592 bytes |
| `valid_from`, `valid_until` | canonical UTC datetimes, `valid_from` before `valid_until` |
| `status` | `active` or `revoked` |
| `capabilities` | `{}` or `{ "itar": true \| false }` — a boolean, not a string |
| `enc_alg`, `enc_public_key` | both or neither: `ML-KEM-1024`; lowercase hex, 1568 bytes |

An entry is **usable** at an instant `t` iff `status` is `active` and
`valid_from ≤ t < valid_until`. An org may have several usable entries (key rotation).

- **To verify a signature** naming `kid`: the entry with that kid must be usable.
- **A capability** holds for an org iff any of its usable entries carries it.
- **To encrypt to an org**: among its usable entries that carry an encryption key, use the
  one with the latest `valid_from`; if two start together, the one with the greater `kid`.
  The choice MUST NOT depend on the order of `entries`.

### Prekey bundle (`sje-prekeys/0.1.0`)

Exactly `{ spec, org_id, kid, enc_alg, issued_at, valid_until, prekeys, sig }`: `org_id`
and `kid` as above, `enc_alg` `ML-KEM-1024`, the window as for a directory, `sig` 4627
bytes of lowercase hex, and `prekeys` an array of at most 256 objects that are exactly
`{ prekey_id, public_key }` — `prekey_id` 1–64 characters of `A–Z a–z 0–9 . _ -` (it is
concatenated into an envelope's key-derivation label), no id twice, `public_key` 1568
bytes of lowercase hex. Text at most 1 MiB. A bundle verifies iff it has this shape, the
directory verifies, the instant is inside the bundle's window, `kid` names a usable entry
**whose org is the bundle's `org_id`**, and that entry's key verifies the signature.

### Verification

Verification takes a document, a directory, a trust-root public key and an instant, and
reports — it never repairs. Each signature yields a **check**: passed (with the `kid` and
the `org_id` the directory binds it to) or refused with a reason. The reasons are
normative; an implementation that refuses a case for a different reason is applying a
different rule.

A signature check, for a signature claimed on behalf of org `A` (`buyer.org_id` for
authorship and awards, `seller.org_id` for a quote), in this order:

| Condition | Reason |
|---|---|
| The directory is not well-formed, not in its window, or not signed by the trust root | `directory does not verify against the trust root` |
| The document is not a valid traveler / quote | `not a valid traveler` / `not a valid quote` |
| The author names no `org_id` | `author names no org_id to bind the signature to` |
| The entry with the signature's `kid` has status `revoked` (inside its window or not) | `signing key is revoked in the directory` |
| No usable entry has the signature's `kid` | `no active in-window directory entry for kid` |
| That entry's `org_id` is not `A` | `signer org does not match author org` |
| The key does not verify the signed message | `signature does not verify` |

An **award** is additionally refused — after its signature has passed — when it does not
commit to something determinate:

| Condition | Reason |
|---|---|
| An award is present with no `sig` | `award is present but not signed by the buyer` |
| `award.quote_hash` is absent | `signed award does not bind a quote_hash` |
| No quote on the traveler has `award.quote_id` | `awarded quote is not present to verify its priced content` |
| That quote's content hash is not `award.quote_hash` | `awarded quote content does not match the buyer-signed quote_hash` |
| That quote's `traveler_hash_quoted` is not this traveler's hash | `awarded quote is not bound to this revision` |
| That quote has no price line whose `qty` is `award.qty` | `awarded quote has no price for the awarded quantity` |

A key the directory lists as **revoked** and a key it does not list are different
answers too. The first is evidence — the root withdrew that key, and something signed
with it should not be acted on; the second is an absence of evidence. A receiver MUST NOT
treat a signature made with a revoked key as merely "unverified".

"No award" and "an award that failed" are different answers and MUST be reported
differently. A traveler is **verified** iff at least one authorship check passes and, if
it carries an award, the award check passes.

**What a passed check means.** It means the org the directory names for that key signed
these bytes, as the org the document names as its author. It does **not** mean that org
is the counterparty the reader believes it is dealing with: any enrolled org can author a
traveler under its own `org_id` and any display name, and that traveler verifies — as
that org (`verify-cases.json`, `reissued-under-another-org`). A receiver MUST compare the
reported `org_id` with the org it expects, and a display name is never evidence.

### The ITAR gate

For an `itar: true` traveler a quote is admissible only if, in this order: the traveler
is a valid traveler (a document that is not is refused, never read as "not ITAR"); the
directory verifies; the quote is a valid quote; its seller names an `org_id`; **the
quote's seller signature passes** (`seller.org_id` is a field the quote's author types —
unsigned, it establishes nothing); and that org holds the `itar` capability. A traveler
that is not `itar: true` imposes no gate. This is a consistency rule between a traveler's
self-declaration and a root's attestation — not an export-control determination.

## Export control & commercial reality

- `itar: true` is a self-declaration that the traveler contains
  ITAR-controlled technical data. 0.1 elevates this to directory attestation —
  an ITAR traveler's seller must hold the directory's attested ITAR capability,
  not merely self-declare `seller.itar`. It is still not DDTC registration, a
  TCP, or an EAR ECCN. Shop `certs[]` is for ISO/AS/AWS; the ITAR bit lives on
  `org.itar`.
- Do not put actual USML/EAR technical data on a public or shared browser
  desk. localStorage is not a CUI system (DFARS 252.204-7012 / NIST
  800-171).
- A bound quote is a structured price; an award is not a PO. The 0.0.1 base
  had no governing law, warranty, inspection, payment terms, or
  battle-of-the-forms handling; 0.1 lets an award carry optional commercial
  terms (governing law, warranty, payment), though an award is still not a
  contract by itself. An award also records `quote_hash` — the content hash of
  the quote it names — so the buyer's award signature commits to the exact priced
  quote (unit price, currency, lead time), and verification requires that quote to
  be present on the traveler and unchanged.
- Incoterms 2020 `FOB` is for sea/inland waterway with a named port; US
  domestic shops usually mean UCC F.O.B. origin/destination. The field is a
  free-form string in 0.1.
- Money is an integer count of the currency's minor unit (e.g. cents) in 0.1 —
  exact, no IEEE-754.

## JSON Schemas

`public/schemas/traveler-0.1.0.json` and `public/schemas/quote-0.1.0.json`
(JSON Schema 2020-12, `$id` under `https://securejobenvelope.org/schemas/`).

The schemas accept every traveler the reference implementations accept, and refuse
every traveler they refuse **except** for the rules a JSON Schema cannot state: rules
about the wire text (parsing rules 6–11), comparisons between members (a quote's
`valid_until` must be later than its `created_at`), uniqueness by one member (rule 5),
and serialized size (rules 8 and 12). Those rules are listed, each with the reason and the reject vectors
that break it, in `public/schemas/not-expressible-0.1.0.json`. **Validate against the
schemas, then apply those rules** — a validator that stops at the schemas accepts
documents a conforming implementation refuses.

The schemas judge numbers as binary64 values, string lengths in Unicode code points and
patterns as ECMA-262 regular expressions. `src/lib/traveler/schema-contract.test.ts`
holds the schemas to the implementation: field for field, on every conformance vector,
and on single-edit probes at every field.
