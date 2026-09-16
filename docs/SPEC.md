# Rivlet Packet — spec 0.0.1

Implementable draft. Media type `application/vnd.rivlet.packet+json`.
Archive name `{packet_id}.rivpkt.zip`. License Apache-2.0.

A packet is the job object — one part family between a buyer and sellers —
not a shop OS and not a marketplace. Quotes bind to `packet_hash_quoted`,
a SHA-256 of the canonical **quoteable body**.

## Identifiers

```
packet_id / quote_id : ^[a-z]{3}_[a-z0-9]{6,24}$     (e.g. pkt_8kq2mfn3, qot_x91k2p)
hash                 : ^sha256:[0-9a-f]{64}$
currency             : ^[A-Z]{3}$    country: ^[A-Z]{2}$
created_at           : ISO-8601 UTC with trailing Z
```

Size caps: packet JSON ≤ 512 KiB; archive ≤ 2 MiB; strings ≤ 2000 chars;
names ≤ 128 chars.

## The quoteable body (closed field set)

The hash covers **exactly** these fields — extra keys on in-memory objects
never enter the hash:

```
spec, packet_id, revision, created_at, buyer, part,
need_by, incoterms, itar
```

`buyer` (Org) and `part` are themselves closed: absent optionals are
dropped, empty strings and empty arrays are dropped, `need_by`/`incoterms`
are `null` when absent, `itar` defaults to `false`. Quotes, award, ops, and
ship_to sit **outside** the hash so a packet can climb L0→L2 without
invalidating quotes. Amending the quoteable body bumps `revision` and
stale-marks every existing quote.

**The hash is integrity of the buyer-authored body, not a signature, and
not non-repudiation.** 0.0.1 does not authenticate parties.

## Canonical JSON

RFC 8785-inspired, restricted for cross-language byte equality:

1. Object keys sorted lexicographically; compact output (no whitespace).
2. `undefined` / absent members are omitted entirely.
3. Strings escape per standard JSON. **Field names in 0.0.1 are ASCII**;
   implementations must not rely on non-ASCII key ordering (JS sorts by
   UTF-16 code units, most other languages by Unicode scalar / UTF-8 bytes
   — these diverge above the BMP).
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
   diverge. Non-finite numbers are refused outright. The JSON Schemas
   bound every numeric field inside this range.

The hash is `"sha256:" + lowercase-hex(SHA-256(canonical_json_bytes))`.

Both reference implementations must reproduce the golden vector
(`crates/rivlet-packet/tests/golden.json`) exactly.

## Conformance ladder

| Level | Name | Meaning |
|---|---|---|
| D | Draft | Missing something L0 needs |
| L0 | Quoteable | A seller can price without guessing material or qty |
| L1 | Awardable | ≥ 1 structured quote bound to the current buyer revision |
| L2 | Executable | Awarded, ops listed, ship-to present; packet locks |
| L3 | As-built | **Reserved.** `as_built` may be null in 0.0.1 |

## Quotes

```
required: quote_id, seller, packet_hash_quoted, created_at,
          valid_until, lead_time_days, pricing
pricing.required: currency, lines[]
lines[]: { qty >= 1, unit >= 0 finite }
```

A quote is **bound** when `packet_hash_quoted` equals the current packet
hash. Guards a conforming desk enforces at bind/award time: quote expiry
(`valid_until`), one quote per seller per revision, a priced line at the
target quantity, and ITAR consistency (a seller with `itar !== true` cannot
quote an `itar: true` packet — a consistency check, not compliance).

## Archive (`{packet_id}.rivpkt.zip`)

Allowlisted members only (max 3):

```
packet.json        the packet document (required, root only)
META.json          { spec, packet_hash, packet_json_sha256 } (recommended)
NOTES.txt          free text (optional)
```

Import rules: refuse paths containing `/` or `\` or `..`; cap compressed
and uncompressed sizes; verify CRC32; when META.json is present, verify
both digests against the received `packet.json`; re-canonicalize and check
`packet_hash` yourself — treat the archive as the document.

## Export control & commercial reality

- `itar: true` is a self-declaration that the packet contains
  ITAR-controlled technical data. It is not DDTC registration, a TCP, or an
  EAR ECCN. Shop `certs[]` is for ISO/AS/AWS; the ITAR bit lives on
  `org.itar`.
- Do not put actual USML/EAR technical data on a public or shared browser
  desk. localStorage is not a CUI system (DFARS 252.204-7012 / NIST
  800-171).
- A bound quote is a structured price; an award is not a PO. 0.0.1 has no
  governing law, warranty, inspection, payment terms, or
  battle-of-the-forms handling.
- Incoterms 2020 `FOB` is for sea/inland waterway with a named port; US
  domestic shops usually mean UCC F.O.B. origin/destination. The field is a
  string in 0.0.1.
- Money is IEEE-754 double under the fixed-notation rule above. Prefer
  integer minor units in a later spec if packets become the commercial
  record.

## JSON Schemas

`public/schemas/packet-0.0.1.json` and `public/schemas/quote-0.0.1.json`
(JSON Schema 2020-12, `$id` under `https://packet.rivlet.io/schemas/`).
