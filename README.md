# Rivlet Packet

**A content-addressed job envelope for parts manufacturing.**
`application/vnd.rivlet.packet+json` · spec `rivlet-packet/0.0.1` · Apache-2.0

A **packet** is the job object — one part family moving between a buyer and a
seller: part, material, quantity (with price breaks), need-by, ship-to, the
quotes it attracted, and the award. It is **not** a shop OS and **not** a
marketplace. Coordination happens through the *file*: shops exchange
`{packet_id}.rivpkt.zip` archives over whatever channel they already use, and
every implementation that follows this spec computes the same
`sha384:…` hash for the same quoteable body — so a quote can bind to
*exactly* the revision it priced.

```
Buyer composes packet  ──►  L0 Quoteable   (can price without guessing)
Sellers attach quotes  ──►  L1 Awardable   (quotes bound to packet_hash)
Buyer awards + ops     ──►  L2 Executable  (locked; traveler + ship-to)
                            L3 As-built    (reserved in 0.0.1)
```

This repo contains:

| Path | What it is |
|---|---|
| `docs/SPEC.md` | The 0.0.1 spec: quoteable body, canonical JSON, hash, conformance ladder, archive layout |
| `public/schemas/` | JSON Schema 2020-12 for packet and quote |
| `src/lib/packet/` | Reference **TypeScript** implementation (canonicalization, hashing, guards, zip import/export) |
| `crates/rivlet-packet/` | Independent **Rust** implementation + CLI (`rivlet-packet hash|level`) |
| `src/` (the rest) | The **desk** — a browser workbench that demonstrates the full L0→L2 flow |
| `examples/` | A worked example packet and how to verify it with both implementations |
| `TRUST.md` | Honest SOC 2 TSC mapping: what this gives you, what it does not |
| `SECURITY.md` | Threat model and how to report issues |

Hashing is **SHA-384** — chosen for post-quantum collision margins (see
`SECURITY.md`), locked in before anything shipped so no deployed hash ever
has to migrate.

The TypeScript and Rust implementations are deliberately independent — no
shared code, no wasm bridge — and are held together by a **golden test
vector** (`crates/rivlet-packet/tests/golden.json`): both must produce the
same hash for the same body, byte for byte. Numbers that would render
differently across languages (exponential notation) are **refused by both
sides** rather than hashed ambiguously; see the canonicalization rules in
[`docs/SPEC.md`](docs/SPEC.md).

## Quickstart — the desk

```bash
npm install
npm run dev        # browser workbench
npm test           # packet test suite (golden hash, guards, zip round-trip)
npm run typecheck
```

The desk stores packets in your browser's localStorage — it is a
demonstration surface for the format, not a hosted service. The Buyer/Seller
toggle is a *view*, not authentication (see `TRUST.md`).

## Quickstart — the Rust verifier

```bash
cd crates/rivlet-packet
cargo test         # includes the shared golden vector
cargo run -- hash  ../../examples/bracket.packet.json
cargo run -- level ../../examples/bracket.packet.json
```

## What 0.0.1 deliberately does not do

Stated here so nobody discovers it the hard way:

- **The hash is integrity, not a signature.** Anyone can mint a quote
  claiming to be a named shop. Party authentication (signing) is the top
  candidate for 0.1.
- **No identity, tenancy, or access control.** `org_id` is self-asserted.
- **`itar: true` is a self-declaration** with a quote/award consistency
  check — not DDTC registration, not a Technology Control Plan. Do not put
  actual USML/EAR technical data in a browser demo (see `TRUST.md`).
- **Money is IEEE-754** with fixed-notation canonical bounds; a later spec
  should prefer integer minor units if packets become the commercial record.
- An award is a structured decision, **not a purchase order** — 0.0.1 has no
  governing law, warranty, or payment terms.

## Why a file format

Every job shop already has systems — an ERP it rents, a desktop app it
fears, spreadsheets that hold it together. A coordination *platform* asks
everyone to move in. A coordination *format* meets every shop where it is:
any tool that can read and write a small, hashable JSON envelope can
participate, and the hash means nobody has to trust anyone's database but
their own. The platform can come later; the envelope has to come first.

## License

Apache-2.0. See [LICENSE](LICENSE).
