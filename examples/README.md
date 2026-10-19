# Worked examples

Two traveler files and three runnable examples. Each example drives the real
library — the same code the MCP server and the browser desk call — and exits
non-zero if any invariant fails, so they are living documentation and smoke tests
at once.

- [`bracket.traveler.json`](bracket.traveler.json) — a complete L0 (Quoteable)
  traveler: a CNC bracket, 6061-T6 plate, 250 target with price breaks, need-by
  and Incoterms set, ITAR false.
- [`itar.traveler.json`](itar.traveler.json) — an L0 traveler with the ITAR flag
  set (demo data only; no controlled technical data). The flag is a self-declared
  consistency check, not an access-control system.
- [`lifecycle.ts`](lifecycle.ts) — compose → quote → amend → re-quote → award: a
  quote binds to the exact revision it priced, and the award locks the traveler.
- [`signed-traveler.ts`](signed-traveler.ts) — ML-DSA-87 authorship: sign the
  quoteable body, verify against a signed directory, and refuse a tampered body or
  a wrong-org signer.
- [`encrypted-exchange.ts`](encrypted-exchange.ts) — a post-quantum encrypted
  exchange between two desks, with a live "attacks refused" section.

## Run the examples

```bash
npm run example:lifecycle    # binding + the executable lock
npm run example:signatures   # authorship: sign, verify, refuse tamper / wrong org
npm run example:exchange      # confidentiality: seal, open, refuse the attacks
```

The three map to SJE's three security properties — integrity + binding,
authenticity, and confidentiality. For a full walkthrough across every surface
(library, Rust CLI, MCP, and the browser desk), see [docs/GUIDE.md](../docs/GUIDE.md).

## Verify it with the Rust CLI

```bash
cd crates/secure-job-envelope
cargo run -- hash  ../../examples/bracket.traveler.json
# sha384:6a0ed45fcbe295e46ba355c679e3d82bb7458d7ed7d0b5f244ee7c2d783524febb77f370c44ff60ce5ec6a98a3d2ec76
cargo run -- level ../../examples/bracket.traveler.json
# L0 Quoteable
```

If your copy hashes to anything else, the file was modified — that is the
whole point.

## Verify it in TypeScript

```ts
import { travelerHash } from "../src/lib/traveler/hash.ts";
import { levelOf, parseTraveler } from "../src/lib/traveler/conformance.ts";
import { readFileSync } from "node:fs";

const traveler = parseTraveler(JSON.parse(readFileSync("examples/bracket.traveler.json", "utf8")));
console.log(travelerHash(traveler)); // sha384:6a0ed45f…d2ec76 — same as the CLI
console.log(levelOf(traveler).code); // L0
```

Both implementations are independent; agreement on this hash (and on the
golden vector in `crates/secure-job-envelope/tests/golden.json`) is what makes a
quote's `traveler_hash_quoted` mean the same thing to both parties.

## The flow from here

1. **Quote (seller):** open the desk (`npm run dev`), import or compose the
   traveler, switch the role toggle to Seller, and attach a quote — it binds
   to the hash above. The traveler is now **L1 Awardable**.
2. **Amend (buyer):** change qty or material — revision bumps to 2, the
   hash changes, and the quote is stale-marked. Sellers re-quote against
   the new hash.
3. **Award (buyer):** award a bound, unexpired quote, list the ops
   traveler, confirm ship-to — **L2 Executable**, and the traveler locks.
4. **Exchange:** on the Keys page load a trust anchor and (to receive) create an
   identity, then **Seal & send** the traveler to a directory-attested recipient —
   the downloaded artifact is an encrypted `.sje` (random filename), the only thing
   meant to leave the desk. The recipient opens it with their unlocked keystore,
   which decrypts and then verifies structure, size caps, and META.json digests and
   re-checks the hash locally. (The plaintext `{traveler_id}.traveler.zip` export
   remains, relabeled a local copy — not for sending.)
