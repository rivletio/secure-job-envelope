# Worked example

[`bracket.traveler.json`](bracket.traveler.json) is a complete L0 (Quoteable)
traveler: a CNC bracket, 6061-T6 plate, 250 target with price breaks, need-by
and Incoterms set, ITAR false.

## Verify it with the Rust CLI

```bash
cd crates/jobseal
cargo run -- hash  ../../examples/bracket.traveler.json
# sha384:548c1e425252e08e479c9d2ac8d583311234fe6813109d1b37655c626807995cf3405df7031d2744b0bb3000a86f8435
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
console.log(travelerHash(traveler)); // sha384:548c1e42…6f8435 — same as the CLI
console.log(levelOf(traveler).code); // L0
```

Both implementations are independent; agreement on this hash (and on the
golden vector in `crates/jobseal/tests/golden.json`) is what makes a
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
4. **Exchange:** export `{traveler_id}.traveler.zip` and send it over whatever
   channel you already use. The recipient's import verifies structure,
   size caps, and META.json digests, then re-checks the hash locally.
