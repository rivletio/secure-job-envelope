# Worked example

[`bracket.packet.json`](bracket.packet.json) is a complete L0 (Quoteable)
packet: a CNC bracket, 6061-T6 plate, 250 target with price breaks, need-by
and Incoterms set, ITAR false.

## Verify it with the Rust CLI

```bash
cd crates/rivlet-packet
cargo run -- hash  ../../examples/bracket.packet.json
# sha256:43ad37e1fdf3d93530f13f7a45fe397682dc1f942d4c82257932aa22c750daf4
cargo run -- level ../../examples/bracket.packet.json
# L0 Quoteable
```

If your copy hashes to anything else, the file was modified — that is the
whole point.

## Verify it in TypeScript

```ts
import { packetHash } from "../src/lib/packet/hash.ts";
import { levelOf, parsePacket } from "../src/lib/packet/conformance.ts";
import { readFileSync } from "node:fs";

const packet = parsePacket(readFileSync("examples/bracket.packet.json", "utf8"));
console.log(packetHash(packet)); // sha256:43ad37e1…50daf4 — same as the CLI
console.log(levelOf(packet).code); // L0
```

Both implementations are independent; agreement on this hash (and on the
golden vector in `crates/rivlet-packet/tests/golden.json`) is what makes a
quote's `packet_hash_quoted` mean the same thing to both parties.

## The flow from here

1. **Quote (seller):** open the desk (`npm run dev`), import or compose the
   packet, switch the role toggle to Seller, and attach a quote — it binds
   to the hash above. The packet is now **L1 Awardable**.
2. **Amend (buyer):** change qty or material — revision bumps to 2, the
   hash changes, and the quote is stale-marked. Sellers re-quote against
   the new hash.
3. **Award (buyer):** award a bound, unexpired quote, list the ops
   traveler, confirm ship-to — **L2 Executable**, and the packet locks.
4. **Exchange:** export `{packet_id}.rivpkt.zip` and send it over whatever
   channel you already use. The recipient's import verifies structure,
   size caps, and META.json digests, then re-checks the hash locally.
