# Claanker carries the envelope. Claanker does not open it.

[Claanker](https://github.com/rivletio/claanker) interviews a shop, finds who can take the stuck job, and introduces the two sides only after both say yes.

This repo is the job. Claanker is the courier.

A traveler here is the part family: material, quantity, need-by, the quotes bound to one hash, the award. Claanker never becomes that file. After the match is revealed, Claanker may carry one of these to the other side:

- a traveler from this spec
- a purchase order
- a job
- a bill of lading
- a sealed envelope

## What the courier is allowed to know

Claanker stores the packet so it can be delivered. The agent is shown metadata only: kind, that it is sealed, status, size, and a short hash. It does not open the body, read it back, quote it, or use the contents to match anyone.

On a call, Claanker does not take the body. The sender texts it.

The hash Claanker keeps is a courier check: the packet that left is the packet that arrived. It is not the SJE `sha384` that binds a quote to a revision. Those stay different on purpose. A quote binds to the traveler hash in this spec. Claanker only proves it did not look inside.

## Order of operations

1. Claanker interviews. Names stay hidden.
2. Both sides opt in. Only then are they introduced.
3. Either side may hand Claanker a sealed packet for that match.
4. Claanker passes it. The receiver opens it in their own system, not in the agent.

If a claim about opening, signing, or reading a packet is not in [CLAIMS.md](CLAIMS.md) with a passing test, it is not a promise of this format. Claanker's promise is narrower: pass the sealed packet, do not open it.
