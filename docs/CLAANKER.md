# Claanker uses Envelope

This repository is the open-source job file. Apache-2.0. Anyone can implement the traveler, the hash, and the desk.

[Claanker](https://github.com/rivletio/claanker) is a product that uses it. Claanker is not this spec, and this spec is not Claanker. Claanker interviews a shop, finds who can take the stuck job, and after both sides opt in hands them an Envelope.

Claanker may carry:

- a traveler from this spec
- a purchase order
- a job
- a bill of lading
- a sealed envelope

The agent stores the packet so it can be delivered. It is shown kind, that it is sealed, status, size, and a short hash. It does not open the body, read it back, quote it, or use the contents to match anyone. On a call it does not take the body. The sender texts it.

The hash Claanker keeps is a courier check. It is not the SJE `sha384` that binds a quote to a revision.

## Order

1. Claanker interviews. Names stay hidden.
2. Both sides opt in.
3. Either side may hand Claanker a sealed Envelope for that match.
4. Claanker passes it. The receiver opens it in their own system.

Envelope is public. Claanker is not.
