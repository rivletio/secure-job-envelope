# Claanker uses SJE

This repository is the open-source job file. MIT. Anyone can implement the traveler, the hash, and the desk.

What a courier may say before both sides opt in is [DISCLOSURE.md](DISCLOSURE.md). `courierView` is the allowlist. It is tested. Claanker is supposed to follow it. This repo cannot see Claanker's model, so a spoken name before opt-in is Claanker breaking a public rule, not a hidden one.

[Claanker](https://github.com/rivletio/claanker) is a product that uses it. Claanker interviews a shop and, after both sides opt in, carries a sealed envelope to the other side. Claanker is not this spec.

## What Claanker may carry

- a traveler from this spec
- a purchase order
- a job
- a bill of lading
- a sealed envelope
- a bond certificate or an insurance certificate, after the shop has stated the carrier, the limit, and the expiry

The claim (carrier, limit, expiry) is something the person said. The certificate is the document. They are not the same thing.

## What the agent cannot do

The document does not go on the call and does not go in the text. The agent has no field for a body. A body sent that way is refused and not stored.

The envelope is encrypted at rest. The agent is shown kind, that it is sealed, status, size, and a short hash. It cannot open the body, read it back, or use the contents to match anyone.

The other party can release the bytes only after both sides have opted in.

Claanker's sha384 is a courier check of the bytes it was handed. It is not the SJE `sha384` that binds a quote to a canonical traveler. Claanker does not open the file to compute that hash.

This is not the 0.1 `.sje` encrypted envelope, not a signature, and not proof that a bond or a policy is real. The other shop reads the certificate. Claanker does not underwrite it.

SJE is public. Claanker is not.
