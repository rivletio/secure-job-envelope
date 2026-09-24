# What is revealed

This is the page to read if you want to know what a traveler shows, and what a courier is allowed to say before both sides opt in. The list is code, not a promise in a PDF. [`src/lib/traveler/disclosure.ts`](../src/lib/traveler/disclosure.ts) classifies every field. [`disclosure.test.ts`](../src/lib/traveler/disclosure.test.ts) fails if a field is added to the schema and not classified, and it fails if the courier view contains a name, a contact, a price, a part number, or an address from the sample traveler.

## The file is not encrypted

Spec `sje/0.0.1` is a plaintext JSON file. The SHA-384 hash does not hide anything. Anyone who holds `traveler.json` can read every field in it: buyer name, contact, part number, notes, prices, ship-to. Holding the file is the reveal.

`quotes.assumptions`, `quotes.capacity`, and `as_built` are objects the schema does not close. A writer can put any key in them, and that key is still in the clear. The courier view omits those objects entirely.

## Before both sides opt in

A courier may compute `courierView` and nothing else from the file. That view is:

- part family, material spec, form, processes, finish
- quantity (the target, not the price breaks)
- need-by
- whether the traveler is self-declared ITAR
- the buyer's cert labels (ISO, AS), not the buyer's name
- how many quotes exist, and whether one was awarded
- the conformance level (draft, quoteable, awardable, executable)

A courier may not say, and `courierView` does not contain:

- names, org ids, cities, contacts, phones, emails
- part numbers, descriptions, drawing revisions, tolerances, notes
- ship-to
- prices, freight, lead time, seller names
- the traveler id

Bond and insurance certificates are not fields in this format. A carrier name, a limit, and an expiry are claims someone said. The certificate bytes are not in the traveler.

## After both sides opt in

The two parties may exchange the file. That is the reveal. The courier still does not need the body. Passing the file is not the same as the courier reading it.

## What this repo does not prove

Claanker is a separate, private program. It is supposed to follow this view. This repository cannot see Claanker's model, so it cannot prove a spoken blurb obeyed the list. What it can prove is the list itself: run `npm test` and read the courier view. If Claanker says a name before both sides opt in, that is Claanker breaking this file, and the break is visible because the allowlist is public.
