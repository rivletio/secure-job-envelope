@epic:quote
Feature: Bind a structured quote to a traveler hash
  A seller prices quantity breaks against the current traveler_hash.
  Quotes outside the hash climb does not cover unit prices; binding is by hash match.

  Background:
    Given the desk is seeded with the demo travelers
    And the role is "seller"
    And the quoting shop is "org_lakeshore"

  @rid:S-ed931467
  Scenario: Seller opens quote dialog on an L0 traveler
    When the seller opens "/p/tvl_wldcart12"
    And the seller clicks "Quote this hash"
    Then the quote dialog shows traveler_hash_quoted equal to the traveler hash
    And the dialog lists unit inputs for qty breaks 4, 12, and 24
    And the seller identity is "Lakeshore Turning"

  @rid:S-3d848957
  Scenario: Bind quote promotes traveler from L0 to L1
    When the seller opens "/p/tvl_wldcart12"
    And the seller clicks "Quote this hash"
    And the seller sets unit at qty 12 to "85"
    And the seller sets NRE to "400"
    And the seller sets lead time days to "21"
    And the seller clicks "Bind quote"
    Then traveler "tvl_wldcart12" is level "L1"
    And it has one bound quote from "Lakeshore Turning"
    And the quote currency is "USD"
    And the quote valid_until is 14 days from now
    And the local audit contains a "quote" event for "tvl_wldcart12"
    And the quote button on the traveler reads "Quoted" and is disabled

  @rid:S-72c55cae
  Scenario: Cannot bind a quote with no priced lines
    When the seller opens "/p/tvl_wldcart12"
    And the seller clicks "Quote this hash"
    And the seller leaves every unit price empty
    And the seller clicks "Bind quote"
    Then an error toast says "Price at least one quantity break."
    And traveler "tvl_wldcart12" remains level "L0"

  @rid:S-21f49a9e
  Scenario: Same seller cannot place a second quote on the same revision
    Given shop "org_lakeshore" already quoted "tvl_wldcart12" on the current hash
    When the seller opens "/p/tvl_wldcart12"
    Then the quote button reads "Quoted" and is disabled

  @rid:S-39a5c4ae
  Scenario: Quote on a Draft traveler is not offered
    Given a draft traveler "tvl_draft01" missing material spec
    And the role is "seller"
    When the seller opens "/p/tvl_draft01"
    Then the "Quote this hash" button is not shown
