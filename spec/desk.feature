@epic:desk
Feature: Desk traveler list
  The home desk lists local travelers, filters by conformance level,
  and lets the buyer open or reset the seed set.

  Background:
    Given the desk is seeded with the demo travelers

  @rid:S-4006e8e8
  Scenario: Seed desk shows four travelers across conformance levels
    When the buyer opens the desk
    Then the desk lists 4 travelers
    And the conformance counts are All 4, L0 1, L1 2, L2 1

  @rid:S-89278d6f
  Scenario: Filter desk to L0 quoteable travelers
    When the buyer opens the desk
    And the buyer filters by "L0"
    Then the desk shows only traveler "tvl_wldcart12"
    And the empty-level message is not shown

  @rid:S-661e8d23
  Scenario: Filter desk to L2 executable travelers
    When the buyer opens the desk
    And the buyer filters by "L2"
    Then the desk shows only traveler "tvl_smenc1601"

  @rid:S-a9928cd6
  Scenario: Empty filter shows a recovery hint
    Given the desk has no travelers at level "L0"
    When the buyer filters by "L0"
    Then the desk shows "No travelers at this level. Compose one, or reset the seed desk."

  @rid:S-b6290ddd
  Scenario: Traveler card links to the traveler page
    When the buyer opens the desk
    And the buyer opens traveler card "tvl_nlbrk4410"
    Then the route is "/p/tvl_nlbrk4410"
    And the page heading is "CNC bracket"

  @rid:S-d3e99edd
  Scenario: Reset seed replaces every traveler and keeps audit
    Given the buyer has composed traveler "tvl_custom01"
    When the buyer confirms "Reset seed"
    Then the desk lists only the four demo travelers
    And the local audit contains a "reset" event

  @rid:S-7a1d7a4a
  Scenario: Buyer sees New traveler; seller sees Spec instead
    Given the role is "buyer"
    When the buyer opens the desk
    Then the primary action is "New traveler" linking to "/new"
    Given the role is "seller"
    When the seller opens the desk
    Then the primary action is "Read spec 0.0.1" linking to "/spec"
