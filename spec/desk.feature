@epic:desk
Feature: Desk packet list
  The home desk lists local packets, filters by conformance level,
  and lets the buyer open or reset the seed set.

  Background:
    Given the desk is seeded with the demo packets

  @rid:S-4006e8e8
  Scenario: Seed desk shows four packets across conformance levels
    When the buyer opens the desk
    Then the desk lists 4 packets
    And the conformance counts are All 4, L0 1, L1 2, L2 1

  @rid:S-89278d6f
  Scenario: Filter desk to L0 quoteable packets
    When the buyer opens the desk
    And the buyer filters by "L0"
    Then the desk shows only packet "pkt_wldcart12"
    And the empty-level message is not shown

  @rid:S-661e8d23
  Scenario: Filter desk to L2 executable packets
    When the buyer opens the desk
    And the buyer filters by "L2"
    Then the desk shows only packet "pkt_smenc1601"

  @rid:S-a9928cd6
  Scenario: Empty filter shows a recovery hint
    Given the desk has no packets at level "L0"
    When the buyer filters by "L0"
    Then the desk shows "No packets at this level. Compose one, or reset the seed desk."

  @rid:S-b6290ddd
  Scenario: Packet card links to the packet page
    When the buyer opens the desk
    And the buyer opens packet card "pkt_nlbrk4410"
    Then the route is "/p/pkt_nlbrk4410"
    And the page heading is "CNC bracket"

  @rid:S-d3e99edd
  Scenario: Reset seed replaces every packet and keeps audit
    Given the buyer has composed packet "pkt_custom01"
    When the buyer confirms "Reset seed"
    Then the desk lists only the four demo packets
    And the local audit contains a "reset" event

  @rid:S-7a1d7a4a
  Scenario: Buyer sees New packet; seller sees Spec instead
    Given the role is "buyer"
    When the buyer opens the desk
    Then the primary action is "New packet" linking to "/new"
    Given the role is "seller"
    When the seller opens the desk
    Then the primary action is "Read spec 0.0.1" linking to "/spec"
