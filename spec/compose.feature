@epic:compose
Feature: Compose a new L0 packet
  A buyer seals a quoteable packet when material and qty are known.
  Draft packets missing required fields stay at level D and cannot be sealed.

  @rid:S-8c76ba69
  Scenario: Live draft is L0 when material and qty are filled
    Given the role is "buyer"
    When the buyer opens "/new"
    And the buyer sets material spec to "6061-T6"
    And the buyer sets target qty to "50"
    And the buyer sets family to "CNC bracket"
    And the buyer sets part number to "NL-BRK-9001"
    And the buyer sets buyer name to "Northline Equipment"
    Then the live level badge is "L0 Quoteable"
    And the live hash is a sha384 digest
    And the aside shows "Quoteable. A seller can price this without guessing."

  @rid:S-31b13e28
  Scenario: Draft missing material stays Draft
    Given the role is "buyer"
    When the buyer opens "/new"
    And the buyer clears the material spec
    And the buyer sets target qty to "50"
    And the buyer sets family to "CNC bracket"
    And the buyer sets part number to "NL-BRK-9001"
    And the buyer sets buyer name to "Northline Equipment"
    Then the live level badge is "D Draft"
    And the aside shows missing "part.material.spec"

  @rid:S-fb69dc1d
  Scenario: Seal creates an L0 packet and navigates to it
    Given the role is "buyer"
    When the buyer opens "/new"
    And the buyer sets buyer name to "Northline Equipment"
    And the buyer sets city to "Milwaukee"
    And the buyer sets region to "WI"
    And the buyer sets family to "CNC bracket"
    And the buyer sets part number to "NL-BRK-9001"
    And the buyer sets drawing rev to "A"
    And the buyer sets material spec to "6061-T6"
    And the buyer sets form to "plate"
    And the buyer sets thickness mm to "9.53"
    And the buyer sets target qty to "50"
    And the buyer sets breaks to "10, 50, 200"
    And the buyer selects process "cnc_mill"
    And the buyer submits "Seal L0 packet"
    Then a new packet is stored at level "L0"
    And the packet id matches "^pkt_[a-z0-9]{6,24}$"
    And the route is "/p/" followed by that packet id
    And the local audit contains a "compose" event for that packet

  @rid:S-addded0e
  Scenario: Cannot seal a Draft packet
    Given the role is "buyer"
    When the buyer opens "/new"
    And the buyer clears the material spec
    And the buyer submits "Seal L0 packet"
    Then no packet is stored
    And an error toast lists the missing fields

  @rid:S-f6d7fcdc
  Scenario: ITAR self-declaration shows a non-compliance notice
    Given the role is "buyer"
    When the buyer opens "/new"
    And the buyer checks "ITAR-controlled technical data (self-declaration)"
    Then a warning explains the desk does not implement ITAR, EAR, or deemed-export controls
