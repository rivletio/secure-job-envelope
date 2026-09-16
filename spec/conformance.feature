@epic:conformance
Feature: Traveler conformance levels
  Levels describe how complete a job object is for quoting, award, and run.

  Rule: Draft needs buyer name, family, part number, material spec, and qty >= 1

  @rid:S-ef846a17
  Scenario Outline: Missing quoteable field keeps the traveler at Draft
    Given a traveler that is otherwise quoteable
    And field <field> is cleared or invalid
    When the conformance level is computed
    Then the level code is "D"
    And missing includes "<missing>"

    Examples:
      | field              | missing            |
      | buyer.name         | buyer.name         |
      | part.family        | part.family        |
      | part.part_number   | part.part_number   |
      | part.material.spec | part.material.spec |
      | part.qty.target    | part.qty.target    |

  @rid:S-d1b8a147
  Scenario: Quoteable L0 has material and qty but no bound quote
    Given traveler "tvl_wldcart12" from the seed desk
    When the conformance level is computed
    Then the level code is "L0"
    And the level name is "Quoteable"
    And missing includes "bound quote (traveler_hash_quoted)"

  @rid:S-ec689298
  Scenario: Awardable L1 has at least one hash-bound quote
    Given traveler "tvl_nlbrk4410" from the seed desk
    When the conformance level is computed
    Then the level code is "L1"
    And the level name is "Awardable"
    And missing includes "award bound to current revision"

  @rid:S-89a6df2d
  Scenario: Executable L2 has award, ops, and ship-to
    Given traveler "tvl_smenc1601" from the seed desk
    When the conformance level is computed
    Then the level code is "L2"
    And the level name is "Executable"
    And missing includes "as_built (reserved in 0.0.1)"

  @rid:S-a3ab4c9d
  Scenario: Bound quotes must match the current traveler hash
    Given traveler "tvl_nlbrk4410" with two quotes on the current hash
    When the part material spec changes and revision is not yet bumped via amend
    And quotes still carry the previous traveler_hash_quoted
    Then those quotes are stale
    And bound quote count is 0 for the new hash

  @rid:S-9b6c36d9
  Scenario: Non-ITAR seller quote is excluded from bound set on an ITAR traveler
    Given an ITAR traveler whose current hash is H
    And a schema-valid quote bound to H from a seller with itar false
    When bound quotes are collected
    Then that quote is not bound
