@epic:lifecycle
Feature: Amend revision and lock executable travelers
  Amending the quoteable body bumps revision and stale-marks prior quotes.
  Once a traveler is L2 executable it cannot be amended or re-quoted.

  @rid:S-1944528f
  Scenario: Amend bumps revision and drops bound quotes to stale
    Given an L0 traveler "tvl_tamend01" on the desk
    And a quote bound to its current hash
    And the traveler is level "L1"
    When the traveler is amended with need_by "2026-12-01"
    Then revision is prior revision plus 1
    And stale quote count is 1
    And the traveler level is "L0"
    And the local audit contains an "amend" event for "tvl_tamend01"

  @rid:S-ca8a13fd
  Scenario: Stale quote cannot be awarded after amend
    Given an L1 traveler with a bound quote
    When the traveler is amended so the hash moves
    And the buyer attempts to award the old quote id
    Then the award is refused because the quote is not bound to the current hash

  @rid:S-6428f647
  Scenario: Executable traveler ignores amend
    Given seed traveler "tvl_smenc1601" at level "L2"
    When an amend sets need_by to "2027-01-01"
    Then revision is unchanged
    And need_by is unchanged
    And the level remains "L2"

  @rid:S-3d08634f
  Scenario: Executable traveler refuses new quotes
    Given seed traveler "tvl_smenc1601" at level "L2"
    And the role is "seller"
    When a seller attempts to add a quote bound to the current hash
    Then the quote is refused with "Executable travelers cannot take new quotes."

  @rid:S-8cf485e5
  Scenario: Upserting over an executable traveler is refused
    Given seed traveler "tvl_smenc1601" at level "L2"
    When the desk tries to upsert a replacement with the same traveler_id
    Then the operation fails with "Executable traveler is locked."
