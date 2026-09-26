@epic:itar
Feature: ITAR self-declaration guards
  itar: true is a self-declaration, not DDTC registration or a TCP.
  The desk blocks non-ITAR sellers from quoting or being awarded, and warns on transfer.

  @rid:S-592f14fc
  Scenario: Non-ITAR seller cannot quote an ITAR traveler
    Given an L0 traveler with itar true
    And the role is "seller"
    And the quoting shop is "org_redriver" with itar false
    When the seller opens the traveler
    And the seller opens the quote dialog
    Then the dialog shows that Red River Machine has not self-declared ITAR
    And "Bind quote" is disabled

  @rid:S-93b9ae51
  Scenario: ITAR self-declared seller can quote an ITAR traveler
    Given an L0 traveler with itar true
    And the role is "seller"
    And the quoting shop is "org_huron" with itar true
    When the seller binds a priced quote to the current hash
    Then the traveler becomes level "L1"
    And the bound quote seller.itar is true

  @rid:S-b6d7545e
  Scenario: Cannot award an ITAR traveler to a non-ITAR seller quote
    Given an ITAR traveler with a quote whose seller.itar is false
    When the buyer attempts to award that quote
    Then the award is refused with "Cannot award an ITAR traveler to a non-ITAR seller."

  @rid:S-fc1aafa4
  Scenario: Import of an ITAR traveler asks for confirmation
    Given a valid .traveler.zip whose traveler has itar true
    When the buyer chooses "Open .traveler" and selects that file
    Then a confirm dialog titled "ITAR self-declaration" appears
    And the body warns the desk does not implement export-control
    When the buyer confirms "Import anyway"
    Then the traveler is stored on the desk

  @rid:S-2b55a99f
  Scenario: Cancel ITAR import leaves the desk unchanged
    Given a valid .traveler.zip whose traveler has itar true
    When the buyer chooses "Open .traveler" and selects that file
    And the buyer cancels the ITAR dialog
    Then the traveler is not stored

  @rid:S-e970044a
  Scenario: Export of an ITAR traveler asks before download
    Given an ITAR traveler on the desk
    When the user clicks ".traveler.zip"
    Then a confirm dialog titled "ITAR self-declaration" appears
    When the user confirms "Download anyway"
    Then the archive downloads and an export audit event is recorded

  @rid:S-58ea8df3
  Scenario: Traveler schema rejects ITAR traveler carrying a non-ITAR seller quote
    Given traveler JSON with itar true and a quote whose seller.itar is not true
    When the traveler is parsed
    Then parse fails mentioning ITAR traveler cannot carry a quote from a non-ITAR seller
