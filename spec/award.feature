@epic:award
Feature: Award a bound quote and make the packet executable
  L2 requires a live bound quote, at least one op, and a complete ship-to.
  Award is not a purchase order.

  Background:
    Given the role is "buyer"

  @rid:S-ffb48ccf
  Scenario: Buyer awards a live quote with ship-to and ops
    Given L1 packet "pkt_award01" with a non-expired bound quote "qte_live01" from "Huron Precision"
    And the quote has a unit price at the packet target qty 50
    When the buyer opens "/p/pkt_award01"
    And the buyer clicks "Award" on quote "qte_live01"
    And the buyer sets ship-to name to "Northline Equipment — Dock 2"
    And the buyer sets street to "4400 W State St"
    And the buyer sets city to "Milwaukee"
    And the buyer sets region to "WI"
    And the buyer sets postal to "53208"
    And the buyer sets ops to "MILL, ANODIZE, INSPECT, PACK"
    And the buyer confirms award to "Huron Precision"
    Then packet "pkt_award01" is level "L2"
    And the award references quote "qte_live01"
    And the award qty is 50
    And ship_to country is "US"
    And ops are sequenced MILL, ANODIZE, INSPECT, PACK
    And the local audit contains an "award" event for "pkt_award01"
    And a success toast says "Packet is L2 executable."

  @rid:S-3c28a4e7
  Scenario: Award requires a complete ship-to
    Given L1 packet "pkt_award01" with a non-expired bound quote "qte_live01"
    When the buyer opens "/p/pkt_award01"
    And the buyer clicks "Award" on quote "qte_live01"
    And the buyer clears the street field
    And the buyer confirms award
    Then an error toast says "Ship-to needs street, city, region, postal."
    And packet "pkt_award01" remains level "L1"

  @rid:S-8567ecbe
  Scenario: Award requires at least one op
    Given L1 packet "pkt_award01" with a non-expired bound quote "qte_live01"
    When the buyer opens "/p/pkt_award01"
    And the buyer clicks "Award" on quote "qte_live01"
    And the buyer sets a complete ship-to
    And the buyer clears the ops field
    And the buyer confirms award
    Then an error toast says "List at least one op."
    And packet "pkt_award01" remains level "L1"

  @rid:S-b04f169e
  Scenario: Cannot award an expired quote
    Given L1 packet "pkt_award01" with bound quote "qte_old01" whose valid_until is in the past
    When the buyer opens "/p/pkt_award01"
    And the buyer clicks "Award" on quote "qte_old01"
    Then the award dialog warns the quote is past valid_until
    And the award confirm button is disabled

  @rid:S-c7c5b590
  Scenario: Cannot award a quote with no unit price at target qty
    Given L1 packet "pkt_award01" with target qty 50
    And a bound quote priced only at qty 7
    When the buyer attempts to award that quote
    Then the award is refused because there is no unit price at qty 50

  @rid:S-a493899f
  Scenario: Seller role does not show Award buttons
    Given the desk is seeded with the demo packets
    And the role is "seller"
    When the seller opens "/p/pkt_nlbrk4410"
    Then no "Award" button is shown on bound quotes

  @rid:S-7cd6dc95
  Scenario: Award is refused when the packet is already executable
    Given L2 packet "pkt_smenc1601" on the desk
    When the store award is invoked again for its existing quote
    Then the operation fails with "Packet is already executable."
