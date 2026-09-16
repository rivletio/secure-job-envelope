@epic:packet
Feature: View a packet on the desk
  Opening a packet shows the quoteable body, bound quotes, hash, and level checklist.

  Background:
    Given the desk is seeded with the demo packets

  @rid:S-e321229f
  Scenario: Missing packet id shows a not-on-desk message
    When the user opens "/p/pkt_doesnotexist"
    Then the page shows "No packet pkt_doesnotexist on this desk."
    And a link "Back to desk" goes to "/"

  @rid:S-0b3a81e6
  Scenario: L0 weldment shows quoteable body and no bound quotes
    When the user opens "/p/pkt_wldcart12"
    Then the heading is "Welded cart frame"
    And the part number line includes "NL-CRT-1200"
    And the level badge is "L0 Quoteable"
    And the quoteable body lists material "A36"
    And the quoteable body lists qty "12"
    And the quotes section shows "None yet. Switch to Seller to bind a structured quote."
    And the bound quote count is 0

  @rid:S-2c7a2f1e
  Scenario: L1 bracket lists two quotes bound to the current hash
    When the user opens "/p/pkt_nlbrk4410"
    Then the level badge is "L1 Awardable"
    And the quotes section lists seller "Huron Precision"
    And the quotes section lists seller "Red River Machine"
    And each listed quote shows unit price, lead time, NRE, and rollup
    And Red River Machine shows exception "FINISH_OUTSOURCE"

  @rid:S-d0d7ab2e
  Scenario: L2 enclosure shows executable ship-to and ops
    When the user opens "/p/pkt_smenc1601"
    Then the level badge is "L2 Executable"
    And the executable section shows awarded seller "Cascade Sheet Metal"
    And the executable section shows ship-to "Pacific Hatch — Receiving"
    And the ops list includes "LASER", "FORM", "PEM", "POWDER", "INSPECT", "PACK"

  @rid:S-8b2475af
  Scenario: Sidebar checklist advances with level
    When the user opens "/p/pkt_wldcart12"
    Then the checklist marks "L0 Material + qty" done
    And the checklist next step is "bound quote (packet_hash_quoted)"
    When the user opens "/p/pkt_smenc1601"
    Then the checklist marks "L0", "L1", and "L2" done
