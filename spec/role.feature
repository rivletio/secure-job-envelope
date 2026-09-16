@epic:role
Feature: Buyer and seller role switch
  Role is a local view switch, not identity or access control.
  Buyer composes and awards; seller binds quotes as a chosen shop.

  @rid:S-c24600bb
  Scenario: Default role is buyer
    When the user opens the desk
    Then the role switch shows "Buyer" selected
    And the banner reads "Buyer view — compose, award, export. Not identity."

  @rid:S-873fb7a6
  Scenario: Switch to seller reveals quoting-as shop picker
    When the user selects role "Seller"
    Then the role switch shows "Seller" selected
    And a "Quoting as" select lists the demo shops
    And the selected shop defaults to "Huron Precision · Toledo, OH"

  @rid:S-f75277fd
  Scenario: Seller can change the quoting shop
    Given the role is "seller"
    When the seller chooses shop "org_cascade"
    Then quotes will be authored as "Cascade Sheet Metal"

  @rid:S-10a2b061
  Scenario: Primary nav is always available
    When the user opens any page
    Then the primary nav includes "Desk", "New packet", "Spec", and "Trust"
    And the footer states role is a view, not authentication
