@epic:shell
Feature: App shell navigation
  Sticky shell with skip link, brand, primary nav, and role strip wraps every page.

  @rid:S-485d185d
  Scenario: Skip link targets main desk content
    When the user opens any route
    Then a skip link "Skip to desk" targets "#main"

  @rid:S-7eefbd72
  Scenario: Brand returns home
    When the user is on "/spec"
    And the user clicks the rivlet.io brand
    Then the route is "/"

  @rid:S-56ed3456
  Scenario: Active nav reflects the current path
    When the user opens "/new"
    Then nav item "New packet" is current
    And nav item "Desk" is not current

  @rid:S-9e04747d
  Scenario: Unknown packet still renders the shell
    When the user opens "/p/pkt_missing0"
    Then the primary nav is visible
    And the role switch is visible
