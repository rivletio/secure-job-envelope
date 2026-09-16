@epic:trust
Feature: Trust page and local audit log
  The desk keeps an append-only local audit of compose, quote, award, import,
  export, amend, and reset. Cap is 100 events. Role is not authentication.

  @rid:S-70d49ee2
  Scenario: Trust page explains the local boundary
    When the user opens "/trust"
    Then the heading mentions SOC 2 and that this desk is not that system
    And a TSC mapping table includes rows for CC6 Access and CC7 Monitoring
    And the page states Buyer/Seller is a view, not login

  @rid:S-5a455334
  Scenario: Empty audit shows a placeholder
    Given the local audit is empty
    When the user opens "/trust"
    Then the page shows "Empty until you compose, quote, award, import, or export."
    And "Export log" is disabled

  @rid:S-00b5968f
  Scenario: Audit lists newest first after desk activity
    Given the buyer composed traveler "tvl_aud01"
    And a seller bound a quote on "tvl_aud01"
    When the user opens "/trust"
    Then the audit list shows act "quote" above act "compose" for "tvl_aud01"
    And each row has an ISO timestamp

  @rid:S-f2b00280
  Scenario: Export audit downloads JSON
    Given the local audit has at least one event
    When the user clicks "Export log" on "/trust"
    Then a file "sje-audit.json" is downloaded
    And the file is a JSON array of audit events

  @rid:S-d639a435
  Scenario: Audit retains at most 100 events
    Given 100 audit events already stored
    When another compose is audited
    Then the audit length is 100
    And the oldest event was dropped
