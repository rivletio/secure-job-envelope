@epic:docs
Feature: Spec documentation page
  The in-app spec describes Rivlet Packet 0.0.1 for implementers.

  @rid:S-75b0c3d7
  Scenario: Spec page states media type and hash rule
    When the user opens "/spec"
    Then the heading is "Rivlet Packet 0.0.1"
    And the page cites media type "application/vnd.rivlet.packet+json"
    And the page states quotes bind to packet_hash_quoted as SHA-384 of the canonical quoteable body
    And the archive name pattern is "{packet_id}.rivpkt.zip"

  @rid:S-079c0655
  Scenario: Conformance table lists L0 through L3
    When the user opens "/spec"
    Then the conformance table includes
      | Level | Name       |
      | L0    | Quoteable  |
      | L1    | Awardable  |
      | L2    | Executable |
      | L3    | As-built   |

  @rid:S-ca67769a
  Scenario: Security section links to Trust
    When the user opens "/spec"
    Then the security section states the hash is not a signature
    And a link to "/trust" is offered for the SOC 2 mapping
