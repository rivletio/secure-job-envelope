@epic:schema
Feature: Packet and quote schema validation
  Strict Zod schemas gate what the desk will store or import.

  @rid:S-b3a29bb1
  Scenario: Packet requires rivlet-packet/0.0.1 spec and id shape
    When a document with spec "nope" is parsed as a packet
    Then parse fails with a message starting "Invalid packet"

  @rid:S-25ff4dda
  Scenario: Packet id must match pkt_ style token
    When a packet has packet_id "PACKET-1"
    Then parse fails

  @rid:S-892f8a4f
  Scenario: Quote rejects negative unit price
    Given a quote otherwise valid for hash H
    And pricing.lines is [{ qty: 1, unit: -5 }]
    When the quote is parsed
    Then parse fails

  @rid:S-d9f02391
  Scenario: Quote rejects non-uppercase currency
    Given a quote otherwise valid for hash H
    And pricing.currency is "usd"
    When the quote is parsed
    Then parse fails

  @rid:S-cd4463f3
  Scenario: Quote rejects non-finite unit price
    Given a quote otherwise valid for hash H
    And a line unit of Infinity
    When the quote is parsed
    Then parse fails

  @rid:S-796ddcb3
  Scenario: Quote valid_until must be after created_at
    Given a quote with created_at "2026-09-09T00:00:00.000Z"
    And valid_until "2026-09-08T00:00:00.000Z"
    When the quote is parsed
    Then parse fails on valid_until

  @rid:S-fc3729f4
  Scenario: Packet JSON larger than 512 KiB is refused
    Given a packet whose JSON serialization exceeds 524288 bytes
    When the packet is parsed
    Then parse fails with "packet exceeds 512 KiB"

  @rid:S-34356641
  Scenario: Seed packets all parse and bind
    Given the four demo seed packets
    When each is parsed
    Then every bound quote packet_hash_quoted equals packet_hash of its packet
    And levels are L1, L2, L1, L0 in seed order
