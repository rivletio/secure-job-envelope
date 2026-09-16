@epic:hash
Feature: Content-addressed traveler hash
  traveler_hash is SHA-384 of the canonical quoteable body.
  Quotes, award, ops, and ship-to sit outside the hash so a traveler can climb L0→L2.

  @rid:S-34a0777b
  Scenario: Golden quoteable body matches the published vector
    Given the golden quoteable body
      | field        | value                |
      | spec         | opentraveler/0.0.1  |
      | traveler_id    | tvl_golden0001       |
      | revision     | 1                    |
      | created_at   | 2026-09-14T00:00:00.000Z |
      | buyer.name   | Northline Equipment  |
      | part.family  | CNC bracket          |
      | part.part_number | NL-BRK-4410      |
      | material.spec| 6061-T6              |
      | qty.target   | 50                   |
      | need_by      | 2026-10-30           |
      | incoterms    | FOB                  |
      | itar         | false                |
    When the quoteable body is hashed
    Then the digest is "sha384:6892aec9ee18e89bd189a646808a4920ca0972a41225d8f8556d796687a14e6213182ea8a657c694023856a712773fac"

  @rid:S-fc5bad61
  Scenario: Canonical JSON sorts keys and uses JS number encoding
    When object {"b":1,"a":2} is canonicalized
    Then the bytes are '{"a":2,"b":1}'
    When object {"t":10.0} is canonicalized
    Then the bytes are '{"t":10}'
    When object {"t":9.53} is canonicalized
    Then the bytes are '{"t":9.53}'

  @rid:S-eccb855a
  Scenario: Extra keys on the in-memory traveler do not enter the hash
    Given seed traveler "tvl_nlbrk4410"
    When the buyer object gains an extra property "extra" = "should-not-hash"
    Then traveler_hash is unchanged
    And the quoteable buyer does not contain "extra"

  @rid:S-9b54f554
  Scenario: Buyer contact is hashed when present
    Given the golden quoteable body
    When buyer.contact is set to "buyer@northline.example"
    Then the hash differs from the golden hash

  @rid:S-b1b7c6e3
  Scenario: Adding quotes does not change traveler_hash
    Given seed traveler "tvl_wldcart12" at L0
    When a bound quote is added and the traveler becomes L1
    Then traveler_hash is unchanged from the L0 value

  @rid:S-2b9028c4
  Scenario: Non-finite and out-of-range numbers are refused by canonicalization
    When canonical JSON is requested for {"n": Infinity}
    Then canonicalization fails
    When canonical JSON is requested for {"n": NaN}
    Then canonicalization fails
    When canonical JSON is requested for {"t": 1e-7}
    Then canonicalization fails
    When canonical JSON is requested for {"t": 0.00001}
    Then the bytes are '{"t":0.00001}'
