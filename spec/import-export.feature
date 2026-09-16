@epic:archive
Feature: Import and export Rivlet packet archives
  Export writes {packet_id}.rivpkt.zip with packet.json, META.json, and
  quoteable.canonical.json. Import verifies paths, size caps, and digests.

  Background:
    Given the desk is seeded with the demo packets

  @rid:S-2f13412c
  Scenario: Export rivpkt zip downloads the archive and audits
    When the user opens "/p/pkt_wldcart12"
    And the user clicks ".rivpkt.zip"
    Then a file "pkt_wldcart12.rivpkt.zip" is downloaded
    And the local audit contains an "export" event for "pkt_wldcart12"
    And a success toast says "Exported .rivpkt.zip"

  @rid:S-81f75882
  Scenario: Export JSON downloads packet json
    When the user opens "/p/pkt_wldcart12"
    And the user clicks "JSON"
    Then a file "pkt_wldcart12.json" is downloaded with media type application/vnd.rivlet.packet+json

  @rid:S-a3fc34f2
  Scenario: Round-trip zip preserves packet id and hash
    Given an exported ".rivpkt.zip" for seed packet "pkt_nlbrk4410"
    When the archive is imported onto a fresh desk
    Then the desk contains packet "pkt_nlbrk4410"
    And its packet_hash matches the pre-export hash
    And the local audit contains an "import" event

  @rid:S-5f007835
  Scenario: Open plain packet JSON from the desk
    Given a valid packet.json file for a new id "pkt_import01"
    When the buyer chooses "Open .rivpkt" and selects that JSON file
    Then packet "pkt_import01" appears on the desk
    And a success toast says "Opened pkt_import01"

  @rid:S-947d4869
  Scenario: Zip without META.json is rejected
    Given a zip that contains only root packet.json
    When the file is imported
    Then import fails with "Archive is missing META.json (required for integrity)"

  @rid:S-426f614a
  Scenario: Zip with path traversal is rejected
    Given a zip whose member is named "../packet.json"
    When the file is imported
    Then import fails because the archive path is not allowed

  @rid:S-f6d69aaa
  Scenario: Zip with unexpected member is rejected
    Given a zip with packet.json, META.json, and payload.bin
    When the file is imported
    Then import fails with "Unexpected archive member: payload.bin"

  @rid:S-27956542
  Scenario: META packet_hash mismatch is rejected
    Given a zip where packet.json notes were tampered but META still has the old packet_hash
    When the file is imported
    Then import fails with "META.json packet_hash does not match quoteable body"

  @rid:S-8fc9037d
  Scenario: META packet_id mismatch is rejected
    Given a zip where META.packet_id differs from packet.json
    When the file is imported
    Then import fails with "META.json packet_id does not match packet.json"

  @rid:S-5b35da2f
  Scenario: File larger than 2 MB is rejected
    Given a file larger than 2097152 bytes
    When the file is imported
    Then import fails with "File exceeds 2 MB limit"

  @rid:S-c1c6d06f
  Scenario: Import will not overwrite a locked L2 packet
    Given seed packet "pkt_smenc1601" is on the desk at L2
    When an archive for "pkt_smenc1601" is imported
    Then import fails with "Executable packet is locked."
