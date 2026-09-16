@epic:archive
Feature: Import and export Rivlet traveler archives
  Export writes {traveler_id}.traveler.zip with traveler.json, META.json, and
  quoteable.canonical.json. Import verifies paths, size caps, and digests.

  Background:
    Given the desk is seeded with the demo travelers

  @rid:S-2f13412c
  Scenario: Export traveler zip downloads the archive and audits
    When the user opens "/p/tvl_wldcart12"
    And the user clicks ".traveler.zip"
    Then a file "tvl_wldcart12.traveler.zip" is downloaded
    And the local audit contains an "export" event for "tvl_wldcart12"
    And a success toast says "Exported .traveler.zip"

  @rid:S-81f75882
  Scenario: Export JSON downloads traveler json
    When the user opens "/p/tvl_wldcart12"
    And the user clicks "JSON"
    Then a file "tvl_wldcart12.json" is downloaded with media type application/vnd.opentraveler+json

  @rid:S-a3fc34f2
  Scenario: Round-trip zip preserves traveler id and hash
    Given an exported ".traveler.zip" for seed traveler "tvl_nlbrk4410"
    When the archive is imported onto a fresh desk
    Then the desk contains traveler "tvl_nlbrk4410"
    And its traveler_hash matches the pre-export hash
    And the local audit contains an "import" event

  @rid:S-5f007835
  Scenario: Open plain traveler JSON from the desk
    Given a valid traveler.json file for a new id "tvl_import01"
    When the buyer chooses "Open .traveler" and selects that JSON file
    Then traveler "tvl_import01" appears on the desk
    And a success toast says "Opened tvl_import01"

  @rid:S-947d4869
  Scenario: Zip without META.json is rejected
    Given a zip that contains only root traveler.json
    When the file is imported
    Then import fails with "Archive is missing META.json (required for integrity)"

  @rid:S-426f614a
  Scenario: Zip with path traversal is rejected
    Given a zip whose member is named "../traveler.json"
    When the file is imported
    Then import fails because the archive path is not allowed

  @rid:S-f6d69aaa
  Scenario: Zip with unexpected member is rejected
    Given a zip with traveler.json, META.json, and payload.bin
    When the file is imported
    Then import fails with "Unexpected archive member: payload.bin"

  @rid:S-27956542
  Scenario: META traveler_hash mismatch is rejected
    Given a zip where traveler.json notes were tampered but META still has the old traveler_hash
    When the file is imported
    Then import fails with "META.json traveler_hash does not match quoteable body"

  @rid:S-8fc9037d
  Scenario: META traveler_id mismatch is rejected
    Given a zip where META.traveler_id differs from traveler.json
    When the file is imported
    Then import fails with "META.json traveler_id does not match traveler.json"

  @rid:S-5b35da2f
  Scenario: File larger than 2 MB is rejected
    Given a file larger than 2097152 bytes
    When the file is imported
    Then import fails with "File exceeds 2 MB limit"

  @rid:S-c1c6d06f
  Scenario: Import will not overwrite a locked L2 traveler
    Given seed traveler "tvl_smenc1601" is on the desk at L2
    When an archive for "tvl_smenc1601" is imported
    Then import fails with "Executable traveler is locked."
