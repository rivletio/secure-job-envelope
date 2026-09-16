```mermaid
graph TD
  E_archive["ARCHIVE"]
  style E_archive fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_archive --> S_import-and-export-rivlet-packet-archives["Import and export Rivlet packet archives"]
  style S_import-and-export-rivlet-packet-archives fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_import-and-export-rivlet-packet-archives --> S_426f614a("·  Zip with path traversal is rejected")
  style S_426f614a fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_f6d69aaa("·  Zip with unexpected member is rejected")
  style S_f6d69aaa fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_8fc9037d("·  META packet_id mismatch is rejected")
  style S_8fc9037d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_947d4869("·  Zip without META.json is rejected")
  style S_947d4869 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_2f13412c("·  Export rivpkt zip downloads the archive and audits")
  style S_2f13412c fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_81f75882("·  Export JSON downloads packet json")
  style S_81f75882 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_5b35da2f("·  File larger than 2 MB is rejected")
  style S_5b35da2f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_5f007835("·  Open plain packet JSON from the desk")
  style S_5f007835 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_c1c6d06f("·  Import will not overwrite a locked L2 packet")
  style S_c1c6d06f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_27956542("·  META packet_hash mismatch is rejected")
  style S_27956542 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_import-and-export-rivlet-packet-archives --> S_a3fc34f2("·  Round-trip zip preserves packet id and hash")
  style S_a3fc34f2 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_award["AWARD"]
  style E_award fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_award --> S_award-a-bound-quote-and-make-the-packet-executable["Award a bound quote and make the packet executable"]
  style S_award-a-bound-quote-and-make-the-packet-executable fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_award-a-bound-quote-and-make-the-packet-executable --> S_ffb48ccf("·  Buyer awards a live quote with ship-to and ops")
  style S_ffb48ccf fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_a493899f("·  Seller role does not show Award buttons")
  style S_a493899f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_7cd6dc95("·  Award is refused when the packet is already executable")
  style S_7cd6dc95 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_b04f169e("·  Cannot award an expired quote")
  style S_b04f169e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_c7c5b590("·  Cannot award a quote with no unit price at target qty")
  style S_c7c5b590 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_3c28a4e7("·  Award requires a complete ship-to")
  style S_3c28a4e7 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_award-a-bound-quote-and-make-the-packet-executable --> S_8567ecbe("·  Award requires at least one op")
  style S_8567ecbe fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_compose["COMPOSE"]
  style E_compose fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_compose --> S_compose-a-new-l0-packet["Compose a new L0 packet"]
  style S_compose-a-new-l0-packet fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_compose-a-new-l0-packet --> S_addded0e("·  Cannot seal a Draft packet")
  style S_addded0e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_compose-a-new-l0-packet --> S_f6d7fcdc("·  ITAR self-declaration shows a non-compliance notice")
  style S_f6d7fcdc fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_compose-a-new-l0-packet --> S_8c76ba69("·  Live draft is L0 when material and qty are filled")
  style S_8c76ba69 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_compose-a-new-l0-packet --> S_31b13e28("·  Draft missing material stays Draft")
  style S_31b13e28 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_compose-a-new-l0-packet --> S_fb69dc1d("·  Seal creates an L0 packet and navigates to it")
  style S_fb69dc1d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_conformance["CONFORMANCE"]
  style E_conformance fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_conformance --> S_packet-conformance-levels["Packet conformance levels"]
  style S_packet-conformance-levels fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_packet-conformance-levels --> S_89a6df2d("·  Executable L2 has award, ops, and ship-to")
  style S_89a6df2d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-conformance-levels --> S_ec689298("·  Awardable L1 has at least one hash-bound quote")
  style S_ec689298 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-conformance-levels --> S_ef846a17("·  Missing quoteable field keeps the packet at Draft")
  style S_ef846a17 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-conformance-levels --> S_9b6c36d9("·  Non-ITAR seller quote is excluded from bound set on an ITAR packet")
  style S_9b6c36d9 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-conformance-levels --> S_d1b8a147("·  Quoteable L0 has material and qty but no bound quote")
  style S_d1b8a147 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-conformance-levels --> S_a3ab4c9d("·  Bound quotes must match the current packet hash")
  style S_a3ab4c9d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_desk["DESK"]
  style E_desk fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_desk --> S_desk-packet-list["Desk packet list"]
  style S_desk-packet-list fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_desk-packet-list --> S_a9928cd6("·  Empty filter shows a recovery hint")
  style S_a9928cd6 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_d3e99edd("·  Reset seed replaces every packet and keeps audit")
  style S_d3e99edd fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_7a1d7a4a("·  Buyer sees New packet; seller sees Spec instead")
  style S_7a1d7a4a fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_661e8d23("·  Filter desk to L2 executable packets")
  style S_661e8d23 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_4006e8e8("·  Seed desk shows four packets across conformance levels")
  style S_4006e8e8 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_89278d6f("·  Filter desk to L0 quoteable packets")
  style S_89278d6f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_desk-packet-list --> S_b6290ddd("·  Packet card links to the packet page")
  style S_b6290ddd fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_docs["DOCS"]
  style E_docs fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_docs --> S_spec-documentation-page["Spec documentation page"]
  style S_spec-documentation-page fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_spec-documentation-page --> S_75b0c3d7("·  Spec page states media type and hash rule")
  style S_75b0c3d7 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_spec-documentation-page --> S_079c0655("·  Conformance table lists L0 through L3")
  style S_079c0655 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_spec-documentation-page --> S_ca67769a("·  Security section links to Trust")
  style S_ca67769a fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_hash["HASH"]
  style E_hash fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_hash --> S_content-addressed-packet-hash["Content-addressed packet hash"]
  style S_content-addressed-packet-hash fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_content-addressed-packet-hash --> S_9b54f554("·  Buyer contact is hashed when present")
  style S_9b54f554 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_content-addressed-packet-hash --> S_b1b7c6e3("·  Adding quotes does not change packet_hash")
  style S_b1b7c6e3 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_content-addressed-packet-hash --> S_fc5bad61("·  Canonical JSON sorts keys and uses JS number encoding")
  style S_fc5bad61 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_content-addressed-packet-hash --> S_2b9028c4("·  Non-finite and out-of-range numbers are refused by canonicalization")
  style S_2b9028c4 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_content-addressed-packet-hash --> S_34a0777b("·  Golden quoteable body matches the published vector")
  style S_34a0777b fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_content-addressed-packet-hash --> S_eccb855a("·  Extra keys on the in-memory packet do not enter the hash")
  style S_eccb855a fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_itar["ITAR"]
  style E_itar fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_itar --> S_itar-self-declaration-guards["ITAR self-declaration guards"]
  style S_itar-self-declaration-guards fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_itar-self-declaration-guards --> S_2b55a99f("·  Cancel ITAR import leaves the desk unchanged")
  style S_2b55a99f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_93b9ae51("·  ITAR-registered seller can quote an ITAR packet")
  style S_93b9ae51 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_58ea8df3("·  Packet schema rejects ITAR packet carrying a non-ITAR seller quote")
  style S_58ea8df3 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_592f14fc("·  Non-ITAR seller cannot quote an ITAR packet")
  style S_592f14fc fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_e970044a("·  Export of an ITAR packet asks before download")
  style S_e970044a fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_b6d7545e("·  Cannot award an ITAR packet to a non-ITAR seller quote")
  style S_b6d7545e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_itar-self-declaration-guards --> S_fc1aafa4("·  Import of an ITAR packet asks for confirmation")
  style S_fc1aafa4 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_lifecycle["LIFECYCLE"]
  style E_lifecycle fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_lifecycle --> S_amend-revision-and-lock-executable-packets["Amend revision and lock executable packets"]
  style S_amend-revision-and-lock-executable-packets fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_amend-revision-and-lock-executable-packets --> S_1944528f("·  Amend bumps revision and drops bound quotes to stale")
  style S_1944528f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_amend-revision-and-lock-executable-packets --> S_6428f647("·  Executable packet ignores amend")
  style S_6428f647 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_amend-revision-and-lock-executable-packets --> S_ca8a13fd("·  Stale quote cannot be awarded after amend")
  style S_ca8a13fd fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_amend-revision-and-lock-executable-packets --> S_8cf485e5("·  Upserting over an executable packet is refused")
  style S_8cf485e5 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_amend-revision-and-lock-executable-packets --> S_3d08634f("·  Executable packet refuses new quotes")
  style S_3d08634f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_packet["PACKET"]
  style E_packet fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_packet --> S_view-a-packet-on-the-desk["View a packet on the desk"]
  style S_view-a-packet-on-the-desk fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_view-a-packet-on-the-desk --> S_8b2475af("·  Sidebar checklist advances with level")
  style S_8b2475af fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_view-a-packet-on-the-desk --> S_e321229f("·  Missing packet id shows a not-on-desk message")
  style S_e321229f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_view-a-packet-on-the-desk --> S_d0d7ab2e("·  L2 enclosure shows executable ship-to and ops")
  style S_d0d7ab2e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_view-a-packet-on-the-desk --> S_2c7a2f1e("·  L1 bracket lists two quotes bound to the current hash")
  style S_2c7a2f1e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_view-a-packet-on-the-desk --> S_0b3a81e6("·  L0 weldment shows quoteable body and no bound quotes")
  style S_0b3a81e6 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_quote["QUOTE"]
  style E_quote fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_quote --> S_bind-a-structured-quote-to-a-packet-hash["Bind a structured quote to a packet hash"]
  style S_bind-a-structured-quote-to-a-packet-hash fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_bind-a-structured-quote-to-a-packet-hash --> S_ed931467("·  Seller opens quote dialog on an L0 packet")
  style S_ed931467 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_bind-a-structured-quote-to-a-packet-hash --> S_72c55cae("·  Cannot bind a quote with no priced lines")
  style S_72c55cae fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_bind-a-structured-quote-to-a-packet-hash --> S_3d848957("·  Bind quote promotes packet from L0 to L1")
  style S_3d848957 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_bind-a-structured-quote-to-a-packet-hash --> S_39a5c4ae("·  Quote on a Draft packet is not offered")
  style S_39a5c4ae fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_bind-a-structured-quote-to-a-packet-hash --> S_21f49a9e("·  Same seller cannot place a second quote on the same revision")
  style S_21f49a9e fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_role["ROLE"]
  style E_role fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_role --> S_buyer-and-seller-role-switch["Buyer and seller role switch"]
  style S_buyer-and-seller-role-switch fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_buyer-and-seller-role-switch --> S_873fb7a6("·  Switch to seller reveals quoting-as shop picker")
  style S_873fb7a6 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_buyer-and-seller-role-switch --> S_10a2b061("·  Primary nav is always available")
  style S_10a2b061 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_buyer-and-seller-role-switch --> S_c24600bb("·  Default role is buyer")
  style S_c24600bb fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_buyer-and-seller-role-switch --> S_f75277fd("·  Seller can change the quoting shop")
  style S_f75277fd fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_schema["SCHEMA"]
  style E_schema fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_schema --> S_packet-and-quote-schema-validation["Packet and quote schema validation"]
  style S_packet-and-quote-schema-validation fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_packet-and-quote-schema-validation --> S_b3a29bb1("·  Packet requires rivlet-packet/0.0.1 spec and id shape")
  style S_b3a29bb1 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_cd4463f3("·  Quote rejects non-finite unit price")
  style S_cd4463f3 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_d9f02391("·  Quote rejects non-uppercase currency")
  style S_d9f02391 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_892f8a4f("·  Quote rejects negative unit price")
  style S_892f8a4f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_25ff4dda("·  Packet id must match pkt_ style token")
  style S_25ff4dda fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_fc3729f4("·  Packet JSON larger than 512 KiB is refused")
  style S_fc3729f4 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_34356641("·  Seed packets all parse and bind")
  style S_34356641 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_packet-and-quote-schema-validation --> S_796ddcb3("·  Quote valid_until must be after created_at")
  style S_796ddcb3 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_shell["SHELL"]
  style E_shell fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_shell --> S_app-shell-navigation["App shell navigation"]
  style S_app-shell-navigation fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_app-shell-navigation --> S_485d185d("·  Skip link targets main desk content")
  style S_485d185d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_app-shell-navigation --> S_9e04747d("·  Unknown packet still renders the shell")
  style S_9e04747d fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_app-shell-navigation --> S_56ed3456("·  Active nav reflects the current path")
  style S_56ed3456 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_app-shell-navigation --> S_7eefbd72("·  Brand returns home")
  style S_7eefbd72 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  E_trust["TRUST"]
  style E_trust fill:#3d4f7c,stroke:#2a3757,color:#ffffff
  E_trust --> S_trust-page-and-local-audit-log["Trust page and local audit log"]
  style S_trust-page-and-local-audit-log fill:#eef1f7,stroke:#3d4f7c,color:#1a1f26
  S_trust-page-and-local-audit-log --> S_00b5968f("·  Audit lists newest first after desk activity")
  style S_00b5968f fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_trust-page-and-local-audit-log --> S_f2b00280("·  Export audit downloads JSON")
  style S_f2b00280 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_trust-page-and-local-audit-log --> S_5a455334("·  Empty audit shows a placeholder")
  style S_5a455334 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_trust-page-and-local-audit-log --> S_70d49ee2("·  Trust page explains the local boundary")
  style S_70d49ee2 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
  S_trust-page-and-local-audit-log --> S_d639a435("·  Audit retains at most 100 events")
  style S_d639a435 fill:#3d4f7c,stroke:#1a1f26,color:#ffffff
```
