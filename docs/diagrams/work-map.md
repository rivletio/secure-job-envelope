```mermaid
flowchart TB
  subgraph W1["Start now · wave 1"]
    S_1944528f["S-1944528f  Amend bumps revision and drops bound quotes to stale"]
    S_ca8a13fd["S-ca8a13fd  Stale quote cannot be awarded after amend"]
    S_6428f647["S-6428f647  Executable traveler ignores amend"]
    S_3d08634f["S-3d08634f  Executable traveler refuses new quotes"]
    S_8cf485e5["S-8cf485e5  Upserting over an executable traveler is refused"]
    S_ffb48ccf["S-ffb48ccf  Buyer awards a live quote with ship-to and ops"]
    S_3c28a4e7["S-3c28a4e7  Award requires a complete ship-to"]
    S_8567ecbe["S-8567ecbe  Award requires at least one op"]
    S_b04f169e["S-b04f169e  Cannot award an expired quote"]
    S_c7c5b590["S-c7c5b590  Cannot award a quote with no unit price at target qty"]
    S_a493899f["S-a493899f  Seller role does not show Award buttons"]
    S_7cd6dc95["S-7cd6dc95  Award is refused when the traveler is already executable"]
    S_8c76ba69["S-8c76ba69  Live draft is L0 when material and qty are filled"]
    S_31b13e28["S-31b13e28  Draft missing material stays Draft"]
    S_fb69dc1d["S-fb69dc1d  Seal creates an L0 traveler and navigates to it"]
    S_addded0e["S-addded0e  Cannot seal a Draft traveler"]
    S_f6d7fcdc["S-f6d7fcdc  ITAR self-declaration shows a non-compliance notice"]
    S_ef846a17["S-ef846a17  Missing quoteable field keeps the traveler at Draft"]
    S_d1b8a147["S-d1b8a147  Quoteable L0 has material and qty but no bound quote"]
    S_ec689298["S-ec689298  Awardable L1 has at least one hash-bound quote"]
    S_89a6df2d["S-89a6df2d  Executable L2 has award, ops, and ship-to"]
    S_a3ab4c9d["S-a3ab4c9d  Bound quotes must match the current traveler hash"]
    S_9b6c36d9["S-9b6c36d9  Non-ITAR seller quote is excluded from bound set on an ITAR traveler"]
    S_4006e8e8["S-4006e8e8  Seed desk shows four travelers across conformance levels"]
    S_89278d6f["S-89278d6f  Filter desk to L0 quoteable travelers"]
    S_661e8d23["S-661e8d23  Filter desk to L2 executable travelers"]
    S_a9928cd6["S-a9928cd6  Empty filter shows a recovery hint"]
    S_b6290ddd["S-b6290ddd  Traveler card links to the traveler page"]
    S_d3e99edd["S-d3e99edd  Reset seed replaces every traveler and keeps audit"]
    S_7a1d7a4a["S-7a1d7a4a  Buyer sees New traveler; seller sees Spec instead"]
    S_34a0777b["S-34a0777b  Golden quoteable body matches the published vector"]
    S_fc5bad61["S-fc5bad61  Canonical JSON sorts keys and uses JS number encoding"]
    S_eccb855a["S-eccb855a  Extra keys on the in-memory traveler do not enter the hash"]
    S_9b54f554["S-9b54f554  Buyer contact is hashed when present"]
    S_b1b7c6e3["S-b1b7c6e3  Adding quotes does not change traveler_hash"]
    S_2b9028c4["S-2b9028c4  Non-finite and out-of-range numbers are refused by canonicalization"]
    S_2f13412c["S-2f13412c  Export traveler zip downloads the archive and audits"]
    S_81f75882["S-81f75882  Export JSON downloads traveler json"]
    S_a3fc34f2["S-a3fc34f2  Round-trip zip preserves traveler id and hash"]
    S_5f007835["S-5f007835  Open plain traveler JSON from the desk"]
    S_947d4869["S-947d4869  Zip without META.json is rejected"]
    S_426f614a["S-426f614a  Zip with path traversal is rejected"]
    S_f6d69aaa["S-f6d69aaa  Zip with unexpected member is rejected"]
    S_27956542["S-27956542  META traveler_hash mismatch is rejected"]
    S_8fc9037d["S-8fc9037d  META traveler_id mismatch is rejected"]
    S_5b35da2f["S-5b35da2f  File larger than 2 MB is rejected"]
    S_c1c6d06f["S-c1c6d06f  Import will not overwrite a locked L2 traveler"]
    S_592f14fc["S-592f14fc  Non-ITAR seller cannot quote an ITAR traveler"]
    S_93b9ae51["S-93b9ae51  ITAR-registered seller can quote an ITAR traveler"]
    S_b6d7545e["S-b6d7545e  Cannot award an ITAR traveler to a non-ITAR seller quote"]
    S_fc1aafa4["S-fc1aafa4  Import of an ITAR traveler asks for confirmation"]
    S_2b55a99f["S-2b55a99f  Cancel ITAR import leaves the desk unchanged"]
    S_e970044a["S-e970044a  Export of an ITAR traveler asks before download"]
    S_58ea8df3["S-58ea8df3  Traveler schema rejects ITAR traveler carrying a non-ITAR seller quote"]
    S_485d185d["S-485d185d  Skip link targets main desk content"]
    S_7eefbd72["S-7eefbd72  Brand returns home"]
    S_56ed3456["S-56ed3456  Active nav reflects the current path"]
    S_9e04747d["S-9e04747d  Unknown traveler still renders the shell"]
    S_e321229f["S-e321229f  Missing traveler id shows a not-on-desk message"]
    S_0b3a81e6["S-0b3a81e6  L0 weldment shows quoteable body and no bound quotes"]
    S_2c7a2f1e["S-2c7a2f1e  L1 bracket lists two quotes bound to the current hash"]
    S_d0d7ab2e["S-d0d7ab2e  L2 enclosure shows executable ship-to and ops"]
    S_8b2475af["S-8b2475af  Sidebar checklist advances with level"]
    S_ed931467["S-ed931467  Seller opens quote dialog on an L0 traveler"]
    S_3d848957["S-3d848957  Bind quote promotes traveler from L0 to L1"]
    S_72c55cae["S-72c55cae  Cannot bind a quote with no priced lines"]
    S_21f49a9e["S-21f49a9e  Same seller cannot place a second quote on the same revision"]
    S_39a5c4ae["S-39a5c4ae  Quote on a Draft traveler is not offered"]
    S_c24600bb["S-c24600bb  Default role is buyer"]
    S_873fb7a6["S-873fb7a6  Switch to seller reveals quoting-as shop picker"]
    S_f75277fd["S-f75277fd  Seller can change the quoting shop"]
    S_10a2b061["S-10a2b061  Primary nav is always available"]
    S_b3a29bb1["S-b3a29bb1  Traveler requires opentraveler/0.0.1 spec and id shape"]
    S_25ff4dda["S-25ff4dda  Traveler id must match tvl_ style token"]
    S_892f8a4f["S-892f8a4f  Quote rejects negative unit price"]
    S_d9f02391["S-d9f02391  Quote rejects non-uppercase currency"]
    S_cd4463f3["S-cd4463f3  Quote rejects non-finite unit price"]
    S_796ddcb3["S-796ddcb3  Quote valid_until must be after created_at"]
    S_fc3729f4["S-fc3729f4  Traveler JSON larger than 512 KiB is refused"]
    S_34356641["S-34356641  Seed travelers all parse and bind"]
    S_75b0c3d7["S-75b0c3d7  Spec page states media type and hash rule"]
    S_079c0655["S-079c0655  Conformance table lists L0 through L3"]
    S_ca67769a["S-ca67769a  Security section links to Trust"]
    S_70d49ee2["S-70d49ee2  Trust page explains the local boundary"]
    S_5a455334["S-5a455334  Empty audit shows a placeholder"]
    S_00b5968f["S-00b5968f  Audit lists newest first after desk activity"]
    S_f2b00280["S-f2b00280  Export audit downloads JSON"]
    S_d639a435["S-d639a435  Audit retains at most 100 events"]
  end
  style S_1944528f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ca8a13fd fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_6428f647 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_3d08634f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_8cf485e5 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ffb48ccf fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_3c28a4e7 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_8567ecbe fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_b04f169e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_c7c5b590 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_a493899f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_7cd6dc95 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_8c76ba69 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_31b13e28 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_fb69dc1d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_addded0e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_f6d7fcdc fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ef846a17 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_d1b8a147 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ec689298 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_89a6df2d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_a3ab4c9d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_9b6c36d9 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_4006e8e8 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_89278d6f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_661e8d23 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_a9928cd6 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_b6290ddd fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_d3e99edd fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_7a1d7a4a fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_34a0777b fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_fc5bad61 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_eccb855a fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_9b54f554 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_b1b7c6e3 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_2b9028c4 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_2f13412c fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_81f75882 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_a3fc34f2 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_5f007835 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_947d4869 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_426f614a fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_f6d69aaa fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_27956542 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_8fc9037d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_5b35da2f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_c1c6d06f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_592f14fc fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_93b9ae51 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_b6d7545e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_fc1aafa4 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_2b55a99f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_e970044a fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_58ea8df3 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_485d185d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_7eefbd72 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_56ed3456 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_9e04747d fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_e321229f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_0b3a81e6 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_2c7a2f1e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_d0d7ab2e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_8b2475af fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ed931467 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_3d848957 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_72c55cae fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_21f49a9e fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_39a5c4ae fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_c24600bb fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_873fb7a6 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_f75277fd fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_10a2b061 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_b3a29bb1 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_25ff4dda fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_892f8a4f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_d9f02391 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_cd4463f3 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_796ddcb3 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_fc3729f4 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_34356641 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_75b0c3d7 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_079c0655 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_ca67769a fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_70d49ee2 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_5a455334 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_00b5968f fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_f2b00280 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
  style S_d639a435 fill:#1f7a4c,stroke:#1a1f26,color:#ffffff
```
