import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import {
  kemKeypairFromSeed,
  sealEnvelope,
  sealEnvelopeDeterministic,
  openEnvelope,
  recipientByOrg,
  encKid,
  sealFsEnvelope,
  sealFsEnvelopeDeterministic,
  openFsEnvelope,
  fsRecipientFromBundle,
  type Envelope,
  type FsEnvelope,
} from "./envelope.ts";
import { assertEnvelopeShape, ENVELOPE_SPEC } from "./envelope.ts";
import { bytesToHex, hexToBytes } from "./bytes.ts";
import type { Directory } from "./directory.ts";
import type { PrekeyBundle } from "./prekeys.ts";
import { parseSjeEnvelope } from "./transport.ts";

const vec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/envelope.json", import.meta.url), "utf8"),
) as {
  recipient: { kid: string; org_id: string; seed_hex: string; public_key_hex: string };
  determinism: { cek_hex: string; payload_nonce_hex: string; coins_hex: string; wrap_nonce_hex: string };
  plaintext_utf8: string;
  envelope: Envelope;
};

const dirVec = JSON.parse(
  readFileSync(new URL("../../../conformance/signatures/directory.json", import.meta.url), "utf8"),
) as { directory: Directory };

const kid = vec.recipient.kid;

/** What an open throws when an AES-256-GCM tag does not verify (the message is
 *  @noble/ciphers'). For an envelope that passes the shape check and lists the kid it is
 *  opened for, a well-formed key can fail on nothing else — and the failure reads the same
 *  whether the key is wrong or the ciphertext, a nonce or the associated data was changed.
 *  So a refusal pinned to it says "got past the shape check and the recipient lookup, then
 *  failed a tag", and no more. What it failed ON comes from the control each one has
 *  beside it: the same key opens the envelope without the one change. */
const TAG_MISMATCH = /^Error: aes-gcm: invalid tag$/;

function det() {
  return {
    cek: hexToBytes(vec.determinism.cek_hex),
    payload_nonce: hexToBytes(vec.determinism.payload_nonce_hex),
    coins: [hexToBytes(vec.determinism.coins_hex)],
    wrap_nonces: [hexToBytes(vec.determinism.wrap_nonce_hex)],
  };
}

describe("encrypted envelope (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM)", () => {
  it("re-derives the recipient key and re-seals deterministically to the vector", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    assert.equal(bytesToHex(kp.publicKey), vec.recipient.public_key_hex);
    const env = sealEnvelopeDeterministic(
      new TextEncoder().encode(vec.plaintext_utf8),
      [{ kid, public_key: vec.recipient.public_key_hex }],
      det(),
    );
    assert.deepEqual(env, vec.envelope);
  });

  it("opens the vector envelope back to the plaintext", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    const opened = new TextDecoder().decode(openEnvelope(vec.envelope, kid, kp.secretKey));
    assert.equal(opened, vec.plaintext_utf8);
  });

  it("rejects a tampered payload and an unknown recipient", () => {
    const kp = kemKeypairFromSeed(hexToBytes(vec.recipient.seed_hex));
    // control for both refusals: the vector, named by its own kid, opens with this key
    assert.equal(
      new TextDecoder().decode(openEnvelope(vec.envelope, kid, kp.secretKey)),
      vec.plaintext_utf8,
    );
    // the last payload byte changed (same length, still lowercase hex) -> the payload tag
    const bad: Envelope = {
      ...vec.envelope,
      payload: vec.envelope.payload.slice(0, -2) + (vec.envelope.payload.endsWith("00") ? "01" : "00"),
    };
    assert.throws(() => openEnvelope(bad, kid, kp.secretKey), TAG_MISMATCH);
    // a kid the envelope does not list -> refused at the lookup, before any key is used
    assert.throws(
      () => openEnvelope(vec.envelope, "no-such-kid", kp.secretKey),
      /^Error: no recipient entry for this kid$/,
    );
  });

  it("resolves a recipient from the signed directory and derives its kid from the key (M3)", () => {
    const r = recipientByOrg(dirVec.directory, "org_northline");
    assert.ok(r);
    // the kid is bound to the key, so the two cannot be pointed at each other's mismatch
    assert.equal(r!.kid, encKid(r!.public_key));
    // an org the directory does not list resolves to nothing
    assert.equal(recipientByOrg(dirVec.directory, "org_unknown"), undefined);
    // …and so does an org it lists WITHOUT an attested encryption key: the same directory
    // with the ML-KEM key taken off org_northline's entry (the entry and its signing key
    // stay). recipientByOrg says only "nothing", so the control is `r` above — the entry
    // as published resolves; the key is the one thing removed.
    const signingOnly = structuredClone(dirVec.directory);
    const entry = signingOnly.entries.find((e) => e.org_id === "org_northline")!;
    delete entry.enc_alg;
    delete entry.enc_public_key;
    assert.equal(recipientByOrg(signingOnly, "org_northline"), undefined);
  });

  it("authenticates the recipient set: reordering or dropping a recipient fails open (L2)", () => {
    const a = recipientByOrg(dirVec.directory, "org_huron")!;
    const b = recipientByOrg(dirVec.directory, "org_northline")!;
    const env = sealEnvelope(new TextEncoder().encode("secret payload"), [a, b]);
    const northlineSk = kemKeypairFromSeed(new Uint8Array(64).fill(0x53)).secretKey;
    // intact -> opens for the second recipient. This is the control for every refusal
    // below: each is this envelope, opened with this key, with ONE change to the recipient
    // list. b's own entry is never touched.
    assert.equal(
      new TextDecoder().decode(openEnvelope(env, b.kid, northlineSk)),
      "secret payload",
    );
    // reordered recipient list -> payload AAD no longer matches -> fails closed
    const reordered: Envelope = { ...env, recipients: [env.recipients[1]!, env.recipients[0]!] };
    assert.throws(() => openEnvelope(reordered, b.kid, northlineSk), TAG_MISMATCH);
    // dropped co-recipient -> also fails
    const dropped: Envelope = { ...env, recipients: [env.recipients[1]!] };
    assert.throws(() => openEnvelope(dropped, b.kid, northlineSk), TAG_MISMATCH);
    // appended co-recipient -> also fails. The added entry is well-formed (a's entry under a
    // kid nobody holds), so the envelope gets past the shape check and it is the recipient
    // set — now three kids, sealed as two — that is refused.
    const added = { ...env.recipients[0]!, kid: "00".repeat(8) };
    const appended: Envelope = { ...env, recipients: [...env.recipients, added] };
    assert.throws(() => openEnvelope(appended, b.kid, northlineSk), TAG_MISMATCH);
    // appended MALFORMED recipient (non-string kid) -> refused too, but not by the above:
    // the shape check refuses the envelope first (on both impls), naming the entry, and
    // nothing is decrypted. So this case does not exercise recipient-set authentication
    // (the well-formed entry above does). What it pins is that a malformed entry
    // invalidates the envelope — it is NOT silently dropped from the recipient set.
    const junk = { ...env.recipients[0]!, kid: null as unknown as string };
    const withJunk: Envelope = { ...env, recipients: [...env.recipients, junk] };
    assert.throws(
      () => openEnvelope(withJunk, b.kid, northlineSk),
      /^Error: malformed envelope: recipients\[2\]\.kid$/,
    );
  });
});

describe("forward-secret envelope (sje-envelope/0.2.0)", () => {
  const fsVec = JSON.parse(
    readFileSync(new URL("../../../conformance/signatures/fs-envelope.json", import.meta.url), "utf8"),
  ) as {
    recipient: {
      kid: string;
      org_id: string;
      prekey_id: string;
      static_seed_hex: string;
      onetime_seed_hex: string;
      static_public_key_hex: string;
      onetime_public_key_hex: string;
    };
    determinism: {
      cek_hex: string;
      payload_nonce_hex: string;
      coins_onetime_hex: string;
      coins_static_hex: string;
      wrap_nonce_hex: string;
    };
    plaintext_utf8: string;
    envelope: FsEnvelope;
  };
  const bundleVec = JSON.parse(
    readFileSync(new URL("../../../conformance/signatures/prekey-bundle.json", import.meta.url), "utf8"),
  ) as { root_public_key_hex: string; at_ms: number; directory: Directory; bundle: PrekeyBundle };

  const kid = fsVec.recipient.kid;
  const at = new Date(bundleVec.at_ms);
  const staticSk = kemKeypairFromSeed(hexToBytes(fsVec.recipient.static_seed_hex)).secretKey;
  const onetimeSk = kemKeypairFromSeed(hexToBytes(fsVec.recipient.onetime_seed_hex)).secretKey;

  function fsDet() {
    return {
      cek: hexToBytes(fsVec.determinism.cek_hex),
      payload_nonce: hexToBytes(fsVec.determinism.payload_nonce_hex),
      coins_onetime: [hexToBytes(fsVec.determinism.coins_onetime_hex)],
      coins_static: [hexToBytes(fsVec.determinism.coins_static_hex)],
      wrap_nonces: [hexToBytes(fsVec.determinism.wrap_nonce_hex)],
    };
  }

  it("re-seals deterministically to the vector", () => {
    const env = sealFsEnvelopeDeterministic(
      new TextEncoder().encode(fsVec.plaintext_utf8),
      [
        {
          kid,
          static_public_key: fsVec.recipient.static_public_key_hex,
          prekey_id: fsVec.recipient.prekey_id,
          onetime_public_key: fsVec.recipient.onetime_public_key_hex,
        },
      ],
      fsDet(),
    );
    assert.deepEqual(env, fsVec.envelope);
  });

  it("opens with both the static and one-time secret keys", () => {
    const opened = new TextDecoder().decode(openFsEnvelope(fsVec.envelope, kid, staticSk, onetimeSk));
    assert.equal(opened, fsVec.plaintext_utf8);
  });

  it("cannot be opened without the correct one-time secret (forward secrecy)", () => {
    // Deleting/losing the one-time secret means the two-KEM KEK can't be rebuilt,
    // so a later static-key compromise alone cannot recover the message.
    // control: with both of its secrets the envelope opens, so each refusal below is down
    // to the ONE secret swapped for another well-formed ML-KEM-1024 secret key. (A wrong
    // key does not make decapsulation fail: it yields a different shared secret, so a
    // different KEK, and the wrapped content key's tag is what refuses.)
    assert.equal(
      new TextDecoder().decode(openFsEnvelope(fsVec.envelope, kid, staticSk, onetimeSk)),
      fsVec.plaintext_utf8,
    );
    const wrongOt = kemKeypairFromSeed(new Uint8Array(64).fill(0x99)).secretKey;
    assert.throws(() => openFsEnvelope(fsVec.envelope, kid, staticSk, wrongOt), TAG_MISMATCH);
    // and a wrong static secret likewise fails (both halves are required)
    const wrongStatic = kemKeypairFromSeed(new Uint8Array(64).fill(0x98)).secretKey;
    assert.throws(() => openFsEnvelope(fsVec.envelope, kid, wrongStatic, onetimeSk), TAG_MISMATCH);
  });

  it("resolves an FS recipient from the directory + signed bundle", () => {
    const r = fsRecipientFromBundle(
      bundleVec.directory,
      bundleVec.bundle,
      "org_northline",
      "northline-ot-1",
      bundleVec.root_public_key_hex,
      at,
    );
    assert.ok(r);
    assert.equal(r!.kid, kid);
    assert.equal(r!.onetime_public_key, fsVec.recipient.onetime_public_key_hex);
    // an unverifiable bundle (wrong root) yields nothing — no sealing to unvetted prekeys
    assert.equal(
      fsRecipientFromBundle(
        bundleVec.directory,
        bundleVec.bundle,
        "org_northline",
        "northline-ot-1",
        "00".repeat(2592),
        at,
      ),
      undefined,
    );
  });

  it("authenticates the recipient set incl prekey_id (reorder/drop fails open, L2)", () => {
    // Two distinct static recipients (northline via ot-1, huron via ot-2).
    const a = fsRecipientFromBundle(
      bundleVec.directory,
      bundleVec.bundle,
      "org_northline",
      "northline-ot-1",
      bundleVec.root_public_key_hex,
      at,
    )!;
    const huronStatic = recipientByOrg(bundleVec.directory, "org_huron", at)!;
    const ot2 = bundleVec.bundle.prekeys.find((p) => p.prekey_id === "northline-ot-2")!;
    const b = {
      kid: huronStatic.kid,
      static_public_key: huronStatic.public_key,
      prekey_id: "northline-ot-2",
      onetime_public_key: ot2.public_key,
    };
    const env = sealFsEnvelope(new TextEncoder().encode("fs secret"), [a, b]);
    const huronStaticSk = kemKeypairFromSeed(new Uint8Array(64).fill(0x51)).secretKey; // org_huron static enc seed
    const ot2Sk = kemKeypairFromSeed(new Uint8Array(64).fill(0x62)).secretKey; // northline-ot-2 seed
    // intact -> b opens. The control for every refusal below: each is this envelope, opened
    // with these two keys, with ONE change to the recipient list; b's own entry is never
    // touched.
    assert.equal(
      new TextDecoder().decode(openFsEnvelope(env, b.kid, huronStaticSk, ot2Sk)),
      "fs secret",
    );
    // reordered recipient list -> payload AAD (which binds kid+prekey_id) mismatches
    const reordered: FsEnvelope = { ...env, recipients: [env.recipients[1]!, env.recipients[0]!] };
    assert.throws(() => openFsEnvelope(reordered, b.kid, huronStaticSk, ot2Sk), TAG_MISMATCH);
    // dropped co-recipient -> also fails
    const dropped: FsEnvelope = { ...env, recipients: [env.recipients[1]!] };
    assert.throws(() => openFsEnvelope(dropped, b.kid, huronStaticSk, ot2Sk), TAG_MISMATCH);
    // the co-recipient's prekey_id changed and nothing else -> also fails. Reordering and
    // dropping change the kids as well, so they would be refused even if only the kids were
    // authenticated; here the kids and their order are as sealed, and the "incl prekey_id"
    // half of the claim is what refuses.
    const relabelled: FsEnvelope = {
      ...env,
      recipients: [{ ...env.recipients[0]!, prekey_id: "northline-ot-9" }, env.recipients[1]!],
    };
    assert.throws(() => openFsEnvelope(relabelled, b.kid, huronStaticSk, ot2Sk), TAG_MISMATCH);
    // appended co-recipient, well-formed (a's entry under a kid nobody holds) -> gets past
    // the shape check and is refused as a change to the recipient set
    const added = { ...env.recipients[0]!, kid: "deadbeefdeadbeef" };
    const appended: FsEnvelope = { ...env, recipients: [...env.recipients, added] };
    assert.throws(() => openFsEnvelope(appended, b.kid, huronStaticSk, ot2Sk), TAG_MISMATCH);
    // appended MALFORMED recipient (string kid, null prekey_id) -> refused before that, by
    // the shape check (on both impls), naming the entry; nothing is decrypted, so this case
    // does not exercise recipient-set authentication. It pins the fix for a parity break:
    // previously TS kept the entry (filtered on kid only) while Rust dropped it (filtered
    // on kid AND prekey_id), so the same bytes made TS reject but Rust decrypt — plus
    // recipient-set malleability. Both now refuse the envelope as malformed.
    const junk = {
      ...env.recipients[0]!,
      kid: "deadbeefdeadbeef",
      prekey_id: null as unknown as string,
    };
    const withJunk: FsEnvelope = { ...env, recipients: [...env.recipients, junk] };
    assert.throws(
      () => openFsEnvelope(withJunk, b.kid, huronStaticSk, ot2Sk),
      /^Error: malformed envelope: recipients\[2\]\.prekey_id$/,
    );
  });
});

/** The shared envelope accept/reject cases (generated by conformance/generate.ts; the Rust
 *  runner replays the same file). The stage of a reject case is checked, not just the
 *  refusal: a "shape" case must be refused by the shape check itself — most of them would
 *  decrypt if that check were missing — and a "crypto" case must PASS the shape check and
 *  then fail to open. */
describe("envelope cases (shared with the Rust core)", () => {
  type Case = {
    name: string;
    kid: string;
    seed_hex: string;
    onetime_seed_hex?: string;
    text: string;
    stage?: "shape" | "crypto";
  };
  const cases = JSON.parse(
    readFileSync(new URL("../../../conformance/signatures/envelope-cases.json", import.meta.url), "utf8"),
  ) as { plaintext_utf8: string; accept: Case[]; reject: Case[] };
  const secret = (seedHex: string) => kemKeypairFromSeed(hexToBytes(seedHex)).secretKey;
  const open = (c: Case): string => {
    const env = parseSjeEnvelope(c.text);
    const bytes =
      env.spec === ENVELOPE_SPEC
        ? openEnvelope(env, c.kid, secret(c.seed_hex))
        : openFsEnvelope(env, c.kid, secret(c.seed_hex), secret(c.onetime_seed_hex!));
    return new TextDecoder().decode(bytes);
  };

  it("the case file is complete", () => {
    assert.ok(cases.accept.length >= 5 && cases.reject.length >= 40, "the case file looks truncated");
  });

  it("accept: passes the shape check and opens to the plaintext", () => {
    for (const c of cases.accept) assert.equal(open(c), cases.plaintext_utf8, c.name);
  });

  /** Why this implementation refuses each "shape" case: the whole message. A stage alone
   *  ("some shape rule refused it") lets a case pass on the wrong rule — a generator edit
   *  that also breaks an earlier-checked field, or the checks reordered — so each case is
   *  held to the rule it is named for. The first group is refused at the text boundary
   *  (wire.ts), the rest by assertEnvelopeShape; neither uses a key. A message names a
   *  field, not the sub-rule, so e.g. the three `payload` cases share one. The wording is
   *  this implementation's own (the case file is shared; the Rust core words its refusals
   *  differently). A case added to the file needs an entry here. */
  const SHAPE_REFUSAL: Record<string, string> = {
    "duplicate-member-payload": 'envelope has a duplicate member name "payload"',
    "duplicate-member-recipient-kid": 'envelope has a duplicate member name "kid"',
    "byte-order-mark": "envelope must not start with a byte-order mark",
    "trailing-content": "envelope is not JSON",

    "extra-member": "malformed envelope: unexpected or missing members",
    "missing-enc-alg": "malformed envelope: unexpected or missing members",
    "envelope-as-array": "malformed envelope: unexpected or missing members",
    "unknown-spec": "malformed envelope: unsupported spec",
    "alg-of-the-other-spec": "malformed envelope: enc_alg does not match spec",
    "payload-nonce-13-bytes": "malformed envelope: payload_nonce",
    "payload-nonce-null": "malformed envelope: payload_nonce",
    "payload-uppercase-hex": "malformed envelope: payload",
    "payload-shorter-than-a-tag": "malformed envelope: payload",
    "payload-odd-length-hex": "malformed envelope: payload",
    "recipients-empty": "malformed envelope: recipients",
    "recipients-seventeen": "malformed envelope: recipients",
    "extra-recipient-member": "malformed envelope: recipients[0] has unexpected or missing members",
    "recipient-as-array": "malformed envelope: recipients[0] has unexpected or missing members",
    "fs-recipient-without-prekey-id":
      "malformed envelope: recipients[0] has unexpected or missing members",
    "static-recipient-in-fs-envelope":
      "malformed envelope: recipients[0] has unexpected or missing members",
    "kid-not-hex": "malformed envelope: recipients[0].kid",
    "same-recipient-twice": "malformed envelope: recipients[1].kid repeats an earlier recipient",
    "fs-prekey-id-with-nul": "malformed envelope: recipients[0].prekey_id",
    "fs-prekey-id-too-long": "malformed envelope: recipients[0].prekey_id",
    "fs-kem-ct-onetime-one-byte-short": "malformed envelope: recipients[0].kem_ct_onetime",
    "fs-kem-ct-onetime-uppercase-hex": "malformed envelope: recipients[0].kem_ct_onetime",
    "fs-kem-ct-static-one-byte-short": "malformed envelope: recipients[0].kem_ct_static",
    "fs-kem-ct-static-uppercase-hex": "malformed envelope: recipients[0].kem_ct_static",
    "kem-ct-uppercase-hex": "malformed envelope: recipients[0].kem_ct",
    "kem-ct-one-byte-short": "malformed envelope: recipients[0].kem_ct",
    "wrap-nonce-11-bytes": "malformed envelope: recipients[0].wrap_nonce",
    "wrapped-cek-uppercase-hex": "malformed envelope: recipients[0].wrapped_cek",
    "content-key-16-bytes": "malformed envelope: recipients[0].wrapped_cek",
    "content-key-24-bytes": "malformed envelope: recipients[0].wrapped_cek",
  };

  it("reject / shape: refused by the shape check alone, before any key is used", () => {
    const shapeCases = cases.reject.filter((x) => x.stage === "shape");
    // every shape case has a reason on record, and every reason on record has its case
    assert.deepEqual(shapeCases.map((c) => c.name).sort(), Object.keys(SHAPE_REFUSAL).sort());
    for (const c of shapeCases) {
      const refusal = { name: "Error", message: SHAPE_REFUSAL[c.name] };
      assert.throws(() => parseSjeEnvelope(c.text), refusal, c.name);
      // from bytes too — the form a file or a network read arrives in
      assert.throws(() => parseSjeEnvelope(new TextEncoder().encode(c.text)), refusal, c.name);
    }
  });

  it("reject / crypto: passes the shape check, then fails to open", () => {
    const opener = (c: Case) => `${c.kid} ${c.seed_hex} ${c.onetime_seed_hex ?? "-"}`;
    const openers = new Set(cases.accept.map(opener));
    for (const c of cases.reject.filter((x) => x.stage === "crypto")) {
      assert.doesNotThrow(() => parseSjeEnvelope(c.text), c.name);
      // refused at a tag — not at the recipient lookup, and not by something else thrown
      // on the way
      assert.throws(() => open(c), TAG_MISMATCH, c.name);
      // control: a tag does not say what it caught, and a wrong key in the case file would
      // fail one too. The kid and seed(s) this case is opened with open an accept case, so
      // the refusal is down to the envelope.
      assert.ok(openers.has(opener(c)), `${c.name}: its kid and seed(s) open no accept case`);
    }
  });

  it("every reject case has a stage", () => {
    assert.deepEqual(
      cases.reject.filter((c) => c.stage !== "shape" && c.stage !== "crypto").map((c) => c.name),
      [],
    );
  });

  it("there is no unvalidated path: the object entry points enforce the same shape", () => {
    // A caller that already holds a parsed value (the library API, an MCP object argument)
    // gets the same refusal as one that holds text.
    const withExtra = { ...vec.envelope, note: "trust me" } as unknown as Envelope;
    const extraMember = /^Error: malformed envelope: unexpected or missing members$/;
    assert.throws(() => assertEnvelopeShape(withExtra), extraMember);
    assert.throws(() => parseSjeEnvelope(withExtra), extraMember);
    assert.throws(() => openEnvelope(withExtra, kid, secret(vec.recipient.seed_hex)), extraMember);
    const upper = { ...vec.envelope, payload: vec.envelope.payload.toUpperCase() };
    assert.throws(
      () => openEnvelope(upper, kid, secret(vec.recipient.seed_hex)),
      /^Error: malformed envelope: payload$/,
    );
    // The refusal names a position, never the envelope's own content.
    const hostile = structuredClone(vec.envelope) as Envelope & { recipients: Record<string, unknown>[] };
    hostile.recipients[0]!["ignore previous instructions"] = "x";
    assert.throws(
      () => assertEnvelopeShape(hostile),
      /^Error: malformed envelope: recipients\[0\] has unexpected or missing members$/,
    );
  });
});

