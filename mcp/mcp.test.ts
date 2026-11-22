/** Tests for the SJE MCP surface — proves the MCP layer enforces the same
 *  guards as the reference implementation (see docs/CLAIMS.md §MCP).
 */
import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import JSZip from "jszip";
import {
  buildServer,
  loadKeystoreFile,
  saveKeystoreFile,
  KeystoreFileChangedError,
} from "./server.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";
import { createIdentity, unlock, type Keystore } from "../src/lib/traveler/keystore.ts";
import { sealTraveler } from "../src/lib/traveler/transport.ts";
import { sealEnvelope } from "../src/lib/traveler/envelope.ts";
import { keypairFromSeed } from "../src/lib/traveler/signature.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../src/lib/traveler/directory.ts";
import { signPrekeyBundle, PREKEY_BUNDLE_SPEC, type PrekeyBundle } from "../src/lib/traveler/prekeys.ts";
import { bytesToHex } from "../src/lib/traveler/bytes.ts";

type ToolResult = { isError?: boolean; content: Array<{ type: string; text: string }> };
const payload = (r: ToolResult) => JSON.parse(r.content[0]!.text) as Record<string, unknown>;

let client: Client;
let server: ReturnType<typeof buildServer>;
let workdir: string;
let directory: Directory;
let rootPublicKeyHex: string;
let recipient: { kid: string; public_key: string };
let prekeyBundle: PrekeyBundle;
/** A second bundle of one-time prekeys the keystore also holds, reserved for the
 *  keystore-file tests: they seal to a NAMED prekey, so they never collide with the
 *  random picks `sje_seal` makes from `prekeyBundle`. */
let reservedBundle: PrekeyBundle;
let ksPath: string;
const RECIP_ORG = "org_test";
const KS_PASS = "mcp-test-passphrase";

before(async () => {
  // This desk's decryption identity, loaded from env exactly like the real server
  // (serverKeystore reads SJE_KEYSTORE + SJE_KEYSTORE_PASSPHRASE on first open). The
  // on-disk blob carries one-time prekeys so the server can open forward-secret
  // envelopes, consuming (and persisting) them as it goes.
  workdir = mkdtempSync(join(tmpdir(), "sje-mcp-test-"));
  ksPath = join(workdir, "desk.keystore.json");
  const id = await createIdentity({ passphrase: KS_PASS, orgId: RECIP_ORG });
  const u = await unlock(id.keystore, KS_PASS);
  const { prekeys } = u.addPrekeys(4);
  const { keystore: ksWithPrekeys, prekeys: reservedPrekeys } = u.addPrekeys(3);
  writeFileSync(ksPath, JSON.stringify(ksWithPrekeys));
  process.env.SJE_KEYSTORE = ksPath;
  process.env.SJE_KEYSTORE_PASSPHRASE = KS_PASS;
  recipient = { kid: id.directoryEntry.kid, public_key: id.directoryEntry.enc_public_key };

  // A signed directory that resolves RECIP_ORG to that encryption key, so sealing
  // (which verifies the directory against the root first) can address this desk.
  const root = keypairFromSeed(new Uint8Array(32).fill(5));
  rootPublicKeyHex = bytesToHex(root.publicKey);
  const signer = keypairFromSeed(new Uint8Array(32).fill(6));
  const body: Directory = {
    spec: DIRECTORY_SPEC,
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    root_kid: "root-2026",
    entries: [
      {
        org_id: RECIP_ORG,
        kid: "desk-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(signer.publicKey),
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_until: "2030-01-01T00:00:00.000Z",
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: id.directoryEntry.enc_public_key,
      },
    ],
  };
  directory = { ...body, sig: signDirectory(body, root.secretKey) };

  // A signed prekey bundle for RECIP_ORG (kid "desk-2026" resolves to it), listing
  // the one-time prekeys the on-disk keystore holds — enables forward-secret seals.
  const bundleBody: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: RECIP_ORG,
    kid: "desk-2026",
    enc_alg: "ML-KEM-1024",
    issued_at: "2026-01-01T00:00:00.000Z",
    valid_until: "2030-01-01T00:00:00.000Z",
    prekeys,
  };
  bundleBody.sig = signPrekeyBundle(bundleBody, signer.secretKey);
  prekeyBundle = bundleBody;
  const reservedBody: PrekeyBundle = { ...bundleBody, prekeys: reservedPrekeys, sig: undefined };
  reservedBody.sig = signPrekeyBundle(reservedBody, signer.secretKey);
  reservedBundle = reservedBody;

  const [ct, st] = InMemoryTransport.createLinkedPair();
  server = buildServer();
  await server.connect(st);
  client = new Client({ name: "test-agent", version: "0.0.1" });
  await client.connect(ct);
});

after(async () => {
  await client.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
  delete process.env.SJE_KEYSTORE;
  delete process.env.SJE_KEYSTORE_PASSPHRASE;
});

const call = async (name: string, args: Record<string, unknown>) =>
  (await client.callTool({ name, arguments: args })) as ToolResult;

const EXAMPLE = JSON.parse(
  readFileSync(new URL("../examples/bracket.traveler.json", import.meta.url), "utf8"),
) as Record<string, unknown>;

const QUOTE_ARGS = {
  seller: { org_id: "org_summitfab", name: "Summit Fabrication" },
  valid_until: "2039-01-01T00:00:00.000Z",
  lead_time_days: 21,
  pricing: { currency: "USD", lines: [{ qty: 250, unit: 1420 }] },
};

describe("sje mcp surface", () => {
  it("lists all nine tools", async () => {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 9);
    assert.ok(tools.every((t) => t.name.startsWith("sje_")));
  });

  it("validates the worked example at L0 with the documented hash", async () => {
    const rep = payload(await call("sje_validate", { traveler: EXAMPLE }));
    assert.equal(rep.level, "L0");
    assert.match(String(rep.traveler_hash), /^sha384:[0-9a-f]{96}$/);
  });

  it("runs compose → quote → award to a locked L2 over MCP", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4410",
          material: { spec: "6061-T6" },
          qty: { target: 250 },
        },
      }),
    );
    assert.equal(composed.level, "L0");

    const quoted = payload(
      await call("sje_quote", { traveler: composed.traveler, ...QUOTE_ARGS }),
    );
    assert.equal(quoted.level, "L1");

    const awarded = payload(
      await call("sje_award", {
        traveler: quoted.traveler,
        quote_id: quoted.quote_id,
        qty: 250,
        ops: [{ seq: 1, code: "laser" }],
        ship_to: {
          name: "Dock 4",
          line1: "1800 Industrial Way",
          city: "Reno",
          region: "NV",
          postal: "89502",
          country: "US",
        },
      }),
    );
    assert.equal(awarded.level, "L2");
    assert.equal(awarded.locked, true);

    // locked traveler refuses amendment
    const amend = await call("sje_amend", {
      traveler: awarded.traveler,
      patch: { need_by: "2027-01-01" },
    });
    assert.ok(amend.isError);
  });

  it("stale quotes cannot be awarded: amend re-binds the world", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4411",
          material: { spec: "6061-T6" },
          qty: { target: 100 },
        },
      }),
    );
    const quoted = payload(
      await call("sje_quote", {
        traveler: composed.traveler,
        ...QUOTE_ARGS,
        pricing: { currency: "USD", lines: [{ qty: 100, unit: 1850 }] },
      }),
    );
    const amended = payload(
      await call("sje_amend", { traveler: quoted.traveler, patch: { incoterms: "EXW" } }),
    );
    assert.equal(amended.level, "L0", "stale quote drops traveler back to L0");
    assert.equal((amended.stale_quotes as string[]).length, 1);

    const award = await call("sje_award", {
      traveler: amended.traveler,
      quote_id: quoted.quote_id,
      qty: 100,
      ops: [{ seq: 1, code: "laser" }],
      ship_to: {
        name: "Dock 4",
        line1: "1800 Industrial Way",
        city: "Reno",
        region: "NV",
        postal: "89502",
        country: "US",
      },
    });
    assert.ok(award.isError, "stale quote must not be awardable");
  });

  it("ITAR traveler refuses a quote from a seller without itar: true", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4412",
          material: { spec: "6061-T6" },
          qty: { target: 50 },
        },
        itar: true,
      }),
    );
    const res = await call("sje_quote", { traveler: composed.traveler, ...QUOTE_ARGS });
    assert.ok(res.isError, "non-ITAR seller must be refused");
  });

  it("sje_identity mints an encrypted keystore and a publishable directory entry", async () => {
    const res = payload(
      await call("sje_identity", { passphrase: "another-strong-pass", org_id: "org_minted", prekeys: 2 }),
    );
    const ks = res.keystore as Record<string, unknown>;
    const entry = res.directory_entry as Record<string, unknown>;
    assert.equal(ks.spec, "sje-keystore/0.2.0");
    assert.equal(ks.enc_alg, "ML-KEM-1024");
    assert.equal(entry.kid, ks.kid);
    assert.equal(entry.org_id, "org_minted");
    // The secret seed is encrypted into `ct`, never a clear field.
    assert.ok(!JSON.stringify(ks).includes("static_seed"), "no secret in the clear keystore");
    assert.equal((res.prekeys as unknown[]).length, 2);
  });

  it("seal → open round-trips; a tampered envelope is refused", async () => {
    const sealed = payload(
      await call("sje_seal", {
        traveler: EXAMPLE,
        directory,
        root_public_key_hex: rootPublicKeyHex,
        recipient_org: RECIP_ORG,
      }),
    );
    assert.equal(sealed.spec, "sje-envelope/0.1.0");
    assert.equal(sealed.forward_secret, false);
    const openRes = payload(await call("sje_open", { sje: sealed.sje }));
    assert.equal(openRes.traveler_hash, sealed.traveler_hash);

    const env = sealed.sje as { payload: string };
    const tamperedEnv = {
      ...(sealed.sje as object),
      payload: (env.payload[0] === "a" ? "b" : "a") + env.payload.slice(1),
    };
    const tampered = await call("sje_open", { sje: tamperedEnv });
    assert.ok(tampered.isError, "tampered envelope must be refused");
  });

  it("the sealed envelope is ciphertext — no plaintext field values, not a zip", async () => {
    const sealed = payload(
      await call("sje_seal", {
        traveler: EXAMPLE,
        directory,
        root_public_key_hex: rootPublicKeyHex,
        recipient_org: RECIP_ORG,
      }),
    );
    const t = parseTraveler(EXAMPLE);
    const wire = JSON.stringify(sealed.sje);
    assert.ok(!wire.includes(t.traveler_id), "traveler_id must not travel in the clear");
    if (t.part.part_number) assert.ok(!wire.includes(t.part.part_number), "part number must not leak");
    const payloadBytes = Buffer.from((sealed.sje as { payload: string }).payload, "hex");
    assert.ok(!payloadBytes.includes(Buffer.from("PK\x03\x04")), "no ZIP header in the ciphertext");
  });

  it("sje_seal with a prekey bundle produces a forward-secret envelope that opens exactly once", async () => {
    const sealed = payload(
      await call("sje_seal", {
        traveler: EXAMPLE,
        directory,
        root_public_key_hex: rootPublicKeyHex,
        recipient_org: RECIP_ORG,
        prekey_bundle: prekeyBundle,
      }),
    );
    assert.equal(sealed.forward_secret, true);
    assert.equal(sealed.spec, "sje-envelope/0.2.0");
    const opened = payload(await call("sje_open", { sje: sealed.sje }));
    assert.equal(opened.traveler_hash, sealed.traveler_hash);
    // The one-time prekey is now spent (consumed + persisted): re-opening is refused.
    const again = await call("sje_open", { sje: sealed.sje });
    assert.ok(again.isError, "a spent one-time prekey cannot be reused");
  });

  it("sje_seal refuses to downgrade when require_forward_secret is set and no bundle is given", async () => {
    const res = await call("sje_seal", {
      traveler: EXAMPLE,
      directory,
      root_public_key_hex: rootPublicKeyHex,
      recipient_org: RECIP_ORG,
      require_forward_secret: true,
    });
    assert.ok(res.isError, "must refuse rather than silently fall back to static");
  });

  it("sje_seal with require_forward_secret AND a bundle succeeds (no downgrade needed)", async () => {
    const sealed = payload(
      await call("sje_seal", {
        traveler: EXAMPLE,
        directory,
        root_public_key_hex: rootPublicKeyHex,
        recipient_org: RECIP_ORG,
        prekey_bundle: prekeyBundle,
        require_forward_secret: true,
      }),
    );
    assert.equal(sealed.forward_secret, true);
    assert.equal(sealed.spec, "sje-envelope/0.2.0");
  });

  it("sje_open refuses input that is not a recognized envelope", async () => {
    for (const sje of [
      {},
      { spec: "not-an-envelope" },
      { spec: "sje-envelope/0.1.0", recipients: [], payload: "x", payload_nonce: "y" }, // empty recipients
      { spec: "sje-envelope/0.1.0", payload: "x", payload_nonce: "y", recipients: [{ kem_ct: "z" }] }, // recipient has no kid
      "not json at all",
    ]) {
      const res = await call("sje_open", { sje });
      assert.ok(res.isError, `must reject ${JSON.stringify(sje)}`);
    }
  });

  it("sje_seal refuses an unknown recipient org and a wrong trust root", async () => {
    const unknownOrg = await call("sje_seal", {
      traveler: EXAMPLE,
      directory,
      root_public_key_hex: rootPublicKeyHex,
      recipient_org: "org_nonesuch",
    });
    assert.ok(unknownOrg.isError, "an org with no directory entry must be refused");

    const wrongRoot = await call("sje_seal", {
      traveler: EXAMPLE,
      directory,
      root_public_key_hex: "00".repeat(2592), // a root the directory does not verify against
      recipient_org: RECIP_ORG,
    });
    assert.ok(wrongRoot.isError, "a directory that doesn't verify against the given root must be refused");
  });

  it("sje_open refuses a decrypted archive whose non-quoteable fields were tampered (F3)", async () => {
    // A well-formed ENVELOPE (AEAD passes on decrypt) whose decrypted payload is a
    // semantically-tampered archive: an award injected (a NON-quoteable field, so
    // traveler_hash is unchanged) and META omitting the required full-bytes digest.
    // Decryption succeeds, but the inner defensive import must still refuse it —
    // otherwise a party could rewrite awarded qty/seller/ship-to under an intact hash.
    const traveler = parseTraveler(EXAMPLE);
    const tampered = {
      ...traveler,
      award: { quote_id: "qot_injected1", awarded_at: "2027-01-01T00:00:00.000Z", qty: 1 },
    };
    const zip = new JSZip();
    zip.file("traveler.json", JSON.stringify(tampered, null, 2));
    zip.file(
      "META.json",
      JSON.stringify({ traveler_id: traveler.traveler_id, traveler_hash: travelerHash(traveler) }),
    );
    const zipBytes = await zip.generateAsync({ type: "uint8array" });
    const env = sealEnvelope(zipBytes, [recipient]);
    const res = await call("sje_open", { sje: env });
    assert.ok(res.isError, "an archive missing the required full-bytes digest must be refused");
  });

  it("binding cannot be asserted: traveler_hash_quoted always comes from the traveler in hand", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4413",
          material: { spec: "6061-T6" },
          qty: { target: 25 },
        },
      }),
    );
    const quoted = payload(
      await call("sje_quote", {
        traveler: composed.traveler,
        ...QUOTE_ARGS,
        pricing: { currency: "USD", lines: [{ qty: 25, unit: 22 }] },
      }),
    );
    const t = quoted.traveler as { quotes: Array<{ traveler_hash_quoted: string }> };
    assert.equal(t.quotes[0]!.traveler_hash_quoted, composed.traveler_hash);
  });

  it("refuses an oversized sealed envelope before decrypting it", async () => {
    const huge = "A".repeat(5_000_000); // exceeds 2x the 2 MiB archive budget + slack
    const res = await call("sje_open", { sje: huge });
    assert.ok(res.isError, "oversized input must be refused");
    assert.match(String(payload(res).error), /exceeds size limit/);
  });

  it("amend cannot inject ops/ship_to/as_built to escalate the level", async () => {
    const composed = payload(
      await call("sje_compose", {
        buyer: { name: "Northline Equipment" },
        part: {
          family: "CNC bracket",
          part_number: "NL-BRK-4414",
          material: { spec: "6061-T6" },
          qty: { target: 40 },
        },
      }),
    );
    const amended = payload(
      await call("sje_amend", {
        traveler: composed.traveler,
        patch: {
          need_by: "2027-01-01",
          ops: [{ seq: 1, code: "laser" }],
          ship_to: { name: "X", line1: "Y", city: "Z", region: "NV", postal: "1", country: "US" },
          as_built: { done: true },
        },
      }),
    );
    const t = amended.traveler as {
      need_by?: string;
      ops?: unknown[];
      ship_to?: unknown;
      as_built?: unknown;
    };
    assert.equal(t.need_by, "2027-01-01", "a real body edit still applies");
    assert.equal(amended.level, "L0", "injected ops/ship_to/as_built must not escalate the level");
    assert.equal(t.ops ?? null, null);
    assert.equal(t.ship_to ?? null, null);
    assert.equal(t.as_built ?? null, null);
  });
});

describe("sje mcp keystore file (shared between processes, private on disk)", () => {
  /** Seal the example traveler to ONE named reserved prekey, with the library. */
  const sealToReserved = async (i: number) =>
    (
      await sealTraveler(parseTraveler(EXAMPLE), {
        directory,
        rootPublicKeyHex,
        recipientOrg: RECIP_ORG,
        prekeyBundle: reservedBundle,
        prekeyId: reservedBundle.prekeys[i]!.prekey_id,
      })
    ).envelope;
  const onDisk = () => JSON.parse(readFileSync(ksPath, "utf8")) as Keystore;
  const mode = (path: string) => statSync(path).mode & 0o777;

  it("save is compare-and-swap on the file's content: a blob this process did not load is never overwritten", () => {
    const path = join(workdir, "cas.keystore.json");
    writeFileSync(path, '{"v":"A"}', { mode: 0o644 });

    // Never loaded by this process: there is nothing to compare with, so no write.
    assert.throws(() => saveKeystoreFile(path, '{"v":"B"}'), KeystoreFileChangedError);
    assert.equal(readFileSync(path, "utf8"), '{"v":"A"}');

    // Loaded, unchanged since: the write goes through.
    assert.deepEqual(loadKeystoreFile(path), { v: "A" });
    saveKeystoreFile(path, '{"v":"B"}');
    assert.equal(readFileSync(path, "utf8"), '{"v":"B"}');
    // …and again, against what this process itself wrote.
    saveKeystoreFile(path, '{"v":"C"}');
    assert.equal(readFileSync(path, "utf8"), '{"v":"C"}');

    // ANOTHER process rewrites the file. This process's next write is refused, with an
    // error that tells the operator what happened, and the file is left alone.
    writeFileSync(path, '{"v":"theirs"}');
    assert.throws(
      () => saveKeystoreFile(path, '{"v":"D"}'),
      (e: unknown) =>
        e instanceof KeystoreFileChangedError &&
        /changed by another process/.test(e.message) &&
        /NOT written/.test(e.message),
    );
    assert.equal(readFileSync(path, "utf8"), '{"v":"theirs"}', "the other process's blob is intact");

    // After loading the current file again, writing works again.
    loadKeystoreFile(path);
    saveKeystoreFile(path, '{"v":"D"}');
    assert.equal(readFileSync(path, "utf8"), '{"v":"D"}');
    // A deleted file is "changed" too.
    rmSync(path);
    assert.throws(() => saveKeystoreFile(path, '{"v":"E"}'), KeystoreFileChangedError);
    // No temp files are left behind, by the successful writes or the refused ones.
    assert.deepEqual(
      readdirSync(workdir).filter((f) => f.includes(".tmp-")),
      [],
    );
  });

  // POSIX permission bits; Windows has no equivalent to assert on.
  const posix = { skip: process.platform === "win32" };

  it("save writes the file 0600 — whatever mode it had, whatever the umask", posix, () => {
    const path = join(workdir, "mode.keystore.json");
    writeFileSync(path, "{}", { mode: 0o644 });
    chmodSync(path, 0o644);
    loadKeystoreFile(path);
    // The most permissive umask there is must not widen it, and the most restrictive
    // must not leave the owner unable to read their own keystore.
    for (const mask of [0o000, 0o777]) {
      const umask = process.umask(mask);
      try {
        saveKeystoreFile(path, JSON.stringify({ saved: true, mask }));
      } finally {
        process.umask(umask);
      }
      assert.equal(mode(path), 0o600, `umask ${mask.toString(8)}`);
    }
  });

  it("sje_open leaves the keystore file 0600 after consuming a one-time prekey", posix, async () => {
    chmodSync(ksPath, 0o644); // as created by a default umask
    const opened = await call("sje_open", { sje: await sealToReserved(0) });
    assert.ok(!opened.isError, "the forward-secret envelope opens");
    assert.equal(mode(ksPath), 0o600, "rewriting the keystore must not widen (or keep wide) its permissions");
  });

  it("a second process sharing the keystore: neither resurrects the other's consumed prekeys nor drops its new ones", async () => {
    const [, r1, r2] = reservedBundle.prekeys.map((p) => p.prekey_id) as [string, string, string];
    // This server has the keystore unlocked in memory (make sure of it).
    const first = payload(
      await call("sje_seal", {
        traveler: EXAMPLE,
        directory,
        root_public_key_hex: rootPublicKeyHex,
        recipient_org: RECIP_ORG,
      }),
    );
    assert.ok(!(await call("sje_open", { sje: first.sje })).isError);

    // A second process — another MCP server, a CLI — unlocks the same file, consumes
    // reserved prekey r1, mints a new prekey, and writes the file.
    const other = await unlock(onDisk(), KS_PASS);
    assert.ok(other.consumePrekey(r1).secretKey, "the other process held r1 and consumed it");
    const { keystore: theirs, prekeys: mintedByOther } = other.addPrekeys(1);
    writeFileSync(ksPath, JSON.stringify(theirs), { mode: 0o600 });

    // This server now opens an envelope sealed to r2. Its in-memory vault predates the
    // other process's write: re-sealing from it would put r1 back on disk and drop the
    // minted prekey.
    const opened = await call("sje_open", { sje: await sealToReserved(2) });
    assert.ok(!opened.isError, "the envelope opens (the server reloaded the keystore first)");

    const after = await unlock(onDisk(), KS_PASS);
    assert.equal(after.peekPrekey(r2), undefined, "r2: consumed by this server");
    assert.equal(after.peekPrekey(r1), undefined, "r1: consumed by the other process — NOT resurrected");
    assert.ok(after.peekPrekey(mintedByOther[0]!.prekey_id), "the prekey the other process minted — NOT dropped");

    // And this server no longer opens an envelope sealed to r1: it works from the file,
    // where r1 is gone, not from the copy it unlocked before.
    const stale = await call("sje_open", { sje: await sealToReserved(1) });
    assert.ok(stale.isError, "a prekey consumed by the other process is spent for this server too");
  });
});
