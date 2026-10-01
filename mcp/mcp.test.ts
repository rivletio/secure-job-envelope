/** Tests for the SJE MCP surface — proves the MCP layer enforces the same
 *  guards as the reference implementation (see docs/CLAIMS.md §MCP).
 */
import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import JSZip from "jszip";
import { buildServer } from "./server.ts";
import { parseTraveler } from "../src/lib/traveler/conformance.ts";
import { travelerHash } from "../src/lib/traveler/hash.ts";
import { createIdentity, unlock } from "../src/lib/traveler/keystore.ts";
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
const RECIP_ORG = "org_test";
const KS_PASS = "mcp-test-passphrase";

before(async () => {
  // This desk's decryption identity, loaded from env exactly like the real server
  // (serverKeystore reads SJE_KEYSTORE + SJE_KEYSTORE_PASSPHRASE on first open). The
  // on-disk blob carries one-time prekeys so the server can open forward-secret
  // envelopes, consuming (and persisting) them as it goes.
  workdir = mkdtempSync(join(tmpdir(), "sje-mcp-test-"));
  const ksPath = join(workdir, "desk.keystore.json");
  const id = await createIdentity({ passphrase: KS_PASS, orgId: RECIP_ORG });
  const u = await unlock(id.keystore, KS_PASS);
  const { keystore: ksWithPrekeys, prekeys } = u.addPrekeys(4);
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
    assert.equal(ks.spec, "sje-keystore/0.1.0");
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
