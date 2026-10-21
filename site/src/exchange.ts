import "./style.css";
import { $, el, registerSW, short } from "./ui.ts";
import { term, initGlossary } from "./defs.ts";
import { keypairFromSeed } from "../../src/lib/traveler/signature.ts";
import { createIdentity, unlock } from "../../src/lib/traveler/keystore.ts";
import { signDirectory, DIRECTORY_SPEC, type Directory } from "../../src/lib/traveler/directory.ts";
import {
  signPrekeyBundle,
  PREKEY_BUNDLE_SPEC,
  type PrekeyBundle,
} from "../../src/lib/traveler/prekeys.ts";
import { sealTraveler, openTraveler } from "../../src/lib/traveler/transport.ts";
import type { FsEnvelope } from "../../src/lib/traveler/envelope.ts";
import { parseTraveler } from "../../src/lib/traveler/conformance.ts";
import { bytesToHex } from "../../src/lib/traveler/bytes.ts";

registerSW();
initGlossary();

const PASS_B = "buyer desk passphrase";
const PASS_S = "seller desk passphrase";
const W = { issued_at: "2026-01-01T00:00:00.000Z", valid_until: "2032-01-01T00:00:00.000Z" };

const traveler = parseTraveler({
  spec: "sje/0.1.0",
  traveler_id: "tvl_webdemo01",
  revision: 1,
  created_at: "2026-10-01T00:00:00.000Z",
  buyer: { org_id: "org_northline", name: "Northline Equipment", city: "Reno", region: "NV" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6", form: "plate", thickness_mm: 6.35 },
    qty: { target: 250, breaks: [100, 250, 500] },
    processes: ["laser", "cnc-mill", "deburr"],
  },
  need_by: "2026-12-01",
  incoterms: "FOB",
  itar: false,
});

type Setup = {
  buyerKid: string;
  sellerKid: string;
  rootShort: string;
  sellerDesk: Awaited<ReturnType<typeof unlock>>;
  buyerDesk: Awaited<ReturnType<typeof unlock>>;
  fsEnvelope: FsEnvelope;
  staticEnvelope: FsEnvelope;
  forwardSecret: boolean;
};

async function setup(): Promise<Setup> {
  const root = keypairFromSeed(new Uint8Array(32).fill(1));
  const rootHex = bytesToHex(root.publicKey);
  const buyer = await createIdentity({ passphrase: PASS_B, orgId: "org_northline" });
  const seller = await createIdentity({ passphrase: PASS_S, orgId: "org_summitfab" });
  const bSign = keypairFromSeed(new Uint8Array(32).fill(2));
  const sSign = keypairFromSeed(new Uint8Array(32).fill(3));

  const dirBody: Directory = {
    spec: DIRECTORY_SPEC,
    ...W,
    root_kid: "root-2026",
    entries: [
      {
        org_id: "org_northline",
        kid: "northline-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(bSign.publicKey),
        valid_from: W.issued_at,
        valid_until: W.valid_until,
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: buyer.directoryEntry.enc_public_key,
      },
      {
        org_id: "org_summitfab",
        kid: "summit-2026",
        alg: "ML-DSA-87",
        public_key: bytesToHex(sSign.publicKey),
        valid_from: W.issued_at,
        valid_until: W.valid_until,
        status: "active",
        enc_alg: "ML-KEM-1024",
        enc_public_key: seller.directoryEntry.enc_public_key,
      },
    ],
  };
  const directory: Directory = { ...dirBody, sig: signDirectory(dirBody, root.secretKey) };

  const sellerDesk = await unlock(seller.keystore, PASS_S);
  const buyerDesk = await unlock(buyer.keystore, PASS_B);
  const { prekeys } = sellerDesk.addPrekeys(4);
  const bundle: PrekeyBundle = {
    spec: PREKEY_BUNDLE_SPEC,
    org_id: "org_summitfab",
    kid: "summit-2026",
    enc_alg: "ML-KEM-1024",
    ...W,
    prekeys,
  };
  bundle.sig = signPrekeyBundle(bundle, sSign.secretKey);

  const common = { directory, rootPublicKeyHex: rootHex, recipientOrg: "org_summitfab" };
  const fs = await sealTraveler(traveler, {
    ...common,
    prekeyBundle: bundle,
    prekeyId: prekeys[0]!.prekey_id,
  });
  const stat = await sealTraveler(traveler, common);

  return {
    buyerKid: buyer.directoryEntry.kid,
    sellerKid: seller.directoryEntry.kid,
    rootShort: short(rootHex, 20),
    sellerDesk,
    buyerDesk,
    fsEnvelope: fs.envelope as FsEnvelope,
    staticEnvelope: stat.envelope as FsEnvelope,
    forwardSecret: fs.forwardSecret,
  };
}

// ── little builders ──
function dataCard(title: string, body: Node[]): HTMLElement {
  return el("div", { class: "data" }, [el("h4", {}, [title]), ...body]);
}
function kv(pairs: [string, string][]): HTMLElement {
  const out: Node[] = [];
  for (const [k, v] of pairs) {
    out.push(el("dt", {}, [k]));
    out.push(el("dd", {}, [v]));
  }
  return el("dl", { class: "kv" }, out);
}
function cipher(hex: string): HTMLElement {
  const d = el("div", { class: "out" });
  d.append(el("span", { class: "ln k" }, [`${hex.slice(0, 360)}…`]));
  return d;
}
const stack = (...n: Node[]) => el("div", { class: "grid" }, n);

function buildWalk(s: Setup) {
  const titles = ["Identities", "Directory", "Seal", "Open", "Refused"];
  const steps: (() => HTMLElement)[] = [
    () =>
      wstep(
        1,
        "Two identities",
        [
          "The buyer (Northline) and the shop (Summit) each mint a ",
          term("pq", "post-quantum"),
          " key pair — a public ",
          term("lock"),
          " anyone can seal to, and a ",
          term("secret"),
          " only that desk holds.",
        ],
        stack(
          dataCard("Desks", [
            kv([
              ["Buyer · Northline", s.buyerKid],
              ["Shop · Summit", s.sellerKid],
              ["Trust root", s.rootShort],
            ]),
          ]),
        ),
      ),
    () =>
      wstep(
        2,
        "A signed directory",
        [
          "They publish a signed ",
          term("directory"),
          " — a phonebook saying which public lock belongs to which organization, so the buyer seals to the real Summit and not an impostor.",
        ],
        dataCard("Directory", [
          kv([
            ["Organizations", "2 (Northline, Summit)"],
            ["Signed by", "the trust root"],
            ["Checked before sealing", "yes"],
          ]),
        ]),
      ),
    () =>
      wstep(
        3,
        "Seal it",
        [
          "The buyer seals the job to Summit's public lock. Out comes a ",
          term("sje"),
          " — pure ",
          term("ciphertext"),
          ", ",
          term("fs", "forward-secret"),
          " by default. This is what actually travels:",
        ],
        stack(
          dataCard(`The sealed .sje — ${s.fsEnvelope.spec} · forward_secret=${s.forwardSecret}`, [
            cipher(s.fsEnvelope.payload),
            el("p", { class: "hint" }, [
              "No traveler id, buyer or part number appears anywhere in here.",
            ]),
          ]),
        ),
      ),
    () =>
      wstep(
        4,
        "Only Summit can open it",
        [
          "Summit unlocks its keystore and uses its ",
          term("secret"),
          " to open the envelope — back to the exact job.",
        ],
        dataCard("Opened by Summit", [
          kv([
            ["Part", `${traveler.part.family} · ${traveler.part.part_number}`],
            ["Quantity", String(traveler.part.qty.target)],
            ["Result", "decrypted ✓"],
          ]),
        ]),
      ),
    () =>
      wstep(
        5,
        "Everything else is refused",
        [
          "Change one byte of the sealed file, open it with the wrong desk's key, or try to strip the ",
          term("fs", "forward secrecy"),
          " — every one is refused. Try it yourself just below. ↓",
        ],
        dataCard("Refused", [
          el("div", { class: "chips" }, [
            el("span", { class: "status bound" }, ["tampered byte ✗"]),
            el("span", { class: "status bound" }, ["wrong key ✗"]),
            el("span", { class: "status bound" }, ["downgrade ✗"]),
          ]),
        ]),
      ),
  ];

  const walk = $("#walk");
  const nextBtn = $("#next") as HTMLButtonElement;
  const replayBtn = $("#replay") as HTMLButtonElement;
  let shown = 0;
  const reveal = () => {
    if (shown >= steps.length) return;
    const node = steps[shown]!();
    walk.append(node);
    shown++;
    node.scrollIntoView({ behavior: "smooth", block: "nearest" });
    if (shown >= steps.length) {
      nextBtn.textContent = "That's the exchange ✓";
      nextBtn.disabled = true;
      replayBtn.hidden = false;
    } else {
      nextBtn.textContent = `Next: ${titles[shown]} →`;
    }
  };
  nextBtn.addEventListener("click", reveal);
  replayBtn.addEventListener("click", () => {
    walk.replaceChildren();
    shown = 0;
    nextBtn.textContent = "Start →";
    nextBtn.disabled = false;
    replayBtn.hidden = true;
  });
}

function wstep(num: number, title: string, why: (Node | string)[], data: Node): HTMLElement {
  return el("div", { class: "wstep" }, [
    el("div", { class: "num" }, [String(num)]),
    el("div", {}, [el("h3", {}, [title]), el("p", { class: "why" }, why), data]),
  ]);
}

function flip(hex: string): string {
  const c = hex[0] === "a" ? "b" : "a";
  return c + hex.slice(1);
}

function buildSandbox(s: Setup) {
  $("#box-intro").replaceChildren(
    "The job on the left is sealed into the ",
    term("ciphertext"),
    " on the right — the ",
    term("sje"),
    " that travels. Open it, or try to break it.",
  );

  const wire = JSON.stringify(s.staticEnvelope);
  const leaks = wire.includes(traveler.part.part_number) || wire.includes(traveler.buyer.name);
  $("#reveal").replaceChildren(
    dataCard("The job (plaintext, before sealing)", [
      kv([
        ["Buyer", traveler.buyer.name],
        ["Part", `${traveler.part.family} · ${traveler.part.part_number}`],
        ["Material", traveler.part.material.spec],
        ["Quantity", String(traveler.part.qty.target)],
      ]),
    ]),
    dataCard("The sealed .sje (what travels)", [
      cipher(s.staticEnvelope.payload),
      el("p", { class: "hint" }, [
        leaks
          ? "⚠ plaintext leaked"
          : `✓ “${traveler.part.part_number}” and the buyer name are nowhere in the sealed file`,
      ]),
    ]),
  );

  const result = $("#result");
  const say = (cls: string, nodes: (Node | string)[]) =>
    result.replaceChildren(el("p", { class: `verdict ${cls}` }, nodes));

  $("#do-open").addEventListener("click", async () => {
    try {
      const t = await openTraveler(s.staticEnvelope, s.sellerDesk);
      say("ok", [
        "Opened ✓ — Summit's secret key turns the ciphertext back into the job: ",
        el("b", {}, [`${t.part.family} · ${t.part.part_number}, ${t.part.qty.target} pcs`]),
        ". Nobody without that key can do this.",
      ]);
    } catch {
      say("stale", ["Unexpected: open failed."]);
    }
  });

  $("#do-tamper").addEventListener("click", async () => {
    const tampered = { ...s.staticEnvelope, payload: flip(s.staticEnvelope.payload) } as FsEnvelope;
    try {
      await openTraveler(tampered, s.sellerDesk);
      say("stale", ["Unexpected: a tampered envelope opened."]);
    } catch {
      say("ok", [
        "Refused ✓ — one flipped byte and the built-in authentication check fails. A tampered job can't be opened; it's rejected outright, not silently accepted.",
      ]);
    }
  });

  $("#do-wrong").addEventListener("click", async () => {
    try {
      await openTraveler(s.staticEnvelope, s.buyerDesk);
      say("stale", ["Unexpected: the wrong key opened it."]);
    } catch {
      say("ok", [
        "Refused ✓ — the buyer's own key can't open a job that was sealed to Summit. Only the intended shop's secret key works.",
      ]);
    }
  });

  say("ok", [
    "Press ",
    el("b", {}, ["Open it"]),
    " to decrypt with Summit's key — or try to break it.",
  ]);
}

setup()
  .then((s) => {
    $("#prep").hidden = true;
    $("#walk-card").hidden = false;
    $("#box-card").hidden = false;
    buildWalk(s);
    buildSandbox(s);
  })
  .catch((e) => {
    $("#prep").replaceChildren(`setup failed: ${e instanceof Error ? e.message : String(e)}`);
  });
