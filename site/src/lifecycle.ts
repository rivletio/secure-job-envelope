import "./style.css";
import { $, el, registerSW, short } from "./ui.ts";
import { term, initGlossary } from "./defs.ts";
import { parseTraveler } from "../../src/lib/traveler/conformance.ts";
import { travelerHash } from "../../src/lib/traveler/hash.ts";
import type { Traveler } from "../../src/lib/traveler/types.ts";

registerSW();
initGlossary();

// ── The job we tell the story with (and let the visitor edit in the sandbox) ──
const baseInput = {
  spec: "sje/0.1.0",
  traveler_id: "tvl_webdemo01",
  revision: 1,
  created_at: "2026-01-01T00:00:00.000Z",
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
};
const base = parseTraveler(baseInput);
const baseHash = travelerHash(base);
const amended = parseTraveler({ ...baseInput, incoterms: "EXW", revision: 2 });
const amendedHash = travelerHash(amended);

const fpLong = (h: string) => (h.length > 46 ? `${h.slice(0, 46)}…` : h);

// ── small readable building blocks (not a JSON dump) ──
function fpChip(hash: string): HTMLElement {
  return el("div", { class: "fp" }, [
    el("span", { class: "lbl" }, ["fingerprint"]),
    el("span", { class: "val" }, [short(hash, 34)]),
  ]);
}
function fpHero(hash: string, flash: boolean): HTMLElement {
  return el("div", { class: `fp-hero${flash ? " fp-flash" : ""}` }, [
    el("span", { class: "lbl" }, ["current fingerprint"]),
    el("span", { class: "val" }, [fpLong(hash)]),
  ]);
}
function specCard(t: Traveler, changed: Set<string> = new Set()): HTMLElement {
  const dd = (v: string, key: string) => el("dd", changed.has(key) ? { class: "chg" } : {}, [v]);
  return el("div", { class: "data" }, [
    el("h4", {}, ["The spec"]),
    el("dl", { class: "kv" }, [
      el("dt", {}, ["Part"]),
      dd(`${t.part.family} · ${t.part.part_number}`, "part"),
      el("dt", {}, ["Material"]),
      dd(t.part.material.spec, "material"),
      el("dt", {}, ["Quantity"]),
      dd(String(t.part.qty.target), "qty"),
      el("dt", {}, ["Incoterms"]),
      dd(t.incoterms ?? "—", "incoterms"),
    ]),
  ]);
}
function quoteCard(who: string, price: string, pinnedTo: string, bound: boolean): HTMLElement {
  return el("div", { class: "quote" }, [
    el("div", { class: "top" }, [
      el("span", { class: "who" }, [who]),
      el("span", { class: `status ${bound ? "bound" : "stale"}` }, [bound ? "bound ✓" : "stale ✗"]),
    ]),
    el("div", { class: "price" }, [price]),
    el("div", { class: "meta" }, [`pinned to ${short(pinnedTo, 30)}`]),
  ]);
}
const stack = (...nodes: Node[]) => el("div", { class: "grid" }, nodes);

// ── guided walkthrough: five steps that reveal one at a time ──
function wstep(num: number, title: string, why: (Node | string)[], data: Node): HTMLElement {
  return el("div", { class: "wstep" }, [
    el("div", { class: "num" }, [String(num)]),
    el("div", {}, [el("h3", {}, [title]), el("p", { class: "why" }, why), data]),
  ]);
}

const titles = ["Compose", "Quote", "Amend", "Re-quote", "Award"];
const steps: (() => HTMLElement)[] = [
  () =>
    wstep(
      1,
      "Compose",
      [
        "Northline Equipment needs 250 CNC brackets. They write down exactly what they want — part, material, quantity. That spec is the ",
        term("traveler"),
        ", and every detail is boiled down to one ",
        term("fingerprint"),
        ": same spec, same fingerprint, for everyone.",
      ],
      stack(specCard(base), fpChip(baseHash)),
    ),
  () =>
    wstep(
      2,
      "Quote",
      [
        "Summit Fabrication reads that exact spec and offers $14.20 a part at 250. Their quote is ",
        term("bound"),
        " to this fingerprint — the price isn't floating, it's tied to the spec it was based on.",
      ],
      quoteCard("Summit Fabrication", "$14.20 / pc at 250 · 21-day lead", baseHash, true),
    ),
  () =>
    wstep(
      3,
      "Amend",
      [
        "The buyer changes one thing — shipping terms, ",
        term("incoterms"),
        " FOB → EXW. A different spec makes a different fingerprint, so Summit's quote no longer matches. It's automatically ",
        term("stale"),
        " — nobody has to remember to flag it.",
      ],
      stack(
        el("div", { class: "data" }, [
          el("h4", {}, ["The fingerprint moved"]),
          el("dl", { class: "kv" }, [
            el("dt", {}, ["before"]),
            el("dd", {}, [short(baseHash, 30)]),
            el("dt", {}, ["after"]),
            el("dd", { class: "chg" }, [short(amendedHash, 30)]),
          ]),
        ]),
        quoteCard("Summit Fabrication", "$14.20 / pc at 250", baseHash, false),
      ),
    ),
  () =>
    wstep(
      4,
      "Re-quote",
      [
        "Because the spec moved, another shop — Red River Machining — prices the new version: $13.65 at 250, ",
        term("bound"),
        " to the new fingerprint. A quote is only ever good for the exact spec it priced.",
      ],
      quoteCard("Red River Machining", "$13.65 / pc at 250 · 18-day lead", amendedHash, true),
    ),
  () =>
    wstep(
      5,
      "Award",
      [
        "The buyer picks the bound quote and commits — adds the operations and a ship-to. The job is now ",
        term("award", "awarded"),
        ": ",
        term("level", "L2 Executable"),
        ", and ",
        term("locked"),
        ". The agreed spec can't be edited out from under the award.",
      ],
      el("div", { class: "data" }, [
        el("h4", {}, ["Result"]),
        el("div", { class: "chips" }, [
          el("span", { class: "badge l2" }, ["level L2"]),
          el("span", { class: "badge" }, ["locked"]),
        ]),
        el("p", { class: "hint" }, [
          "The award records which quote, the quantity, the ops and the ship-to — the quoteable fingerprint itself is unchanged.",
        ]),
      ]),
    ),
];

const walk = $("#walk");
const nextBtn = $("#next") as HTMLButtonElement;
const replayBtn = $("#replay") as HTMLButtonElement;
let shown = 0;

function reveal() {
  if (shown >= steps.length) return;
  const node = steps[shown]!();
  walk.append(node);
  shown++;
  node.scrollIntoView({ behavior: "smooth", block: "nearest" });
  if (shown >= steps.length) {
    nextBtn.textContent = "That's the lifecycle ✓";
    nextBtn.disabled = true;
    replayBtn.hidden = false;
  } else {
    nextBtn.textContent = `Next: ${titles[shown]} →`;
  }
}
nextBtn.addEventListener("click", reveal);
replayBtn.addEventListener("click", () => {
  walk.replaceChildren();
  shown = 0;
  nextBtn.textContent = "Start →";
  nextBtn.disabled = false;
  replayBtn.hidden = true;
});

// ── sandbox: you're the buyer — edit the spec and watch binding react ──
const QTY = ["100", "250", "500", "1000"];
const MATERIAL = ["6061-T6", "7075-T6", "A36 steel", "304 stainless"];
const INCOTERMS = ["FOB", "EXW", "DAP", "CIF"];
const state = { qty: "250", material: "6061-T6", incoterms: "FOB" };

function selectField(label: string, id: string, options: string[], value: string): HTMLElement {
  const sel = el("select", { id });
  for (const o of options) {
    const opt = el("option", { value: o }, [o]);
    if (o === value) opt.selected = true;
    sel.append(opt);
  }
  return el("div", { class: "field" }, [el("label", { for: id }, [label]), sel]);
}

$("#box-intro").replaceChildren(
  "Change the job and watch its ",
  term("fingerprint"),
  " move — and Summit's quote flip from ",
  term("bound"),
  " to ",
  term("stale"),
  " the instant the spec changes.",
);

const controls = $("#controls");
controls.append(
  selectField("Quantity", "f-qty", QTY, state.qty),
  selectField("Material", "f-material", MATERIAL, state.material),
  selectField("Incoterms (shipping terms)", "f-incoterms", INCOTERMS, state.incoterms),
);

const live = $("#live");
let lastHash = "";

function current(): Traveler {
  return parseTraveler({
    ...baseInput,
    part: {
      ...baseInput.part,
      material: { ...baseInput.part.material, spec: state.material },
      qty: { ...baseInput.part.qty, target: Number(state.qty) },
    },
    incoterms: state.incoterms,
  });
}

function render(flash: boolean) {
  const cur = current();
  const h = travelerHash(cur);
  const bound = h === baseHash;
  const changed = new Set<string>();
  const names: string[] = [];
  if (state.qty !== "250") {
    changed.add("qty");
    names.push("quantity");
  }
  if (state.material !== "6061-T6") {
    changed.add("material");
    names.push("material");
  }
  if (state.incoterms !== "FOB") {
    changed.add("incoterms");
    names.push("shipping terms");
  }

  const verdict = bound
    ? el("p", { class: "verdict ok" }, [
        "Your spec matches the quote's fingerprint, so Summit's quote is ",
        el("b", {}, ["bound"]),
        " — this job is L1 Awardable.",
      ])
    : el("p", { class: "verdict stale" }, [
        "You changed the ",
        el("b", {}, [names.join(" and ")]),
        ". The fingerprint moved, so Summit's quote — priced for the original spec — is now ",
        el("b", {}, ["stale"]),
        ". They'd have to re-quote this version.",
      ]);

  live.replaceChildren(
    fpHero(h, flash && h !== lastHash),
    specCard(cur, changed),
    el("div", { class: "data" }, [
      el("h4", {}, ["Summit's quote (priced for the original spec)"]),
      quoteCard("Summit Fabrication", "$14.20 / pc at 250", baseHash, bound),
    ]),
    verdict,
  );
  lastHash = h;
}

for (const [id, key] of [
  ["f-qty", "qty"],
  ["f-material", "material"],
  ["f-incoterms", "incoterms"],
] as const) {
  ($(`#${id}`) as HTMLSelectElement).addEventListener("change", (e) => {
    state[key] = (e.target as HTMLSelectElement).value;
    render(true);
  });
}

$("#reset-box").addEventListener("click", () => {
  state.qty = "250";
  state.material = "6061-T6";
  state.incoterms = "FOB";
  ($("#f-qty") as HTMLSelectElement).value = "250";
  ($("#f-material") as HTMLSelectElement).value = "6061-T6";
  ($("#f-incoterms") as HTMLSelectElement).value = "FOB";
  render(true);
});

render(false);
