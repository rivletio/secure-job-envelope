import "./style.css";
import { $, Out, Steps, sleep, short, registerSW } from "./ui.ts";
import {
  boundQuotes,
  levelOf,
  parseQuote,
  parseTraveler,
  staleQuotes,
} from "../../src/lib/traveler/conformance.ts";
import { cannotAward, cannotQuote, locked } from "../../src/lib/traveler/guards.ts";
import { travelerHash } from "../../src/lib/traveler/hash.ts";
import { isoNow, newQuoteId, newTravelerId } from "../../src/lib/traveler/ids.ts";
import type { Quote, Traveler } from "../../src/lib/traveler/types.ts";

registerSW();

const out = new Out($("#out"));
const stateEl = $("#state");
const runBtn = $("#run") as HTMLButtonElement;
const steps = new Steps($("#steps"), [
  { t: "Compose", d: "buyer creates an L0 (Quoteable) traveler" },
  { t: "Quote", d: "seller binds a price to the current hash" },
  { t: "Amend", d: "spec changes → hash moves → quote goes stale" },
  { t: "Re-quote", d: "a different shop binds the new hash" },
  { t: "Award", d: "ops + ship-to → L2 Executable, and it locks" },
]);

function setState(t: Traveler) {
  const info = levelOf(t);
  const chip = (label: string, cls = "badge") => {
    const s = document.createElement("span");
    s.className = cls;
    s.textContent = label;
    return s;
  };
  stateEl.replaceChildren(
    chip(`level ${info.code}`, `badge${info.code === "L2" ? " l2" : ""}`),
    chip(`bound ${boundQuotes(t).length}`),
    chip(`stale ${staleQuotes(t).length}`),
    chip(locked(t) ? "locked" : "open"),
  );
}

const pause = () => sleep(650);

async function run() {
  runBtn.disabled = true;
  runBtn.textContent = "Running…";
  steps.reset();
  out.clear();
  stateEl.replaceChildren();

  // 1 — compose
  steps.on(0);
  out.line("[1] Buyer composes an L0 traveler (CNC bracket, 250 pcs)", "hl");
  const l0 = parseTraveler({
    spec: "sje/0.1.0",
    traveler_id: newTravelerId(),
    revision: 1,
    created_at: isoNow(),
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
  const hash1 = travelerHash(l0);
  out.line(`    hash ${short(hash1)}`, "k");
  setState(l0);
  steps.done(0);
  await pause();

  // 2 — quote binds to hash1
  steps.on(1);
  out.line("[2] Summit Fabrication quotes — binds to this exact revision", "hl");
  const quote = parseQuote({
    quote_id: newQuoteId(),
    seller: { org_id: "org_summitfab", name: "Summit Fabrication", certs: ["ISO 9001"] },
    traveler_hash_quoted: hash1,
    created_at: isoNow(),
    valid_until: "2030-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: {
      currency: "USD",
      nre: 35000,
      lines: [
        { qty: 100, unit: 1850 },
        { qty: 250, unit: 1420 },
        { qty: 500, unit: 1175 },
      ],
    },
  }) as Quote;
  const err = cannotQuote(l0, quote);
  if (err) throw new Error(err);
  const l1: Traveler = { ...l0, quotes: [quote] };
  out.line("    $14.20/pc at 250 · 21-day lead · bound ✓", "ok");
  setState(l1);
  steps.done(1);
  await pause();

  // 3 — amend moves the hash, the quote goes stale
  steps.on(2);
  out.line("[3] Buyer amends Incoterms (FOB → EXW) — the hash moves", "hl");
  const amended = parseTraveler({ ...l1, incoterms: "EXW", revision: 2 });
  const hash2 = travelerHash(amended);
  out.line(`    ${short(hash1)} → ${short(hash2)}`, "k");
  out.line("    the earlier quote no longer binds — it is now STALE", "warn");
  setState(amended);
  steps.done(2);
  await pause();

  // 4 — a different shop quotes the amended spec
  steps.on(3);
  out.line("[4] Red River Machining quotes the amended spec", "hl");
  const quote2 = parseQuote({
    quote_id: newQuoteId(),
    seller: { org_id: "org_redriver", name: "Red River Machining", certs: ["ISO 9001", "AS9100"] },
    traveler_hash_quoted: hash2,
    created_at: isoNow(),
    valid_until: "2030-01-01T00:00:00.000Z",
    lead_time_days: 18,
    pricing: {
      currency: "USD",
      nre: 28000,
      lines: [
        { qty: 100, unit: 1790 },
        { qty: 250, unit: 1365 },
        { qty: 500, unit: 1120 },
      ],
    },
  }) as Quote;
  const l1b: Traveler = { ...amended, quotes: [quote, quote2] };
  out.line("    $13.65/pc at 250 · binds the new hash ✓", "ok");
  setState(l1b);
  steps.done(3);
  await pause();

  // 5 — award → L2, locked
  steps.on(4);
  out.line("[5] Buyer awards the bound quote — ops + ship-to", "hl");
  const blocker = cannotAward(l1b, quote2);
  if (blocker) throw new Error(blocker);
  const awarded: Traveler = {
    ...l1b,
    award: { quote_id: quote2.quote_id, awarded_at: isoNow(), qty: 250 },
    ship_to: {
      name: "Northline — Dock 4",
      line1: "1800 Industrial Way",
      city: "Reno",
      region: "NV",
      postal: "89502",
      country: "US",
    },
    ops: [
      { seq: 1, code: "laser" },
      { seq: 2, code: "cnc-mill" },
      { seq: 3, code: "deburr" },
    ],
  };
  out.line(`    level ${levelOf(awarded).code} · locked=${locked(awarded)}`, "ok");
  out.line(
    `    the quoteable hash is unchanged by the award: ${short(travelerHash(awarded))}`,
    "k",
  );
  setState(awarded);
  steps.done(4);
  await pause();

  out.line("");
  out.line("Done — a quote bound to its exact revision; award locked at L2.", "ok");
  runBtn.disabled = false;
  runBtn.textContent = "Run again";
}

runBtn.addEventListener("click", () => {
  run().catch((e) => {
    out.line(`error: ${e instanceof Error ? e.message : String(e)}`, "no");
    runBtn.disabled = false;
    runBtn.textContent = "Run again";
  });
});
