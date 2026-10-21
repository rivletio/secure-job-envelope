/** A tiny glossary with tap/click-to-define terms, so a newcomer never hits a word
 *  they can't unpack. `term("fingerprint")` renders a dotted-underline button; clicking
 *  it shows a plain-language definition in a shared popover. Call initGlossary() once. */

type Def = { label: string; def: string };

export const GLOSSARY: Record<string, Def> = {
  traveler: {
    label: "traveler",
    def: "The job itself — one shared record of exactly what's being made (part, material, quantity, process) that moves between the buyer and the shops.",
  },
  fingerprint: {
    label: "fingerprint",
    def: "A short code (a SHA-384 hash) computed from the exact spec. Change any detail and the code changes completely — so everyone can tell at a glance whether they're looking at the same job.",
  },
  bound: {
    label: "bound",
    def: "A quote is “bound” when it's pinned to one exact fingerprint — i.e. priced against that precise spec. If the spec changes, the pin no longer matches.",
  },
  stale: {
    label: "stale",
    def: "A quote that was bound, but whose spec has since changed. Its fingerprint no longer matches the current job, so the old price can't be trusted for the new spec.",
  },
  level: {
    label: "stage (L0–L2)",
    def: "How far along the job is. L0 Quoteable (the spec is set) → L1 Awardable (a bound quote exists) → L2 Executable (awarded, with operations and a ship-to).",
  },
  incoterms: {
    label: "Incoterms",
    def: "Standard international shipping terms — who pays for and owns the freight at each step. FOB and EXW are two common ones; they change the deal, so they're part of the spec.",
  },
  locked: {
    label: "locked",
    def: "Once a job is awarded (L2) it's locked: the agreed spec can't be quietly edited out from under the award.",
  },
  award: {
    label: "award",
    def: "The buyer picking one bound quote and committing to it. It records which quote, the quantity, the operations and where to ship — and locks the job.",
  },
  ciphertext: {
    label: "ciphertext",
    def: "Scrambled data. Without the right secret key it's useless noise — the job's details (who, what part, how many) can't be read out of it.",
  },
  lock: {
    label: "public key",
    def: "The “lock” half of a key pair. It's public: anyone can use a desk's public key to seal a message TO that desk. It can't open anything.",
  },
  secret: {
    label: "secret key",
    def: "The “key” half of a key pair. A desk keeps it private; it's the only thing that can open messages sealed to that desk's public key.",
  },
  pq: {
    label: "post-quantum (ML-KEM)",
    def: "Encryption built to resist a future quantum computer. SJE seals with ML-KEM-1024, a standardized post-quantum algorithm — so a sealed job stays private even against tomorrow's hardware.",
  },
  fs: {
    label: "forward secrecy",
    def: "Each exchange uses a fresh one-time key, so even if a desk's long-term secret leaks later, past sealed jobs can't be opened. SJE prefers this (one-time prekeys) by default.",
  },
  directory: {
    label: "directory",
    def: "A signed phonebook: which organization is which, and what public key is theirs — so the buyer seals to the right shop and not an impostor.",
  },
  sje: {
    label: ".sje envelope",
    def: "The sealed file that actually travels between desks. It's ciphertext plus the bits needed to open it — nothing readable about the job is in the clear.",
  },
};

let pop: HTMLDivElement | null = null;

function ensurePop(): HTMLDivElement {
  if (pop) return pop;
  pop = document.createElement("div");
  pop.className = "term-pop";
  pop.setAttribute("role", "tooltip");
  pop.hidden = true;
  document.body.append(pop);
  return pop;
}

function showPop(btn: HTMLElement) {
  const g = GLOSSARY[btn.dataset.term ?? ""];
  if (!g) return;
  const p = ensurePop();
  p.replaceChildren();
  const h = document.createElement("strong");
  h.textContent = g.label;
  const d = document.createElement("span");
  d.textContent = g.def;
  p.append(h, d);
  p.dataset.for = btn.dataset.term ?? "";
  p.hidden = false;
  // Position below the term, clamped to the viewport.
  const r = btn.getBoundingClientRect();
  p.style.top = `${r.bottom + window.scrollY + 7}px`;
  p.style.left = `${r.left + window.scrollX}px`;
  const pr = p.getBoundingClientRect();
  const over = pr.right - (window.innerWidth - 12);
  if (over > 0) p.style.left = `${r.left + window.scrollX - over}px`;
}

function hidePop() {
  if (pop) pop.hidden = true;
}

/** One dotted-underline term button. `text` overrides the displayed label. */
export function term(key: string, text?: string): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "term";
  b.dataset.term = key;
  b.setAttribute("aria-label", `define: ${GLOSSARY[key]?.label ?? key}`);
  b.textContent = text ?? GLOSSARY[key]?.label ?? key;
  return b;
}

/** Wire the shared popover once (event delegation; click a term to toggle). */
export function initGlossary() {
  document.addEventListener("click", (e) => {
    const t = (e.target as HTMLElement).closest(".term") as HTMLElement | null;
    if (t) {
      e.preventDefault();
      if (pop && !pop.hidden && pop.dataset.for === t.dataset.term) hidePop();
      else showPop(t);
      return;
    }
    if (!(e.target as HTMLElement).closest(".term-pop")) hidePop();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hidePop();
  });
  window.addEventListener("resize", hidePop);
}
