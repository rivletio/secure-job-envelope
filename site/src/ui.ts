/** Tiny framework-free DOM helpers shared by the demo pages. */

export function $(sel: string): HTMLElement {
  const n = document.querySelector(sel);
  if (!n) throw new Error(`missing element: ${sel}`);
  return n as HTMLElement;
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A scrolling console-style output pane with light syntax coloring. */
export class Out {
  constructor(private node: HTMLElement) {}
  clear() {
    this.node.textContent = "";
  }
  /** Append a line. `cls` ∈ {"", "ok", "no", "hl", "warn", "k"}. */
  line(text = "", cls = "") {
    const s = document.createElement("span");
    s.className = `ln ${cls}`.trim();
    s.textContent = text;
    this.node.append(s);
    this.node.scrollTop = this.node.scrollHeight;
  }
}

type StepDef = { t: string; d?: string };

/** A vertical step tracker; `on(i)` lights a step, `done(i)` marks it complete. */
export class Steps {
  private items: HTMLLIElement[] = [];
  constructor(node: HTMLElement, defs: StepDef[]) {
    const ul = document.createElement("ul");
    ul.className = "steps";
    defs.forEach((d, i) => {
      const li = document.createElement("li");
      const n = document.createElement("span");
      n.className = "n";
      n.textContent = String(i + 1);
      const t = document.createElement("span");
      t.className = "t";
      t.textContent = d.t;
      if (d.d) {
        const small = document.createElement("small");
        small.textContent = d.d;
        t.append(small);
      }
      li.append(n, t);
      ul.append(li);
      this.items.push(li);
    });
    node.append(ul);
  }
  reset() {
    this.items.forEach((li) => (li.className = ""));
  }
  on(i: number) {
    this.items[i]?.classList.add("on");
    this.items[i]?.classList.remove("done");
  }
  done(i: number) {
    this.items[i]?.classList.add("on", "done");
  }
}

export const short = (h: string, n = 26) => (h.length > n ? `${h.slice(0, n)}…` : h);

/** Tiny hyperscript: el("div", { class: "x" }, ["hi", child]). */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

/** Register the hand-rolled service worker so the demos install + work offline. */
export function registerSW() {
  if (!("serviceWorker" in navigator)) return;
  const base = import.meta.env.BASE_URL;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register(`${base}sw.js`, { scope: base }).catch(() => {});
  });
}
