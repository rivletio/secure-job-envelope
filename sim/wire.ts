/** The wire tree: a JSON document as it will be SPELLED, not as it parses.
 *
 *  A JavaScript value can only hold what `JSON.parse` would hand back, so a fuzzer
 *  that mutates values never writes the documents two parsers actually disagree
 *  about: a member name written twice, `250` written `2.5e2`, a name spelled with an
 *  escape, a comment, a raw control byte, a byte that is not UTF-8. This tree keeps
 *  every token's spelling, so each of those is an ordinary edit:
 *
 *    value --toWire--> tree --(wire mutations)--> printWire --> text --encodeWire--> bytes
 *
 *  `toWire` spells a value exactly as `JSON.stringify` would, so a document no wire
 *  mutation touched reaches both implementations as the bytes the old harness sent.
 */

/** Text emitted verbatim before / after a node — whitespace, a comment, anything. */
type Trivia = { pre?: string; post?: string };

/** A string token. `spell` (quotes included) overrides the default spelling. */
export type WStr = Trivia & { k: "str"; value: string; spell?: string };
/** A number token. `spell` overrides the default (shortest) spelling. */
export type WNum = Trivia & { k: "num"; value: number; spell?: string };
export type WLit = Trivia & { k: "lit"; value: boolean | null };
/** Arbitrary text in a value (or name) position: `1e309`, `NaN`, `'x'`, `[[[[…]]]]`. */
export type WRaw = Trivia & { k: "raw"; text: string };
/** `members` is a list, not a map: order is kept and a name may repeat. */
export type WObj = Trivia & { k: "obj"; members: WMember[]; tail?: string };
export type WArr = Trivia & { k: "arr"; items: WNode[]; tail?: string };
/** `sep` overrides the `:` between name and value. */
export type WMember = { name: WStr | WRaw; value: WNode; sep?: string };
export type WNode = WObj | WArr | WStr | WNum | WLit | WRaw;

/** A document under construction: the tree plus raw byte runs that the encoder drops
 *  in wherever the text carries their marker (see `splice`). */
export type Wire = { root: WNode; splices: Uint8Array[] };

// A value a mutation wants on the wire verbatim. `JSON.stringify` collapses a JS
// number (`250.0` -> `250`), so an object-level mutation cannot hold `250.0` as a
// number: it stores this sentinel STRING and `toWire` turns it into a raw token.
const RAW = /^@@RAW#([\s\S]*)#@@$/;
export function rawText(text: string): string {
  return `@@RAW#${text}#@@`;
}

export const str = (value: string, spell?: string): WStr =>
  spell === undefined ? { k: "str", value } : { k: "str", value, spell };
export const num = (value: number, spell?: string): WNum =>
  spell === undefined ? { k: "num", value } : { k: "num", value, spell };
export const raw = (text: string): WRaw => ({ k: "raw", text });
export const lit = (value: boolean | null): WLit => ({ k: "lit", value });
export const member = (name: string, value: WNode): WMember => ({ name: str(name), value });

/** Spell a JavaScript value as `JSON.stringify` would (same member order, `undefined`
 *  members dropped, non-finite numbers as `null`), keeping raw sentinels raw. */
export function toWire(value: unknown): WNode {
  if (typeof value === "string") {
    const m = RAW.exec(value);
    return m ? raw(m[1]!) : str(value);
  }
  if (typeof value === "number") return Number.isFinite(value) ? num(value) : lit(null);
  if (typeof value === "boolean") return lit(value);
  if (Array.isArray(value)) return { k: "arr", items: value.map((v) => toWire(v ?? null)) };
  if (value && typeof value === "object") {
    const members: WMember[] = [];
    for (const key of Object.keys(value)) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) members.push({ name: str(key), value: toWire(v) });
    }
    return { k: "obj", members };
  }
  return lit(null);
}

export function printWire(n: WNode): string {
  let core: string;
  switch (n.k) {
    case "str":
    case "num":
      core = n.spell ?? JSON.stringify(n.value);
      break;
    case "lit":
      core = String(n.value);
      break;
    case "raw":
      core = n.text;
      break;
    case "arr":
      core = `[${n.items.map(printWire).join(",")}${n.tail ?? ""}]`;
      break;
    case "obj":
      core = `{${n.members.map((m) => `${printWire(m.name)}${m.sep ?? ":"}${printWire(m.value)}`).join(",")}${n.tail ?? ""}}`;
      break;
  }
  return (n.pre ?? "") + core + (n.post ?? "");
}

/* ---------------- raw bytes at a chosen place in the text ---------------- */

// Each spliced byte run is stood in for, in the text, by one plane-16 private-use
// character (U+100000 + index) — a code point nothing in the generators emits.
const SPLICE_BASE = 0x100000;
const MAX_SPLICES = 0x400;

/** Register `bytes` and return the marker to put in the text where they belong. */
export function splice(w: Wire, bytes: Uint8Array): string {
  if (w.splices.length >= MAX_SPLICES) throw new Error("too many byte splices in one case");
  w.splices.push(bytes);
  return String.fromCodePoint(SPLICE_BASE + w.splices.length - 1);
}

// A lone surrogate, or a splice marker (U+100000..U+1003FF is \uDBC0 + any low).
const SPECIAL =
  /\uDBC0[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** Text -> bytes. UTF-8, except that a splice marker becomes its registered bytes and
 *  a lone surrogate becomes the three bytes a naive encoder would write for it
 *  (ED A0 80 .. ED BF BF — not valid UTF-8; `TextEncoder` would hide it as U+FFFD). */
export function encodeWire(text: string, splices: Uint8Array[] = []): Uint8Array {
  const utf8 = new TextEncoder();
  SPECIAL.lastIndex = 0;
  if (!SPECIAL.test(text)) return utf8.encode(text);
  const parts: Uint8Array[] = [];
  let at = 0;
  SPECIAL.lastIndex = 0;
  for (let m = SPECIAL.exec(text); m; m = SPECIAL.exec(text)) {
    if (m.index > at) parts.push(utf8.encode(text.slice(at, m.index)));
    const unit = text.charCodeAt(m.index);
    if (m[0].length === 2) {
      const bytes = splices[text.codePointAt(m.index)! - SPLICE_BASE];
      if (!bytes) throw new Error("splice marker without registered bytes");
      parts.push(bytes);
    } else {
      parts.push(Uint8Array.of(0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)));
    }
    at = m.index + m[0].length;
  }
  if (at < text.length) parts.push(utf8.encode(text.slice(at)));
  return concatBytes(parts);
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/* ---------------- finding places to edit ---------------- */

export type Path = (string | number)[];
/** A node together with where it sits, so a mutation can replace or remove it. */
export type Site<N extends WNode = WNode> = {
  node: N;
  path: Path;
  parent?: WObj | WArr;
  index: number;
};

/** Every node of the tree, parents before children. A member's path step is its name
 *  (as parsed), an element's is its index. */
export function sites(root: WNode): Site[] {
  const out: Site[] = [];
  const visit = (node: WNode, path: Path, parent: WObj | WArr | undefined, index: number) => {
    out.push({ node, path, parent, index });
    if (node.k === "obj") {
      node.members.forEach((m, i) =>
        visit(m.value, [...path, m.name.k === "str" ? m.name.value : m.name.text], node, i),
      );
    } else if (node.k === "arr") {
      node.items.forEach((item, i) => visit(item, [...path, i], node, i));
    }
  };
  visit(root, [], undefined, 0);
  return out;
}

export function sitesOf<K extends WNode["k"]>(root: WNode, kind: K): Site<Extract<WNode, { k: K }>>[] {
  return sites(root).filter((s) => s.node.k === kind) as Site<Extract<WNode, { k: K }>>[];
}

/** Put `node` where `site` is (the root included). */
export function replaceAt(w: Wire, site: Site, node: WNode): void {
  if (!site.parent) w.root = node;
  else if (site.parent.k === "obj") site.parent.members[site.index]!.value = node;
  else site.parent.items[site.index] = node;
}

/** The value of member `name` of an object node (the last one, if it repeats). */
export function memberOf(node: WNode | undefined, name: string): WNode | undefined {
  if (!node || node.k !== "obj") return undefined;
  for (let i = node.members.length - 1; i >= 0; i--) {
    const m = node.members[i]!;
    if (m.name.k === "str" && m.name.value === name) return m.value;
  }
  return undefined;
}

/** Set (or add) member `name` of an object node. */
export function setMember(node: WObj, name: string, value: WNode): void {
  const existing = node.members.find((m) => m.name.k === "str" && m.name.value === name);
  if (existing) existing.value = value;
  else node.members.push(member(name, value));
}

/** True for the three free-form blobs and everything inside them. */
export function inBlob(path: Path): boolean {
  if (path[0] === "as_built") return true;
  return (
    path[0] === "quotes" &&
    typeof path[1] === "number" &&
    (path[2] === "assumptions" || path[2] === "capacity")
  );
}

export const showPath = (path: Path): string => (path.length ? path.join(".") : "$");

export function cloneNode<N extends WNode>(node: N): N {
  return structuredClone(node);
}
