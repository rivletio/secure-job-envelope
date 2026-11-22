/** Mutation catalog, part 3 of 4: WIRE mutations — edits to the document's spelling.
 *
 *  Nearly everything here is something a JS value cannot hold or `JSON.stringify`
 *  never emits — a member name written twice, a number respelled, a name escaped, a
 *  member named `__proto__`, a comment, a byte that is not UTF-8 — which is why the
 *  old fuzzer (mutate a value, stringify it, hand the parsed value to TypeScript) ran
 *  past every bug in this class. They operate on the wire tree (wire.ts), so they
 *  compose with each other and with the value-level mutations.
 *
 *  Two kinds, and the harness needs neither told apart: spellings that MEAN the same
 *  document (both sides must reach the same verdict as before) and spellings that are
 *  not JSON, or not a traveler, at all (both must refuse). The respellers and the
 *  tables of edge-case literals live in spelling.ts.
 */
import { canonicalJson } from "../src/lib/traveler/canonical.ts";
import { MAX_TRAVELER_JSON_BYTES } from "../src/lib/traveler/types.ts";
import { utf8ByteLength } from "../src/lib/traveler/wire.ts";
import type { Ctx, WireMutation } from "./mutations.ts";
import { SPACEY, uPlus } from "./mutations-object.ts";
import {
  NUM_BIG,
  NUM_EXTREME,
  NUM_INVALID,
  UTF8_INVALID,
  UTF8_RARE,
  midpointAbove,
  respellNumber,
  respellString,
  spellWith,
} from "./spelling.ts";
import {
  cloneNode,
  encodeWire,
  inBlob,
  lit,
  member,
  memberOf,
  num,
  printWire,
  raw,
  replaceAt,
  setMember,
  showPath,
  sites,
  sitesOf,
  splice,
  str,
  type Path,
  type Site,
  type WMember,
  type WNode,
  type WObj,
  type WStr,
  type Wire,
} from "./wire.ts";

const cp = String.fromCodePoint;
const nameOf = (m: WMember): string => (m.name.k === "str" ? m.name.value : m.name.text);
const obj = (...members: WMember[]): WObj => ({ k: "obj", members });
const nest = (open: string, close: string, n: number, bottom = ""): string =>
  open.repeat(Math.max(0, n)) + bottom + close.repeat(Math.max(0, n));

/* ---------------- finding places to edit ---------------- */

const isBlobRoot = (p: Path): boolean =>
  (p.length === 1 && p[0] === "as_built") ||
  (p.length === 3 && p[0] === "quotes" && (p[2] === "assumptions" || p[2] === "capacity"));

/** Objects in typed positions (everything outside the three free-form blobs). */
const typedObjects = (w: Wire): Site<WObj>[] => sitesOf(w.root, "obj").filter((s) => !inBlob(s.path));

/** A free-form blob to work in: one the document already has, or a fresh `as_built`
 *  (legal on any traveler, and outside the hash). */
function someBlob(w: Wire, ctx: Ctx): { node: WObj; path: Path } | undefined {
  if (w.root.k !== "obj") return undefined;
  const have = sitesOf(w.root, "obj").filter((s) => isBlobRoot(s.path));
  if (have.length && ctx.rng.bool(0.7)) return ctx.rng.pick(have);
  const node = obj(member("lot", str("A-7")), member("n", num(3)));
  setMember(w.root, "as_built", node);
  return { node, path: ["as_built"] };
}

/** Any object inside a blob (the blob itself included). */
function someBlobObject(w: Wire, ctx: Ctx): { node: WObj; path: Path } | undefined {
  const blob = someBlob(w, ctx);
  if (!blob) return undefined;
  const inner = sitesOf(blob.node, "obj");
  const pick = ctx.rng.pick(inner);
  return { node: pick.node, path: [...blob.path, ...pick.path] };
}

/** Members whose value is free text — a length cap and no pattern — so its content
 *  can change without the schema refusing it for an unrelated reason. */
const PROSE = new Set(
  "name city region contact family part_number description drawing_rev form finish tolerances notes line1 line2 postal code on proposal governing_law warranty payment_terms kid incoterms certs processes".split(" "),
);
function isProse(path: Path): boolean {
  if (inBlob(path)) return true;
  const last = path[path.length - 1];
  const field = typeof last === "number" ? path[path.length - 2] : last;
  if (field === "spec") return path.length > 1; // material.spec is prose; the traveler's `spec` is not
  return typeof field === "string" && PROSE.has(field);
}

/** A string token with where it is: any value or member name — or, with `prose`,
 *  only a free-text value. */
function someString(w: Wire, ctx: Ctx, prose = false): { node: WStr; where: string } | undefined {
  const all: { node: WStr; where: string }[] = [];
  for (const s of sites(w.root)) {
    if (s.node.k === "str" && (!prose || isProse(s.path))) all.push({ node: s.node, where: showPath(s.path) });
    if (s.node.k === "obj" && !prose) {
      for (const m of s.node.members) {
        if (m.name.k === "str") all.push({ node: m.name, where: `name ${showPath([...s.path, m.name.value])}` });
      }
    }
  }
  return all.length ? ctx.rng.pick(all) : undefined;
}

/** A number to replace: an existing one, or a new member of a blob (where any number
 *  is legal, so the literal is judged by the parser alone). */
function someNumberSlot(w: Wire, ctx: Ctx): { put: (n: WNode) => void; where: string } | undefined {
  const nums = sitesOf(w.root, "num");
  if (nums.length && ctx.rng.bool(0.5)) {
    const s = ctx.rng.pick(nums);
    return { put: (n) => replaceAt(w, s, n), where: showPath(s.path) };
  }
  const blob = someBlobObject(w, ctx);
  if (!blob) return undefined;
  return { put: (n) => setMember(blob.node, "x", n), where: showPath([...blob.path, "x"]) };
}

/* ---------------- duplicate members ---------------- */

/** A value that cannot be what `value` was: wrong JSON type. */
function wrongType(value: WNode): WNode {
  if (value.k === "num") return str("x");
  if (value.k === "obj") return { k: "arr", items: [] };
  if (value.k === "arr") return obj();
  return num(0);
}

/** A value of the same type that is not `value`. */
function differentValue(value: WNode): WNode {
  const copy = cloneNode(value);
  if (copy.k === "num") return num(copy.value + 1);
  if (copy.k === "str") return str(`${copy.value}x`);
  if (copy.k === "lit") return lit(copy.value !== true);
  // A container: one entry fewer, or one more if it was empty.
  if (copy.k === "arr" && !copy.items.pop()) copy.items.push(num(1));
  if (copy.k === "obj" && !copy.members.pop()) copy.members.push(member("x", num(1)));
  return copy;
}

/** Give `node` a second member with the name of one it already has. Returns a note.
 *  The variants are chosen so that a first-wins reader, a last-wins reader and a
 *  strict reader each reach a different verdict on at least one of them. */
function addTwin(node: WObj, ctx: Ctx, spellName?: (name: string) => string | undefined): string | undefined {
  const i = ctx.rng.int(0, node.members.length - 1);
  const original = node.members[i]!;
  const variant = ctx.rng.pick(["same", "differ", "first-wrong", "last-wrong"] as const);
  const twin: WMember = { name: cloneNode(original.name), value: cloneNode(original.value) };
  if (spellName) {
    if (twin.name.k !== "str") return undefined;
    const spelled = spellName(twin.name.value);
    if (spelled === undefined) return undefined;
    twin.name.spell = spelled;
  }
  if (variant === "differ") twin.value = differentValue(original.value);
  if (variant === "first-wrong" || variant === "last-wrong") twin.value = wrongType(original.value);
  // "first-wrong": the twin goes first; otherwise after, adjacent or at the far end.
  const at = variant === "first-wrong" ? ctx.rng.int(0, i) : ctx.rng.bool() ? i + 1 : node.members.length;
  node.members.splice(at, 0, twin);
  return `${variant} ${nameOf(original)}`;
}

/** Hide `hidden` behind a member of the same name: `{"x": <hidden>, "x": <fine>}`.
 *  A last-wins parser never looks at the first value; a strict one lexes it. */
function shadow(w: Wire, ctx: Ctx, hidden: WNode): string | undefined {
  let host: { node: WObj; path: Path } | undefined;
  if (ctx.rng.bool(0.4)) {
    const typed = typedObjects(w).filter((s) => s.node.members.length > 0);
    if (typed.length) host = ctx.rng.pick(typed);
  }
  host ??= someBlobObject(w, ctx);
  if (!host) return undefined;
  if (!host.node.members.length) host.node.members.push(member("x", num(1)));
  const i = ctx.rng.int(0, host.node.members.length - 1);
  const original = host.node.members[i]!;
  const hiddenFirst = ctx.rng.bool(0.8);
  host.node.members.splice(hiddenFirst ? i : i + 1, 0, { name: cloneNode(original.name), value: hidden });
  return `${hiddenFirst ? "hidden-first" : "hidden-last"} ${showPath([...host.path, nameOf(original)])}`;
}

/* ---------------- structs written as arrays ---------------- */

/** Member order of every structured value, as the Rust structs declare it — the order
 *  a derive-generated deserializer reads a positional array in. */
const STRUCTS = {
  traveler: ["spec", "traveler_id", "revision", "created_at", "buyer", "part", "need_by", "incoterms", "itar", "ship_to", "ops", "quotes", "award", "as_built", "signatures"],
  org: ["org_id", "name", "city", "region", "contact", "certs", "itar"],
  part: ["family", "part_number", "description", "drawing_rev", "material", "qty", "processes", "finish", "tolerances", "notes"],
  material: ["spec", "form", "thickness_mm"],
  qty: ["target", "breaks"],
  ship_to: ["name", "line1", "line2", "city", "region", "postal", "country"],
  op: ["seq", "code", "notes"],
  quote: ["quote_id", "seller", "traveler_hash_quoted", "created_at", "valid_until", "lead_time_days", "need_by_feasible", "pricing", "assumptions", "exceptions", "capacity", "sig"],
  pricing: ["currency", "nre", "lines", "freight_estimate", "tax_excluded"],
  line: ["qty", "unit"],
  exception: ["code", "on", "proposal", "price_delta"],
  signature: ["alg", "kid", "sig"],
  award: ["quote_id", "quote_hash", "awarded_at", "qty", "terms", "sig"],
  terms: ["governing_law", "warranty", "payment_terms"],
} as const;

/** Where each struct sits (`#` is any array index). A Map, not an object literal: a
 *  path can be `toString` or `constructor` here, and those must find nothing. */
const STRUCT_AT = new Map<string, keyof typeof STRUCTS>([
  ["", "traveler"],
  ["buyer", "org"],
  ["part", "part"],
  ["part.material", "material"],
  ["part.qty", "qty"],
  ["ship_to", "ship_to"],
  ["ops.#", "op"],
  ["quotes.#", "quote"],
  ["quotes.#.seller", "org"],
  ["quotes.#.pricing", "pricing"],
  ["quotes.#.pricing.lines.#", "line"],
  ["quotes.#.exceptions.#", "exception"],
  ["quotes.#.sig", "signature"],
  ["award", "award"],
  ["award.terms", "terms"],
  ["award.sig", "signature"],
  ["signatures.#", "signature"],
]);
const structAt = (path: Path): keyof typeof STRUCTS | undefined =>
  STRUCT_AT.get(path.map((step) => (typeof step === "number" ? "#" : step)).join("."));

/* ---------------- blobs at their size cap ---------------- */

/** A way to fill a blob: as many members as fit in `room` UTF-16 units of wire text. */
export type Filler = { name: string; fill: (room: number) => WMember[] };

/** One string member made of a repeated character (optionally spelled its own way). */
const textFiller = (name: string, value: string, spell?: string): Filler => ({
  name,
  fill: (room) => {
    const unit = (spell ?? JSON.stringify(value).slice(1, -1)).length;
    const n = Math.max(0, Math.floor((room - '"fill":""'.length) / unit));
    return [member("fill", str(value.repeat(n), spell === undefined ? undefined : `"${spell.repeat(n)}"`))];
  },
});
/** One array member holding a repeated element. */
const itemFiller = (name: string, item: () => WNode): Filler => ({
  name,
  fill: (room) => {
    const unit = printWire(item()).length + 1; // the element and its comma
    const n = Math.max(0, Math.floor((room - '"fill":[]'.length + 1) / unit));
    return [member("fill", { k: "arr", items: Array.from({ length: n }, item) })];
  },
});

/** What a blob is filled with. Strings are measured in three different units by three
 *  different length functions; numbers are re-rendered by whoever measures them. */
export const BLOB_FILLERS: readonly Filler[] = [
  textFiller("ascii", "x"),
  textFiller("cjk", cp(0x6f22)),
  textFiller("astral", cp(0x1f600)),
  textFiller("newlines", "\n"),
  textFiller("quotes", '"'),
  textFiller("nul", cp(0)),
  textFiller("line-separators", cp(0x2028)),
  textFiller("u-escaped-ascii", "A", "\\u0041"),
  itemFiller("integers", () => num(7)),
  itemFiller("fractions", () => num(1.5)),
  itemFiller("nulls", () => lit(null)),
  itemFiller("booleans", () => lit(true)),
  itemFiller("empty-strings", () => str("")),
  itemFiller("empty-arrays", () => ({ k: "arr", items: [] })),
  itemFiller("empty-objects", () => obj()),
  itemFiller("n.0", () => num(1, "1.0")),
  itemFiller("exponent", () => num(100, "1e2")),
  itemFiller("minus-zero", () => num(-0, "-0")),
  itemFiller("1e15", () => num(1e15, "1e15")),
  itemFiller("1e-7", () => num(1e-7, "1e-7")),
  itemFiller("0.000001", () => num(0.000001, "0.000001")),
  itemFiller("1e21", () => num(1e21, "1e21")),
  itemFiller("21-digit-integer", () => num(1e20, "100000000000000000000")),
  itemFiller("u64-max", () => num(2 ** 64, "18446744073709551615")),
  itemFiller("2^53+1", () => num(2 ** 53, "9007199254740993")),
  {
    name: "many-members",
    fill: (room) => {
      const members: WMember[] = [];
      for (let used = -1; ; ) {
        const m = member(`k${members.length}`, num(0));
        used += printWire(m.name).length + 3; // name, colon, value, comma
        if (used > room) return members;
        members.push(m);
      }
    },
  },
];

/** A way of measuring a blob — every unit someone might count its cap in. The format
 *  measures the canonical form in bytes (SPEC, parsing rule 12); an implementation that
 *  counted any of the others would agree on most blobs and split on the ones built here. */
export type BlobMeasure = { name: string; of: (blob: WObj) => number };

/** The blob's canonical JSON — or, when it has none (a number outside the canonical
 *  range), its wire text: such a blob is refused whatever its size. */
const canonicalOrWire = (blob: WObj): string => {
  const text = printWire(blob);
  try {
    return canonicalJson(JSON.parse(text));
  } catch {
    return text;
  }
};

export const BLOB_MEASURES: readonly BlobMeasure[] = [
  { name: "canonical-bytes", of: (blob) => utf8ByteLength(canonicalOrWire(blob)) },
  { name: "canonical-units", of: (blob) => canonicalOrWire(blob).length },
  { name: "wire-bytes", of: (blob) => utf8ByteLength(printWire(blob)) },
  { name: "wire-units", of: (blob) => printWire(blob).length },
];

/** An object that measures exactly `target` by `measure`: as much of the filler as
 *  fits, then ASCII padding (one more of every unit per character). */
export function blobOfSize(filler: Filler, target: number, measure: BlobMeasure = BLOB_MEASURES[0]!): WObj {
  const pad = (n: number) => member("pad", str("x".repeat(Math.max(0, n))));
  const build = (room: number) => obj(...filler.fill(room), pad(0));
  // The most filler that still fits. A filler is asked for `room` units of wire text,
  // which can be several times what it measures (six characters of `\u0041` are one
  // byte of canonical text), and more filler never measures less: bisect.
  let lo = 0;
  let hi = target * 8;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure.of(build(mid)) <= target) lo = mid;
    else hi = mid - 1;
  }
  const blob = build(lo);
  blob.members[blob.members.length - 1] = pad(target - measure.of(blob));
  return blob;
}

/** Put a byte run inside a string token, or between two tokens. `prose` keeps it to
 *  free-text values, where a legal character would be accepted. */
function placeBytes(w: Wire, ctx: Ctx, bytes: number[], prose = false): string | undefined {
  const marker = splice(w, Uint8Array.from(bytes));
  if (prose || ctx.rng.bool(0.7)) {
    const target = someString(w, ctx, prose);
    if (!target) return undefined;
    target.node.spell = spellWith(target.node.value, marker, ctx.rng);
    return `in ${target.where}`;
  }
  const all = sites(w.root);
  const site = ctx.rng.pick(all);
  if (ctx.rng.bool()) site.node.pre = marker + (site.node.pre ?? "");
  else site.node.post = (site.node.post ?? "") + marker;
  return `beside ${showPath(site.path)}`;
}

/* ---------------- the catalog ---------------- */

export const WIRE_MUTATIONS: WireMutation[] = [
  // ---- a member name written twice (K6) ----
  {
    name: "dup-member-typed",
    why: "a member name written twice in a typed object, at any depth: JSON.parse keeps the last, a typed reader refuses (K6)",
    weight: 8,
    apply: (w, ctx) => {
      const hosts = typedObjects(w).filter((s) => s.node.members.length > 0);
      if (!hosts.length) return;
      const host = ctx.rng.pick(hosts);
      const what = addTwin(host.node, ctx);
      if (what) ctx.note(`${what} in ${showPath(host.path)}`);
    },
  },
  {
    name: "dup-member-blob",
    why: "a member name written twice inside a free-form blob, where a generic JSON value reader keeps the last silently (K6)",
    weight: 6,
    apply: (w, ctx) => {
      const host = someBlobObject(w, ctx);
      if (!host) return;
      if (!host.node.members.length) host.node.members.push(member("lot", str("A")));
      const what = addTwin(host.node, ctx);
      if (what) ctx.note(`${what} in ${showPath(host.path)}`);
    },
  },
  {
    name: "near-twin-blob",
    why: "two blob names that only LOOK alike (case, a zero-width joiner, composed vs decomposed): not a duplicate, on either side",
    weight: 3,
    apply: (w, ctx) => {
      const host = someBlobObject(w, ctx);
      if (!host) return;
      const base = `caf${cp(0xe9)}`;
      const [label, other] = ctx.rng.pick<[string, string]>([
        ["case", `Caf${cp(0xe9)}`],
        ["decomposed", `cafe${cp(0x301)}`],
        ["zero-width-joiner", `${base}${cp(0x200d)}`],
        ["trailing-space", `${base} `],
        ["nul-suffix", `${base}${cp(0)}`],
        ["fullwidth", `${cp(0xff43)}af${cp(0xe9)}`],
      ]);
      host.node.members.push(member(base, num(1)), member(other, num(2)));
      ctx.note(`${label} in ${showPath(host.path)}`);
    },
  },
  {
    name: "dup-member-escaped",
    why: 'the twin spelled with an escape ("lot" and "lo\\u0074"): names must be compared after unescaping (K6)',
    weight: 6,
    apply: (w, ctx) => {
      const hosts = sitesOf(w.root, "obj").filter((s) => s.node.members.some((m) => m.name.k === "str" && m.name.value));
      if (!hosts.length) return;
      const host = ctx.rng.pick(hosts);
      const what = addTwin(host.node, ctx, (name) => {
        if (!name) return undefined;
        const some = respellString(name, ctx.rng, 0.3);
        return some === JSON.stringify(name) ? respellString(name, ctx.rng, 1) : some;
      });
      if (what) ctx.note(`${what} in ${showPath(host.path)}`);
    },
  },
  {
    name: "dup-shadow-range",
    why: 'an out-of-range number hidden behind a duplicate ({"x":1e309,"x":1}): a last-wins parser never lexes it (K6)',
    weight: 5,
    apply: (w, ctx) => {
      const hidden = ctx.rng.pick(["1e309", "-1e309", "1e999999", `1${"0".repeat(400)}`]);
      const where = shadow(w, ctx, raw(hidden));
      if (where) ctx.note(`${hidden.slice(0, 9)} ${where}`);
    },
  },
  {
    name: "dup-shadow-surrogate",
    why: "a lone-surrogate escape hidden behind a duplicate: unrepresentable in UTF-8, invisible to a last-wins parser (K6)",
    weight: 5,
    apply: (w, ctx) => {
      const hidden = ctx.rng.pick(['"\\ud800"', '"a\\udfffb"', '"\\ude00\\ud83d"']);
      const where = shadow(w, ctx, raw(hidden));
      if (where) ctx.note(`${hidden} ${where}`);
    },
  },
  {
    name: "dup-shadow-deep",
    why: "a value nested past the recursion limit hidden behind a duplicate (K6)",
    weight: 5,
    apply: (w, ctx) => {
      const depth = ctx.rng.pick([128, 200, 5000]);
      const where = shadow(w, ctx, raw(nest("[", "]", depth)));
      if (where) ctx.note(`depth-${depth} ${where}`);
    },
  },
  {
    name: "dup-member-whole",
    why: "a whole top-level member twice (two awards, two quote lists): which one was signed, which one is shown (K6)",
    weight: 6,
    apply: (w, ctx) => {
      if (w.root.k !== "obj") return;
      const wanted = ["award", "quotes", "ops", "as_built", "ship_to", "signatures", "buyer", "part", "itar"];
      const have = w.root.members.filter((m) => wanted.includes(nameOf(m)));
      if (!have.length) return;
      const original = ctx.rng.pick(have);
      const variant = ctx.rng.pick(["same", "emptied", "null"] as const);
      const value =
        variant === "same"
          ? cloneNode(original.value)
          : variant === "null"
            ? lit(null)
            : original.value.k === "arr"
              ? ({ k: "arr", items: [] } as WNode)
              : obj();
      const first = ctx.rng.bool();
      w.root.members.splice(first ? 0 : w.root.members.length, 0, { name: cloneNode(original.name), value });
      ctx.note(`${nameOf(original)} ${variant} ${first ? "first" : "last"}`);
    },
  },

  // ---- whitespace ----
  {
    name: "ws-legal",
    why: "legal JSON whitespace (space, tab, LF, CR) between tokens: the verdict and the hash must not move",
    weight: 10,
    apply: (w, ctx) => {
      const density = ctx.rng.pick([0.05, 0.3, 1]);
      const ws = () => Array.from({ length: ctx.rng.int(1, 3) }, () => ctx.rng.pick([" ", "\t", "\n", "\r", "\r\n"])).join("");
      for (const s of sites(w.root)) {
        const tokens: (WNode | WStr)[] = [s.node];
        if (s.node.k === "obj") for (const m of s.node.members) if (m.name.k === "str") tokens.push(m.name);
        for (const t of tokens) {
          if (ctx.rng.bool(density)) t.pre = (t.pre ?? "") + ws();
          if (ctx.rng.bool(density)) t.post = (t.post ?? "") + ws();
        }
        if ((s.node.k === "obj" || s.node.k === "arr") && ctx.rng.bool(density)) s.node.tail = (s.node.tail ?? "") + ws();
      }
      ctx.note(`density ${density}`);
    },
  },
  {
    name: "ws-illegal",
    why: "a code point some languages call whitespace, between tokens: JSON allows exactly four, and a BOM is not one",
    weight: 5,
    apply: (w, ctx) => {
      const c = ctx.rng.pick(SPACEY.filter((x) => ![0x09, 0x0a, 0x0d, 0x20].includes(x)).concat(0x00, 0x7f));
      const site = ctx.rng.pick(sites(w.root));
      if (ctx.rng.bool()) site.node.pre = cp(c) + (site.node.pre ?? "");
      else site.node.post = (site.node.post ?? "") + cp(c);
      ctx.note(`${uPlus(c)} beside ${showPath(site.path)}`);
    },
  },

  // ---- numbers respelled ----
  {
    name: "num-respell",
    why: "the same number spelled differently (250 / 250.0 / 2.5e2 / 25E+1 / -0): same value, so same verdict and same hash",
    weight: 10,
    apply: (w, ctx) => {
      const nums = sitesOf(w.root, "num");
      if (!nums.length) return;
      const all = ctx.rng.bool(0.4);
      const chosen = all ? nums.filter(() => ctx.rng.bool()) : [ctx.rng.pick(nums)];
      for (const s of chosen) s.node.spell = respellNumber(s.node.value, ctx.rng);
      ctx.note(all ? `${chosen.length} numbers` : `${chosen[0]!.node.spell} ${showPath(chosen[0]!.path)}`);
    },
  },
  {
    name: "num-invalid",
    why: "number spellings JSON forbids (+1, 0250, 1., .5, 0x1F, NaN, non-ASCII digits): both lexers must refuse",
    weight: 5,
    apply: (w, ctx) => {
      const nums = sitesOf(w.root, "num");
      if (!nums.length) return;
      const s = ctx.rng.pick(nums);
      const [label, make] = ctx.rng.pick(NUM_INVALID);
      replaceAt(w, s, raw(make(s.node.spell ?? JSON.stringify(s.node.value))));
      ctx.note(`${label} ${showPath(s.path)}`);
    },
  },
  {
    name: "num-big",
    why: "integers straddling 2^53, i64 and u64: exact on one side, rounded on the other, out of range in any typed field",
    weight: 5,
    apply: (w, ctx) => {
      const slot = someNumberSlot(w, ctx);
      if (!slot) return;
      const literal = ctx.rng.pick(NUM_BIG);
      slot.put(raw(literal));
      ctx.note(`${literal} ${slot.where}`);
    },
  },
  {
    name: "num-extreme",
    why: "literals at the ends of the double range and of a lexer's patience: overflow, underflow, 400 digits, a 20-digit exponent",
    weight: 5,
    apply: (w, ctx) => {
      const slot = someNumberSlot(w, ctx);
      if (!slot) return;
      const [label, literal] = ctx.rng.pick(NUM_EXTREME);
      slot.put(raw(literal));
      ctx.note(`${label} ${slot.where}`);
    },
  },
  {
    name: "num-halfway",
    why: "a number spelled as the exact midpoint between two doubles (or a hair to either side): correct rounding decides integer-ness and the hash",
    weight: 6,
    apply: (w, ctx) => {
      const nums = sitesOf(w.root, "num").filter((s) => s.node.value !== 0);
      if (!nums.length) return;
      const s = ctx.rng.pick(nums);
      const exact = midpointAbove(s.node.value);
      if (!exact || !exact.includes(".")) return;
      const side = ctx.rng.pick(["tie", "below", "above"] as const);
      const digits = side === "tie" ? exact : side === "below" ? `${exact.slice(0, -1)}4${"9".repeat(30)}` : `${exact}${"0".repeat(30)}1`;
      replaceAt(w, s, raw(`${s.node.value < 0 ? "-" : ""}${digits}`));
      ctx.note(`${side} ${showPath(s.path)}`);
    },
  },

  // ---- strings respelled ----
  {
    name: "str-respell",
    why: "the same string spelled with escapes (\\uXXXX in either case, surrogate pairs, \\/): names and values, same document",
    weight: 10,
    apply: (w, ctx) => {
      const p = ctx.rng.pick([0.1, 0.5, 1]);
      if (ctx.rng.bool(0.4)) {
        let n = 0;
        for (const s of sites(w.root)) {
          const tokens: WNode[] = s.node.k === "obj" ? s.node.members.map((m) => m.name) : [s.node];
          for (const t of tokens) {
            if (t.k === "str" && ctx.rng.bool()) {
              t.spell = respellString(t.value, ctx.rng, p);
              n++;
            }
          }
        }
        ctx.note(`${n} strings p=${p}`);
      } else {
        const target = someString(w, ctx);
        if (!target) return;
        target.node.spell = respellString(target.node.value, ctx.rng, p);
        ctx.note(`p=${p} ${target.where}`);
      }
    },
  },
  {
    name: "str-lone-surrogate",
    why: "a lone surrogate — as an escape (JSON.parse takes it, UTF-8 cannot hold it) or as raw bytes: both must refuse",
    weight: 6,
    apply: (w, ctx) => {
      const target = someString(w, ctx);
      if (!target) return;
      const [label, text] = ctx.rng.pick<[string, string]>([
        ["high", "\\ud800"],
        ["high-max", "\\udbff"],
        ["low", "\\udc00"],
        ["low-max", "\\udfff"],
        ["uppercase-hex", "\\uD83D"],
        ["reversed-pair", "\\ude00\\ud83d"],
        ["high-then-escaped-ascii", "\\ud83d\\u0041"],
        ["high-then-newline", "\\ud83d\\n"],
        ["high-high-low", "\\ud83d\\ud83d\\ude00"],
        ["raw-high", String.fromCharCode(0xd83d)],
        ["raw-low", String.fromCharCode(0xde00)],
      ]);
      target.node.spell = spellWith(target.node.value, text, ctx.rng);
      ctx.note(`${label} ${target.where}`);
    },
  },
  {
    name: "str-control-raw",
    why: "a raw control character inside a string: U+0000..U+001F must be escaped; U+007F and C1 need not be",
    weight: 5,
    apply: (w, ctx) => {
      const target = someString(w, ctx, ctx.rng.bool());
      if (!target) return;
      const c = ctx.rng.pick([0x00, 0x01, 0x08, 0x09, 0x0a, 0x0d, 0x1b, 0x1f, 0x7f, 0x80, 0x9f]);
      target.node.spell = spellWith(target.node.value, cp(c), ctx.rng);
      ctx.note(`${uPlus(c)} ${target.where}`);
    },
  },
  {
    name: "str-bad-escape",
    why: "an escape JSON does not define (\\x41, \\', \\0, \\u{41}, a short \\u12, a dangling backslash): both lexers must refuse",
    weight: 5,
    apply: (w, ctx) => {
      const target = someString(w, ctx);
      if (!target) return;
      const text = ctx.rng.pick(["\\x41", "\\'", "\\0", "\\a", "\\v", "\\e", "\\U0041", "\\u12G4", "\\u+123", "\\u 041", "\\u12", "\\u{41}", "\\N{DOLLAR SIGN}", "\\\n", "\\"]);
      const chars = JSON.stringify(target.node.value).slice(1, -1);
      target.node.spell = text === "\\" ? `"${chars}\\"` : spellWith(target.node.value, text, ctx.rng);
      ctx.note(`${JSON.stringify(text)} ${target.where}`);
    },
  },
  {
    name: "quote-style",
    why: "a string or name quoted the way other languages allow (single quotes, bare word, curly quotes): not JSON",
    weight: 4,
    apply: (w, ctx) => {
      const target = someString(w, ctx);
      if (!target) return;
      const v = JSON.stringify(target.node.value).slice(1, -1);
      const [label, spell] = ctx.rng.pick<[string, string]>([
        ["single", `'${v}'`],
        ["bare", v || "x"],
        ["backtick", `\`${v}\``],
        ["curly", `${cp(0x201c)}${v}${cp(0x201d)}`],
        ["unterminated", `"${v}`],
        ["doubled", `""${v}""`],
        ["fullwidth", `${cp(0xff02)}${v}${cp(0xff02)}`],
      ]);
      target.node.spell = spell;
      ctx.note(`${label} ${target.where}`);
    },
  },

  // ---- structure respelled ----
  {
    name: "reorder-members",
    why: "members in another order: neither the verdict nor the hash may depend on the order members arrive in",
    weight: 10,
    apply: (w, ctx) => {
      const objects = sitesOf(w.root, "obj").filter((s) => s.node.members.length > 1);
      if (!objects.length) return;
      const how = ctx.rng.pick(["shuffle", "reverse", "sort"] as const);
      const all = ctx.rng.bool(0.5);
      for (const s of all ? objects : [ctx.rng.pick(objects)]) {
        if (how === "shuffle") s.node.members = ctx.rng.shuffle(s.node.members);
        else if (how === "reverse") s.node.members.reverse();
        else s.node.members.sort((a, b) => (nameOf(a) < nameOf(b) ? -1 : 1));
      }
      ctx.note(`${how} ${all ? "everywhere" : "one object"}`);
    },
  },
  {
    name: "positional-struct",
    why: 'a structured value written as a positional array ("material": ["6061-T6"]): a derived deserializer reads it, a schema does not (K1)',
    weight: 8,
    apply: (w, ctx) => {
      const structs = typedObjects(w).filter((s) => structAt(s.path));
      if (!structs.length) return;
      const s = ctx.rng.pick(structs);
      const kind = structAt(s.path)!;
      const variant = ctx.rng.pick(["declared-order", "declared-order", "as-written", "empty"] as const);
      let items: WNode[] = [];
      if (variant === "as-written") items = s.node.members.map((m) => m.value);
      if (variant === "declared-order") {
        // Up to the last member present; a gap before it can only be written `null`.
        const values = STRUCTS[kind].map((field) => memberOf(s.node, field));
        while (values.length && values[values.length - 1] === undefined) values.pop();
        items = values.map((v) => v ?? lit(null));
      }
      replaceAt(w, s, { k: "arr", items });
      ctx.note(`${variant} ${kind} at ${showPath(s.path)}`);
    },
  },
  {
    name: "top-level",
    why: "the document is not an object at the top: a scalar, an array, the traveler one level down, or JSON inside a JSON string",
    weight: 3,
    apply: (w, ctx) => {
      const doc = w.root;
      const [label, root] = ctx.rng.pick<[string, WNode]>([
        ["null", lit(null)],
        ["true", lit(true)],
        ["zero", num(0)],
        ["empty-string", str("")],
        ["spec-string", str("sje/0.1.0")],
        ["empty-array", { k: "arr", items: [] }],
        ["empty-object", obj()],
        ["in-array", { k: "arr", items: [doc] }],
        ["in-member", obj(member("traveler", doc))],
        ["as-json-string", str(printWire(doc))],
      ]);
      w.root = root;
      ctx.note(label);
    },
  },

  // ---- names a JavaScript object treats specially (K2) ----
  {
    name: "proto-name-blob",
    why: "a blob member named __proto__ (a JS schema library may drop it silently) or after another Object.prototype property (K2)",
    weight: 8,
    apply: (w, ctx) => {
      const host = someBlobObject(w, ctx);
      if (!host) return;
      const name = ctx.rng.pick(["__proto__", "__proto__", "__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf", "toJSON", "__defineGetter__", "then"]);
      const value = ctx.rng.pick<WNode>([obj(member("x", num(1))), obj(), str("x"), lit(null), num(1), { k: "arr", items: [] }, str("x".repeat(9000))]);
      const m = member(name, value);
      if (ctx.rng.bool(0.2)) m.name = str(name, respellString(name, ctx.rng, 0.3));
      host.node.members.splice(ctx.rng.int(0, host.node.members.length), 0, m);
      ctx.note(`${name}=${value.k === "str" && value.value.length > 1 ? "9000-chars" : printWire(value)} in ${showPath(host.path)}`);
    },
  },
  {
    name: "proto-only-blob",
    why: "a blob whose ONLY member is __proto__: empty to a reader that drops the name, non-empty to one that keeps it (K2)",
    weight: 5,
    apply: (w, ctx) => {
      if (w.root.k !== "obj") return;
      const value = ctx.rng.pick<WNode>([obj(member("lot", str("A-7"))), obj(), lit(null), num(1), str("x")]);
      const blob = obj(member("__proto__", value));
      const quotes = memberOf(w.root, "quotes");
      const quote = quotes?.k === "arr" && quotes.items[0]?.k === "obj" ? quotes.items[0] : undefined;
      const site = quote && ctx.rng.bool(0.3) ? ctx.rng.pick(["assumptions", "capacity"]) : "as_built";
      setMember(site === "as_built" ? w.root : quote!, site, blob);
      ctx.note(`${printWire(value)} ${site}`);
    },
  },
  {
    name: "proto-name-typed",
    why: "__proto__ / constructor / toString as an extra member of a typed object: unknown there, however a JS object sees it",
    weight: 4,
    apply: (w, ctx) => {
      const hosts = typedObjects(w);
      if (!hosts.length) return;
      const host = ctx.rng.pick(hosts);
      const name = ctx.rng.pick(["__proto__", "__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf"]);
      const value = ctx.rng.bool() ? cloneNode(host.node) : ctx.rng.pick<WNode>([lit(null), obj(), str("x"), num(1)]);
      host.node.members.splice(ctx.rng.int(0, host.node.members.length), 0, member(name, value));
      ctx.note(`${name} in ${showPath(host.path)}`);
    },
  },

  // ---- size and depth inside blobs ----
  {
    name: "blob-fill",
    why: "a blob at 8191 / 8192 / 8193 of every kind of content, counted in every unit (canonical or wire text, bytes or UTF-16 units): the 8 KiB cap must be measured the same way on both sides",
    weight: 8,
    apply: (w, ctx) => {
      if (w.root.k !== "obj") return;
      const filler = ctx.rng.pick(BLOB_FILLERS);
      const target = ctx.rng.pick([8191, 8192, 8193, 8192 + ctx.rng.int(-40, 40), ctx.rng.int(2000, 16_000)]);
      const measure = ctx.rng.pick(BLOB_MEASURES);
      const quotes = memberOf(w.root, "quotes");
      const quote = quotes?.k === "arr" && quotes.items[0]?.k === "obj" ? quotes.items[0] : undefined;
      const site = quote && ctx.rng.bool(0.3) ? ctx.rng.pick(["assumptions", "capacity"]) : "as_built";
      setMember(site === "as_built" ? w.root : quote!, site, blobOfSize(filler, target, measure));
      ctx.note(`${filler.name} ${target} ${measure.name} ${site}`);
    },
  },
  {
    name: "blob-depth",
    why: "nesting inside a blob so the document is 126 / 127 / 128 / 129 containers deep: both parsers stop at the same level",
    weight: 6,
    apply: (w, ctx) => {
      const blob = someBlob(w, ctx);
      if (!blob) return;
      const depth = ctx.rng.pick([126, 127, 127, 128, 128, 129, 130, 200, 1000, 50_000]);
      const levels = depth - (blob.path.length + 1);
      const shape = ctx.rng.pick(["arrays", "objects", "mixed", "arrays-around-scalar"] as const);
      let text: string;
      if (shape === "arrays") text = nest("[", "]", levels);
      else if (shape === "arrays-around-scalar") text = nest("[", "]", levels, "1");
      else if (shape === "objects") text = nest('{"a":', "}", levels - 1, "{}");
      else text = nest('[{"a":', "}]", Math.floor(levels / 2), levels % 2 ? "[]" : "1");
      setMember(blob.node, "deep", raw(text));
      ctx.note(`${depth} ${shape} ${showPath(blob.path)}`);
    },
  },
  {
    name: "deep-anywhere",
    why: "deep nesting where no blob is: around the whole document, or in place of a typed value — a refusal, never a stack overflow",
    weight: 3,
    apply: (w, ctx) => {
      const depth = ctx.rng.pick([127, 128, 129, 1000, 100_000]);
      if (ctx.rng.bool(0.4)) {
        const how = ctx.rng.pick(["wrap", "replace"] as const);
        if (how === "wrap") {
          w.root.pre = "[".repeat(depth) + (w.root.pre ?? "");
          w.root.post = (w.root.post ?? "") + "]".repeat(depth);
        } else {
          w.root = raw(nest("[", "]", depth));
        }
        ctx.note(`${depth} ${how} document`);
      } else {
        const site = ctx.rng.pick(sites(w.root));
        const levels = depth - site.path.length;
        replaceAt(w, site, raw(ctx.rng.bool() ? nest("[", "]", levels, "0") : nest('{"a":', "}", levels, "0")));
        ctx.note(`${depth} at ${showPath(site.path)}`);
      }
    },
  },
  {
    name: "huge-array",
    why: "an array of 4,096 … 200,000 trivial elements in a typed list or a blob: refused by count, cheaply, on both sides",
    weight: 4,
    apply: (w, ctx) => {
      if (w.root.k !== "obj") return;
      const element = ctx.rng.pick(["0", "null", '""', "{}", "[]", "true"]);
      const room = MAX_TRAVELER_JSON_BYTES - encodeWire(printWire(w.root), w.splices).length - 16;
      const fit = Math.max(1, Math.floor(room / (element.length + 1)));
      const count = ctx.rng.pick([4096, 4097, 5000, 65_536, 200_000, fit]);
      const text = raw(`[${Array.from({ length: count }, () => element).join(",")}]`);
      const lists: [string[], string][] = [
        [[], "quotes"],
        [[], "ops"],
        [[], "signatures"],
        [["buyer"], "certs"],
        [["part"], "processes"],
        [["part", "qty"], "breaks"],
      ];
      let where: string;
      const blob = ctx.rng.bool(0.4) ? someBlob(w, ctx) : undefined;
      if (blob) {
        setMember(blob.node, "list", text);
        where = showPath([...blob.path, "list"]);
      } else {
        const [path, name] = ctx.rng.pick(lists);
        let host: WNode | undefined = w.root;
        for (const step of path) host = memberOf(host, step);
        if (host?.k !== "obj") return;
        setMember(host, name, text);
        where = [...path, name].join(".");
      }
      ctx.note(`${count === fit ? "fills-to-cap" : count} x ${element} ${where}`);
    },
  },
  {
    name: "huge-object",
    why: "an object of 500 … 60,000 members — unknown ones in a typed object, legal ones in a blob: judged without a slow walk",
    weight: 2,
    apply: (w, ctx) => {
      const count = ctx.rng.pick([500, 1000, 5000, 60_000]);
      const members = Array.from({ length: count }, (_, i) => `"m${i}":0`).join(",");
      const host = ctx.rng.bool() ? someBlob(w, ctx) : ctx.rng.pick(typedObjects(w));
      if (!host) return;
      // One raw run of members appended to the object (after a comma, if it has any).
      host.node.tail = `${host.node.members.length ? "," : ""}${members}${host.node.tail ?? ""}`;
      ctx.note(`${count} in ${showPath(host.path)}`);
    },
  },

  // ---- not JSON ----
  {
    name: "trailing-comma",
    why: "a trailing comma in an object or array: JSON5 and JavaScript allow it, JSON does not",
    weight: 3,
    apply: (w, ctx) => {
      const containers = sites(w.root).filter((s) => s.node.k === "obj" || s.node.k === "arr");
      if (!containers.length) return;
      const s = ctx.rng.pick(containers) as Site<WObj>;
      s.node.tail = (s.node.tail ?? "") + ctx.rng.pick([",", " ,", ",,", ",\n"]);
      ctx.note(showPath(s.path));
    },
  },
  {
    name: "comment",
    why: "a comment between tokens (/* */, //, #, <!-- -->): JSONC allows some, JSON none",
    weight: 3,
    apply: (w, ctx) => {
      const s = ctx.rng.pick(sites(w.root));
      const text = ctx.rng.pick(["/* c */", "/**/", "// c\n", "# c\n", "<!-- c -->"]);
      if (ctx.rng.bool()) s.node.pre = text + (s.node.pre ?? "");
      else s.node.post = (s.node.post ?? "") + text;
      ctx.note(`${JSON.stringify(text)} beside ${showPath(s.path)}`);
    },
  },
  {
    name: "bare-literal",
    why: "a literal other languages have and JSON does not (NaN, Infinity, undefined, True, None, nil) in place of a value",
    weight: 3,
    apply: (w, ctx) => {
      const scalars = sites(w.root).filter((s) => s.node.k !== "obj" && s.node.k !== "arr" && s.parent);
      if (!scalars.length) return;
      const s = ctx.rng.pick(scalars);
      const text = ctx.rng.pick(["NaN", "Infinity", "-Infinity", "+Infinity", "undefined", "None", "nil", "True", "False", "TRUE", "Null", "NULL", "void 0", "yes"]);
      replaceAt(w, s, raw(text));
      ctx.note(`${text} at ${showPath(s.path)}`);
    },
  },
  {
    name: "punctuation",
    why: "a separator missing, doubled or swapped (two commas, = for :, a stray closing brace): one lexer must not be more forgiving",
    weight: 3,
    apply: (w, ctx) => {
      const objects = sitesOf(w.root, "obj").filter((s) => s.node.members.length > 1);
      if (!objects.length) return;
      const s = ctx.rng.pick(objects);
      const m = s.node.members[ctx.rng.int(1, s.node.members.length - 1)]!;
      const variants: [string, () => void][] = [
        ["double-comma", () => (m.name.pre = `,${m.name.pre ?? ""}`)],
        ["equals", () => (m.sep = "=")],
        ["arrow", () => (m.sep = "=>")],
        ["no-colon", () => (m.sep = " ")],
        ["double-colon", () => (m.sep = "::")],
        ["semicolon", () => (m.value.post = `${m.value.post ?? ""};`)],
        ["stray-close", () => (s.node.post = `${s.node.post ?? ""}}`)],
        ["stray-open", () => (s.node.pre = `{${s.node.pre ?? ""}`)],
        [
          "missing-comma",
          () => {
            const i = s.node.members.indexOf(m);
            const prev = s.node.members[i - 1]!;
            prev.value = raw(`${printWire(prev.value)} ${printWire(m.name)}:${printWire(m.value)}`);
            s.node.members.splice(i, 1);
          },
        ],
      ];
      const [label, edit] = ctx.rng.pick(variants);
      edit();
      ctx.note(`${label} in ${showPath(s.path)}`);
    },
  },

  // ---- bytes at a chosen place in the text (K7) ----
  {
    name: "utf8-invalid",
    why: "a byte sequence that is not UTF-8 (overlong, surrogate, truncated, 0xFF) in a string or between tokens: refused, not replaced by U+FFFD (K7)",
    weight: 8,
    apply: (w, ctx) => {
      // Half the time in free text — where a decoder that substitutes U+FFFD would
      // hand the schema a perfectly acceptable string.
      const [label, bytes] = ctx.rng.pick(UTF8_INVALID);
      const where = placeBytes(w, ctx, bytes, ctx.rng.bool());
      if (where) ctx.note(`${label} ${where}`);
    },
  },
  {
    name: "utf8-rare",
    why: "well-formed but unusual UTF-8 (noncharacters, U+10FFFF, U+FFFD itself, DEL): a too-strict decoder must not refuse what the other takes",
    weight: 5,
    apply: (w, ctx) => {
      const [label, bytes] = ctx.rng.pick(UTF8_RARE);
      const where = placeBytes(w, ctx, bytes, ctx.rng.bool(0.8));
      if (where) ctx.note(`${label} ${where}`);
    },
  },
];
