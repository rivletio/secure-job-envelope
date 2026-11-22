/** Mutation catalog, part 2 of 4: STRUCTURE mutations on the traveler as a JS value.
 *
 *  Where the field mutations (mutations.ts) each pin one named field to one value,
 *  these are families: each picks WHERE to bite (any position in the document, any
 *  signature site, any length-capped field) and WHICH variant, from its own random
 *  stream, and notes the choice. Over many seeds a family reaches every position.
 *
 *  They stay inside what a JS value can hold; what only the text can hold lives in
 *  mutations-wire.ts.
 */
import { MAX_TRAVELER_JSON_BYTES } from "../src/lib/traveler/types.ts";
import { genQuote } from "./generate.ts";
import { rawNumber, serializeDoc, type Ctx, type Doc, type ObjectMutation } from "./mutations.ts";
import type { Rng } from "./rng.ts";

const cp = String.fromCodePoint;
export const uPlus = (c: number): string => `u+${c.toString(16).padStart(4, "0")}`;
const isObj = (v: unknown): v is Doc => !!v && typeof v === "object" && !Array.isArray(v);
const utf8Length = (s: string): number => new TextEncoder().encode(s).length;

/* ---------------- finding places to bite ---------------- */

type Pos = { parent: any; key: string | number; path: string };

/** Every position in the document — each member and each element, at any depth. */
function positions(doc: Doc): Pos[] {
  const out: Pos[] = [];
  const walk = (v: unknown, path: string) => {
    if (Array.isArray(v)) {
      v.forEach((x, i) => {
        out.push({ parent: v, key: i, path: `${path}[${i}]` });
        walk(x, `${path}[${i}]`);
      });
    } else if (isObj(v)) {
      for (const k of Object.keys(v)) {
        const p = path ? `${path}.${k}` : k;
        out.push({ parent: v, key: k, path: p });
        walk(v[k], p);
      }
    }
  };
  walk(doc, "");
  return out;
}

/** The container and key a dotted path (`quotes.0.seller.name`) ends at, if every
 *  step before the last exists. */
function resolve(doc: Doc, path: string): { parent: any; key: string } | undefined {
  const steps = path.split(".");
  let cur: any = doc;
  for (const step of steps.slice(0, -1)) {
    cur = cur?.[step];
    if (cur === null || typeof cur !== "object") return undefined;
  }
  return { parent: cur, key: steps[steps.length - 1]! };
}

/** Pick one of the paths that exist in this document and set it; false if none do. */
function setOneOf(doc: Doc, ctx: Ctx, paths: readonly string[], value: (current: unknown) => unknown): string | false {
  const live = paths.filter((p) => resolve(doc, p));
  if (!live.length) return false;
  const path = ctx.rng.pick(live);
  const { parent, key } = resolve(doc, path)!;
  parent[key] = value(parent[key]);
  return path;
}

const firstQuote = (d: Doc): Doc | undefined => (Array.isArray(d.quotes) && isObj(d.quotes[0]) ? d.quotes[0] : undefined);

/* ---------------- tables ---------------- */

/** Every code point some runtime treats as whitespace or as invisible. ECMAScript
 *  `trim` strips most of them but NOT U+0085, U+180E, U+200B or U+001C..1F; Rust's
 *  `char::is_whitespace` strips U+0085 and keeps U+FEFF. A parser that reaches for its
 *  own language's notion of "blank" lands on the wrong side of one of these. */
export const SPACEY: readonly number[] = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x180e, 0x2000, 0x2001,
  0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x200b, 0x200c, 0x200d, 0x2028,
  0x2029, 0x202f, 0x205f, 0x2060, 0x3000, 0xfeff,
];

/** The ones the definitions actually disagree on (drawn half the time). */
const CONTESTED: readonly number[] = [0x85, 0x85, 0xfeff, 0xfeff, 0x180e, 0x200b, 0x1c, 0x1f, 0x2060];
const spacey = (rng: Rng): number => rng.pick(rng.bool() ? CONTESTED : SPACEY);

/** The four names the level ladder calls "blank" when empty. */
const REQUIRED_NAMES = ["buyer.name", "part.family", "part.part_number", "part.material.spec"] as const;

/** Every string field that has only a length cap, in code points (names, addresses
 *  and terms also refuse leading or trailing whitespace; notes and codes do not). */
const TEXT_FIELDS: readonly { path: string; max: number }[] = [
  { path: "buyer.name", max: 128 },
  { path: "buyer.city", max: 128 },
  { path: "buyer.region", max: 128 },
  { path: "buyer.contact", max: 200 },
  { path: "buyer.certs.0", max: 64 },
  { path: "part.family", max: 128 },
  { path: "part.part_number", max: 128 },
  { path: "part.description", max: 2000 },
  { path: "part.drawing_rev", max: 32 },
  { path: "part.material.spec", max: 128 },
  { path: "part.material.form", max: 128 },
  { path: "part.processes.0", max: 32 },
  { path: "part.finish", max: 2000 },
  { path: "part.tolerances", max: 2000 },
  { path: "part.notes", max: 2000 },
  { path: "incoterms", max: 64 },
  { path: "ship_to.name", max: 128 },
  { path: "ship_to.line1", max: 200 },
  { path: "ship_to.line2", max: 200 },
  { path: "ship_to.city", max: 128 },
  { path: "ship_to.region", max: 128 },
  { path: "ship_to.postal", max: 16 },
  { path: "ops.0.code", max: 32 },
  { path: "ops.0.notes", max: 2000 },
  { path: "quotes.0.seller.name", max: 128 },
  { path: "quotes.0.seller.contact", max: 200 },
  { path: "quotes.0.exceptions.0.code", max: 64 },
  { path: "quotes.0.exceptions.0.on", max: 128 },
  { path: "quotes.0.exceptions.0.proposal", max: 2000 },
  { path: "quotes.0.sig.kid", max: 64 },
  { path: "award.terms.governing_law", max: 128 },
  { path: "award.terms.warranty", max: 2000 },
  { path: "award.terms.payment_terms", max: 128 },
  { path: "award.sig.kid", max: 64 },
  { path: "signatures.0.kid", max: 64 },
];

/** One repeating unit per way of counting a string: bytes, UTF-16 units and code
 *  points all agree only for ASCII. */
const ALPHABETS: readonly { name: string; unit: string }[] = [
  { name: "ascii", unit: "x" }, //            1 byte,  1 unit,  1 code point
  { name: "latin", unit: cp(0xe9) }, //       2 bytes, 1 unit,  1 code point
  { name: "cjk", unit: cp(0x6f22) }, //       3 bytes, 1 unit,  1 code point
  { name: "astral", unit: cp(0x1f600) }, //   4 bytes, 2 units, 1 code point
  { name: "combining", unit: `e${cp(0x301)}` }, // 3 bytes, 2 units, 2 code points, 1 glyph
];

/** Exactly `n` code points of an alphabet. */
function codePoints(unit: string, n: number): string {
  const per = [...unit].length;
  return [...unit.repeat(Math.ceil(n / per))].slice(0, n).join("");
}

/** Content that is legal in a JSON string but that escapers, canonicalizers and
 *  length counters get wrong: controls, noncharacters, bidi, the edges of the planes. */
const EXOTIC: readonly [string, string][] = [
  ["nul", cp(0)],
  ["soh", cp(1)],
  ["unit-sep", cp(0x1f)],
  ["del", cp(0x7f)],
  ["c1", cp(0x80, 0x9f)],
  ["nel", cp(0x85)],
  ["soft-hyphen", cp(0xad)],
  ["bidi-override", cp(0x202e)],
  ["bidi-isolate", cp(0x2066, 0x2069)],
  ["line-sep", cp(0x2028, 0x2029)],
  ["zwj", cp(0x200d)],
  ["bom-inside", cp(0xfeff)],
  ["replacement", cp(0xfffd)],
  ["nonchar-bmp", cp(0xfffe, 0xffff)],
  ["before-surrogates", cp(0xd7ff, 0xe000)],
  ["private-use", cp(0xf8ff)],
  ["astral-first", cp(0x10000)],
  ["astral-last", cp(0x10ffff)],
  ["lang-tag", cp(0xe0001)],
  ["quote-backslash", `"\\`],
  ["solidus", "</script>"],
  ["escape-lookalike", "\\u0041\\n"],
  ["newlines", "a\r\nb\nc"],
  ["tab", "a\tb"],
  ["backspace-formfeed", "\b\f"],
  ["combining-only", cp(0x301)],
];

const HEX96 = "0123456789abcdef".repeat(6);

/* ---------------- the families ---------------- */

/** A signature object as the schema wants it, to break one aspect of. */
const goodSig = (): Doc => ({ alg: "ML-DSA-87", kid: "k1", sig: "ab12" });

const SIG_VARIANTS: readonly [string, (s: Doc) => unknown][] = [
  ["valid", (s) => s],
  ["alg-other", (s) => ((s.alg = "ML-DSA-65"), s)],
  ["alg-lowercase", (s) => ((s.alg = "ml-dsa-87"), s)],
  ["alg-padded", (s) => ((s.alg = "ML-DSA-87 "), s)],
  ["alg-empty", (s) => ((s.alg = ""), s)],
  ["alg-missing", (s) => (delete s.alg, s)],
  ["sig-not-hex", (s) => ((s.sig = "xyz"), s)],
  ["sig-uppercase", (s) => ((s.sig = "AB12"), s)],
  ["sig-empty", (s) => ((s.sig = ""), s)],
  ["sig-odd-length", (s) => ((s.sig = "abc"), s)],
  ["sig-0x", (s) => ((s.sig = "0xab12"), s)],
  ["sig-inner-space", (s) => ((s.sig = "ab 12"), s)],
  ["sig-trailing-newline", (s) => ((s.sig = "ab12\n"), s)],
  ["sig-fullwidth", (s) => ((s.sig = cp(0xff41, 0xff42)), s)],
  ["sig-at-max", (s) => ((s.sig = "ab".repeat(10_000)), s)],
  ["sig-over-max", (s) => ((s.sig = `${"ab".repeat(10_000)}c`), s)],
  ["sig-number", (s) => ((s.sig = 1234), s)],
  ["sig-array", (s) => ((s.sig = ["ab12"]), s)],
  ["kid-empty", (s) => ((s.kid = ""), s)],
  ["kid-at-max", (s) => ((s.kid = "k".repeat(64)), s)],
  ["kid-over-max", (s) => ((s.kid = "k".repeat(65)), s)],
  ["kid-astral-at-max", (s) => ((s.kid = cp(0x1f600).repeat(64)), s)],
  ["kid-astral-over-max", (s) => ((s.kid = cp(0x1f600).repeat(65)), s)],
  ["kid-untrimmed", (s) => ((s.kid = " k1 "), s)],
  ["kid-number", (s) => ((s.kid = 7), s)],
  ["extra-member", (s) => ((s.note = "x"), s)],
  ["as-null", () => null],
  ["as-string", (s) => s.sig],
  ["as-array", (s) => [s.alg, s.kid, s.sig]],
];

/** Fill long text fields so the whole document serializes to exactly `target` bytes.
 *  Only un-hashed fields are used (op notes, quote exception proposals), so a quote
 *  bound to the body stays bound. */
function fillToBytes(d: Doc, rng: Rng, unit: string, target: number): void {
  const unitBytes = utf8Length(unit);
  const unitCps = [...unit].length;
  const perSlot = Math.floor(1999 / unitCps) * unitBytes;
  d.ops = Array.from({ length: 64 }, (_, i) => ({ seq: i + 1, code: "op", notes: "x" }));
  const quotes: Doc[] = (Array.isArray(d.quotes) ? d.quotes : []).filter(isObj);
  const hostQuotes = Math.min(64, Math.max(0, Math.ceil((target / perSlot + 2 - 64) / 16)));
  const quoted = typeof quotes[0]?.traveler_hash_quoted === "string" ? quotes[0].traveler_hash_quoted : `sha384:${HEX96}`;
  while (quotes.length < hostQuotes) {
    quotes.push(genQuote(rng, quoted, d.itar === true ? { sellerItar: true } : {}) as Doc);
  }
  if (quotes.length) d.quotes = quotes;
  const slots: [Doc, string][] = d.ops.map((op: Doc) => [op, "notes"]);
  for (const q of quotes.slice(0, hostQuotes)) {
    q.exceptions = Array.from({ length: 16 }, (_, i) => ({ code: `F${i}`, proposal: "x" }));
    for (const ex of q.exceptions) slots.push([ex, "proposal"]);
  }
  let need = target - utf8Length(serializeDoc(d));
  const spare: [Doc, string, number][] = [];
  for (const [obj, key] of slots) {
    const units = Math.max(0, Math.min(Math.floor(1999 / unitCps), Math.floor(need / unitBytes)));
    obj[key] = `x${unit.repeat(units)}`;
    need -= units * unitBytes;
    spare.push([obj, key, 1999 - units * unitCps]);
  }
  // Whatever is left is smaller than one unit (or the slots ran out): top up in ASCII.
  for (const [obj, key, room] of spare) {
    if (need <= 0) break;
    const add = Math.min(room, need);
    obj[key] += "x".repeat(add);
    need -= add;
  }
}

export const OBJECT_MUTATIONS: ObjectMutation[] = [
  {
    name: "ws-whole-name",
    why: "a name that is ONLY a whitespace-like code point: 'blank' differs between JS trim and Rust trim (K4)",
    weight: 6,
    apply: (d, ctx) => {
      const c = spacey(ctx.rng);
      const paths = ctx.rng.bool(0.7) ? REQUIRED_NAMES : TEXT_FIELDS.map((f) => f.path);
      const path = setOneOf(d, ctx, paths, () => cp(c).repeat(ctx.rng.int(1, 3)));
      if (path) ctx.note(`${uPlus(c)} ${path}`);
    },
  },
  {
    name: "ws-pad-name",
    why: "a whitespace-like code point leading, trailing or inside a name: which ones count as 'untrimmed'",
    weight: 6,
    apply: (d, ctx) => {
      const c = spacey(ctx.rng);
      const where = ctx.rng.pick(["lead", "trail", "both", "inside"] as const);
      const path = setOneOf(
        d,
        ctx,
        TEXT_FIELDS.map((f) => f.path),
        (cur) => {
          const base = typeof cur === "string" && cur.length ? cur : "Acme";
          if (where === "inside") return `${base}${cp(c)}${base}`;
          return `${where === "trail" ? "" : cp(c)}${base}${where === "lead" ? "" : cp(c)}`;
        },
      );
      if (path) ctx.note(`${uPlus(c)} ${where} ${path}`);
    },
  },
  {
    name: "sig-shape",
    why: "one aspect of a signature object broken, at each of the three signature sites — one site was once unvalidated (K3)",
    weight: 6,
    apply: (d, ctx) => {
      const sites: [string, (v: unknown) => void][] = [["signatures[0]", (v) => (d.signatures = [v])]];
      if (isObj(d.award)) sites.push(["award.sig", (v) => (d.award.sig = v)]);
      const q = firstQuote(d);
      if (q) sites.push(["quotes[0].sig", (v) => (q.sig = v)]);
      // Prefer the award and quote sites when they exist: the list was always checked.
      const [site, put] = ctx.rng.weighted(sites, ([s]) => (s === "signatures[0]" ? 1 : 3));
      const [variant, edit] = ctx.rng.pick(SIG_VARIANTS);
      put(edit(goodSig()));
      ctx.note(`${variant} ${site}`);
    },
  },
  {
    name: "dup-quote-id",
    why: "two quotes sharing a quote_id: an award names its quote by id, so the first match must not be ambiguous (K5)",
    weight: 4,
    apply: (d, ctx) => {
      const q = firstQuote(d);
      if (!q) return;
      const variant = ctx.rng.pick(["twin", "twin-repriced", "twin-stale", "rename"] as const);
      if (variant === "rename" && isObj(d.quotes[1])) {
        d.quotes[1].quote_id = q.quote_id;
      } else {
        const twin = structuredClone(q);
        if (variant === "twin-repriced" && isObj(twin.pricing?.lines?.[0])) twin.pricing.lines[0].unit = 1;
        if (variant === "twin-stale") twin.traveler_hash_quoted = `sha384:${HEX96}`;
        if (ctx.rng.bool()) d.quotes.push(twin);
        else d.quotes.unshift(twin);
      }
      ctx.note(variant);
    },
  },
  {
    name: "dup-line-qty",
    why: "two price lines for one quantity: the unit price under an award must not depend on which is read (K5)",
    weight: 3,
    apply: (d, ctx) => {
      const lines = firstQuote(d)?.pricing?.lines;
      if (!Array.isArray(lines) || !isObj(lines[0]) || typeof lines[0].qty !== "number") return;
      const variant = ctx.rng.pick(["same", "repriced", "spelled-n.0"] as const);
      lines.push({
        qty: variant === "spelled-n.0" ? rawNumber(`${lines[0].qty}.0`) : lines[0].qty,
        unit: variant === "same" ? lines[0].unit : 1,
      });
      ctx.note(variant);
    },
  },
  {
    name: "dup-op-seq",
    why: "two ops with one seq: the routing order must not be ambiguous (K5)",
    weight: 3,
    apply: (d, ctx) => {
      if (!Array.isArray(d.ops) || !isObj(d.ops[0])) d.ops = [{ seq: 1, code: "saw" }];
      const variant = ctx.rng.pick(["same", "spelled-n.0"] as const);
      const seq = typeof d.ops[0].seq === "number" ? d.ops[0].seq : 1;
      d.ops.push({ seq: variant === "same" ? seq : rawNumber(`${seq}.0`), code: "again" });
      ctx.note(variant);
    },
  },
  {
    name: "dup-allowed",
    why: "repeats the schema permits (a cert, a process, a break, a signature kid): the uniqueness rules must not over-reach",
    weight: 2,
    apply: (d, ctx) => {
      const variant = ctx.rng.pick(["certs", "processes", "breaks", "signatures"] as const);
      if (variant === "certs" && isObj(d.buyer)) d.buyer.certs = ["ISO 9001", "ISO 9001"];
      if (variant === "processes" && isObj(d.part)) d.part.processes = ["laser", "laser"];
      if (variant === "breaks" && isObj(d.part?.qty)) d.part.qty.breaks = [10, 10];
      if (variant === "signatures") d.signatures = [goodSig(), goodSig()];
      ctx.note(variant);
    },
  },
  {
    name: "inflate-to-cap",
    why: "long text fields filled until the document sits at the 512 KiB cap: bytes vs UTF-16 units vs code points (K8)",
    weight: 3,
    liveOnly: true,
    apply: (d, ctx) => {
      const alphabet = ctx.rng.pick(ALPHABETS);
      const cap = MAX_TRAVELER_JSON_BYTES;
      const [label, target] = ctx.rng.pick<[string, number]>([
        ["cap-1", cap - 1],
        ["cap", cap],
        ["cap+1", cap + 1],
        ["under", cap - ctx.rng.int(2, 4096)],
        ["over", cap + ctx.rng.int(2, 150_000)],
        ["over", cap + ctx.rng.int(2, 150_000)],
      ]);
      fillToBytes(d, ctx.rng, alphabet.unit, target);
      ctx.note(`${alphabet.name} ${label}`);
    },
  },
  {
    name: "field-cap",
    why: "a capped string field at max-1 / max / max+1 code points, in alphabets where bytes, UTF-16 units and code points disagree",
    weight: 6,
    apply: (d, ctx) => {
      const live = TEXT_FIELDS.filter((f) => resolve(d, f.path));
      if (!live.length) return;
      const field = ctx.rng.pick(live);
      const alphabet = ctx.rng.pick(ALPHABETS);
      const delta = ctx.rng.pick([-1, 0, 0, 1, 1]);
      const { parent, key } = resolve(d, field.path)!;
      parent[key] = codePoints(alphabet.unit, field.max + delta);
      ctx.note(`${alphabet.name} max${delta < 0 ? delta : `+${delta}`} ${field.path}`);
    },
  },
  {
    name: "exotic-text",
    why: "controls, noncharacters, bidi and plane-edge code points in a string: escaping and canonical bytes must match",
    weight: 6,
    apply: (d, ctx) => {
      const [label, text] = ctx.rng.pick(EXOTIC);
      const where = ctx.rng.pick(["inside", "start", "end", "whole"] as const);
      const path = setOneOf(
        d,
        ctx,
        TEXT_FIELDS.map((f) => f.path),
        (cur) => {
          const base = typeof cur === "string" && cur.length ? cur : "Acme";
          if (where === "whole") return text;
          if (where === "start") return text + base;
          if (where === "end") return base + text;
          return `${base}${text}${base}`;
        },
      );
      if (path) ctx.note(`${label} ${where} ${path}`);
    },
  },
  {
    name: "null-anywhere",
    why: "an explicit null at a random position: only five fields are nullable, and serde's Option says yes by default",
    weight: 6,
    apply: (d, ctx) => {
      const pos = ctx.rng.pick(positions(d));
      pos.parent[pos.key] = null;
      ctx.note(pos.path);
    },
  },
  {
    name: "type-swap",
    why: "a number as a string, a string as a number, a scalar as a container (and back) at a random position",
    weight: 6,
    apply: (d, ctx) => {
      const pos = ctx.rng.pick(positions(d));
      const v = pos.parent[pos.key];
      const r = ctx.rng;
      let next: unknown;
      if (typeof v === "number") next = r.pick([String(v), `${v}.0`, [v], { value: v }, true, v + 0.5]);
      else if (typeof v === "string") next = r.pick([/^\d+$/.test(v) ? Number(v) : v.length, [v], { value: v }, true, 0]);
      else if (typeof v === "boolean") next = r.pick([String(v), v ? 1 : 0, v ? "yes" : "", [v]]);
      else if (Array.isArray(v)) next = r.pick([v[0] ?? "", { 0: v[0] ?? null }, JSON.stringify(v), v.length]);
      else if (isObj(v)) next = r.pick([JSON.stringify(v), Object.entries(v), Object.values(v), [v], "{}"]);
      else next = r.pick(["null", 0, false, {}, [], ""]);
      pos.parent[pos.key] = next;
      ctx.note(`${Array.isArray(v) ? "array" : v === null ? "null" : typeof v} ${pos.path}`);
    },
  },
  {
    name: "delete-member",
    why: "a random member removed: required-ness must match field for field",
    weight: 5,
    apply: (d, ctx) => {
      const members = positions(d).filter((p) => typeof p.key === "string");
      const pos = ctx.rng.pick(members);
      delete pos.parent[pos.key];
      ctx.note(pos.path);
    },
  },
  {
    name: "unknown-member",
    why: "an unexpected member in a random object: every typed object is closed, every blob is open",
    weight: 5,
    apply: (d, ctx) => {
      const objects: [Doc, string][] = [[d, "$"]];
      for (const p of positions(d)) if (isObj(p.parent[p.key])) objects.push([p.parent[p.key], p.path]);
      const [obj, path] = ctx.rng.pick(objects);
      const own = Object.keys(obj);
      const key = ctx.rng.pick([
        "extra",
        "",
        "0",
        "$schema",
        "length",
        cp(0x1f600),
        ...(own.length ? [`${own[0]} `, own[0]!.toUpperCase(), `${own[0]}s`] : []),
      ]);
      if (key in obj) return;
      obj[key] = ctx.rng.pick([1, "x", null, {}, [], true]);
      ctx.note(`${JSON.stringify(key)} in ${path}`);
    },
  },
  {
    name: "empty-value",
    why: "the empty string / array / object / zero at a random position: min-length and drop-when-empty rules",
    weight: 5,
    apply: (d, ctx) => {
      const pos = ctx.rng.pick(positions(d));
      const v = pos.parent[pos.key];
      pos.parent[pos.key] = typeof v === "string" ? "" : typeof v === "number" ? 0 : Array.isArray(v) ? [] : isObj(v) ? {} : "";
      ctx.note(pos.path);
    },
  },
  {
    name: "array-length",
    why: "a random list grown past any cap by repeating its first element (4 / 17 / 65 / 4097 entries)",
    weight: 3,
    apply: (d, ctx) => {
      const lists = positions(d).filter((p) => Array.isArray(p.parent[p.key]) && p.parent[p.key].length > 0);
      if (!lists.length) return;
      const pos = ctx.rng.pick(lists);
      const n = ctx.rng.pick([4, 9, 17, 33, 65, 4097]);
      const first = pos.parent[pos.key][0];
      pos.parent[pos.key] = Array.from({ length: n }, () => structuredClone(first));
      ctx.note(`${n} ${pos.path}`);
    },
  },
  {
    name: "datetime-shape",
    why: "timestamps a lenient date parser would coerce: the two sides share one strict grammar and one calendar",
    weight: 5,
    apply: (d, ctx) => {
      const digits = (base: number) => cp(base + 2, base, base + 2, base + 6); // "2026" in another script
      const [label, value] = ctx.rng.pick<[string, string]>([
        ["year-0000", "0000-01-01T00:00:00.000Z"],
        ["year-9999", "9999-12-31T23:59:59.999Z"],
        ["leap-day", "2028-02-29T12:00:00.000Z"],
        ["not-leap-day", "2100-02-29T12:00:00.000Z"],
        ["leap-400", "2000-02-29T12:00:00.000Z"],
        ["frac-1", "2026-05-01T12:00:00.5Z"],
        ["frac-9", "2026-05-01T12:00:00.123456789Z"],
        ["frac-10", "2026-05-01T12:00:00.1234567890Z"],
        ["frac-empty", "2026-05-01T12:00:00.Z"],
        ["lowercase-z", "2026-05-01T12:00:00.000z"],
        ["lowercase-t", "2026-05-01t12:00:00.000Z"],
        ["space-separator", "2026-05-01 12:00:00.000Z"],
        ["no-zone", "2026-05-01T12:00:00.000"],
        ["minus-zero-offset", "2026-05-01T12:00:00.000-00:00"],
        ["month-13", "2026-13-01T12:00:00.000Z"],
        ["day-00", "2026-05-00T12:00:00.000Z"],
        ["minute-60", "2026-05-01T12:60:00.000Z"],
        ["signed-year", "+2026-05-01T12:00:00.000Z"],
        ["five-digit-year", "12026-05-01T12:00:00.000Z"],
        ["trailing-newline", "2026-05-01T12:00:00.000Z\n"],
        ["leading-space", " 2026-05-01T12:00:00.000Z"],
        ["arabic-digits", `${digits(0x660)}-05-01T12:00:00.000Z`],
        ["fullwidth-digits", `${digits(0xff10)}-05-01T12:00:00.000Z`],
        ["day-only", "2026-05-01"],
        ["week-date", "2026-W18-5"],
        ["basic-format", "20260501T120000Z"],
        ["empty", ""],
      ]);
      const path = setOneOf(
        d,
        ctx,
        ["created_at", "need_by", "quotes.0.created_at", "quotes.0.valid_until", "award.awarded_at"],
        () => value,
      );
      if (path) ctx.note(`${label} ${path}`);
    },
  },
  {
    name: "validity-window",
    why: "a quote's valid_until against its created_at at and around equality: instants are compared in whole milliseconds",
    weight: 3,
    apply: (d, ctx) => {
      const q = firstQuote(d);
      if (!q) return;
      const [label, created, until] = ctx.rng.pick<[string, string, string]>([
        ["equal", "2026-05-01T12:00:00.000Z", "2026-05-01T12:00:00.000Z"],
        ["one-ms-later", "2026-05-01T12:00:00.000Z", "2026-05-01T12:00:00.001Z"],
        ["one-ms-earlier", "2026-05-01T12:00:00.001Z", "2026-05-01T12:00:00.000Z"],
        ["sub-ms-later", "2026-05-01T12:00:00.0001Z", "2026-05-01T12:00:00.0009Z"],
        ["same-instant-respelled", "2026-05-01T12:00:00Z", "2026-05-01T12:00:00.000000000Z"],
        ["across-year-0", "0000-12-31T23:59:59.999Z", "0001-01-01T00:00:00.000Z"],
        ["across-leap-day", "2028-02-28T23:59:59.999Z", "2028-02-29T00:00:00.000Z"],
        ["century-apart", "1999-12-31T23:59:59.999Z", "9999-12-31T23:59:59.999Z"],
      ]);
      q.created_at = created;
      q.valid_until = until;
      ctx.note(label);
    },
  },
  {
    name: "id-shape",
    why: "ids, hashes and codes at the edges of their patterns: anchors, case, length, look-alike letters",
    weight: 5,
    apply: (d, ctx) => {
      const ids: [string, string][] = [
        ["min", "tvl_abc123"],
        ["max", `tvl_${"a".repeat(24)}`],
        ["one-short", "tvl_abc12"],
        ["one-long", `tvl_${"a".repeat(25)}`],
        ["two-underscores", "tvl_abc_123"],
        ["uppercase-suffix", "tvl_ABC123"],
        ["digit-prefix", "t1l_abc123"],
        ["trailing-newline", "tvl_abc123\n"],
        ["cyrillic-a", `tvl_${cp(0x430)}bc123`],
        ["fullwidth", `tvl_${cp(0xff41)}bc123`],
        ["nul-inside", `tvl_abc${cp(0)}123`],
        ["empty", ""],
      ];
      const hashes: [string, string][] = [
        ["valid", `sha384:${HEX96}`],
        ["uppercase-hex", `sha384:${HEX96.toUpperCase()}`],
        ["95-hex", `sha384:${HEX96.slice(1)}`],
        ["97-hex", `sha384:${HEX96}0`],
        ["no-prefix", HEX96],
        ["sha256-prefix", `sha256:${HEX96}`],
        ["uppercase-prefix", `SHA384:${HEX96}`],
        ["non-hex", `sha384:${"g".repeat(96)}`],
        ["multibyte-tail", `sha384:${HEX96.slice(3)}${cp(0x20ac)}`],
        ["trailing-newline", `sha384:${HEX96}\n`],
      ];
      const codes: [string, string][] = [
        ["lowercase", "us"],
        ["three-letters", "USA"],
        ["one-letter", "U"],
        ["digit", "U5"],
        ["fullwidth", cp(0xff35, 0xff33)],
        ["trailing-space", "US "],
        ["multibyte", cp(0xc9) + cp(0xc9)],
        ["empty", ""],
      ];
      const orgIds: [string, string][] = [
        ["min", "ab"],
        ["one-char", "a"],
        ["max", `a${"b".repeat(63)}`],
        ["over-max", `a${"b".repeat(64)}`],
        ["uppercase", "Org_huron"],
        ["hyphen", "org-huron"],
        ["leading-underscore", "_org"],
        ["multibyte", `org_${cp(0xe9)}`],
      ];
      const [kind, paths, table] = ctx.rng.pick<[string, string[], [string, string][]]>([
        ["id", ["traveler_id", "quotes.0.quote_id", "award.quote_id"], ids],
        ["hash", ["quotes.0.traveler_hash_quoted", "award.quote_hash"], hashes],
        ["code", ["ship_to.country", "quotes.0.pricing.currency"], codes],
        ["org", ["buyer.org_id", "quotes.0.seller.org_id"], orgIds],
      ]);
      const [label, value] = ctx.rng.pick(table);
      const path = setOneOf(d, ctx, paths, () => value);
      if (path) ctx.note(`${kind}:${label} ${path}`);
    },
  },
  {
    name: "bind-shape",
    why: "the ingredients of a level changed on an otherwise valid traveler: stale / foreign / ITAR-mismatched quotes, a re-pointed award",
    weight: 6,
    apply: (d, ctx) => {
      const q = firstQuote(d);
      const variants: [string, () => void][] = [
        ["ops-empty", () => (d.ops = [])],
        ["ship-to-null", () => (d.ship_to = null)],
        ["award-null", () => (d.award = null)],
        ["as-built-empty", () => (d.as_built = {})],
        ["as-built-null", () => (d.as_built = null)],
        ["as-built-added", () => (d.as_built = { lot: "L-1" })],
        ["itar-on", () => (d.itar = true)],
        ["itar-off", () => (d.itar = false)],
        ["itar-absent", () => delete d.itar],
      ];
      if (q) {
        variants.push(
          ["quote-stale", () => (q.traveler_hash_quoted = `sha384:${HEX96}`)],
          ["seller-itar-off", () => isObj(q.seller) && (q.seller.itar = false)],
          ["seller-itar-absent", () => isObj(q.seller) && delete q.seller.itar],
          ["seller-itar-on", () => isObj(q.seller) && (q.seller.itar = true)],
          ["quotes-reversed", () => d.quotes.reverse()],
          ["quotes-empty", () => (d.quotes = [])],
        );
        if (isObj(d.award)) {
          variants.push(
            ["award-unknown-quote", () => (d.award.quote_id = "qot_nosuchquote")],
            ["award-other-quote", () => isObj(d.quotes[1]) && (d.award.quote_id = d.quotes[1].quote_id)],
          );
        } else {
          variants.push([
            "award-added",
            () => (d.award = { quote_id: q.quote_id, awarded_at: "2027-06-01T00:00:00.000Z", qty: 1 }),
          ]);
        }
      }
      const [label, edit] = ctx.rng.pick(variants);
      edit();
      ctx.note(label);
    },
  },
  {
    name: "blob-shape",
    why: "a free-form blob that is not an object, or is an edge-case one: the level asks 'non-empty object?' on both sides",
    weight: 4,
    apply: (d, ctx) => {
      const [label, value] = ctx.rng.pick<[string, unknown]>([
        ["array", [1, 2]],
        ["empty-array", []],
        ["string", "lot 7"],
        ["number", 7],
        ["true", true],
        ["empty-object", {}],
        ["only-null-member", { a: null }],
        ["empty-name", { "": 0 }],
        ["index-names", { 2: "b", 10: "a", 1: "c" }],
        ["name-collides-with-typed", { spec: "sje/0.1.0", revision: 0 }],
        ["nested-empties", { a: [{}, [], [[]], ""] }],
        ["prototype-names", { constructor: { prototype: 1 }, toString: "x", hasOwnProperty: null, valueOf: [] }],
      ]);
      const q = firstQuote(d);
      const site = q ? ctx.rng.pick(["as_built", "as_built", "assumptions", "capacity"]) : "as_built";
      if (site === "as_built") d.as_built = value;
      else q![site] = value;
      ctx.note(`${label} ${site}`);
    },
  },
  {
    name: "zero-spelling",
    why: "zero written -0, 0.0, 0e0 or -0.0e-5, where zero is legal and where it is not: a sign bit must not move a verdict",
    weight: 4,
    apply: (d, ctx) => {
      const literal = ctx.rng.pick(["-0", "0.0", "-0.0", "0e0", "-0e0", "0E+5", "0.000", "-0.0e-5", "0"]);
      const path = setOneOf(
        d,
        ctx,
        [
          "quotes.0.lead_time_days",
          "quotes.0.pricing.nre",
          "quotes.0.pricing.freight_estimate",
          "quotes.0.pricing.lines.0.unit",
          "quotes.0.exceptions.0.price_delta",
          "revision",
          "part.qty.target",
        ],
        () => rawNumber(literal),
      );
      if (path) ctx.note(`${literal} ${path}`);
    },
  },
  {
    name: "int-bounds",
    why: "an integer field at min-1 / min / max / max+1, written as an integer, as N.0 and in exponent form: range checks must see the same number",
    weight: 5,
    apply: (d, ctx) => {
      const fields: [string, number, number][] = [
        ["revision", 1, 10_000],
        ["part.qty.target", 1, 1_000_000],
        ["part.qty.breaks.0", 1, 1_000_000],
        ["ops.0.seq", 1, 1000],
        ["award.qty", 1, 1_000_000],
        ["quotes.0.lead_time_days", 0, 3650],
        ["quotes.0.pricing.nre", 0, 1e12],
        ["quotes.0.pricing.freight_estimate", 0, 1e12],
        ["quotes.0.pricing.lines.0.qty", 1, 1_000_000],
        ["quotes.0.pricing.lines.0.unit", 0, 1e12],
        ["quotes.0.exceptions.0.price_delta", -1e12, 1e12],
      ];
      const live = fields.filter(([path]) => resolve(d, path));
      if (!live.length) return;
      const [path, min, max] = ctx.rng.pick(live);
      const [edge, value] = ctx.rng.pick<[string, number]>([
        ["min-1", min - 1],
        ["min", min],
        ["max", max],
        ["max+1", max + 1],
      ]);
      const form = ctx.rng.pick(["integer", "n.0", "exponent"] as const);
      const literal = form === "integer" ? String(value) : form === "n.0" ? `${value}.0` : value.toExponential().replace("+", "");
      const { parent, key } = resolve(d, path)!;
      parent[key] = rawNumber(literal);
      ctx.note(`${edge} ${literal} ${path}`);
    },
  },
  {
    name: "thickness-shape",
    why: "the one hashed float at the edges of its range and of double precision: the hash renders whatever the parser rounded to",
    weight: 5,
    apply: (d, ctx) => {
      if (!isObj(d.part?.material)) return;
      const literal = ctx.rng.pick([
        "0.0001",
        "1e-4",
        "0.00010000000000000000000000000000000001",
        "0.000099999999999999999999999999999999999",
        "0.00009999999999999999",
        "1000000",
        "1e6",
        "1E+6",
        "1000000.0000000000000000000000000000001",
        "999999.99999999999999999999",
        "1000000.0000000001",
        "0.1",
        "0.30000000000000004",
        "0.1234567890123456789012345678901234567890",
        "123456.789012345678901234567890",
        "5e-1",
        "12.5e0",
        "1.7976931348623157e308",
        "4.9e-324",
        "-0.0",
        "0",
        "25",
        "25.0",
        "2.5e1",
        "8.5",
        "100.00000000000001",
        "100.000000000000007105427357601001858711242675781250",
      ]);
      d.part.material.thickness_mm = rawNumber(literal);
      ctx.note(literal);
    },
  },
];
