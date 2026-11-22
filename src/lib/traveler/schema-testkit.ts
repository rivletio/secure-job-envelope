/** Test support for the published JSON Schemas (public/schemas/). NOT part of the library:
 *  it reads files and compiles with ajv, a dev dependency. Imported only by *.test.ts.
 *
 *  Two tests need the same reading of a schema — `schema-contract.test.ts` (does the
 *  published schema agree with the implementation?) and `disclosure.test.ts` (is every
 *  field classified?) — and they must not each keep their own, or one can go blind to a
 *  field the other sees. That is how `award.quote_hash` and `award.sig` went unclassified:
 *  the published schema did not list them, and the only enumeration there was read it.
 *
 *  The reader here is strict about what it does not understand. A keyword it has not been
 *  taught is an error, never something to skip: a field introduced through a construct
 *  this code ignored would be a field no test looks at.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import { z } from "zod";
import { parseTravelerJson } from "./conformance.ts";
import { quoteSchema, travelerSchema } from "./schema.ts";
import { MAX_TRAVELER_JSON_BYTES } from "./types.ts";
import { parseStrictJson } from "./wire.ts";

export type SchemaNode = { readonly [keyword: string]: unknown };
/** A schema document plus the file name other documents refer to it by. */
export type SchemaDoc = { readonly file: string; readonly root: SchemaNode };

const SCHEMA_DIR = new URL("../../../public/schemas/", import.meta.url);
const readJson = (file: string): unknown =>
  JSON.parse(readFileSync(new URL(file, SCHEMA_DIR), "utf8"));

export const TRAVELER_SCHEMA_FILE = "traveler-0.1.0.json";
export const QUOTE_SCHEMA_FILE = "quote-0.1.0.json";
export const NOT_EXPRESSIBLE_FILE = "not-expressible-0.1.0.json";

/** The schemas as published. */
export const published = {
  traveler: { file: TRAVELER_SCHEMA_FILE, root: readJson(TRAVELER_SCHEMA_FILE) as SchemaNode },
  quote: { file: QUOTE_SCHEMA_FILE, root: readJson(QUOTE_SCHEMA_FILE) as SchemaNode },
} as const;

/** What the implementation's own schema (schema.ts, zod) accepts as input, rendered as
 *  JSON Schema by zod itself. Refinements (`.refine`, `.superRefine`) have no JSON Schema
 *  form and are absent from this rendering; everything else zod enforces is in it. */
export const implemented = {
  traveler: {
    file: "zod:traveler",
    root: z.toJSONSchema(travelerSchema, { io: "input" }) as SchemaNode,
  },
  quote: { file: "zod:quote", root: z.toJSONSchema(quoteSchema, { io: "input" }) as SchemaNode },
} as const;

/** One rule of `not-expressible-0.1.0.json`. */
export type NotExpressibleRule = {
  rule: string;
  kind: "wire-text" | "cross-member" | "serialized-size";
  spec: string;
  requires: string;
  why: string;
  refusal: { ts: string[] };
  lenient_reading?: "json-parse" | "strip-bom" | "replace-invalid-utf8";
  reject_vectors: string[];
};
export const notExpressible = readJson(NOT_EXPRESSIBLE_FILE) as {
  spec: string;
  schemas: string[];
  note: string;
  rules: NotExpressibleRule[];
};

/** ajv validators for the published schemas. `strictSchema` turns a misspelt or unknown
 *  keyword into an error instead of a constraint that silently is not applied.
 *  `removeAdditional` selects one of ajv's clean-up modes, in which validating a value
 *  also deletes members from it. */
export function compilePublished(removeAdditional: boolean | "all" | "failing" = false): {
  traveler: ValidateFunction;
  quote: ValidateFunction;
} {
  const ajv = new Ajv2020({
    allErrors: true,
    strictSchema: true,
    strictTypes: false,
    strictTuples: false,
    removeAdditional,
  });
  ajv.addSchema(published.quote.root, QUOTE_SCHEMA_FILE);
  const traveler = ajv.compile(published.traveler.root);
  const quote = ajv.getSchema(QUOTE_SCHEMA_FILE);
  if (!quote) throw new Error("quote schema did not compile");
  return { traveler, quote };
}

const isNode = (v: unknown): v is SchemaNode =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Resolve a `$ref`: `#/$defs/x`, `file.json`, or `file.json#/$defs/x`. Only the published
 *  pair of files can be named. */
function resolveRef(ref: string, from: SchemaDoc): { node: SchemaNode; doc: SchemaDoc } {
  const hash = ref.indexOf("#");
  const file = hash < 0 ? ref : ref.slice(0, hash);
  const pointer = hash < 0 ? "" : ref.slice(hash + 1);
  const doc = file === "" ? from : Object.values(published).find((d) => d.file === file);
  if (!doc) throw new Error(`$ref "${ref}" names a schema file that is not published here`);
  let node: unknown = doc.root;
  if (pointer !== "") {
    if (!pointer.startsWith("/")) throw new Error(`unsupported $ref "${ref}"`);
    for (const raw of pointer.slice(1).split("/")) {
      const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
      node = isNode(node) ? node[key] : undefined;
    }
  }
  if (!isNode(node)) throw new Error(`$ref "${ref}" does not resolve to a schema`);
  return { node, doc };
}

/* ------------------------------------------------------------------------------------ */
/* Shape: what a schema says, in one comparable form                                     */
/* ------------------------------------------------------------------------------------ */

/** A schema reduced to what it constrains, so two schemas written differently (inline or
 *  through `$ref`; `["string","null"]` or `anyOf` with null) compare equal exactly when
 *  they state the same constraints — of the kinds listed here, which are the kinds zod can
 *  render. `patterns` is a set: a string must match every one. */
export type Shape = { nullable: boolean } & (
  | { kind: "object"; required: string[]; members: Record<string, Shape> }
  | { kind: "free-form" }
  | { kind: "array"; minItems: number; maxItems: number | null; items: Shape }
  | {
      kind: "string";
      minLength: number;
      maxLength: number | null;
      patterns: string[];
      const?: string;
    }
  | { kind: "number" | "integer"; minimum: number | null; maximum: number | null }
  | { kind: "boolean" }
);

/** A constraint `shapeOf` met that has no place in a `Shape`. It is reported, never
 *  dropped: the caller decides whether each one is expected. */
export type Aside = { path: string; what: string };

const ANNOTATIONS = new Set(["$schema", "$id", "$defs", "$comment", "title", "description"]);
/** How zod renders "any string" as a member name — no constraint at all. */
const ANY_NAME = JSON.stringify({ type: "string" });

type Given = { value: unknown; doc: SchemaDoc };

/** Reduce a schema document to a `Shape`. Understood: `type`, `const`, the numeric, length
 *  and item bounds, `pattern`, `properties` / `required` / `additionalProperties: false`,
 *  `items`, `$ref` and `allOf` (both mean "also this"), and `anyOf` in the single form
 *  "this, or null". Reported through `asides`, and not looked into: an `if`/`then` pair,
 *  and a rule on a free-form object's member names. Everything else is an error. */
export function shapeOf(doc: SchemaDoc, asides: Aside[] = []): Shape {
  /** The keywords that apply at one place, with `$ref` and `allOf` folded in. */
  const fold = (
    node: SchemaNode,
    from: SchemaDoc,
    into = new Map<string, Given[]>(),
  ): Map<string, Given[]> => {
    for (const [keyword, value] of Object.entries(node)) {
      if (ANNOTATIONS.has(keyword)) continue;
      if (keyword === "$ref") {
        const target = resolveRef(value as string, from);
        fold(target.node, target.doc, into);
      } else if (keyword === "allOf") {
        for (const part of value as SchemaNode[]) fold(part, from, into);
      } else {
        into.set(keyword, [...(into.get(keyword) ?? []), { value, doc: from }]);
      }
    }
    return into;
  };

  const shape = (node: SchemaNode, from: SchemaDoc, path: string): Shape => {
    const given = fold(node, from);
    const where = path || "the root";
    const take = (keyword: string): Given[] => {
      const all = given.get(keyword) ?? [];
      given.delete(keyword);
      return all;
    };
    /** A keyword that must not be given two different values. */
    const one = <T>(keyword: string): T | undefined => {
      const all = take(keyword);
      if (new Set(all.map((g) => JSON.stringify(g.value))).size > 1) {
        throw new Error(`${where}: "${keyword}" is given more than one value`);
      }
      return all[0]?.value as T | undefined;
    };
    const done = <S extends Shape>(s: S): S => {
      if (given.size > 0) {
        throw new Error(`${where}: ${[...given.keys()].join(", ")} not understood on a ${s.kind}`);
      }
      return s;
    };

    const anyOf = take("anyOf");
    if (anyOf.length > 0) {
      const branches = anyOf.flatMap((g) =>
        (g.value as SchemaNode[]).map((b) => ({ value: b, doc: g.doc })),
      );
      const rest = branches.filter((b) => JSON.stringify(b.value) !== '{"type":"null"}');
      if (anyOf.length !== 1 || branches.length !== 2 || rest.length !== 1 || given.size > 0) {
        throw new Error(
          `${where}: anyOf is understood only as [schema, {"type":"null"}], with no sibling constraints`,
        );
      }
      return { ...shape(rest[0]!.value, rest[0]!.doc, path), nullable: true };
    }

    if (given.has("if") || given.has("then")) {
      take("if");
      take("then");
      asides.push({ path, what: "if/then" });
    }

    const constant = one<unknown>("const");
    const declared = one<string | string[]>("type");
    const types = declared === undefined ? [] : [declared].flat();
    const nullable = types.includes("null");
    const named = types.filter((t) => t !== "null");
    if (named.length > 1) throw new Error(`${where}: more than one non-null type`);
    const kind = named[0] ?? (constant === undefined ? undefined : typeof constant);

    switch (kind) {
      case "object": {
        const listed = take("properties");
        const additional = one<unknown>("additionalProperties");
        if (listed.length === 0) {
          // No member is named: a free-form object. Its rule about member names is not
          // part of a Shape; neither is how that rule is carried down into members
          // (`additionalProperties`, or `patternProperties` with the match-everything
          // pattern "") and into nested arrays (`items`).
          if (additional === false)
            throw new Error(`${where}: an object that allows no member at all`);
          const names = one<SchemaNode>("propertyNames");
          const everyMember = one<SchemaNode>("patternProperties");
          if (everyMember !== undefined && JSON.stringify(Object.keys(everyMember)) !== '[""]') {
            throw new Error(
              `${where}: patternProperties on a free-form object is understood only with the one pattern ""`,
            );
          }
          take("items");
          if (names !== undefined && JSON.stringify(names) !== ANY_NAME) {
            asides.push({ path, what: `propertyNames ${JSON.stringify(names)}` });
          }
          return done({ kind: "free-form", nullable });
        }
        if (additional !== false) {
          throw new Error(
            `${where}: names its members but does not close the set (additionalProperties: false)`,
          );
        }
        const members: Record<string, Shape> = {};
        for (const g of listed) {
          for (const [name, child] of Object.entries(g.value as Record<string, SchemaNode>)) {
            if (name in members) throw new Error(`${where}: member "${name}" is defined twice`);
            members[name] = shape(child, g.doc, path === "" ? name : `${path}.${name}`);
          }
        }
        const required = take("required")
          .flatMap((g) => g.value as string[])
          .sort();
        for (const name of required) {
          if (!(name in members))
            throw new Error(`${where}: requires a member it does not define: "${name}"`);
        }
        return done({ kind: "object", nullable, required, members });
      }
      case "array": {
        const items = take("items");
        if (items.length !== 1)
          throw new Error(`${where}: an array needs exactly one items schema`);
        return done({
          kind: "array",
          nullable,
          minItems: one<number>("minItems") ?? 0,
          maxItems: one<number>("maxItems") ?? null,
          items: shape(items[0]!.value as SchemaNode, items[0]!.doc, path),
        });
      }
      case "string": {
        const s: Extract<Shape, { kind: "string" }> = {
          kind: "string",
          nullable,
          minLength: one<number>("minLength") ?? 0,
          maxLength: one<number>("maxLength") ?? null,
          patterns: [...new Set(take("pattern").map((g) => g.value as string))].sort(),
        };
        if (constant !== undefined) s.const = constant as string;
        return done(s);
      }
      case "number":
      case "integer":
        return done({
          kind,
          nullable,
          minimum: one<number>("minimum") ?? null,
          maximum: one<number>("maximum") ?? null,
        });
      case "boolean":
        return done({ kind: "boolean", nullable });
      default:
        throw new Error(
          `${where}: no type, or one this reader does not handle (${JSON.stringify(declared)})`,
        );
    }
  };
  return shape(doc.root, doc, "");
}

/** One leaf field of a schema. */
export type Field = { path: string; shape: Shape };

/** Every leaf field of a shape, sorted by dotted path. Array items add no path segment
 *  (`quotes.pricing.lines.qty`); an array of scalars is itself a leaf (`buyer.certs`); so
 *  is a free-form object, whose member names the schema does not fix (`as_built`). This is
 *  the convention of `FIELD_DISCLOSURE`. */
export function fieldsOf(shape: Shape): Field[] {
  const out: Field[] = [];
  const walk = (s: Shape, path: string): void => {
    if (s.kind === "object") {
      for (const [name, member] of Object.entries(s.members))
        walk(member, path === "" ? name : `${path}.${name}`);
    } else if (s.kind === "array" && s.items.kind === "object") {
      walk(s.items, path);
    } else {
      out.push({ path, shape: s });
    }
  };
  walk(shape, "");
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** The dotted paths of every leaf field a schema document defines. */
export const fieldPaths = (doc: SchemaDoc): string[] => fieldsOf(shapeOf(doc)).map((f) => f.path);

/* ------------------------------------------------------------------------------------ */
/* A traveler that carries every field                                                   */
/* ------------------------------------------------------------------------------------ */

/** A valid traveler in which every field of the format is present, non-empty and non-null
 *  — so a test that walks it reaches every field. The tests that use it assert that it
 *  covers the schema; a field added to the format fails them until it is added here too.
 *  A fresh copy on every call. */
export function fullTraveler(): Record<string, unknown> {
  return {
    spec: "sje/0.1.0",
    traveler_id: "tvl_fullcover01",
    revision: 7,
    created_at: "2026-09-08T15:12:00.000Z",
    buyer: {
      org_id: "org_northline",
      name: "Northline Equipment",
      city: "Reno",
      region: "NV",
      contact: "buyer@northline.example",
      certs: ["ISO 9001"],
      itar: false,
    },
    part: {
      family: "CNC bracket",
      part_number: "NL-BRK-4410",
      description: "Mounting bracket, left hand",
      drawing_rev: "C",
      material: { spec: "6061-T6", form: "plate", thickness_mm: 6.35 },
      qty: { target: 250, breaks: [100, 500] },
      processes: ["laser", "cnc_mill"],
      finish: "Clear anodize, Type II",
      tolerances: "ISO 2768-m",
      notes: "Deburr all edges",
    },
    need_by: "2026-10-24",
    incoterms: "FOB",
    itar: false,
    ship_to: {
      name: "Northline Equipment, Dock 4",
      line1: "1800 Industrial Way",
      line2: "Building C",
      city: "Reno",
      region: "NV",
      postal: "89502",
      country: "US",
    },
    ops: [
      { seq: 1, code: "laser", notes: "Nest on a 4x8 sheet" },
      { seq: 2, code: "deburr", notes: "All edges" },
    ],
    quotes: [
      {
        quote_id: "qot_fullcover01",
        seller: {
          org_id: "org_summitfab",
          name: "Summit Fabrication",
          city: "Sparks",
          region: "NV",
          contact: "quotes@summit.example",
          certs: ["AS9100"],
          itar: false,
        },
        traveler_hash_quoted: `sha384:${"5e".repeat(48)}`,
        created_at: "2026-09-16T12:00:00.000Z",
        valid_until: "2039-01-01T00:00:00.000Z",
        lead_time_days: 21,
        need_by_feasible: true,
        pricing: {
          currency: "USD",
          nre: 35000,
          lines: [
            { qty: 100, unit: 1850 },
            { qty: 250, unit: 1420 },
          ],
          freight_estimate: 12000,
          tax_excluded: true,
        },
        assumptions: { material: "customer supplied", lots: [1, { split: true }] },
        exceptions: [
          {
            code: "TOL-1",
            on: "part.tolerances",
            proposal: "Hold 0.2 mm on the slot",
            price_delta: -1500,
          },
        ],
        capacity: { machines: 3, shifts: { day: true } },
        sig: { alg: "ML-DSA-87", kid: "summit-2026", sig: "0a1b" },
      },
    ],
    award: {
      quote_id: "qot_fullcover01",
      quote_hash: `sha384:${"ab".repeat(48)}`,
      awarded_at: "2026-09-17T09:00:00.000Z",
      qty: 250,
      terms: {
        governing_law: "US-DE",
        warranty: "12 months, parts and labor",
        payment_terms: "Net 30",
      },
      sig: { alg: "ML-DSA-87", kid: "northline-2026", sig: "0c2d" },
    },
    as_built: { lot: "L-0042", measured_mm: [6.34, 6.36], inspector: { id: "qa-7" } },
    signatures: [{ alg: "ML-DSA-87", kid: "northline-2026", sig: "0e3f" }],
  };
}

/** One place in a JSON value that a schema field describes: where it is, and what the
 *  schema says about it. */
export type Site = { pointer: (string | number)[]; shape: Shape; value: unknown };

/** Walk a value alongside the shape that describes it, and list every place the shape
 *  speaks about: each object, each array, each array element, each leaf. Throws if the
 *  value lacks a member the shape defines (so a caller that needs full coverage gets an
 *  error instead of a silently shorter list) or carries one it does not define. */
export function sitesOf(shape: Shape, value: unknown): Site[] {
  const out: Site[] = [];
  const at = (pointer: (string | number)[]) =>
    pointer.length === 0 ? "the root" : pointer.join(".");
  const walk = (s: Shape, v: unknown, pointer: (string | number)[]): void => {
    out.push({ pointer, shape: s, value: v });
    if (s.kind === "object") {
      if (!isNode(v)) throw new Error(`${at(pointer)}: expected an object`);
      for (const name of Object.keys(v)) {
        if (!(name in s.members))
          throw new Error(`${at(pointer)}: member "${name}" is not in the schema`);
      }
      for (const [name, member] of Object.entries(s.members)) {
        if (!(name in v)) throw new Error(`${at(pointer)}: the value does not carry "${name}"`);
        walk(member, v[name], [...pointer, name]);
      }
    } else if (s.kind === "array") {
      if (!Array.isArray(v) || v.length === 0)
        throw new Error(`${at(pointer)}: expected a non-empty array`);
      v.forEach((item, i) => walk(s.items, item, [...pointer, i]));
    }
  };
  walk(shape, value, []);
  return out;
}

/* ------------------------------------------------------------------------------------ */
/* The implementation's verdict, and the reasons for a refusal                           */
/* ------------------------------------------------------------------------------------ */

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** The errors of a validator's last run, on one line. */
export const schemaErrors = (v: ValidateFunction): string =>
  (v.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ");

/** Why the implementation refuses this traveler text, or `undefined` if it accepts it. */
export function refusal(wire: Uint8Array): string | undefined {
  try {
    parseTravelerJson(wire);
    return undefined;
  } catch (e) {
    return (e instanceof Error ? e.message : String(e)).replace(/^Invalid traveler\. /, "");
  }
}

/** The JSON value a strict reader takes from the text. NOT wrapped in a try: a text that
 *  cannot be read strictly has to be named in not-expressible-0.1.0.json with the lenient
 *  reading to use instead, and a caller that reaches here with one should fail loudly. */
export const strictValue = (wire: Uint8Array): unknown =>
  parseStrictJson(wire, { maxBytes: MAX_TRAVELER_JSON_BYTES, label: "traveler" });

/** What a lenient reader makes of a text a strict reader refuses (the `lenient_reading`
 *  of a wire-text rule). A schema validator can only ever be shown this value. */
export const LENIENT: Record<
  NonNullable<NotExpressibleRule["lenient_reading"]>,
  (wire: Uint8Array) => unknown
> = {
  "json-parse": (wire) =>
    JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(wire)),
  "strip-bom": (wire) => {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(wire);
    assert.equal(text.codePointAt(0), 0xfeff, "strip-bom is for a text that starts with U+FEFF");
    return JSON.parse(text.slice(1));
  },
  "replace-invalid-utf8": (wire) =>
    JSON.parse(new TextDecoder("utf-8", { fatal: false }).decode(wire)),
};

export const RULES = notExpressible.rules;
export const ruleNamed = (name: string): NotExpressibleRule => {
  const rule = RULES.find((r) => r.rule === name);
  assert.ok(rule, `no rule "${name}" in not-expressible-0.1.0.json`);
  return rule;
};
/** The listed rule a refusal reason belongs to, if any. */
export const ruleOf = (reason: string): NotExpressibleRule | undefined =>
  RULES.find((r) => r.refusal.ts.some((fragment) => reason.includes(fragment)));

/** Every reason the implementation has to refuse a document: what its entry point said,
 *  plus every issue its schema raises on the value. (The entry point reports one reason
 *  and stops; a document with a second defect, one a schema *could* catch, must not hide
 *  behind a first that it could not.) */
function reasons(entryPoint: string, value: unknown): string[] {
  const parsed = travelerSchema.safeParse(value);
  const issues = parsed.success
    ? []
    : parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
  return [entryPoint, ...issues];
}

/** For a document the implementation refuses and the schema accepts: the rule that
 *  explains each reason. Throws (failing the test) if any reason has none. */
export function explain(label: string, entryPoint: string, value: unknown): NotExpressibleRule[] {
  const all = reasons(entryPoint, value);
  const unexplained = all.filter((reason) => !ruleOf(reason));
  assert.deepEqual(
    unexplained,
    [],
    `${label}: the schema accepts a document the implementation refuses, and the refusal is not for a rule ` +
      `listed in not-expressible-0.1.0.json. Tighten the schema — or, only if JSON Schema cannot state the ` +
      `rule, list it there with the reason.`,
  );
  return [...new Set(all.map((reason) => ruleOf(reason)!))];
}

/* ------------------------------------------------------------------------------------ */
/* Where each side objects                                                               */
/* ------------------------------------------------------------------------------------ */

/* "Both refuse it" is not agreement. A schema with no `award.sig` also refused a signature
   written in the wrong alphabet: as an unknown member. Agreement is refusing a document
   at the same place. */

const escaped = (name: PropertyKey): string =>
  String(name).replaceAll("~", "~0").replaceAll("/", "~1");
/** The JSON Pointer (RFC 6901) of a path of member names and indices; "" is the document. */
export const pointerOf = (path: readonly PropertyKey[]): string =>
  path.map((name) => `/${escaped(name)}`).join("");

/** Where the published schema objects to the value a validator was last run on, as JSON
 *  Pointers. A validator's errors are adjusted in three ways, so that a place is named
 *  the way the implementation names it:
 *
 *   - a missing member is reported on the object that lacks it, and named here as the
 *     member;
 *   - the error that sums up a failed `if` or `anyOf` repeats, on the enclosing value,
 *     what the errors beneath it say exactly, and is left out;
 *   - so is "must be null" from the null alternative of `as_built`: the errors of the
 *     other alternative say what is wrong with a value that is not null.
 *
 *  Nothing else is left out, so a refusal these three account for entirely comes back as
 *  no place at all, which no refusal by the implementation equals. */
export function schemaObjections(v: ValidateFunction): string[] {
  const places = new Set<string>();
  for (const e of v.errors ?? []) {
    if (e.keyword === "if" || e.keyword === "anyOf") continue;
    if (e.keyword === "type" && e.params.type === "null") continue;
    places.add(
      e.keyword === "required"
        ? `${e.instancePath}/${escaped(e.params.missingProperty as string)}`
        : e.instancePath,
    );
  }
  return [...places].sort();
}

/** Where the implementation objects to a value, as JSON Pointers: every issue its own
 *  schema raises, and every object holding a member named `__proto__` — which it refuses
 *  in a guard that runs before its schema and names no place (conformance.ts). */
export function implementationObjections(
  value: unknown,
  kind: "traveler" | "quote" = "traveler",
): string[] {
  const places = new Set<string>();
  const parsed = (kind === "traveler" ? travelerSchema : quoteSchema).safeParse(value);
  if (!parsed.success) for (const issue of parsed.error.issues) places.add(pointerOf(issue.path));
  const walk = (v: unknown, path: (string | number)[]): void => {
    if (Array.isArray(v)) v.forEach((item, i) => walk(item, [...path, i]));
    else if (v !== null && typeof v === "object") {
      for (const [name, member] of Object.entries(v)) {
        if (name === "__proto__") places.add(pointerOf(path));
        walk(member, [...path, name]);
      }
    }
  };
  walk(value, []);
  return [...places].sort();
}
