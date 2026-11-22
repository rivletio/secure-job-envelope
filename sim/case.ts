/** One fuzz case: a seed turned into the exact wire BYTES both implementations judge.
 *
 *      seed ─► valid traveler (JS value)
 *                 │  object stage   mutations.ts, mutations-object.ts
 *                 ▼
 *              wire tree            (wire.ts: every token's spelling)
 *                 │  wire stage     mutations-wire.ts
 *                 ▼
 *              bytes
 *                 │  bytes stage    mutations-bytes.ts
 *                 ▼
 *              the case
 *
 *  A case is a pure function of its seed: `buildCase(seed)` always returns the same
 *  bytes, so a seed is a complete bug report. About a fifth of the cases stay
 *  unmutated (hash / level / bound parity on well-formed input); the rest stack one
 *  to three mutations drawn from all three stages — interactions shake out bugs a
 *  single mutation hides.
 */
import { genPlan, genTraveler } from "./generate.ts";
import {
  FIELD_MUTATIONS,
  serializeDoc,
  type ByteMutation,
  type Ctx,
  type Doc,
  type ObjectMutation,
  type WireMutation,
} from "./mutations.ts";
import { BYTE_MUTATIONS } from "./mutations-bytes.ts";
import { OBJECT_MUTATIONS } from "./mutations-object.ts";
import { WIRE_MUTATIONS } from "./mutations-wire.ts";
import { Rng } from "./rng.ts";
import { encodeWire, printWire, toWire, type Wire } from "./wire.ts";

export type Stage = "object" | "wire" | "bytes";
export type Entry =
  | ({ stage: "object" } & ObjectMutation)
  | ({ stage: "wire" } & WireMutation)
  | ({ stage: "bytes" } & ByteMutation);

/** Every mutation, in the order the stages run. */
export const CATALOG: readonly Entry[] = [
  ...FIELD_MUTATIONS.map((m) => ({ stage: "object" as const, ...m })),
  ...OBJECT_MUTATIONS.map((m) => ({ stage: "object" as const, ...m })),
  ...WIRE_MUTATIONS.map((m) => ({ stage: "wire" as const, ...m })),
  ...BYTE_MUTATIONS.map((m) => ({ stage: "bytes" as const, ...m })),
];

const BY_NAME = new Map(CATALOG.map((m) => [m.name, m]));
if (BY_NAME.size !== CATALOG.length) throw new Error("mutation names must be unique");

export function mutationNamed(name: string): Entry {
  const m = BY_NAME.get(name);
  if (!m) throw new Error(`no mutation named "${name}"`);
  return m;
}

/** A mutation that changed the document, and the variant it reported choosing. */
export type Applied = { name: string; detail?: string; stage: Stage; slot: number };
/** `name[variant]` — how reports and the corpus manifest show one applied mutation. */
export const showApplied = (a: Applied): string => (a.detail ? `${a.name}[${a.detail}]` : a.name);

export type Case = {
  seed: number;
  /** The mutations that actually bit, in the order they ran. */
  applied: Applied[];
  /** `name[variant]+name[variant]`, or `none` — one line for a report. */
  label: string;
  /** The exact wire bytes. Not necessarily JSON, UTF-8, or under the size cap. */
  bytes: Uint8Array;
};

export type BuildOptions = {
  /** Apply exactly these mutations (by name) instead of the ones the seed draws. The
   *  traveler underneath is still the seed's. For targeted sweeps: `--only`. */
  only?: readonly string[];
  /** Of the mutations in play, run only those in these slots. Lets the harness drop
   *  one mutation at a time from a diverging stack to find the one responsible; each
   *  slot has its own random stream, so the others keep their choices. */
  keep?: ReadonlySet<number>;
};

const UNMUTATED_SHARE = 0.2;
const RICH_SHARE = 0.6;

/** The mutations a seed draws: none, or one to three distinct ones, by weight. */
function draw(rng: Rng): Entry[] {
  if (rng.bool(UNMUTATED_SHARE)) return [];
  const count = rng.weighted([1, 2, 3], (n) => [5, 3, 2][n - 1]!);
  const out: Entry[] = [];
  while (out.length < count) {
    const m = rng.weighted(CATALOG, (e) => e.weight ?? 1);
    if (!out.includes(m)) out.push(m);
  }
  return out;
}

/** The names a seed draws, without building the case (cheap: the corpus generator
 *  scans tens of thousands of seeds for the ones it wants). */
export function drawnNames(seed: number): string[] {
  return draw(new Rng(seed)).map((m) => m.name);
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && Buffer.compare(a, b) === 0;

export function buildCase(seed: number, opts: BuildOptions = {}): Case {
  const rng = new Rng(seed);
  // Drawn first (and always, even when `only` overrides it) so the traveler a seed
  // generates does not depend on how its mutations were chosen.
  const drawn = draw(rng);
  const inPlay = (opts.only ? opts.only.map(mutationNamed) : drawn)
    .map((m, slot) => ({ m, slot }))
    .filter(({ slot }) => !opts.keep || opts.keep.has(slot));
  const doc = structuredClone(genTraveler(rng, { ...genPlan(rng), rich: rng.bool(RICH_SHARE) })) as Doc;

  const applied: Applied[] = [];
  // Run one stage's mutations in slot order. A mutation "bit" iff the document's
  // rendering changed. One that throws met a document already too mangled for it
  // (`part` is null by now, say): whatever it changed before giving up still counts.
  const runStage = <T>(stage: Stage, start: T, render: (target: T) => string | Uint8Array): T => {
    let target = start;
    let before = render(target);
    for (const { m, slot } of inPlay) {
      if (m.stage !== stage) continue;
      let detail: string | undefined;
      const ctx: Ctx = { rng: Rng.derive(seed, slot), note: (d) => (detail = d) };
      try {
        const result = (m.apply as (target: T, ctx: Ctx) => unknown)(target, ctx);
        if (stage === "bytes") target = result as T;
      } catch {
        detail = undefined;
      }
      const after = render(target);
      const changed = typeof after === "string" ? after !== before : !sameBytes(after, before as Uint8Array);
      if (changed) applied.push({ name: m.name, detail, stage, slot });
      before = after;
    }
    return target;
  };

  runStage<Doc>("object", doc, serializeDoc);
  const wire = runStage<Wire>("wire", { root: toWire(doc), splices: [] }, (w) => printWire(w.root));
  const bytes = runStage<Uint8Array>("bytes", encodeWire(printWire(wire.root), wire.splices), (b) => b);

  const label = applied.map(showApplied).join("+") || "none";
  return { seed, applied, label, bytes };
}
