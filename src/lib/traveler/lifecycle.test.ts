/** Lifecycle rules of the desk that a file exchange leans on, each pinned against the
 *  weakness it closes:
 *   - one quote per seller per REVISION (a stale quote must not block a re-quote);
 *   - the store never holds a traveler the schema refuses (a 65th quote once made the
 *     whole traveler vanish on the next reload);
 *   - "locked" has one definition — level >= 2 — shared by guards, store and UI;
 *   - deleting a traveler is possible, at any level, and audited.
 */
import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { readFileSync, readdirSync } from "node:fs";

// zustand/persist wants Storage; give node a minimal one BEFORE importing the store.
const mem = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
  clear: () => mem.clear(),
  key: (i: number) => [...mem.keys()][i] ?? null,
  get length() {
    return mem.size;
  },
};

const { useTravelerStore, sanitizeTravelers, sanitizeAudit } = await import("./store.ts");
const { amendMerge, boundQuotes, levelOf, parseTraveler, staleQuotes } = await import(
  "./conformance.ts"
);
const { awardStanding, cannotAward, cannotQuote, locked, lockedAtLevel } = await import(
  "./guards.ts"
);
const { seedTravelers } = await import("./fixtures.ts");
const { travelerHash } = await import("./hash.ts");
const { randToken } = await import("./ids.ts");
import type { Op, Quote, ShipTo, Traveler } from "./types.ts";

const root = new URL("../../../conformance/", import.meta.url).pathname;
const S = () => useTravelerStore.getState();
const held = (id: string) => S().get(id)!;

/** Put a traveler on the desk exactly as it is — as if it had arrived some other way
 *  (an import, an earlier session) — without going through a mutation under test. */
function hold(t: Traveler): void {
  const parsed = parseTraveler(t);
  useTravelerStore.setState((s) => ({
    travelers: [parsed, ...s.travelers.filter((x) => x.traveler_id !== parsed.traveler_id)],
  }));
}

function freshTraveler(): Traveler {
  const p = parseTraveler(JSON.parse(readFileSync(`${root}travelers/l0-bracket.json`, "utf8")));
  return { ...p, traveler_id: `tvl_t${randToken(8)}`, quotes: [] };
}

function quoteFor(t: Traveler, org = "org_huron", over: Partial<Quote> = {}): Quote {
  return {
    quote_id: `qot_t${randToken(8)}`,
    seller: { org_id: org, name: `Shop ${org}` },
    traveler_hash_quoted: travelerHash(t),
    created_at: "2026-09-16T12:00:00.000Z",
    valid_until: "2039-01-01T00:00:00.000Z",
    lead_time_days: 21,
    pricing: { currency: "USD", lines: [{ qty: t.part.qty.target, unit: 1420 }] },
    ...over,
  };
}

const SHIP: ShipTo = {
  name: "Northline Equipment — Dock 4",
  line1: "1800 Industrial Way",
  city: "Reno",
  region: "NV",
  postal: "89502",
  country: "US",
};
const OPS: Op[] = [{ seq: 1, code: "MILL" }];
const awardOf = (q: Quote, t: Traveler) => ({
  quote_id: q.quote_id,
  awarded_at: "2026-10-01T00:00:00.000Z",
  qty: t.part.qty.target,
});

/** A traveler at revision 2 whose award names a quote priced against revision 1 — the
 *  award, the ops and a ship-to are all there, but the awarded quote is stale. With
 *  `withLiveQuote` a second seller has quoted revision 2, so the traveler is L1. */
function voidAwardTraveler(withLiveQuote: boolean): { t: Traveler; staleQuote: Quote; live?: Quote } {
  const rev1 = freshTraveler();
  const staleQuote = quoteFor(rev1, "org_huron");
  const rev2 = amendMerge({ ...rev1, quotes: [staleQuote] }, { need_by: "2026-12-01" });
  const live = withLiveQuote ? quoteFor(rev2, "org_redriver") : undefined;
  const t = parseTraveler({
    ...rev2,
    quotes: live ? [staleQuote, live] : [staleQuote],
    award: awardOf(staleQuote, rev2),
    ops: OPS,
    ship_to: SHIP,
  });
  return { t, staleQuote, live };
}

/** What `guards.locked` used to be — kept here only to prove the cases below are ones
 *  the two definitions disagreed on. */
const lockedByFieldsPresent = (t: Traveler) =>
  Boolean(t.award) && Boolean(t.ops?.length) && Boolean(t.ship_to?.name);

describe("one quote per seller, per revision", () => {
  beforeEach(() => S().resetDesk());

  it("a seller can re-quote after an amend; the stale quote stays as history", () => {
    const t = freshTraveler();
    S().upsert(t);
    const first = quoteFor(t, "org_huron");
    S().addQuote(t.traveler_id, first);
    S().amend(t.traveler_id, { need_by: "2026-12-01" });
    const amended = held(t.traveler_id);
    assert.equal(staleQuotes(amended).length, 1, "the first quote is stale after the amend");

    const second = quoteFor(amended, "org_huron");
    assert.equal(cannotQuote(amended, second), null, "the guard lets the same seller quote the new revision");
    S().addQuote(t.traveler_id, second);

    const after = held(t.traveler_id);
    assert.deepEqual(
      after.quotes!.map((q) => q.quote_id),
      [first.quote_id, second.quote_id],
      "both quotes are on the traveler: the stale one is not discarded",
    );
    assert.deepEqual(boundQuotes(after).map((q) => q.quote_id), [second.quote_id]);
    assert.deepEqual(staleQuotes(after).map((q) => q.quote_id), [first.quote_id]);
    assert.equal(levelOf(after).code, "L1");
  });

  it("a second quote from the same seller on the SAME revision is still refused", () => {
    const t = freshTraveler();
    S().upsert(t);
    S().addQuote(t.traveler_id, quoteFor(t, "org_huron"));
    const again = quoteFor(held(t.traveler_id), "org_huron");
    assert.equal(cannotQuote(held(t.traveler_id), again), "This seller already has a quote on this revision.");
    assert.throws(() => S().addQuote(t.traveler_id, again), /already has a quote on this revision/);
    assert.equal(held(t.traveler_id).quotes!.length, 1);
  });

  it("an unbound quote planted under a rival's org_id does not lock the rival out", () => {
    const t = freshTraveler();
    const planted = quoteFor(t, "org_huron", { traveler_hash_quoted: `sha384:${"0".repeat(96)}` });
    hold({ ...t, quotes: [planted] });
    const real = quoteFor(held(t.traveler_id), "org_huron");
    assert.equal(cannotQuote(held(t.traveler_id), real), null);
    S().addQuote(t.traveler_id, real);
    assert.deepEqual(boundQuotes(held(t.traveler_id)).map((q) => q.quote_id), [real.quote_id]);
  });
});

describe("the store never holds a traveler the schema refuses", () => {
  beforeEach(() => S().resetDesk());

  const withQuotes = (n: number): Traveler => {
    const t = freshTraveler();
    // Unbound fillers from distinct sellers: valid quotes that occupy slots without
    // tripping the one-quote-per-seller rule.
    const fillers = Array.from({ length: n }, (_, i) =>
      quoteFor(t, `org_filler${String(i).padStart(2, "0")}`, {
        quote_id: `qot_filler${String(i).padStart(4, "0")}`,
        traveler_hash_quoted: `sha384:${"0".repeat(96)}`,
      }),
    );
    return { ...t, quotes: fillers };
  };

  it("the schema caps a traveler at 64 quotes (the cap addQuote words its refusal around)", () => {
    assert.doesNotThrow(() => parseTraveler(withQuotes(64)));
    assert.throws(() => parseTraveler(withQuotes(65)), /quotes/);
  });

  it("the 64th quote is accepted", () => {
    const t = withQuotes(63);
    hold(t);
    S().addQuote(t.traveler_id, quoteFor(held(t.traveler_id), "org_huron"));
    assert.equal(held(t.traveler_id).quotes!.length, 64);
    assert.doesNotThrow(() => parseTraveler(held(t.traveler_id)));
  });

  it("a 65th quote is refused with a clear error and the held traveler is unchanged", () => {
    const t = withQuotes(64);
    hold(t);
    const before = held(t.traveler_id);
    const auditBefore = S().audit.length;

    assert.throws(
      () => S().addQuote(t.traveler_id, quoteFor(before, "org_huron")),
      /already carries 64 quotes.*cannot take another/i,
    );

    assert.equal(held(t.traveler_id), before, "the very same object is still held: nothing was written");
    assert.equal(S().audit.length, auditBefore, "a refused quote is not audited as a quote");
    // What made the old behaviour a data loss: the invalid traveler was dropped whole
    // by the rehydrate sanitizer. Now there is nothing invalid to drop.
    assert.doesNotThrow(() => parseTraveler(held(t.traveler_id)));
    const reloaded = sanitizeTravelers(JSON.parse(JSON.stringify(S().travelers)));
    assert.ok(
      reloaded.some((x) => x.traveler_id === t.traveler_id),
      "the traveler survives a reload",
    );
  });

  it("every traveler-writing mutation leaves only schema-valid, reload-safe travelers in state", () => {
    const t = freshTraveler();
    S().upsert(t);
    const q = quoteFor(t, "org_huron");
    S().addQuote(t.traveler_id, q);
    S().amend(t.traveler_id, { incoterms: "EXW" });
    const q2 = quoteFor(held(t.traveler_id), "org_huron");
    S().addQuote(t.traveler_id, q2);
    S().award(t.traveler_id, awardOf(q2, held(t.traveler_id)), SHIP, OPS);

    const state = S().travelers;
    for (const x of state) assert.doesNotThrow(() => parseTraveler(x), x.traveler_id);
    const reloaded = sanitizeTravelers(JSON.parse(JSON.stringify(state)));
    assert.deepEqual(
      reloaded.map((x) => x.traveler_id),
      state.map((x) => x.traveler_id),
      "a reload drops nothing",
    );
    assert.deepEqual(reloaded.map(travelerHash), state.map(travelerHash));
    assert.deepEqual(
      reloaded.map((x) => levelOf(x).code),
      state.map((x) => levelOf(x).code),
    );
  });

  it("a mutation that would produce an invalid traveler throws and writes nothing", () => {
    const t = freshTraveler();
    S().upsert(t);
    const q = quoteFor(t, "org_huron");
    S().addQuote(t.traveler_id, q);
    const before = held(t.traveler_id);

    // upsert: a malformed replacement
    assert.throws(() => S().upsert({ ...before, revision: 0 }), /Invalid traveler/);
    // amend: a patch the schema refuses
    assert.throws(() => S().amend(t.traveler_id, { need_by: "next Tuesday" }), /Invalid traveler/);
    // award: an op code past the schema's cap
    assert.throws(
      () => S().award(t.traveler_id, awardOf(q, before), SHIP, [{ seq: 1, code: "X".repeat(33) }]),
      /Invalid traveler/,
    );
    // addQuote: a malformed quote
    assert.throws(
      () => S().addQuote(t.traveler_id, { ...quoteFor(before, "org_redriver"), lead_time_days: 1.5 }),
      /Invalid quote/,
    );
    assert.equal(held(t.traveler_id), before, "the held traveler is untouched by every refusal");
  });
});

describe("locked has one definition: level >= 2", () => {
  beforeEach(() => S().resetDesk());

  it("locked(t) is exactly levelOf(t).level >= 2 — seeds, conformance vectors and edge cases", () => {
    const vectors = readdirSync(`${root}travelers`)
      .filter((f) => /^(l\d|part-).*\.json$/.test(f))
      .map((f) => parseTraveler(JSON.parse(readFileSync(`${root}travelers/${f}`, "utf8"))));
    const l2 = vectors.find((v) => levelOf(v).code === "L2")!;
    const edge: Traveler[] = [
      voidAwardTraveler(false).t,
      voidAwardTraveler(true).t,
      { ...l2, ops: [] }, // award names a bound quote, but no ops
      { ...l2, ship_to: null }, // …or no ship-to
      { ...l2, ship_to: { ...l2.ship_to!, line1: "" } }, // …or a ship-to with only a name
      { ...l2, award: null },
      { ...l2, as_built: { lot: "A1" } }, // L3
      { ...l2, award: { ...l2.award!, quote_id: "qot_notthere1" } }, // award names an absent quote
    ];
    const all = [...seedTravelers(), ...vectors, ...edge];
    const levels = new Set<number>();
    for (const t of all) {
      const info = levelOf(t);
      levels.add(info.level);
      assert.equal(locked(t), info.level >= 2, `${t.traveler_id} at ${info.code}`);
      assert.equal(lockedAtLevel(info), info.level >= 2);
    }
    assert.ok(all.some((t) => locked(t)) && all.some((t) => !locked(t)), "both outcomes are exercised");
    assert.ok(levels.has(3), "an L3 traveler is among them, and is locked");
    assert.ok(
      all.some((t) => lockedByFieldsPresent(t) !== locked(t)),
      "the set includes travelers the old field-presence test got wrong",
    );
  });

  it("the store and the guards lock exactly the travelers that are locked(t)", () => {
    const l2 = seedTravelers().find((t) => levelOf(t).code === "L2")!;
    const samples: Traveler[] = [
      ...seedTravelers(),
      voidAwardTraveler(false).t,
      voidAwardTraveler(true).t,
      parseTraveler({ ...l2, ops: [] }),
      parseTraveler({ ...l2, award: { ...l2.award!, quote_id: "qot_notthere1" } }),
      parseTraveler({ ...l2, as_built: { lot: "A1" } }),
    ];
    for (const sample of samples) {
      const expected = locked(sample);
      const id = sample.traveler_id;
      const label = `${id} (${levelOf(sample).code})`;
      const alone = () => useTravelerStore.setState({ travelers: [sample] });
      const refuses = (fn: () => void, why: RegExp) => {
        try {
          fn();
          return false;
        } catch (e) {
          assert.match((e as Error).message, why, label);
          return true;
        }
      };

      alone();
      assert.equal(refuses(() => S().upsert({ ...sample, incoterms: "DAP" }), /locked/), expected, `upsert ${label}`);

      alone();
      S().amend(id, { incoterms: "DAP" });
      assert.equal(held(id).revision === sample.revision, expected, `amend ${label}`);

      alone();
      assert.equal(
        refuses(() => S().addQuote(id, quoteFor(sample, "org_newseller")), /Executable travelers/),
        expected,
        `addQuote ${label}`,
      );

      const bound = boundQuotes(sample)[0];
      if (bound) {
        assert.equal(cannotAward(sample, bound) === "Traveler is already executable.", expected, `award ${label}`);
      }
    }
  });

  for (const withLiveQuote of [false, true]) {
    const level = withLiveQuote ? "L1" : "L0";
    it(`an award naming a stale quote does not lock (${level}): the traveler can be quoted, awarded and amended`, () => {
      const { t, staleQuote, live } = voidAwardTraveler(withLiveQuote);
      assert.equal(levelOf(t).code, level);
      assert.equal(lockedByFieldsPresent(t), true, "the old field-presence test called this locked");
      assert.equal(locked(t), false, "the one definition does not");
      assert.deepEqual(awardStanding(t), { state: "void", quote_id: staleQuote.quote_id, reason: "stale" });

      hold(t);
      const id = t.traveler_id;

      // quotable: a third seller binds a quote to the current revision
      const fresh = quoteFor(held(id), "org_cascade");
      assert.equal(cannotQuote(held(id), fresh), null);
      S().addQuote(id, fresh);
      assert.equal(levelOf(held(id)).code, "L1");
      assert.equal(locked(held(id)), false);

      // not awardable through the stale quote the old award names…
      assert.match(cannotAward(held(id), staleQuote) ?? "", /not bound/);
      // …but awardable through a bound one, which replaces the void award and locks
      const pick = live ?? fresh;
      assert.equal(cannotAward(held(id), pick), null);
      S().award(id, awardOf(pick, held(id)), SHIP, OPS);
      assert.equal(levelOf(held(id)).code, "L2");
      assert.equal(locked(held(id)), true);
      assert.equal(held(id).award!.quote_id, pick.quote_id);
      assert.equal(awardStanding(held(id)).state, "in-effect");

      // and NOW it is locked for every mutation
      const rev = held(id).revision;
      S().amend(id, { incoterms: "EXW" });
      assert.equal(held(id).revision, rev, "amend is a no-op on a locked traveler");
      assert.throws(() => S().upsert({ ...held(id), need_by: "2027-01-01" }), /locked/);
      assert.throws(() => S().addQuote(id, quoteFor(held(id), "org_lakeshore")), /Executable/);
      assert.throws(() => S().award(id, awardOf(pick, held(id)), SHIP, OPS), /already executable/);
    });
  }

  it("amending a traveler with a void award drops that award and bumps the revision", () => {
    const { t } = voidAwardTraveler(true);
    hold(t);
    S().amend(t.traveler_id, { incoterms: "EXW" });
    const after = held(t.traveler_id);
    assert.equal(after.revision, t.revision + 1);
    assert.equal(after.award ?? null, null);
    assert.deepEqual(awardStanding(after), { state: "none" });
    assert.equal(locked(after), false);
    assert.doesNotThrow(() => parseTraveler(after));
  });

  it("awardStanding tells the four cases apart, and agrees with locked", () => {
    const l2 = seedTravelers().find((t) => levelOf(t).code === "L2")!;
    const quote = boundQuotes(l2)[0]!;

    assert.deepEqual(awardStanding({ ...l2, award: null }), { state: "none" });
    assert.deepEqual(awardStanding(l2), { state: "in-effect", quote });
    assert.deepEqual(awardStanding({ ...l2, ops: [] }), {
      state: "incomplete",
      quote,
      missing: ["ops[]"],
    });
    assert.deepEqual(awardStanding({ ...l2, ship_to: null, ops: [] }), {
      state: "incomplete",
      quote,
      missing: ["ops[]", "ship_to"],
    });
    assert.deepEqual(awardStanding({ ...l2, award: { ...l2.award!, quote_id: "qot_notthere1" } }), {
      state: "void",
      quote_id: "qot_notthere1",
      reason: "absent",
    });

    for (const t of [...seedTravelers(), voidAwardTraveler(true).t, { ...l2, ops: [] }]) {
      assert.equal(awardStanding(t).state === "in-effect", locked(t), t.traveler_id);
    }
  });
});

describe("deleting a traveler", () => {
  beforeEach(() => S().resetDesk());

  it("removes it and audits the deletion with the hash of what was deleted", () => {
    const t = freshTraveler();
    S().upsert(t);
    const hash = travelerHash(held(t.traveler_id));
    const others = S().travelers.filter((x) => x.traveler_id !== t.traveler_id);

    S().remove(t.traveler_id);

    assert.equal(S().get(t.traveler_id), undefined);
    assert.deepEqual(S().travelers, others, "no other traveler is touched");
    const last = S().audit.at(-1)!;
    assert.deepEqual(
      { act: last.act, traveler_id: last.traveler_id, hash: last.hash },
      { act: "delete", traveler_id: t.traveler_id, hash },
    );
    assert.ok(last.at, "timestamped");
  });

  it("a locked (L2) traveler can still be deleted locally", () => {
    const l2 = seedTravelers().find((t) => locked(t))!;
    assert.ok(S().get(l2.traveler_id), "the seed L2 traveler is on the desk");
    S().remove(l2.traveler_id);
    assert.equal(S().get(l2.traveler_id), undefined);
    assert.equal(S().audit.at(-1)!.act, "delete");
  });

  it("removing an id that is not held changes nothing and logs nothing", () => {
    const before = S().travelers;
    const audit = S().audit;
    S().remove("tvl_notthere01");
    assert.equal(S().travelers, before);
    assert.equal(S().audit, audit);
  });

  it("the delete entry survives a reload (the audit sanitizer knows the act)", () => {
    const t = freshTraveler();
    S().upsert(t);
    S().remove(t.traveler_id);
    const reloaded = sanitizeAudit(JSON.parse(JSON.stringify(S().audit)));
    assert.deepEqual(reloaded, S().audit);
    assert.ok(reloaded.some((e) => e.act === "delete" && e.traveler_id === t.traveler_id));
  });
});
