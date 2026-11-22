import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { amendMerge, levelOf, parseTraveler, parseQuote } from "./conformance.ts";
import { seedTravelers } from "./fixtures.ts";
import { cannotAward, cannotQuote } from "./guards.ts";
import { quoteContentHash, verificationReport } from "./authenticity.ts";
import type { Directory } from "./directory.ts";
import { travelerHash } from "./hash.ts";
import { decideImport, type ImportDecision, type ImportKind } from "./import-policy.ts";
import { isoNow } from "./ids.ts";
import { SHOPS, shopById } from "./network.ts";
import type { Award, Op, Traveler, Quote, ShipTo, Shop } from "./types.ts";

export type Role = "buyer" | "seller";

export type AuditAct =
  | "compose"
  | "quote"
  | "award"
  | "import"
  | "export"
  | "amend"
  | "reset";

export type AuditEvent = {
  at: string;
  act: AuditAct;
  traveler_id?: string;
  hash?: string;
};

const MAX_AUDIT = 100;
/** The localStorage key the desk's travelers persist under. */
export const TRAVELER_STORE_KEY = "sje-001";

type TravelerState = {
  travelers: Traveler[];
  role: Role;
  sellerOrgId: string;
  hydrated: boolean;
  audit: AuditEvent[];
  setHydrated: (v: boolean) => void;
  setRole: (role: Role) => void;
  setSellerOrgId: (id: string) => void;
  seller: () => Shop;
  logAudit: (ev: Omit<AuditEvent, "at">) => void;
  upsert: (traveler: Traveler) => void;
  remove: (travelerId: string) => void;
  get: (travelerId: string) => Traveler | undefined;
  addQuote: (travelerId: string, quote: Quote) => void;
  award: (travelerId: string, award: Award, shipTo: ShipTo, ops: Op[]) => void;
  amend: (travelerId: string, patch: Partial<Traveler>) => void;
  /** What the receive policy would do with `traveler` right now — nothing is stored. */
  previewImport: (traveler: Traveler, opts?: ImportOptions) => ImportDecision;
  /** Admit a received traveler under the receive policy (import-policy.ts). Throws an
   *  Error carrying the policy's reason when it is refused, and
   *  `ImportNeedsAcknowledgment` — storing nothing — when the policy requires the
   *  reader to acknowledge something first and `opts.acknowledged` is not set. */
  importOne: (traveler: Traveler, opts?: ImportOptions) => ImportOutcome;
  resetDesk: () => void;
};

export type ImportOptions = {
  /** The trust anchor to verify against. Omit it and nothing can be verified — which
   *  the policy treats as "unverified", never as "fine". */
  trust?: { directory: Directory; rootPublicKeyHex: string };
  /** The reader has read and accepted the statements the policy raised. */
  acknowledged?: boolean;
  /** The instant to verify at (default: now). */
  at?: Date;
};

export type ImportOutcome = { kind: ImportKind; notes: string[]; traveler: Traveler };

/** The policy would admit this traveler, but only after the reader has explicitly
 *  acknowledged what is unproven about it. Nothing was stored. */
export class ImportNeedsAcknowledgment extends Error {
  readonly statements: string[];
  readonly notes: string[];
  constructor(statements: string[], notes: string[]) {
    super("This traveler needs your acknowledgment before it is opened.");
    this.name = "ImportNeedsAcknowledgment";
    this.statements = statements;
    this.notes = notes;
  }
}

function executable(p: Traveler): boolean {
  const code = levelOf(p).code;
  return code === "L2" || code === "L3";
}

function withAudit(audit: AuditEvent[], ev: Omit<AuditEvent, "at">): AuditEvent[] {
  return [...audit, { at: isoNow(), ...ev }].slice(-MAX_AUDIT);
}

/** Rehydrate defensively: keep only persisted travelers that still parse.
 *  A malformed entry (schema drift across app versions, hand-edited storage,
 *  a partial write) must not load into state and crash every route on the
 *  first render — drop it instead of trusting the blob. */
export function sanitizeTravelers(list: unknown): Traveler[] {
  if (!Array.isArray(list)) return [];
  return list.flatMap((t) => {
    try {
      return [parseTraveler(t)];
    } catch {
      return [];
    }
  });
}

const AUDIT_ACTS = new Set<AuditAct>([
  "compose",
  "quote",
  "award",
  "import",
  "export",
  "amend",
  "reset",
]);

/** Rehydrate the audit log defensively, like sanitizeTravelers: keep only well-formed
 *  events so a hand-edited or schema-drifted localStorage blob cannot crash the Trust
 *  route (which reads `ev.at` / `ev.hash` as strings) on first render. */
export function sanitizeAudit(list: unknown): AuditEvent[] {
  if (!Array.isArray(list)) return [];
  return list.filter(
    (e): e is AuditEvent =>
      typeof e === "object" &&
      e !== null &&
      typeof (e as AuditEvent).at === "string" &&
      AUDIT_ACTS.has((e as AuditEvent).act) &&
      ((e as AuditEvent).traveler_id === undefined ||
        typeof (e as AuditEvent).traveler_id === "string") &&
      ((e as AuditEvent).hash === undefined || typeof (e as AuditEvent).hash === "string"),
  );
}

/** localStorage that never throws: a quota-exceeded write, a blocked or absent
 *  store (private mode, SSR), or a disabled origin degrades to a no-op / null
 *  rather than crashing the desk. The traveler file is the source of truth;
 *  browser persistence is only a convenience. */
export const safeStorage = {
  getItem: (name: string): string | null => {
    try {
      return typeof localStorage === "undefined" ? null : localStorage.getItem(name);
    } catch {
      return null;
    }
  },
  setItem: (name: string, value: string): void => {
    try {
      if (typeof localStorage !== "undefined") localStorage.setItem(name, value);
    } catch {
      /* quota exceeded or storage blocked — drop the write, don't crash */
    }
  },
  removeItem: (name: string): void => {
    try {
      if (typeof localStorage !== "undefined") localStorage.removeItem(name);
    } catch {
      /* ignore */
    }
  },
};

export const useTravelerStore = create<TravelerState>()(
  persist(
    (set, get) => ({
      travelers: seedTravelers(),
      role: "buyer",
      sellerOrgId: "org_huron",
      hydrated: false,
      audit: [],
      setHydrated: (v) => set({ hydrated: v }),
      setRole: (role) => set({ role }),
      setSellerOrgId: (id) => set({ sellerOrgId: id }),
      seller: () => shopById(get().sellerOrgId) ?? SHOPS[0]!,
      logAudit: (ev) => set((s) => ({ audit: withAudit(s.audit, ev) })),
      get: (travelerId) => get().travelers.find((p) => p.traveler_id === travelerId),
      upsert: (traveler) =>
        set((s) => {
          const parsed = parseTraveler(traveler);
          const i = s.travelers.findIndex((p) => p.traveler_id === parsed.traveler_id);
          const travelers = [...s.travelers];
          if (i >= 0) {
            if (executable(travelers[i]!)) {
              throw new Error("Executable traveler is locked.");
            }
            travelers[i] = parsed;
          } else travelers.unshift(parsed);
          return {
            travelers,
            audit: withAudit(s.audit, {
              act: i >= 0 ? "amend" : "compose",
              traveler_id: parsed.traveler_id,
              hash: travelerHash(parsed),
            }),
          };
        }),
      remove: (travelerId) =>
        set((s) => ({ travelers: s.travelers.filter((p) => p.traveler_id !== travelerId) })),
      addQuote: (travelerId, quote) => {
        const traveler = get().get(travelerId);
        if (!traveler) throw new Error("Traveler is not on this desk.");
        const parsed = parseQuote(quote);
        const err = cannotQuote(traveler, parsed);
        if (err) throw new Error(err);
        set((s) => ({
          travelers: s.travelers.map((p) => {
            if (p.traveler_id !== travelerId) return p;
            const rest = (p.quotes ?? []).filter((q) => q.quote_id !== parsed.quote_id);
            return { ...p, quotes: [...rest, parsed] };
          }),
          audit: withAudit(s.audit, {
            act: "quote",
            traveler_id: travelerId,
            hash: parsed.traveler_hash_quoted,
          }),
        }));
      },
      award: (travelerId, award, shipTo, ops) => {
        const traveler = get().get(travelerId);
        if (!traveler) throw new Error("Traveler is not on this desk.");
        const quote = (traveler.quotes ?? []).find((q) => q.quote_id === award.quote_id);
        if (!quote) throw new Error("Award references a quote that is not on the traveler.");
        const err = cannotAward(traveler, quote);
        if (err) throw new Error(err);
        if (!ops.length) throw new Error("List at least one op.");
        if (!shipTo.name.trim() || !shipTo.line1.trim() || !shipTo.city.trim() || !shipTo.country) {
          throw new Error("Ship-to is incomplete.");
        }
        // Bind the awarded quote's priced content into the award record, so the award the
        // buyer later signs commits to the exact quote (unit price, currency, lead time), not
        // just its id. The desk never signs; it only records a sign-ready award.
        const awardWithHash: Award = { ...award, quote_hash: quoteContentHash(quote) };
        // Re-validate the merged result through the schema (as amend/importOne do, and
        // as the MCP sje_award handler does) so a malformed award / ship-to / ops — e.g.
        // an op code past the 32-char cap, which the dialog does not bound — cannot land
        // unvalidated in state and then be silently dropped by sanitizeTravelers on the
        // next reload (losing the whole job). A throw here surfaces as a toast via the
        // award dialog's try/catch.
        const next = parseTraveler({ ...traveler, award: awardWithHash, ship_to: shipTo, ops });
        set((s) => ({
          travelers: s.travelers.map((p) => (p.traveler_id === travelerId ? next : p)),
          audit: withAudit(s.audit, {
            act: "award",
            traveler_id: travelerId,
            hash: travelerHash(traveler),
          }),
        }));
      },
      amend: (travelerId, patch) =>
        set((s) => {
          const current = s.travelers.find((p) => p.traveler_id === travelerId);
          if (!current || executable(current)) return s;
          // Shared with the MCP sje_amend handler: re-validate through the schema,
          // force the same key set, and drop the now-stale buyer signatures.
          const next = amendMerge(current, patch);
          return {
            travelers: s.travelers.map((p) => (p.traveler_id === travelerId ? next : p)),
            audit: withAudit(s.audit, {
              act: "amend",
              traveler_id: travelerId,
              hash: travelerHash(next),
            }),
          };
        }),
      previewImport: (raw, opts = {}) => {
        const incoming = parseTraveler(raw);
        const held = get().get(incoming.traveler_id);
        const at = opts.at ?? new Date();
        const trust = opts.trust;
        const reportOf = (t: Traveler) =>
          trust ? verificationReport(t, trust.directory, trust.rootPublicKeyHex, at) : undefined;
        return decideImport(incoming, {
          held,
          incomingReport: reportOf(incoming),
          heldReport: held ? reportOf(held) : undefined,
        });
      },
      importOne: (raw, opts = {}) => {
        // Decided against the copy held at THIS moment (not at preview time), and applied
        // in the same synchronous step, so nothing can change in between.
        const decision = get().previewImport(raw, opts);
        if (decision.action === "refuse") throw new Error(decision.reason);
        if (decision.acknowledge.length > 0 && !opts.acknowledged) {
          throw new ImportNeedsAcknowledgment(decision.acknowledge, decision.notes);
        }
        // Re-validate what the policy assembled (a merge can exceed a cap the parts did
        // not) so nothing the schema refuses can land in state.
        const traveler = parseTraveler(decision.traveler);
        set((s) => {
          const i = s.travelers.findIndex((p) => p.traveler_id === traveler.traveler_id);
          const travelers = [...s.travelers];
          if (i >= 0) travelers[i] = traveler;
          else travelers.unshift(traveler);
          return {
            travelers,
            audit: withAudit(s.audit, {
              act: "import",
              traveler_id: traveler.traveler_id,
              hash: travelerHash(traveler),
            }),
          };
        });
        return { kind: decision.kind, notes: decision.notes, traveler };
      },
      resetDesk: () =>
        set((s) => ({
          travelers: seedTravelers(),
          audit: withAudit(s.audit, { act: "reset" }),
        })),
    }),
    {
      name: TRAVELER_STORE_KEY,
      skipHydration: true,
      storage: createJSONStorage(() => safeStorage),
      partialize: (s) => ({
        travelers: s.travelers,
        role: s.role,
        sellerOrgId: s.sellerOrgId,
        audit: s.audit,
      }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<TravelerState>;
        return {
          ...current,
          ...p,
          travelers: Array.isArray(p.travelers)
            ? sanitizeTravelers(p.travelers)
            : current.travelers,
          audit: sanitizeAudit(p.audit),
          hydrated: false,
        };
      },
    },
  ),
);

