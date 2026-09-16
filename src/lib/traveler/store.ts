import { create } from "zustand";
import { persist } from "zustand/middleware";
import { levelOf, parseTraveler, parseQuote } from "./conformance.ts";
import { seedTravelers } from "./fixtures.ts";
import { cannotAward, cannotQuote } from "./guards.ts";
import { travelerHash } from "./hash.ts";
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
  importOne: (traveler: Traveler) => void;
  resetDesk: () => void;
};

function executable(p: Traveler): boolean {
  const code = levelOf(p).code;
  return code === "L2" || code === "L3";
}

function withAudit(audit: AuditEvent[], ev: Omit<AuditEvent, "at">): AuditEvent[] {
  return [...audit, { at: isoNow(), ...ev }].slice(-MAX_AUDIT);
}

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
        set((s) => ({
          travelers: s.travelers.map((p) =>
            p.traveler_id === travelerId ? { ...p, award, ship_to: shipTo, ops } : p,
          ),
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
          const travelers = s.travelers.map((p) => {
            if (p.traveler_id !== travelerId) return p;
            return {
              ...p,
              ...patch,
              traveler_id: p.traveler_id,
              spec: p.spec,
              created_at: p.created_at,
              revision: p.revision + 1,
              quotes: p.quotes,
              award: null,
              ship_to: p.ship_to,
              ops: p.ops,
            };
          });
          const next = travelers.find((p) => p.traveler_id === travelerId)!;
          return {
            travelers,
            audit: withAudit(s.audit, {
              act: "amend",
              traveler_id: travelerId,
              hash: travelerHash(next),
            }),
          };
        }),
      importOne: (raw) => {
        const traveler = parseTraveler(raw);
        set((s) => {
          const i = s.travelers.findIndex((p) => p.traveler_id === traveler.traveler_id);
          const travelers = [...s.travelers];
          if (i >= 0) {
            if (executable(travelers[i]!)) {
              throw new Error("Executable traveler is locked.");
            }
            travelers[i] = traveler;
          } else travelers.unshift(traveler);
          return {
            travelers,
            audit: withAudit(s.audit, {
              act: "import",
              traveler_id: traveler.traveler_id,
              hash: travelerHash(traveler),
            }),
          };
        });
      },
      resetDesk: () =>
        set((s) => ({
          travelers: seedTravelers(),
          audit: withAudit(s.audit, { act: "reset" }),
        })),
    }),
    {
      name: "jobseal-001",
      skipHydration: true,
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
          travelers: Array.isArray(p.travelers) ? p.travelers : current.travelers,
          audit: Array.isArray(p.audit) ? p.audit : [],
          hydrated: false,
        };
      },
    },
  ),
);

