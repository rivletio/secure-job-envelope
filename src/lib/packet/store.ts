import { create } from "zustand";
import { persist } from "zustand/middleware";
import { levelOf, parsePacket, parseQuote } from "./conformance.ts";
import { seedPackets } from "./fixtures.ts";
import { cannotAward, cannotQuote } from "./guards.ts";
import { packetHash } from "./hash.ts";
import { isoNow } from "./ids.ts";
import { SHOPS, shopById } from "./network.ts";
import type { Award, Op, Packet, Quote, ShipTo, Shop } from "./types.ts";

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
  packet_id?: string;
  hash?: string;
};

const MAX_AUDIT = 100;

type PacketState = {
  packets: Packet[];
  role: Role;
  sellerOrgId: string;
  hydrated: boolean;
  audit: AuditEvent[];
  setHydrated: (v: boolean) => void;
  setRole: (role: Role) => void;
  setSellerOrgId: (id: string) => void;
  seller: () => Shop;
  logAudit: (ev: Omit<AuditEvent, "at">) => void;
  upsert: (packet: Packet) => void;
  remove: (packetId: string) => void;
  get: (packetId: string) => Packet | undefined;
  addQuote: (packetId: string, quote: Quote) => void;
  award: (packetId: string, award: Award, shipTo: ShipTo, ops: Op[]) => void;
  amend: (packetId: string, patch: Partial<Packet>) => void;
  importOne: (packet: Packet) => void;
  resetDesk: () => void;
};

function executable(p: Packet): boolean {
  const code = levelOf(p).code;
  return code === "L2" || code === "L3";
}

function withAudit(audit: AuditEvent[], ev: Omit<AuditEvent, "at">): AuditEvent[] {
  return [...audit, { at: isoNow(), ...ev }].slice(-MAX_AUDIT);
}

export const usePacketStore = create<PacketState>()(
  persist(
    (set, get) => ({
      packets: seedPackets(),
      role: "buyer",
      sellerOrgId: "org_huron",
      hydrated: false,
      audit: [],
      setHydrated: (v) => set({ hydrated: v }),
      setRole: (role) => set({ role }),
      setSellerOrgId: (id) => set({ sellerOrgId: id }),
      seller: () => shopById(get().sellerOrgId) ?? SHOPS[0]!,
      logAudit: (ev) => set((s) => ({ audit: withAudit(s.audit, ev) })),
      get: (packetId) => get().packets.find((p) => p.packet_id === packetId),
      upsert: (packet) =>
        set((s) => {
          const parsed = parsePacket(packet);
          const i = s.packets.findIndex((p) => p.packet_id === parsed.packet_id);
          const packets = [...s.packets];
          if (i >= 0) {
            if (executable(packets[i]!)) {
              throw new Error("Executable packet is locked.");
            }
            packets[i] = parsed;
          } else packets.unshift(parsed);
          return {
            packets,
            audit: withAudit(s.audit, {
              act: i >= 0 ? "amend" : "compose",
              packet_id: parsed.packet_id,
              hash: packetHash(parsed),
            }),
          };
        }),
      remove: (packetId) =>
        set((s) => ({ packets: s.packets.filter((p) => p.packet_id !== packetId) })),
      addQuote: (packetId, quote) => {
        const packet = get().get(packetId);
        if (!packet) throw new Error("Packet is not on this desk.");
        const parsed = parseQuote(quote);
        const err = cannotQuote(packet, parsed);
        if (err) throw new Error(err);
        set((s) => ({
          packets: s.packets.map((p) => {
            if (p.packet_id !== packetId) return p;
            const rest = (p.quotes ?? []).filter((q) => q.quote_id !== parsed.quote_id);
            return { ...p, quotes: [...rest, parsed] };
          }),
          audit: withAudit(s.audit, {
            act: "quote",
            packet_id: packetId,
            hash: parsed.packet_hash_quoted,
          }),
        }));
      },
      award: (packetId, award, shipTo, ops) => {
        const packet = get().get(packetId);
        if (!packet) throw new Error("Packet is not on this desk.");
        const quote = (packet.quotes ?? []).find((q) => q.quote_id === award.quote_id);
        if (!quote) throw new Error("Award references a quote that is not on the packet.");
        const err = cannotAward(packet, quote);
        if (err) throw new Error(err);
        if (!ops.length) throw new Error("List at least one op.");
        if (!shipTo.name.trim() || !shipTo.line1.trim() || !shipTo.city.trim() || !shipTo.country) {
          throw new Error("Ship-to is incomplete.");
        }
        set((s) => ({
          packets: s.packets.map((p) =>
            p.packet_id === packetId ? { ...p, award, ship_to: shipTo, ops } : p,
          ),
          audit: withAudit(s.audit, {
            act: "award",
            packet_id: packetId,
            hash: packetHash(packet),
          }),
        }));
      },
      amend: (packetId, patch) =>
        set((s) => {
          const current = s.packets.find((p) => p.packet_id === packetId);
          if (!current || executable(current)) return s;
          const packets = s.packets.map((p) => {
            if (p.packet_id !== packetId) return p;
            return {
              ...p,
              ...patch,
              packet_id: p.packet_id,
              spec: p.spec,
              created_at: p.created_at,
              revision: p.revision + 1,
              quotes: p.quotes,
              award: null,
              ship_to: p.ship_to,
              ops: p.ops,
            };
          });
          const next = packets.find((p) => p.packet_id === packetId)!;
          return {
            packets,
            audit: withAudit(s.audit, {
              act: "amend",
              packet_id: packetId,
              hash: packetHash(next),
            }),
          };
        }),
      importOne: (raw) => {
        const packet = parsePacket(raw);
        set((s) => {
          const i = s.packets.findIndex((p) => p.packet_id === packet.packet_id);
          const packets = [...s.packets];
          if (i >= 0) {
            if (executable(packets[i]!)) {
              throw new Error("Executable packet is locked.");
            }
            packets[i] = packet;
          } else packets.unshift(packet);
          return {
            packets,
            audit: withAudit(s.audit, {
              act: "import",
              packet_id: packet.packet_id,
              hash: packetHash(packet),
            }),
          };
        });
      },
      resetDesk: () =>
        set((s) => ({
          packets: seedPackets(),
          audit: withAudit(s.audit, { act: "reset" }),
        })),
    }),
    {
      name: "rivlet-packets-001",
      skipHydration: true,
      partialize: (s) => ({
        packets: s.packets,
        role: s.role,
        sellerOrgId: s.sellerOrgId,
        audit: s.audit,
      }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<PacketState>;
        return {
          ...current,
          ...p,
          packets: Array.isArray(p.packets) ? p.packets : current.packets,
          audit: Array.isArray(p.audit) ? p.audit : [],
          hydrated: false,
        };
      },
    },
  ),
);

