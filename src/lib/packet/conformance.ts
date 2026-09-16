import { packetHash } from "./hash.ts";
import { packetSchema, quoteSchema } from "./schema.ts";
import type { ConformanceLevel, Packet, Quote } from "./types.ts";

export type LevelInfo = {
  level: ConformanceLevel;
  name: "Draft" | "Quoteable" | "Awardable" | "Executable" | "As-built";
  code: "D" | "L0" | "L1" | "L2" | "L3";
  missing: string[];
};

export function isQuoteable(packet: Packet): boolean {
  return (
    packet.buyer.name.trim().length > 0 &&
    packet.part.family.trim().length > 0 &&
    packet.part.part_number.trim().length > 0 &&
    packet.part.material.spec.trim().length > 0 &&
    packet.part.qty.target >= 1
  );
}

export function boundQuotes(packet: Packet): Quote[] {
  const hash = packetHash(packet);
  return (packet.quotes ?? []).filter((q) => {
    const parsed = quoteSchema.safeParse(q);
    if (!parsed.success) return false;
    if (q.packet_hash_quoted !== hash) return false;
    if (packet.itar && q.seller.itar !== true) return false;
    return true;
  });
}

export function staleQuotes(packet: Packet): Quote[] {
  const hash = packetHash(packet);
  return (packet.quotes ?? []).filter((q) => q.packet_hash_quoted !== hash);
}

export function awardedQuote(packet: Packet): Quote | undefined {
  if (!packet.award) return undefined;
  return boundQuotes(packet).find((q) => q.quote_id === packet.award?.quote_id);
}

export function levelOf(packet: Packet): LevelInfo {
  const missing: string[] = [];
  if (!packet.buyer.name.trim()) missing.push("buyer.name");
  if (!packet.part.family.trim()) missing.push("part.family");
  if (!packet.part.part_number.trim()) missing.push("part.part_number");
  if (!packet.part.material.spec.trim()) missing.push("part.material.spec");
  if (!(packet.part.qty.target >= 1)) missing.push("part.qty.target");

  if (missing.length) {
    return { level: 0, name: "Draft", code: "D", missing };
  }

  const bound = boundQuotes(packet);
  if (bound.length === 0) {
    return {
      level: 0,
      name: "Quoteable",
      code: "L0",
      missing: ["bound quote (packet_hash_quoted)"],
    };
  }

  const awardOk = Boolean(packet.award && bound.some((q) => q.quote_id === packet.award?.quote_id));
  const opsOk = (packet.ops ?? []).length >= 1;
  const shipOk = Boolean(
    packet.ship_to?.name && packet.ship_to.line1 && packet.ship_to.city && packet.ship_to.country,
  );

  if (!awardOk || !opsOk || !shipOk) {
    const l1missing: string[] = [];
    if (!awardOk) l1missing.push("award bound to current revision");
    if (!opsOk) l1missing.push("ops[]");
    if (!shipOk) l1missing.push("ship_to");
    return { level: 1, name: "Awardable", code: "L1", missing: l1missing };
  }

  if (packet.as_built && Object.keys(packet.as_built).length > 0) {
    return { level: 3, name: "As-built", code: "L3", missing: [] };
  }

  return {
    level: 2,
    name: "Executable",
    code: "L2",
    missing: ["as_built (reserved in 0.0.1)"],
  };
}

export function parsePacket(data: unknown): Packet {
  const r = packetSchema.safeParse(data);
  if (!r.success) throw new Error(formatZod(r.error, "packet"));
  return r.data as Packet;
}

export function parseQuote(data: unknown): Quote {
  const r = quoteSchema.safeParse(data);
  if (!r.success) throw new Error(formatZod(r.error, "quote"));
  return r.data as Quote;
}

function formatZod(err: { issues: { path: PropertyKey[]; message: string }[] }, kind: string): string {
  const issue = err.issues[0];
  if (!issue) return `Invalid ${kind}`;
  const path = issue.path.length ? `${issue.path.map(String).join(".")}: ` : "";
  return `Invalid ${kind}. ${path}${issue.message}`;
}
