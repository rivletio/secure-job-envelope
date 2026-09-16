import { Link } from "@tanstack/react-router";
import { LevelStamp } from "@/components/level-badge";
import { HashChip } from "@/components/hash-chip";
import { boundQuotes, levelOf } from "@/lib/packet/conformance";
import { formatDay } from "@/lib/packet/format";
import { packetHash } from "@/lib/packet/hash";
import type { Packet } from "@/lib/packet/types";
import { cn } from "@/lib/utils";

export function PacketCard({ packet }: { packet: Packet }) {
  const info = levelOf(packet);
  const quotes = boundQuotes(packet);
  const hash = packetHash(packet);
  return (
    <Link
      to="/p/$packetId"
      params={{ packetId: packet.packet_id }}
      className={cn(
        "on-paper traveler-shadow group flex overflow-hidden rounded-sm",
      )}
    >
      <LevelStamp info={info} />
      <div className="flex min-w-0 flex-1 flex-col gap-2 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-mono text-xs text-muted-foreground">
              {packet.part.part_number}
              {packet.part.drawing_rev ? ` · rev ${packet.part.drawing_rev}` : ""}
            </p>
            <h2 className="truncate text-base font-medium tracking-tight">
              {packet.part.family}
            </h2>
          </div>
          <span className="shrink-0 font-mono text-xs text-faint">r{packet.revision}</span>
        </div>
        <p className="text-sm text-muted-foreground">
          {packet.buyer.name}
          {packet.buyer.region ? ` · ${packet.buyer.city}, ${packet.buyer.region}` : ""}
        </p>
        <p className="text-sm">
          <span className="font-medium">{packet.part.material.spec}</span>
          <span className="text-muted-foreground">
            {" "}
            · qty {packet.part.qty.target}
            {packet.need_by ? ` · need ${formatDay(packet.need_by)}` : ""}
          </span>
        </p>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <HashChip hash={hash} />
          <span className="font-mono text-xs text-muted-foreground">
            {quotes.length} bound quote{quotes.length === 1 ? "" : "s"}
          </span>
        </div>
      </div>
    </Link>
  );
}
