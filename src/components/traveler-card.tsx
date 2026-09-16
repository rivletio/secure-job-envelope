import { Link } from "@tanstack/react-router";
import { LevelStamp } from "@/components/level-badge";
import { HashChip } from "@/components/hash-chip";
import { boundQuotes, levelOf } from "@/lib/traveler/conformance";
import { formatDay } from "@/lib/traveler/format";
import { travelerHash } from "@/lib/traveler/hash";
import type { Traveler } from "@/lib/traveler/types";
import { cn } from "@/lib/utils";

export function TravelerCard({ traveler }: { traveler: Traveler }) {
  const info = levelOf(traveler);
  const quotes = boundQuotes(traveler);
  const hash = travelerHash(traveler);
  return (
    <Link
      to="/t/$travelerId"
      params={{ travelerId: traveler.traveler_id }}
      className={cn(
        "on-paper traveler-shadow group flex overflow-hidden rounded-sm",
      )}
    >
      <LevelStamp info={info} />
      <div className="flex min-w-0 flex-1 flex-col gap-2 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-mono text-xs text-muted-foreground">
              {traveler.part.part_number}
              {traveler.part.drawing_rev ? ` · rev ${traveler.part.drawing_rev}` : ""}
            </p>
            <h2 className="truncate text-base font-medium tracking-tight">
              {traveler.part.family}
            </h2>
          </div>
          <span className="shrink-0 font-mono text-xs text-faint">r{traveler.revision}</span>
        </div>
        <p className="text-sm text-muted-foreground">
          {traveler.buyer.name}
          {traveler.buyer.region ? ` · ${traveler.buyer.city}, ${traveler.buyer.region}` : ""}
        </p>
        <p className="text-sm">
          <span className="font-medium">{traveler.part.material.spec}</span>
          <span className="text-muted-foreground">
            {" "}
            · qty {traveler.part.qty.target}
            {traveler.need_by ? ` · need ${formatDay(traveler.need_by)}` : ""}
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
