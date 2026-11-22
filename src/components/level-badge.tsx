import { Badge } from "@/components/ui/badge";
import type { LevelInfo } from "@/lib/traveler/conformance";
import { lockedAtLevel } from "@/lib/traveler/guards";
import { cn } from "@/lib/utils";

export function LevelBadge({
  info,
  className,
}: {
  info: LevelInfo;
  className?: string;
}) {
  // The filled badge is the locked (executable) look — asked of the one lock
  // definition, not re-derived from level codes here.
  const variant = lockedAtLevel(info)
    ? "default"
    : info.code === "L1"
      ? "mill"
      : info.code === "L0"
        ? "outline"
        : "paper";
  return (
    <Badge variant={variant} className={cn("uppercase", className)}>
      {info.code} {info.name}
    </Badge>
  );
}

export function LevelStamp({ info }: { info: LevelInfo }) {
  const filled = lockedAtLevel(info);
  return (
    <div
      className={cn(
        "flex h-full min-w-14 flex-col items-center justify-center gap-1 px-2 py-3 font-mono",
        filled ? "bg-primary text-primary-foreground" : "bg-wash text-foreground",
        info.code === "L1" && "bg-accent/15 text-accent",
      )}
    >
      <span className="text-lg font-medium tracking-tight">{info.code}</span>
      <span className="text-xs leading-none tracking-wide uppercase opacity-80">
        {info.name}
      </span>
    </div>
  );
}
