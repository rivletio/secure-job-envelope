import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { shortHash } from "@/lib/traveler/hash";
import { cn } from "@/lib/utils";

export function HashChip({
  hash,
  className,
}: {
  hash: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* ignore */
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      title={hash}
      className={cn(
        "inline-flex max-w-full items-center gap-1.5 rounded-sm bg-wash px-2 py-1 font-mono text-xs text-foreground hover:bg-line",
        className,
      )}
    >
      <span className="truncate">{shortHash(hash)}</span>
      {copied ? <Check className="size-3 text-ok" /> : <Copy className="size-3 text-faint" />}
    </button>
  );
}
