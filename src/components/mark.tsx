import { cn } from "@/lib/utils";

/** Rivet crosshair — same mark as rivlet.io */
export function RivletMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      className={cn("size-8 shrink-0 text-text", className)}
      fill="none"
      aria-hidden="true"
    >
      <circle cx="16" cy="16" r="12.5" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="16" cy="16" r="4.5" fill="#e8501a" />
      <line x1="16" y1="0.5" x2="16" y2="6.5" stroke="currentColor" strokeWidth="1.2" />
      <line x1="16" y1="25.5" x2="16" y2="31.5" stroke="currentColor" strokeWidth="1.2" />
      <line x1="0.5" y1="16" x2="6.5" y2="16" stroke="currentColor" strokeWidth="1.2" />
      <line x1="25.5" y1="16" x2="31.5" y2="16" stroke="currentColor" strokeWidth="1.2" />
      <path d="M8 24 L24 8" stroke="#e8501a" strokeWidth="1.2" strokeDasharray="2.5 2.5" />
    </svg>
  );
}
