import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/** What the reader is asked before a received traveler is stored.
 *
 *  The receive policy (import-policy.ts) admits some travelers only after the reader has
 *  acknowledged what is unproven about them — an award nobody signed, a new revision of
 *  the part that nothing ties to the buyer. Each statement gets its own checkbox, and the
 *  traveler is stored only once every one of them is ticked: a single "OK" on a wall of
 *  text is how a forged ship-to address gets acted on. */
export function ImportReviewDialog({
  review,
  onCancel,
  onConfirm,
}: {
  review: { travelerId: string; notes: string[]; statements: string[] } | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [ticked, setTicked] = useState<boolean[]>([]);
  useEffect(() => {
    setTicked((review?.statements ?? []).map(() => false));
  }, [review]);
  const statements = review?.statements ?? [];
  const ready = statements.length > 0 && statements.every((_, i) => ticked[i]);

  return (
    <Dialog
      open={review !== null}
      onOpenChange={(v) => {
        if (!v) onCancel();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Before this traveler is opened</DialogTitle>
          <DialogDescription>
            <span className="font-mono">{review?.travelerId}</span> — read each statement. Nothing
            is stored until you confirm.
          </DialogDescription>
        </DialogHeader>
        {review && review.notes.length > 0 && (
          <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
            {review.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
        <div className="mt-3 flex flex-col gap-3">
          {statements.map((s, i) => (
            <label
              key={s}
              className="flex items-start gap-3 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-sm text-warn"
            >
              <input
                type="checkbox"
                checked={ticked[i] ?? false}
                onChange={(e) => setTicked((t) => t.map((v, k) => (k === i ? e.target.checked : v)))}
                className="mt-0.5 size-4 shrink-0 accent-primary"
              />
              <span>{s}</span>
            </label>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <Button type="button" variant="outline" onClick={onCancel}>
            Don&apos;t open
          </Button>
          <Button type="button" variant="destructive" disabled={!ready} onClick={onConfirm}>
            I have read this — open it
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
