import { useEffect } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { useCustodyStatus, useKeysStore } from "@/lib/traveler/keys-store";

/** Notices already raised as a toast, so one is never announced twice (a remount, a
 *  second mount). */
const announced = new Set<number>();

/** Raise a toast for anything that happened to this tab's key custody from outside it
 *  — another tab changed the keystore and this tab locked, the trust anchor was
 *  replaced elsewhere. Renders nothing. Mounted once, in the app shell, so it is heard
 *  on every route; the notice itself stays on the keys page until dismissed
 *  (`CustodyAlerts`). */
export function CustodyToasts() {
  const notices = useCustodyStatus((s) => s.notices);
  useEffect(() => {
    for (const n of notices) {
      if (announced.has(n.id)) continue;
      announced.add(n.id);
      toast.warning(n.summary, { duration: 20_000 });
    }
  }, [notices]);
  return null;
}

/** Standing alerts about this desk's key custody, for the keys page: a write the
 *  browser did not store (with a retry), and what other tabs did to this one. They
 *  stay until the condition clears or the person dismisses them. */
export function CustodyAlerts() {
  const storageError = useCustodyStatus((s) => s.storageError);
  const notices = useCustodyStatus((s) => s.notices);
  const dismissNotice = useCustodyStatus((s) => s.dismissNotice);
  const retrySave = useKeysStore((s) => s.retrySave);
  if (!storageError && notices.length === 0) return null;
  return (
    <div className="mb-6 grid gap-3">
      {storageError && (
        <div
          role="alert"
          data-testid="storage-error"
          className="on-paper rounded-sm border-2 border-danger px-4 py-3 text-sm"
        >
          <p className="font-mono text-xs font-semibold tracking-widest text-danger uppercase">
            Not saved
          </p>
          <p className="mt-1">
            {storageError} After a reload you would get the stored copy back: a one-time prekey
            used since then would be on disk again, and prekeys or an identity created since
            then would be gone.
          </p>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="mt-2"
            onClick={() => {
              if (retrySave()) toast.success("Saved");
              else toast.error("Still not saved — free up this site's storage and try again");
            }}
          >
            Retry saving
          </Button>
        </div>
      )}
      {notices.map((n) => (
        <div
          key={n.id}
          role="alert"
          data-testid="custody-notice"
          className="on-paper rounded-sm border-2 border-warn px-4 py-3 text-sm"
        >
          <p className="font-mono text-xs font-semibold tracking-widest uppercase">
            {n.kind === "trust-changed-elsewhere" ? "Trust anchor changed" : "Changed in another tab"}
          </p>
          <p className="mt-1">{n.message}</p>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="mt-1"
            onClick={() => dismissNotice(n.id)}
          >
            Dismiss
          </Button>
        </div>
      ))}
    </div>
  );
}
