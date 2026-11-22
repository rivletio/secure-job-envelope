import { useMemo } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { rootFingerprint } from "@/lib/traveler/fingerprint";
import {
  reviewTrustChange,
  useKeysStore,
  type TrustAnchorInput,
  type TrustReview,
} from "@/lib/traveler/keys-store";
import { cn } from "@/lib/utils";

/** The banner shown everywhere the DEMO trust anchor is the active one — the keys
 *  page, the authenticity panel, the seal dialog. Solid, high-contrast, and worded the
 *  same in all three: the anchor's keys are public, so nothing under it proves
 *  anything and nothing sealed to it is private. Whether the anchor IS the demo one is
 *  decided from its root key (`isDemoTrustRoot`), by the caller. */
export function DemoAnchorBanner({ className }: { className?: string }) {
  return (
    <div
      role="alert"
      data-testid="demo-anchor-banner"
      className={cn("rounded-sm border-2 border-ink bg-warn px-3 py-2 text-ink", className)}
    >
      <p className="font-mono text-xs font-semibold tracking-widest uppercase">
        Demo trust anchor — proves nothing
      </p>
      <p className="mt-1 text-sm leading-snug">
        The keys behind this anchor are <strong>public</strong>: they are printed in this
        project&apos;s source code. A signature that verifies under it{" "}
        <strong>proves nothing</strong> — anyone can produce one — and anything sealed to these
        recipients <strong>can be read by anyone</strong>. Use it only to try the desk.
      </p>
    </div>
  );
}

function copy(text: string, what: string) {
  void navigator.clipboard
    ?.writeText(text)
    .then(() => toast.success(`${what} copied`))
    .catch(() => toast.error("Copy failed"));
}

/** A trust root as a person can compare it: the short fingerprint, large and
 *  monospaced, with the full 5,184-character key still one click away. */
export function RootFingerprint({
  rootPublicKeyHex,
  label = "Root fingerprint",
}: {
  rootPublicKeyHex: string;
  label?: string;
}) {
  const fingerprint = rootFingerprint(rootPublicKeyHex);
  return (
    <div>
      <p className="text-xs text-muted-foreground">
        {label} — SHA-384 of the root public key, first 32 hex characters
      </p>
      <p
        data-testid="root-fingerprint"
        className="mt-1 rounded-sm bg-wash px-2 py-1.5 font-mono text-sm font-medium tracking-wide break-words"
      >
        {fingerprint}
      </p>
      <div className="mt-1 flex flex-wrap items-center gap-1">
        <Button type="button" size="sm" variant="ghost" onClick={() => copy(fingerprint, "Fingerprint")}>
          Copy fingerprint
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => copy(rootPublicKeyHex, "Full root key")}>
          Copy full key
        </Button>
      </div>
      <details className="mt-1">
        <summary className="cursor-pointer text-xs text-muted-foreground">
          Full root public key ({rootPublicKeyHex.length.toLocaleString("en-US")} hex characters)
        </summary>
        <code className="mt-1 block max-h-32 overflow-auto rounded-sm bg-wash p-2 font-mono text-xs break-all">
          {rootPublicKeyHex}
        </code>
      </details>
    </div>
  );
}

function Fingerprint({ value, tone }: { value: string; tone?: "old" | "new" }) {
  return (
    <span
      className={cn(
        "block rounded-sm px-2 py-1.5 font-mono text-sm font-medium tracking-wide break-words",
        tone === "old" ? "bg-wash text-muted-foreground" : "bg-wash",
      )}
    >
      {value}
    </span>
  );
}

const day = (iso: string) => iso.slice(0, 10);

/** What the person is asked to confirm, by kind of change. */
function ReviewBody({ review }: { review: TrustReview }) {
  const compare = review.root.demo ? (
    <p>
      This is the built-in demo anchor. There is nothing to compare its fingerprint with: its
      keys are public.
    </p>
  ) : (
    <p>
      <strong>Compare this fingerprint</strong> with one you obtained from the root&apos;s
      operator another way — a phone call, in person, a printed notice — not from the message
      that delivered this file. If they differ, cancel: whoever supplies the root supplies
      every verdict this desk will show.
    </p>
  );
  const memory =
    review.knownIssuedAt !== undefined ? (
      <p>
        This desk has accepted this root before. The newest directory it has seen under it was
        issued <span className="font-mono">{review.knownIssuedAt}</span>; an older one would be
        refused.
      </p>
    ) : (
      <p>
        This desk has <strong>no record of this root</strong> — a first load, or this
        browser&apos;s storage was cleared — so it cannot tell whether this is the newest
        directory the root has issued. Rollback protection starts with this load.
        {review.otherKnownRoots.length > 0 && (
          <>
            {" "}
            Roots it has accepted before:{" "}
            <span className="font-mono">{review.otherKnownRoots.join(" · ")}</span>. This is
            not one of them.
          </>
        )}
      </p>
    );
  const facts = (
    <p className="font-mono text-xs text-muted-foreground">
      directory issued {day(review.issuedAt)} · valid until {day(review.validUntil)} ·{" "}
      {review.entries} entr{review.entries === 1 ? "y" : "ies"}
      {review.bundles.kept.length > 0 && ` · ${review.bundles.kept.length} prekey bundle(s)`}
      {review.bundles.dropped.length > 0 &&
        ` · ${review.bundles.dropped.length} bundle(s) do not verify and will be dropped (${review.bundles.dropped.join(", ")})`}
    </p>
  );

  if (review.kind === "same-root") {
    const same = review.held?.issuedAt === review.issuedAt;
    return (
      <div className="grid gap-3 text-sm">
        <p>
          Same trust root as the one loaded — fingerprint{" "}
          <span className="font-mono">{review.root.fingerprint}</span>.{" "}
          {same ? (
            <>This is the directory already loaded (issued {day(review.issuedAt)}).</>
          ) : (
            <>
              The directory changes from the one issued{" "}
              <span className="font-mono">{review.held ? day(review.held.issuedAt) : "?"}</span>{" "}
              to a newer one issued <span className="font-mono">{day(review.issuedAt)}</span>.
            </>
          )}
        </p>
        {facts}
      </div>
    );
  }

  return (
    <div className="grid gap-3 text-sm">
      {review.root.demo && <DemoAnchorBanner />}
      {review.kind === "root-change" && review.held ? (
        <div className="grid gap-1" data-testid="root-change">
          <p className="text-xs text-muted-foreground">
            Current root{review.held.demo ? " (the DEMO root)" : ""}
          </p>
          <Fingerprint value={review.held.fingerprint} tone="old" />
          <p className="text-center font-mono text-xs text-muted-foreground" aria-hidden>
            ↓ replaced by
          </p>
          <p className="text-xs text-muted-foreground">
            New root{review.root.demo ? " (the DEMO root)" : ""}
          </p>
          <Fingerprint value={review.root.fingerprint} tone="new" />
          <p className="mt-2">
            <strong>Every verdict this desk shows, and every key it seals to, will depend on the
            new root</strong>{" "}
            from now on. Documents are judged by the new root&apos;s directory, not the current
            one&apos;s.
          </p>
        </div>
      ) : (
        <div className="grid gap-1">
          <p className="text-xs text-muted-foreground">
            Root fingerprint{review.root.demo ? " (the DEMO root)" : ""}
          </p>
          <Fingerprint value={review.root.fingerprint} tone="new" />
          <p className="mt-2">
            Every verdict this desk shows, and every key it seals to, will depend on this root.
          </p>
        </div>
      )}
      {compare}
      {memory}
      {facts}
    </div>
  );
}

/** The one way a trust anchor gets onto the desk: show what loading it would do —
 *  the root's fingerprint (old → new when a root is being replaced), what this desk
 *  remembers about it — and load it only on an explicit confirmation. An anchor that
 *  can never be loaded (its directory does not verify, or it is OLDER than one already
 *  accepted under the same root) is refused here, with the reason. */
export function TrustChangeDialog({
  proposal,
  onClose,
  onLoaded,
}: {
  proposal: TrustAnchorInput | null;
  /** The dialog is done with this proposal — loaded, cancelled or refused. */
  onClose: () => void;
  /** The proposal was confirmed and loaded (called before `onClose`). */
  onLoaded?: () => void;
}) {
  const trust = useKeysStore((s) => s.trust);
  const trustMarks = useKeysStore((s) => s.trustMarks);
  const setTrust = useKeysStore((s) => s.setTrust);

  const outcome = useMemo(() => {
    if (!proposal) return null;
    try {
      return { review: reviewTrustChange({ trust, trustMarks }, proposal) } as const;
    } catch (err) {
      return {
        refused: err instanceof Error ? err.message : "This trust anchor cannot be loaded.",
      } as const;
    }
  }, [proposal, trust, trustMarks]);

  function confirm(review: TrustReview) {
    if (!proposal) return;
    try {
      setTrust(proposal, { confirmedRoot: review.root.digest });
      if (review.root.demo) {
        toast.warning("Demo trust anchor loaded — it proves nothing and protects nothing");
      } else if (review.kind === "same-root") {
        toast.success("Directory loaded and verified");
      } else {
        toast.success(`Trust root ${review.root.fingerprint} loaded`);
      }
      onLoaded?.();
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not load trust anchor");
    }
  }

  const review = outcome && "review" in outcome ? outcome.review : null;
  const refused = outcome && "refused" in outcome ? outcome.refused : null;
  const title = refused
    ? "Trust anchor refused"
    : review?.kind === "root-change"
      ? "Replace the trust root?"
      : review?.kind === "same-root"
        ? "Load this directory?"
        : "Trust this root?";

  return (
    <Dialog
      open={proposal !== null}
      onOpenChange={(v) => {
        if (!v) onClose();
      }}
    >
      <DialogContent data-testid="trust-change-dialog">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {refused
              ? "Nothing was changed."
              : "Nothing is loaded until you confirm. The trust anchor decides what this desk calls verified and who it encrypts to."}
          </DialogDescription>
        </DialogHeader>
        <div className="mt-4">
          {refused && (
            <p
              role="alert"
              data-testid="trust-refused"
              className="rounded-sm border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger"
            >
              {refused}
            </p>
          )}
          {review && <ReviewBody review={review} />}
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            {refused ? "Close" : "Cancel"}
          </Button>
          {review && (
            <Button
              type="button"
              variant={review.kind === "root-change" ? "destructive" : "default"}
              onClick={() => confirm(review)}
            >
              {review.root.demo
                ? "Load the demo anchor"
                : review.kind === "root-change"
                  ? "Replace the root"
                  : review.kind === "same-root"
                    ? "Load directory"
                    : "The fingerprints match — trust this root"}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
