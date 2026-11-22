import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { DemoAnchorBanner } from "@/components/trust-notices";
import { useKeysStore } from "@/lib/traveler/keys-store";
import {
  authenticityView,
  VERDICT_MEANING,
  type VerdictRow,
  type VerdictStatus,
} from "@/lib/traveler/authenticity-view";
import type { Traveler } from "@/lib/traveler/types";
import { cn } from "@/lib/utils";

/** Verify-on-receive for the desk: check a traveler's buyer authorship signature,
 *  the buyer's award signature (award + ship-to), and each seller quote signature
 *  against the loaded trust anchor, and show the verdicts — so a desk user can tell
 *  a genuine quote / award from a spoofed one. The desk only ever verifies; signing
 *  happens off the desk (it holds no signing keys).
 *
 *  What is drawn, and at what level, is decided in `authenticityView` (tested there):
 *  the identity shown for a passed check is the directory's org_id + kid; the
 *  document's own names are labelled self-asserted; under the DEMO anchor a passed
 *  check is a warning that proves nothing; and every string from a document or a
 *  directory has its invisible characters made visible. Each such string is also
 *  drawn in its own `<bdi>`, so a name in a right-to-left script cannot reorder the
 *  text around it. */
export function AuthenticityPanel({ traveler }: { traveler: Traveler }) {
  const trust = useKeysStore((s) => s.trust);
  const hydrated = useKeysStore((s) => s.hydrated);

  const view = useMemo(() => (trust ? authenticityView(traveler, trust) : null), [traveler, trust]);

  return (
    <div className="on-paper traveler-shadow rounded-sm p-4" data-testid="authenticity-panel">
      <p className="font-mono text-xs text-muted-foreground">Authenticity</p>
      {!hydrated ? (
        <p className="mt-2 text-sm text-muted-foreground">Checking…</p>
      ) : view === null ? (
        <p className="mt-2 text-sm text-muted-foreground">
          Load a trust anchor in{" "}
          <Link to="/keys" className="underline underline-offset-2 hover:text-accent">
            Keys
          </Link>{" "}
          to verify these signatures against the signed directory.
        </p>
      ) : (
        <>
          {view.demo && <DemoAnchorBanner className="mt-2" />}
          <ul className="mt-3 grid gap-3">
            {view.rows.map((r) => (
              <Verdict key={r.key} row={r} />
            ))}
          </ul>
          <p className="mt-3 border-t border-border pt-2 text-xs leading-snug text-muted-foreground">
            {VERDICT_MEANING}
          </p>
          <p className="mt-2 font-mono text-xs text-muted-foreground">
            trust root {view.rootFingerprint}
            {view.demo ? " (DEMO)" : ""} ·{" "}
            <Link to="/keys" className="underline underline-offset-2 hover:text-accent">
              Keys
            </Link>
          </p>
        </>
      )}
    </div>
  );
}

function Verdict({ row }: { row: VerdictRow }) {
  return (
    <li className="flex items-start gap-2 text-sm" data-testid="verdict" data-status={row.status}>
      <StatusIcon status={row.status} />
      <div className="min-w-0">
        <p>
          <span className="font-medium">
            <bdi>{row.label}</bdi>:
          </span>{" "}
          <span
            className={cn(
              row.status === "bad" && "text-danger",
              row.status === "warn" && row.signer && "font-medium",
            )}
          >
            {row.verdict}
          </span>
        </p>
        {row.signer && (
          // The identity the check established: what the DIRECTORY binds to the key.
          <p className="mt-0.5 font-mono text-xs break-words" data-testid="verdict-signer">
            <span className="text-muted-foreground">signed by </span>
            <bdi className="font-semibold">{row.signer.org_id}</bdi>
            <span className="text-muted-foreground"> · key </span>
            <bdi>{row.signer.kid}</bdi>
          </p>
        )}
        {row.claimed && (
          // What the document says about itself: shown, labelled, never the headline.
          <p className="mt-0.5 text-xs break-words text-muted-foreground" data-testid="verdict-claimed">
            {row.signer ? "document names itself " : "document claims "}
            {!row.signer && row.claimed.org_id && (
              <>
                <bdi className="font-mono">{row.claimed.org_id}</bdi>,{" "}
              </>
            )}
            &ldquo;<bdi>{row.claimed.name}</bdi>&rdquo;{" "}
            <span className="whitespace-nowrap">— self-asserted, not verified</span>
          </p>
        )}
      </div>
    </li>
  );
}

function StatusIcon({ status }: { status: VerdictStatus }) {
  // The desk's semantic status tokens: ok = --color-ok (blue, the app's success
  // signal), warn = --color-warn (amber caution), bad = --color-danger (the same
  // red-orange the quote/award dialogs use for errors). Verified must not reuse
  // --color-accent, which is identical to --color-danger — a verified signature
  // can't look like an error.
  if (status === "ok") return <ShieldCheck className="mt-0.5 size-4 shrink-0 text-ok" />;
  if (status === "bad") return <ShieldAlert className="mt-0.5 size-4 shrink-0 text-danger" />;
  return <ShieldQuestion className="mt-0.5 size-4 shrink-0 text-warn" />;
}
