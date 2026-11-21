import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { useKeysStore } from "@/lib/traveler/keys-store";
import {
  verifyTravelerSignatures,
  verifyAwardSignature,
  verifyQuoteSignature,
} from "@/lib/traveler/authenticity";
import type { Traveler } from "@/lib/traveler/types";
import { cn } from "@/lib/utils";

type Status = "ok" | "warn" | "bad";
type Row = { label: string; status: Status; detail: string };

/** Verify-on-receive for the desk: check a traveler's buyer authorship signature,
 *  the buyer's award signature (award + ship-to), and each seller quote signature
 *  against the loaded trust anchor, and show the verdicts — so a desk user can tell
 *  a genuine quote / award from a spoofed one. The desk only ever verifies; signing
 *  happens off the desk (it holds no signing keys). */
export function AuthenticityPanel({ traveler }: { traveler: Traveler }) {
  const trust = useKeysStore((s) => s.trust);
  const hydrated = useKeysStore((s) => s.hydrated);

  const rows = useMemo<Row[] | null>(() => {
    if (!trust) return null;
    const { directory, rootPublicKeyHex } = trust;
    const out: Row[] = [];

    // Buyer authorship over the quoteable body.
    const sigs = verifyTravelerSignatures(traveler, directory, rootPublicKeyHex);
    const okAuthor = sigs.find((s) => s.ok);
    if (okAuthor) {
      out.push({ label: "Author", status: "ok", detail: `Signed by ${okAuthor.org_id}` });
    } else if ((traveler.signatures?.length ?? 0) === 0) {
      out.push({ label: "Author", status: "warn", detail: "Not signed" });
    } else {
      out.push({ label: "Author", status: "bad", detail: sigs[0]?.reason ?? "Signature invalid" });
    }

    // Buyer's award signature (award decision + ship-to). Only when an award exists.
    const award = verifyAwardSignature(traveler, directory, rootPublicKeyHex);
    if (award !== undefined) {
      if (award.ok) {
        out.push({ label: "Award", status: "ok", detail: `Buyer-signed by ${award.org_id}` });
      } else if (/not signed/.test(award.reason ?? "")) {
        out.push({ label: "Award", status: "warn", detail: "Not signed by the buyer" });
      } else {
        out.push({ label: "Award", status: "bad", detail: award.reason ?? "Signature invalid" });
      }
    }

    // Each seller quote signature.
    for (const q of traveler.quotes ?? []) {
      const seller = q.seller.name || q.seller.org_id || "seller";
      const c = verifyQuoteSignature(q, directory, rootPublicKeyHex);
      if (c === undefined) {
        out.push({ label: `Quote · ${seller}`, status: "warn", detail: "Not signed" });
      } else if (c.ok) {
        out.push({ label: `Quote · ${seller}`, status: "ok", detail: `Signed by ${c.org_id}` });
      } else {
        out.push({ label: `Quote · ${seller}`, status: "bad", detail: c.reason ?? "Signature invalid" });
      }
    }
    return out;
  }, [traveler, trust]);

  return (
    <div className="on-paper traveler-shadow rounded-sm p-4">
      <p className="font-mono text-xs text-muted-foreground">Authenticity</p>
      {!hydrated ? (
        <p className="mt-2 text-sm text-muted-foreground">Checking…</p>
      ) : rows === null ? (
        <p className="mt-2 text-sm text-muted-foreground">
          Load a trust anchor in{" "}
          <Link to="/keys" className="underline underline-offset-2 hover:text-accent">
            Keys
          </Link>{" "}
          to verify these signatures against the signed directory.
        </p>
      ) : (
        <ul className="mt-2 grid gap-2">
          {rows.map((r) => (
            <li key={r.label} className="flex items-start gap-2 text-sm">
              <StatusIcon status={r.status} />
              <span>
                <span className="font-medium">{r.label}:</span>{" "}
                <span className={cn(r.status === "bad" && "text-warn")}>{r.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: Status }) {
  if (status === "ok") return <ShieldCheck className="mt-0.5 size-4 shrink-0 text-accent" />;
  if (status === "bad") return <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />;
  return <ShieldQuestion className="mt-0.5 size-4 shrink-0 text-muted-foreground" />;
}
