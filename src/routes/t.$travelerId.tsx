import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Download, FileJson, Lock, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { AuthenticityPanel } from "@/components/authenticity-panel";
import { AwardDialog } from "@/components/award-dialog";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { SealDialog } from "@/components/seal-dialog";
import { HashChip } from "@/components/hash-chip";
import { LevelBadge } from "@/components/level-badge";
import { QuoteDialog } from "@/components/quote-dialog";
import { QuoteTermsView } from "@/components/quote-terms";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { boundQuotes, levelOf, staleQuotes } from "@/lib/traveler/conformance";
import { formatDay, processLabel } from "@/lib/traveler/format";
import { awardStanding, itarExportWarning, lockedAtLevel } from "@/lib/traveler/guards";
import { travelerHash } from "@/lib/traveler/hash";
import { quoteTerms } from "@/lib/traveler/quote-terms";
import { useTravelerStore } from "@/lib/traveler/store";
import { TRAVELER_ID_RE, type Quote } from "@/lib/traveler/types";
import { downloadJson, downloadArchive } from "@/lib/traveler/zip";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/t/$travelerId")({ component: TravelerPage });

function TravelerPage() {
  const { travelerId } = Route.useParams();
  const traveler = useTravelerStore((s) => s.travelers.find((p) => p.traveler_id === travelerId));
  const hydrated = useTravelerStore((s) => s.hydrated);
  const role = useTravelerStore((s) => s.role);
  const seller = useTravelerStore((s) => s.seller());
  const logAudit = useTravelerStore((s) => s.logAudit);
  const remove = useTravelerStore((s) => s.remove);
  const navigate = useNavigate();
  const [quoteOpen, setQuoteOpen] = useState(false);
  const [awardOpen, setAwardOpen] = useState(false);
  const [sealOpen, setSealOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [pick, setPick] = useState<Quote | null>(null);
  const [itarExport, setItarExport] = useState<"zip" | "json" | null>(null);

  if (!traveler) {
    // A well-formed id we simply have not rehydrated yet is "loading", not "gone".
    if (!hydrated && TRAVELER_ID_RE.test(travelerId)) {
      return (
        <AppShell>
          <p className="text-sm text-muted-foreground">Loading traveler {travelerId}…</p>
        </AppShell>
      );
    }
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">No traveler {travelerId} on this desk.</p>
        <Button asChild variant="outline" className="mt-4">
          <Link to="/">Back to desk</Link>
        </Button>
      </AppShell>
    );
  }

  const info = levelOf(traveler);
  // One lock, one award standing: every badge, button and notice below reads these
  // two, so the page cannot say "Executable" in one place and "L1" in another.
  const isLocked = lockedAtLevel(info);
  const standing = awardStanding(traveler);
  const hash = travelerHash(traveler);
  const bound = boundQuotes(traveler);
  const stale = staleQuotes(traveler);
  const alreadyQuoted = bound.some((q) => q.seller.org_id === seller.org_id);
  const current = traveler;
  const quoteCount = traveler.quotes?.length ?? 0;

  function runExport(kind: "zip" | "json") {
    // Audit the export only once it actually produced a file (the zip path is async
    // and can reject) — otherwise a failed export leaves a phantom entry in the
    // append-only log. Mirrors SealDialog, which logs after downloadEnvelope succeeds.
    if (kind === "zip") {
      void downloadArchive(current)
        .then(() => {
          logAudit({ act: "export", traveler_id: current.traveler_id, hash });
          toast.success("Exported .traveler.zip");
        })
        .catch((err) => toast.error(err instanceof Error ? err.message : "Export failed"));
    } else {
      downloadJson(current);
      logAudit({ act: "export", traveler_id: current.traveler_id, hash });
    }
  }

  function requestExport(kind: "zip" | "json") {
    if (itarExportWarning(current)) setItarExport(kind);
    else runExport(kind);
  }

  function deleteTraveler() {
    remove(current.traveler_id);
    toast.success(`Deleted ${current.traveler_id} from this desk`);
    void navigate({ to: "/" });
  }

  return (
    <AppShell>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs text-faint">{traveler.traveler_id}</p>
          <h1 className="mt-1 text-3xl tracking-tight text-paper">{traveler.part.family}</h1>
          <p className="text-sm text-soft">
            {traveler.part.part_number}
            {traveler.part.drawing_rev ? ` · drawing ${traveler.part.drawing_rev}` : ""} · r
            {traveler.revision}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <LevelBadge info={info} />
          {role === "seller" && info.code !== "D" && (
            <Button type="button" onClick={() => setQuoteOpen(true)} disabled={alreadyQuoted}>
              {alreadyQuoted ? "Quoted" : "Quote this hash"}
            </Button>
          )}
          <Button type="button" onClick={() => setSealOpen(true)}>
            <Lock className="size-4" />
            Seal &amp; send
          </Button>
          <Button
            type="button"
            variant="outline"
            title="Local copy — not for sending (plaintext)"
            onClick={() => requestExport("zip")}
          >
            <Download className="size-4" />
            Local .zip
          </Button>
          <Button
            type="button"
            variant="ghost"
            title="Local copy — not for sending (plaintext)"
            onClick={() => requestExport("json")}
          >
            <FileJson className="size-4" />
            Local JSON
          </Button>
          <Button type="button" variant="ghost" onClick={() => setDeleteOpen(true)}>
            <Trash2 className="size-4" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_18rem]">
        <div className="grid gap-6">
          <section className="on-paper traveler-shadow rounded-sm p-5">
            <h2 className="text-sm font-medium">Quoteable body</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Sellers bind to this hash. Amend material or qty and every quote goes stale.
            </p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <Fact
                k="Buyer"
                v={`${traveler.buyer.name}${traveler.buyer.region ? ` · ${traveler.buyer.city}, ${traveler.buyer.region}` : ""}`}
              />
              <Fact
                k="Material"
                v={`${traveler.part.material.spec}${traveler.part.material.form ? ` ${traveler.part.material.form}` : ""}${traveler.part.material.thickness_mm ? ` ${traveler.part.material.thickness_mm} mm` : ""}`}
              />
              <Fact
                k="Qty"
                v={`${traveler.part.qty.target}${traveler.part.qty.breaks?.length ? ` · breaks ${traveler.part.qty.breaks.join("/")}` : ""}`}
              />
              <Fact k="Need by" v={formatDay(traveler.need_by)} />
              <Fact k="Finish" v={traveler.part.finish ?? "—"} />
              <Fact k="Tolerances" v={traveler.part.tolerances ?? "—"} />
              <Fact
                k="ITAR"
                v={traveler.itar ? "Self-declared — not an access-control system" : "No"}
              />
              <Fact k="Incoterms" v={traveler.incoterms ?? "—"} />
            </div>
            {traveler.part.processes?.length ? (
              <p className="mt-4 font-mono text-xs text-muted-foreground">
                {traveler.part.processes.map(processLabel).join(" · ")}
              </p>
            ) : null}
            {traveler.part.description && (
              <p className="mt-3 text-sm leading-relaxed">{traveler.part.description}</p>
            )}
            {traveler.part.notes && (
              <p className="mt-2 text-sm text-muted-foreground">{traveler.part.notes}</p>
            )}
          </section>

          <section className="on-paper traveler-shadow rounded-sm p-5">
            <div className="flex items-baseline justify-between gap-2">
              <h2 className="text-sm font-medium">Quotes bound to this hash</h2>
              <span className="font-mono text-xs text-muted-foreground">{bound.length}</span>
            </div>
            {bound.length === 0 ? (
              <p className="mt-3 text-sm text-muted-foreground">
                None yet. Switch to Seller to bind a structured quote.
              </p>
            ) : (
              <ul className="mt-3 grid gap-3">
                {bound.map((q) => {
                  // The award on file names this quote. Whether that award is in
                  // effect is `standing`'s call, not this card's.
                  const named = standing.state !== "none" && traveler.award?.quote_id === q.quote_id;
                  const awarded = named && standing.state === "in-effect";
                  // The awarded quote is totalled at the quantity it was awarded for;
                  // any other at the target quantity, which is what an award would be for.
                  const qty = awarded && traveler.award ? traveler.award.qty : traveler.part.qty.target;
                  return (
                    <li
                      key={q.quote_id}
                      className={cn(
                        "rounded-sm border p-4",
                        awarded ? "border-accent bg-accent/10" : "border-border",
                      )}
                    >
                      <QuoteTermsView terms={quoteTerms(q, qty)} />
                      {role === "buyer" && !isLocked && (
                        <Button
                          type="button"
                          size="sm"
                          className="mt-4"
                          variant={named ? "secondary" : "default"}
                          onClick={() => {
                            setPick(q);
                            setAwardOpen(true);
                          }}
                        >
                          Award
                        </Button>
                      )}
                      {awarded && (
                        <p className="mt-3 font-mono text-xs text-accent">Awarded · qty {qty}</p>
                      )}
                      {named && standing.state === "incomplete" && (
                        <p className="mt-3 text-xs text-warn">
                          An award for this quote is on file, but the traveler is not executable
                          yet — still missing {standing.missing.join(", ")}.
                        </p>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {stale.length > 0 && (
              <p className="mt-4 text-xs text-warn">
                {stale.length} stale quote{stale.length === 1 ? "" : "s"} from a prior revision —
                hash no longer matches.
              </p>
            )}
            {standing.state === "void" && (
              <p className="mt-4 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-foreground">
                This traveler carries an award naming quote{" "}
                <span className="font-mono">{standing.quote_id}</span>, which is{" "}
                {standing.reason === "stale"
                  ? "stale — not bound to the current revision"
                  : "not on this traveler"}
                . That award is not in effect and locks nothing: the traveler is {info.code}{" "}
                {info.name}, and can still be quoted, amended and awarded.
              </p>
            )}
          </section>

          {(traveler.ops?.length || traveler.ship_to) && (
            <section className="on-paper traveler-shadow rounded-sm p-5">
              <h2 className="text-sm font-medium">
                {isLocked ? "Executable" : "Ops and ship-to on file"}
              </h2>
              {!isLocked && (
                <p className="mt-1 text-sm text-muted-foreground">
                  Not executable — this traveler is {info.code} {info.name}. Still missing:{" "}
                  {info.missing.join(", ")}.
                </p>
              )}
              {standing.state === "in-effect" && (
                <p className="mt-2 text-sm">
                  Awarded to <bdi>{standing.quote.seller.name}</bdi> on{" "}
                  {formatDay(traveler.award?.awarded_at)} · qty {traveler.award?.qty}
                </p>
              )}
              {traveler.ship_to && (
                <p className="mt-2 text-sm text-muted-foreground">
                  Ship-to {traveler.ship_to.name}, {traveler.ship_to.line1}, {traveler.ship_to.city},{" "}
                  {traveler.ship_to.region} {traveler.ship_to.postal}
                </p>
              )}
              {traveler.ops?.length ? (
                <ol className="mt-4 grid gap-1">
                  {traveler.ops.map((op) => (
                    <li key={op.seq} className="flex gap-3 font-mono text-sm">
                      <span className="w-6 text-faint">{String(op.seq).padStart(2, "0")}</span>
                      <span className="font-medium">{op.code}</span>
                      {op.notes && <span className="text-muted-foreground">{op.notes}</span>}
                    </li>
                  ))}
                </ol>
              ) : null}
            </section>
          )}
        </div>

        <aside className="grid h-fit gap-4 lg:sticky lg:top-28">
          <div className="on-paper traveler-shadow rounded-sm p-4">
            <p className="font-mono text-xs text-muted-foreground">traveler_hash</p>
            <HashChip hash={hash} className="mt-2 w-full justify-between" />
            <Separator className="my-4" />
            <Checklist infoCode={info.code} missing={info.missing} locked={isLocked} />
          </div>
          <AuthenticityPanel traveler={traveler} />
        </aside>
      </div>

      <QuoteDialog traveler={traveler} open={quoteOpen} onOpenChange={setQuoteOpen} />
      <SealDialog traveler={traveler} open={sealOpen} onOpenChange={setSealOpen} />
      <AwardDialog
        traveler={traveler}
        quote={pick}
        open={awardOpen}
        onOpenChange={setAwardOpen}
      />
      <ConfirmDialog
        open={Boolean(itarExport)}
        onOpenChange={(v) => {
          if (!v) setItarExport(null);
        }}
        title="ITAR self-declaration"
        body="This traveler is self-declared ITAR. The desk does not implement export-control. Download from this local desk anyway?"
        confirmLabel="Download anyway"
        destructive
        onConfirm={() => {
          if (itarExport) runExport(itarExport);
          setItarExport(null);
        }}
      />
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${traveler.traveler_id}?`}
        body={
          isLocked
            ? `${traveler.traveler_id} is ${info.code} ${info.name} — an executable, locked traveler carrying the award, the ops and the ship-to. Deleting it removes this desk's copy and cannot be undone. It does not cancel the award, and it does not reach any copy another party holds. Export it first if you need the record.`
            : `This removes ${traveler.traveler_id} (${traveler.part.family}, ${traveler.part.part_number}, revision ${traveler.revision}) and the ${quoteCount} quote${quoteCount === 1 ? "" : "s"} on it from this desk. It cannot be undone — the desk keeps no copy. Export it first if you may need it again. Copies other parties hold are not affected.`
        }
        confirmLabel={`Delete ${traveler.traveler_id}`}
        destructive
        onConfirm={deleteTraveler}
      />
    </AppShell>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{k}</dt>
      <dd className="text-sm">{v}</dd>
    </div>
  );
}

function Checklist({
  infoCode,
  missing,
  locked,
}: {
  infoCode: string;
  missing: string[];
  locked: boolean;
}) {
  const rows = [
    { code: "L0", label: "Material + qty" },
    { code: "L1", label: "Bound quote" },
    { code: "L2", label: "Award, ops, ship-to" },
    { code: "L3", label: "As-built" },
  ];
  const here = ["D", "L0", "L1", "L2", "L3"].indexOf(infoCode);
  return (
    <ul className="grid gap-2 text-sm">
      {rows.map((r, i) => {
        const done = here > i || infoCode === r.code;
        return (
          <li key={r.code} className="flex items-center gap-2">
            <span className={cn("size-2 rounded-full", done ? "bg-accent" : "bg-line")} />
            <span className={done ? "text-foreground" : "text-muted-foreground"}>
              <span className="font-mono text-xs">{r.code}</span> {r.label}
            </span>
          </li>
        );
      })}
      {!locked && missing.length > 0 && (
        <li className="pt-1 text-xs text-muted-foreground">Next: {missing[0]}</li>
      )}
    </ul>
  );
}
