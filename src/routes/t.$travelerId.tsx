import { createFileRoute, Link } from "@tanstack/react-router";
import { Download, FileJson } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { AwardDialog } from "@/components/award-dialog";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { HashChip } from "@/components/hash-chip";
import { LevelBadge } from "@/components/level-badge";
import { QuoteDialog } from "@/components/quote-dialog";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { boundQuotes, levelOf, staleQuotes } from "@/lib/traveler/conformance";
import { formatDay, money, processLabel, quoteTotal } from "@/lib/traveler/format";
import { itarExportWarning } from "@/lib/traveler/guards";
import { travelerHash } from "@/lib/traveler/hash";
import { useTravelerStore } from "@/lib/traveler/store";
import type { Quote } from "@/lib/traveler/types";
import { downloadJson, downloadRivpkt } from "@/lib/traveler/zip";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/t/$travelerId")({ component: TravelerPage });

function TravelerPage() {
  const { travelerId } = Route.useParams();
  const traveler = useTravelerStore((s) => s.travelers.find((p) => p.traveler_id === travelerId));
  const role = useTravelerStore((s) => s.role);
  const seller = useTravelerStore((s) => s.seller());
  const logAudit = useTravelerStore((s) => s.logAudit);
  const [quoteOpen, setQuoteOpen] = useState(false);
  const [awardOpen, setAwardOpen] = useState(false);
  const [pick, setPick] = useState<Quote | null>(null);
  const [itarExport, setItarExport] = useState<"zip" | "json" | null>(null);

  if (!traveler) {
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
  const hash = travelerHash(traveler);
  const bound = boundQuotes(traveler);
  const stale = staleQuotes(traveler);
  const awarded = bound.find((q) => q.quote_id === traveler.award?.quote_id);
  const alreadyQuoted = bound.some((q) => q.seller.org_id === seller.org_id);
  const current = traveler;

  function runExport(kind: "zip" | "json") {
    logAudit({ act: "export", traveler_id: current.traveler_id, hash });
    if (kind === "zip") {
      void downloadRivpkt(current).then(() => toast.success("Exported .traveler.zip"));
    } else {
      downloadJson(current);
    }
  }

  function requestExport(kind: "zip" | "json") {
    if (itarExportWarning(current)) setItarExport(kind);
    else runExport(kind);
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
          <Button type="button" variant="outline" onClick={() => requestExport("zip")}>
            <Download className="size-4" />
            .traveler.zip
          </Button>
          <Button type="button" variant="ghost" onClick={() => requestExport("json")}>
            <FileJson className="size-4" />
            JSON
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
                  const selected = traveler.award?.quote_id === q.quote_id;
                  const target =
                    q.pricing.lines.find((l) => l.qty === traveler.part.qty.target) ??
                    q.pricing.lines[0];
                  const total = quoteTotal(
                    q.pricing.lines,
                    q.pricing.nre ?? 0,
                    q.pricing.freight_estimate ?? 0,
                    traveler.part.qty.target,
                  );
                  return (
                    <li
                      key={q.quote_id}
                      className={cn(
                        "rounded-sm border p-4",
                        selected ? "border-accent bg-accent/10" : "border-border",
                      )}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <p className="font-medium">{q.seller.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {q.seller.certs?.join(" · ")}
                            {q.seller.itar ? " · ITAR" : ""}
                          </p>
                        </div>
                        <p className="font-mono text-sm tabular-nums">
                          {target ? money(target.unit, q.pricing.currency) : "—"}
                          <span className="text-muted-foreground"> /ea</span>
                        </p>
                      </div>
                      <dl className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                        <Fact k="Lead" v={`${q.lead_time_days}d`} />
                        <Fact k="NRE" v={money(q.pricing.nre ?? 0, q.pricing.currency)} />
                        <Fact k="Need-by" v={q.need_by_feasible ? "feasible" : "not feasible"} />
                        <Fact k="Rollup" v={money(total, q.pricing.currency)} />
                      </dl>
                      <div className="mt-3 flex flex-wrap gap-2 font-mono text-xs text-muted-foreground">
                        {q.pricing.lines.map((l) => (
                          <span key={l.qty}>
                            {l.qty} @ {money(l.unit, q.pricing.currency)}
                          </span>
                        ))}
                      </div>
                      {q.exceptions?.map((ex) => (
                        <p key={ex.code} className="mt-2 text-xs text-warn">
                          {ex.code}: {ex.proposal}
                        </p>
                      ))}
                      {role === "buyer" && info.level < 2 && (
                        <Button
                          type="button"
                          size="sm"
                          className="mt-3"
                          variant={selected ? "secondary" : "default"}
                          onClick={() => {
                            setPick(q);
                            setAwardOpen(true);
                          }}
                        >
                          Award
                        </Button>
                      )}
                      {selected && (
                        <p className="mt-2 font-mono text-xs text-accent">Awarded</p>
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
          </section>

          {(traveler.ops?.length || traveler.ship_to) && (
            <section className="on-paper traveler-shadow rounded-sm p-5">
              <h2 className="text-sm font-medium">Executable</h2>
              {awarded && (
                <p className="mt-2 text-sm">
                  Awarded to {awarded.seller.name} on {formatDay(traveler.award?.awarded_at)} · qty{" "}
                  {traveler.award?.qty}
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
            <Checklist infoCode={info.code} missing={info.missing} />
          </div>
        </aside>
      </div>

      <QuoteDialog traveler={traveler} open={quoteOpen} onOpenChange={setQuoteOpen} />
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

function Checklist({ infoCode, missing }: { infoCode: string; missing: string[] }) {
  const rows = [
    { code: "L0", label: "Material + qty" },
    { code: "L1", label: "Bound quote" },
    { code: "L2", label: "Award, ops, ship-to" },
    { code: "L3", label: "As-built (reserved)" },
  ];
  const here = ["D", "L0", "L1", "L2", "L3"].indexOf(infoCode);
  return (
    <ul className="grid gap-2 text-sm">
      {rows.map((r, i) => {
        const done = here > i || (infoCode === r.code && r.code !== "L3");
        return (
          <li key={r.code} className="flex items-center gap-2">
            <span className={cn("size-2 rounded-full", done ? "bg-accent" : "bg-line")} />
            <span className={done ? "text-foreground" : "text-muted-foreground"}>
              <span className="font-mono text-xs">{r.code}</span> {r.label}
            </span>
          </li>
        );
      })}
      {infoCode !== "L2" && infoCode !== "L3" && missing.length > 0 && (
        <li className="pt-1 text-xs text-muted-foreground">Next: {missing[0]}</li>
      )}
    </ul>
  );
}
