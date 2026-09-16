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
import { boundQuotes, levelOf, staleQuotes } from "@/lib/packet/conformance";
import { formatDay, money, processLabel, quoteTotal } from "@/lib/packet/format";
import { itarExportWarning } from "@/lib/packet/guards";
import { packetHash } from "@/lib/packet/hash";
import { usePacketStore } from "@/lib/packet/store";
import type { Quote } from "@/lib/packet/types";
import { downloadJson, downloadRivpkt } from "@/lib/packet/zip";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/p/$packetId")({ component: PacketPage });

function PacketPage() {
  const { packetId } = Route.useParams();
  const packet = usePacketStore((s) => s.packets.find((p) => p.packet_id === packetId));
  const role = usePacketStore((s) => s.role);
  const seller = usePacketStore((s) => s.seller());
  const logAudit = usePacketStore((s) => s.logAudit);
  const [quoteOpen, setQuoteOpen] = useState(false);
  const [awardOpen, setAwardOpen] = useState(false);
  const [pick, setPick] = useState<Quote | null>(null);
  const [itarExport, setItarExport] = useState<"zip" | "json" | null>(null);

  if (!packet) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">No packet {packetId} on this desk.</p>
        <Button asChild variant="outline" className="mt-4">
          <Link to="/">Back to desk</Link>
        </Button>
      </AppShell>
    );
  }

  const info = levelOf(packet);
  const hash = packetHash(packet);
  const bound = boundQuotes(packet);
  const stale = staleQuotes(packet);
  const awarded = bound.find((q) => q.quote_id === packet.award?.quote_id);
  const alreadyQuoted = bound.some((q) => q.seller.org_id === seller.org_id);
  const current = packet;

  function runExport(kind: "zip" | "json") {
    logAudit({ act: "export", packet_id: current.packet_id, hash });
    if (kind === "zip") {
      void downloadRivpkt(current).then(() => toast.success("Exported .rivpkt.zip"));
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
          <p className="font-mono text-xs text-faint">{packet.packet_id}</p>
          <h1 className="mt-1 text-3xl tracking-tight text-paper">{packet.part.family}</h1>
          <p className="text-sm text-soft">
            {packet.part.part_number}
            {packet.part.drawing_rev ? ` · drawing ${packet.part.drawing_rev}` : ""} · r
            {packet.revision}
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
            .rivpkt.zip
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
                v={`${packet.buyer.name}${packet.buyer.region ? ` · ${packet.buyer.city}, ${packet.buyer.region}` : ""}`}
              />
              <Fact
                k="Material"
                v={`${packet.part.material.spec}${packet.part.material.form ? ` ${packet.part.material.form}` : ""}${packet.part.material.thickness_mm ? ` ${packet.part.material.thickness_mm} mm` : ""}`}
              />
              <Fact
                k="Qty"
                v={`${packet.part.qty.target}${packet.part.qty.breaks?.length ? ` · breaks ${packet.part.qty.breaks.join("/")}` : ""}`}
              />
              <Fact k="Need by" v={formatDay(packet.need_by)} />
              <Fact k="Finish" v={packet.part.finish ?? "—"} />
              <Fact k="Tolerances" v={packet.part.tolerances ?? "—"} />
              <Fact
                k="ITAR"
                v={packet.itar ? "Self-declared — not an access-control system" : "No"}
              />
              <Fact k="Incoterms" v={packet.incoterms ?? "—"} />
            </div>
            {packet.part.processes?.length ? (
              <p className="mt-4 font-mono text-xs text-muted-foreground">
                {packet.part.processes.map(processLabel).join(" · ")}
              </p>
            ) : null}
            {packet.part.description && (
              <p className="mt-3 text-sm leading-relaxed">{packet.part.description}</p>
            )}
            {packet.part.notes && (
              <p className="mt-2 text-sm text-muted-foreground">{packet.part.notes}</p>
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
                  const selected = packet.award?.quote_id === q.quote_id;
                  const target =
                    q.pricing.lines.find((l) => l.qty === packet.part.qty.target) ??
                    q.pricing.lines[0];
                  const total = quoteTotal(
                    q.pricing.lines,
                    q.pricing.nre ?? 0,
                    q.pricing.freight_estimate ?? 0,
                    packet.part.qty.target,
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

          {(packet.ops?.length || packet.ship_to) && (
            <section className="on-paper traveler-shadow rounded-sm p-5">
              <h2 className="text-sm font-medium">Executable</h2>
              {awarded && (
                <p className="mt-2 text-sm">
                  Awarded to {awarded.seller.name} on {formatDay(packet.award?.awarded_at)} · qty{" "}
                  {packet.award?.qty}
                </p>
              )}
              {packet.ship_to && (
                <p className="mt-2 text-sm text-muted-foreground">
                  Ship-to {packet.ship_to.name}, {packet.ship_to.line1}, {packet.ship_to.city},{" "}
                  {packet.ship_to.region} {packet.ship_to.postal}
                </p>
              )}
              {packet.ops?.length ? (
                <ol className="mt-4 grid gap-1">
                  {packet.ops.map((op) => (
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
            <p className="font-mono text-xs text-muted-foreground">packet_hash</p>
            <HashChip hash={hash} className="mt-2 w-full justify-between" />
            <Separator className="my-4" />
            <Checklist infoCode={info.code} missing={info.missing} />
          </div>
        </aside>
      </div>

      <QuoteDialog packet={packet} open={quoteOpen} onOpenChange={setQuoteOpen} />
      <AwardDialog
        packet={packet}
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
        body="This packet is self-declared ITAR. The desk does not implement export-control. Download from this local desk anyway?"
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
