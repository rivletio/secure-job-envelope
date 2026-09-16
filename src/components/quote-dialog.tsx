import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { cannotQuoteAs } from "@/lib/packet/guards";
import { packetHash } from "@/lib/packet/hash";
import { daysFromNow, isoNow, newQuoteId } from "@/lib/packet/ids";
import { usePacketStore } from "@/lib/packet/store";
import type { Packet, Quote } from "@/lib/packet/types";
import { HashChip } from "./hash-chip";

export function QuoteDialog({
  packet,
  open,
  onOpenChange,
}: {
  packet: Packet;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const seller = usePacketStore((s) => s.seller());
  const addQuote = usePacketStore((s) => s.addQuote);
  const hash = packetHash(packet);
  const qtys = useMemo(() => {
    const breaks = packet.part.qty.breaks?.length
      ? packet.part.qty.breaks
      : [packet.part.qty.target];
    const set = new Set(breaks);
    set.add(packet.part.qty.target);
    return [...set].sort((a, b) => a - b);
  }, [packet]);

  const [units, setUnits] = useState<Record<number, string>>(() =>
    Object.fromEntries(qtys.map((q) => [q, ""])),
  );
  const [nre, setNre] = useState("0");
  const [lead, setLead] = useState("14");
  const [freight, setFreight] = useState("");
  const [feasible, setFeasible] = useState(true);
  const [exception, setException] = useState("");
  const [blocked, setBlocked] = useState(false);

  const itarBlocked = cannotQuoteAs(packet, seller);

  function submit() {
    if (itarBlocked) {
      toast.error(itarBlocked);
      return;
    }
    const lines = qtys
      .map((qty) => ({ qty, unit: Number(units[qty]) }))
      .filter((l) => Number.isFinite(l.unit) && l.unit > 0);
    if (!lines.length) {
      toast.error("Price at least one quantity break.");
      return;
    }
    if (blocked) return;
    setBlocked(true);
    const freightN = freight === "" ? undefined : Number(freight);
    if (freightN !== undefined && (!Number.isFinite(freightN) || freightN < 0)) {
      setBlocked(false);
      toast.error("Freight must be zero or more.");
      return;
    }
    const quote: Quote = {
      quote_id: newQuoteId(),
      seller: {
        org_id: seller.org_id,
        name: seller.name,
        city: seller.city,
        region: seller.region,
        certs: seller.certs,
        itar: seller.itar,
      },
      packet_hash_quoted: hash,
      created_at: isoNow(),
      valid_until: daysFromNow(14),
      lead_time_days: Math.max(0, Number(lead) || 0),
      need_by_feasible: feasible,
      pricing: {
        currency: "USD",
        nre: Math.max(0, Number(nre) || 0),
        lines,
        freight_estimate: freightN,
        tax_excluded: true,
      },
      exceptions: exception.trim()
        ? [{ code: "NOTE", proposal: exception.trim() }]
        : undefined,
    };
    try {
      addQuote(packet.packet_id, quote);
      toast.success(`Quote bound to ${packet.packet_id}`);
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not bind quote");
    } finally {
      setBlocked(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Quote {packet.part.part_number}</DialogTitle>
          <DialogDescription>
            Bound to this buyer revision. If the packet hash moves, this quote goes stale.
            A bound quote is a structured price, not a signed offer.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="rounded-md bg-wash p-3">
            <p className="text-xs text-muted-foreground">packet_hash_quoted</p>
            <HashChip hash={hash} className="mt-1" />
            <p className="mt-2 text-sm">
              {seller.name} · {seller.certs?.join(", ") || "no certs"}
              {seller.itar ? " · ITAR-registered (self-declared)" : ""}
            </p>
          </div>
          {itarBlocked && (
            <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {itarBlocked} The ITAR flag is a declaration, not DDTC registration proof.
            </p>
          )}
          <div className="grid gap-3">
            {qtys.map((qty) => (
              <div key={qty} className="grid grid-cols-[1fr_8rem] items-end gap-2">
                <Label htmlFor={`u-${qty}`}>Unit at qty {qty}</Label>
                <Input
                  id={`u-${qty}`}
                  inputMode="decimal"
                  placeholder="USD"
                  value={units[qty] ?? ""}
                  onChange={(e) => setUnits((u) => ({ ...u, [qty]: e.target.value }))}
                />
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1">
              <Label htmlFor="nre">NRE</Label>
              <Input id="nre" inputMode="decimal" value={nre} onChange={(e) => setNre(e.target.value)} />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="lead">Lead time (days)</Label>
              <Input id="lead" inputMode="numeric" value={lead} onChange={(e) => setLead(e.target.value)} />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="freight">Freight estimate</Label>
              <Input
                id="freight"
                inputMode="decimal"
                value={freight}
                onChange={(e) => setFreight(e.target.value)}
              />
            </div>
            <label className="flex items-end gap-2 pb-2 text-sm">
              <input
                type="checkbox"
                checked={feasible}
                onChange={(e) => setFeasible(e.target.checked)}
                className="size-4 accent-primary"
              />
              Need-by feasible
            </label>
          </div>
          <div className="grid gap-1">
            <Label htmlFor="ex">Exception (optional)</Label>
            <Textarea
              id="ex"
              rows={2}
              value={exception}
              onChange={(e) => setException(e.target.value)}
              placeholder="Process exception or assumption"
            />
          </div>
          <Button type="button" onClick={submit} disabled={Boolean(itarBlocked) || blocked}>
            Bind quote
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
