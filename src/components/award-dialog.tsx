import { useState } from "react";
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
import { cannotAward, isQuoteExpired } from "@/lib/packet/guards";
import { money, pricedLine } from "@/lib/packet/format";
import { isoNow } from "@/lib/packet/ids";
import { opsFromProcesses } from "@/lib/packet/network";
import { usePacketStore } from "@/lib/packet/store";
import type { Packet, Quote } from "@/lib/packet/types";

export function AwardDialog({
  packet,
  quote,
  open,
  onOpenChange,
}: {
  packet: Packet;
  quote: Quote | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const award = usePacketStore((s) => s.award);
  const [name, setName] = useState(packet.ship_to?.name ?? packet.buyer.name);
  const [line1, setLine1] = useState(packet.ship_to?.line1 ?? "");
  const [city, setCity] = useState(packet.ship_to?.city ?? packet.buyer.city ?? "");
  const [region, setRegion] = useState(packet.ship_to?.region ?? packet.buyer.region ?? "");
  const [postal, setPostal] = useState(packet.ship_to?.postal ?? "");
  const [opsText, setOpsText] = useState(() =>
    (packet.ops?.length ? packet.ops : opsFromProcesses(packet.part.processes))
      .map((o) => o.code)
      .join(", "),
  );

  function submit() {
    if (!quote) return;
    const blocked = cannotAward(packet, quote);
    if (blocked) {
      toast.error(blocked);
      return;
    }
    if (!line1.trim() || !city.trim() || !region.trim() || !postal.trim()) {
      toast.error("Ship-to needs street, city, region, postal.");
      return;
    }
    const ops = opsText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((code, i) => ({ seq: i + 1, code: code.toUpperCase() }));
    if (!ops.length) {
      toast.error("List at least one op.");
      return;
    }
    try {
      award(
        packet.packet_id,
        { quote_id: quote.quote_id, awarded_at: isoNow(), qty: packet.part.qty.target },
        {
          name: name.trim(),
          line1: line1.trim(),
          city: city.trim(),
          region: region.trim(),
          postal: postal.trim(),
          country: "US",
        },
        ops,
      );
      toast.success("Packet is L2 executable.");
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not award");
    }
  }

  const targetLine = quote ? pricedLine(quote.pricing.lines, packet.part.qty.target) : undefined;
  const expired = quote ? isQuoteExpired(quote) : false;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Award & make executable</DialogTitle>
          <DialogDescription>
            L2 needs a live bound quote, an ops list, and a ship-to. Award is not a purchase
            order and does not form a contract by itself.
          </DialogDescription>
        </DialogHeader>
        {quote && (
          <p className="rounded-md bg-wash px-3 py-2 text-sm">
            {quote.seller.name} · {quote.lead_time_days}d
            {targetLine
              ? ` · ${money(targetLine.unit, quote.pricing.currency)} × ${targetLine.qty}`
              : " · no price at target qty"}
            {expired ? " · expired" : ""}
          </p>
        )}
        {expired && (
          <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            This quote is past valid_until. Amend the packet or request a new quote.
          </p>
        )}
        {packet.itar && (
          <p className="rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-foreground">
            ITAR-declared. Awarding here does not license export or deemed export of technical data.
          </p>
        )}
        <div className="grid gap-3">
          <Field label="Ship to" value={name} onChange={setName} />
          <Field label="Street" value={line1} onChange={setLine1} />
          <div className="grid grid-cols-2 gap-3">
            <Field label="City" value={city} onChange={setCity} />
            <Field label="Region" value={region} onChange={setRegion} />
          </div>
          <Field label="Postal" value={postal} onChange={setPostal} />
          <Field
            label="Ops (comma-separated)"
            value={opsText}
            onChange={setOpsText}
          />
        </div>
        <Button type="button" onClick={submit} disabled={!quote || expired}>
          Award to {quote?.seller.name ?? "seller"}
        </Button>
      </DialogContent>
    </Dialog>
  );
}

function Field({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const id = label.replaceAll(" ", "-").toLowerCase();
  return (
    <div className="grid gap-1">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
