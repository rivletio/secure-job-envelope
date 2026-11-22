import { DocText } from "@/components/doc-text";
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
import { FieldError } from "@/components/ui/field-error";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { money } from "@/lib/traveler/format";
import { cannotQuoteAs } from "@/lib/traveler/guards";
import { travelerHash } from "@/lib/traveler/hash";
import { daysFromNow, isoNow, newQuoteId } from "@/lib/traveler/ids";
import { parseQuoteForm } from "@/lib/traveler/input";
import { useTravelerStore } from "@/lib/traveler/store";
import type { Traveler, Quote } from "@/lib/traveler/types";
import { HashChip } from "./hash-chip";

/** The desk quotes in US dollars. Every amount field is parsed against this currency's
 *  minor unit, and shown back in it. */
const CURRENCY = "USD";

export function QuoteDialog({
  traveler,
  open,
  onOpenChange,
}: {
  traveler: Traveler;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const seller = useTravelerStore((s) => s.seller());
  const addQuote = useTravelerStore((s) => s.addQuote);
  const hash = travelerHash(traveler);
  const qtys = useMemo(() => {
    const breaks = traveler.part.qty.breaks?.length
      ? traveler.part.qty.breaks
      : [traveler.part.qty.target];
    const set = new Set(breaks);
    set.add(traveler.part.qty.target);
    return [...set].sort((a, b) => a - b);
  }, [traveler]);

  const [units, setUnits] = useState<Record<number, string>>(() =>
    Object.fromEntries(qtys.map((q) => [q, ""])),
  );
  const [nre, setNre] = useState("0");
  const [lead, setLead] = useState("14");
  const [freight, setFreight] = useState("");
  const [feasible, setFeasible] = useState(true);
  const [exception, setException] = useState("");
  const [attempted, setAttempted] = useState(false);

  const itarBlocked = cannotQuoteAs(traveler, seller);

  // The typed text is parsed strictly on every render, so each field shows its own
  // error as it is typed, and `values` exists only when every field means exactly one
  // number. Nothing typed is ever dropped, rounded or replaced by a default.
  const { values, errors, priced } = parseQuoteForm({ units, nre, lead, freight }, qtys, CURRENCY);

  function submit() {
    if (itarBlocked) {
      toast.error(itarBlocked);
      return;
    }
    if (!values) {
      // Refused: say so, put the cursor on the first field that is wrong, bind nothing.
      setAttempted(true);
      toast.error(errors.form ?? "Fix the highlighted fields. Nothing was bound.");
      const wrong = [
        ...qtys.map((qty) => [`u-${qty}`, errors.units[qty]] as const),
        ["nre", errors.nre] as const,
        ["lead", errors.lead] as const,
        ["freight", errors.freight] as const,
      ].find(([, error]) => error);
      document.getElementById(wrong?.[0] ?? `u-${qtys[0]}`)?.focus();
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
      traveler_hash_quoted: hash,
      created_at: isoNow(),
      valid_until: daysFromNow(14),
      lead_time_days: values.lead_time_days,
      need_by_feasible: feasible,
      pricing: {
        currency: CURRENCY,
        nre: values.nre,
        lines: values.lines,
        ...(values.freight_estimate === undefined
          ? {}
          : { freight_estimate: values.freight_estimate }),
        tax_excluded: true,
      },
      exceptions: exception.trim()
        ? [{ code: "NOTE", proposal: exception.trim() }]
        : undefined,
    };
    try {
      addQuote(traveler.traveler_id, quote);
      toast.success(`Quote bound to ${traveler.traveler_id}`);
      setAttempted(false);
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not bind quote");
    }
  }

  const formError = attempted ? errors.form : undefined;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            Quote <DocText text={traveler.part.part_number} />
          </DialogTitle>
          <DialogDescription>
            Bound to this buyer revision. If the traveler hash moves, this quote goes stale.
            A bound quote is a structured price, not a signed offer.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="rounded-md bg-wash p-3">
            <p className="text-xs text-muted-foreground">traveler_hash_quoted</p>
            <HashChip hash={hash} className="mt-1" />
            <p className="mt-2 text-sm">
              {seller.name} · {seller.certs?.join(", ") || "no certs"}
              {seller.itar ? " · ITAR self-declared" : ""}
            </p>
          </div>
          {itarBlocked && (
            <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {itarBlocked} The ITAR flag is a declaration, not DDTC registration proof.
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Amounts are in {CURRENCY}: plain digits with a period for cents, like 1250.00. An
            entry that is not exactly that is refused, never adjusted.
          </p>
          <div className="grid gap-3">
            {qtys.map((qty) => {
              const id = `u-${qty}`;
              const error = errors.units[qty];
              const line = priced.find((l) => l.qty === qty);
              return (
                <div key={qty} className="grid gap-1">
                  <div className="grid grid-cols-[1fr_8rem] items-end gap-2">
                    <Label htmlFor={id}>Unit at qty {qty}</Label>
                    <Input
                      id={id}
                      inputMode="decimal"
                      placeholder={CURRENCY}
                      value={units[qty] ?? ""}
                      aria-invalid={error ? true : undefined}
                      aria-describedby={error ? `${id}-error` : undefined}
                      className={error ? "border-danger" : undefined}
                      onChange={(e) => setUnits((u) => ({ ...u, [qty]: e.target.value }))}
                    />
                  </div>
                  <FieldError id={`${id}-error`} message={error} />
                  {line && (
                    <p className="text-right font-mono text-xs text-muted-foreground">
                      {money(line.unit, CURRENCY, { minorDigits: "always" })} /ea ·{" "}
                      {money(BigInt(line.unit) * BigInt(line.qty), CURRENCY, { minorDigits: "always" })} at
                      qty {qty}
                    </p>
                  )}
                </div>
              );
            })}
            <FieldError id="units-error" message={formError} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid content-start gap-1">
              <Label htmlFor="nre">NRE ({CURRENCY})</Label>
              <Input
                id="nre"
                inputMode="decimal"
                value={nre}
                aria-invalid={errors.nre ? true : undefined}
                aria-describedby={errors.nre ? "nre-error" : undefined}
                className={errors.nre ? "border-danger" : undefined}
                onChange={(e) => setNre(e.target.value)}
              />
              <FieldError id="nre-error" message={errors.nre} />
            </div>
            <div className="grid content-start gap-1">
              <Label htmlFor="lead">Lead time (days)</Label>
              <Input
                id="lead"
                inputMode="numeric"
                value={lead}
                aria-invalid={errors.lead ? true : undefined}
                aria-describedby={errors.lead ? "lead-error" : undefined}
                className={errors.lead ? "border-danger" : undefined}
                onChange={(e) => setLead(e.target.value)}
              />
              <FieldError id="lead-error" message={errors.lead} />
            </div>
            <div className="grid content-start gap-1">
              <Label htmlFor="freight">Freight estimate ({CURRENCY}, optional)</Label>
              <Input
                id="freight"
                inputMode="decimal"
                value={freight}
                aria-invalid={errors.freight ? true : undefined}
                aria-describedby={errors.freight ? "freight-error" : undefined}
                className={errors.freight ? "border-danger" : undefined}
                onChange={(e) => setFreight(e.target.value)}
              />
              <FieldError id="freight-error" message={errors.freight} />
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
          <Button type="button" onClick={submit} disabled={Boolean(itarBlocked)}>
            Bind quote
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
