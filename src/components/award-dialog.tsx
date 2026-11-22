import { useRef, useState } from "react";
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
import { cannotAward } from "@/lib/traveler/guards";
import { isoNow } from "@/lib/traveler/ids";
import { opsFromProcesses } from "@/lib/traveler/network";
import { quoteTerms } from "@/lib/traveler/quote-terms";
import { useTravelerStore } from "@/lib/traveler/store";
import type { Traveler, Quote, AwardTerms } from "@/lib/traveler/types";
import { QuoteTermsView } from "./quote-terms";

export function AwardDialog({
  traveler,
  quote,
  open,
  onOpenChange,
}: {
  traveler: Traveler;
  quote: Quote | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const award = useTravelerStore((s) => s.award);
  const contentRef = useRef<HTMLDivElement>(null);
  // Nothing below is pre-filled from `traveler.ship_to`, `traveler.ops` or a previous
  // award's terms. Those are not part of what the buyer signed, and on a traveler that
  // was received from someone else they are whatever that file said — a seller returning
  // a quote can put a ship-to in it. Pre-filled silently, the buyer would confirm an
  // address it never typed. What the file carries is shown separately, labelled, and
  // copied in only when the buyer asks for it.
  const [name, setName] = useState(traveler.buyer.name);
  const [line1, setLine1] = useState("");
  const [city, setCity] = useState(traveler.buyer.city ?? "");
  const [region, setRegion] = useState(traveler.buyer.region ?? "");
  const [postal, setPostal] = useState("");
  const [opsText, setOpsText] = useState(() =>
    opsFromProcesses(traveler.part.processes)
      .map((o) => o.code)
      .join(", "),
  );
  const [law, setLaw] = useState("");
  const [warranty, setWarranty] = useState("");
  const [pay, setPay] = useState("");

  const fileShipTo = traveler.ship_to ?? null;
  const fileOps = traveler.ops?.length ? traveler.ops.map((o) => o.code).join(", ") : null;
  const fileTerms = traveler.award?.terms ?? null;
  const fileTermsText = fileTerms
    ? [fileTerms.governing_law, fileTerms.warranty, fileTerms.payment_terms].filter(Boolean).join(" · ")
    : "";
  /** The ops exactly as they will be recorded, so nothing is changed between what is
   *  typed and what is stored without the buyer seeing it. */
  const opsToRecord = opsText
    .split(",")
    .map((code) => code.trim())
    .filter(Boolean)
    .map((code, i) => ({ seq: i + 1, code: code.toUpperCase() }));

  function submit() {
    if (!quote) return;
    const blocked = cannotAward(traveler, quote);
    if (blocked) {
      toast.error(blocked);
      return;
    }
    if (!line1.trim() || !city.trim() || !region.trim() || !postal.trim()) {
      toast.error("Ship-to needs street, city, region, postal.");
      return;
    }
    const ops = opsToRecord;
    if (!ops.length) {
      toast.error("List at least one op.");
      return;
    }
    const terms: AwardTerms = {};
    if (law.trim()) terms.governing_law = law.trim();
    if (warranty.trim()) terms.warranty = warranty.trim();
    if (pay.trim()) terms.payment_terms = pay.trim();
    try {
      award(
        traveler.traveler_id,
        {
          quote_id: quote.quote_id,
          awarded_at: isoNow(),
          qty: traveler.part.qty.target,
          ...(Object.keys(terms).length ? { terms } : {}),
        },
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
      toast.success("Traveler is L2 executable.");
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not award");
    }
  }

  // The award is for the traveler's target quantity (see `submit`), so that is the
  // quantity the terms are totalled at.
  const terms = quote ? quoteTerms(quote, traveler.part.qty.target) : null;
  const expired = terms?.expired ?? false;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        ref={contentRef}
        className="max-w-2xl gap-4"
        // Open at the top, on the terms. By default the first input takes focus, which
        // would scroll the ship-to form into view and the terms out of it.
        onOpenAutoFocus={(e) => {
          e.preventDefault();
          contentRef.current?.focus();
        }}
      >
        <DialogHeader>
          <DialogTitle>Award & make executable</DialogTitle>
          <DialogDescription>
            L2 needs a live bound quote, an ops list, and a ship-to. Award is not a purchase
            order and does not form a contract by itself.
          </DialogDescription>
        </DialogHeader>
        {terms && (
          <section
            aria-label="What you are awarding"
            className="rounded-sm border border-border p-4"
          >
            <h3 className="font-sans text-sm font-medium tracking-normal">What you are awarding</h3>
            <p className="mt-1 mb-4 text-xs text-muted-foreground">
              The award records this quote&apos;s content hash, so it commits to every term below —
              totalled at qty {terms.total.qty}, the traveler&apos;s target quantity.
            </p>
            <QuoteTermsView terms={terms} />
          </section>
        )}
        {expired && (
          <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            This quote is past valid_until. Amend the traveler or request a new quote.
          </p>
        )}
        {traveler.itar && (
          <p className="rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-foreground">
            ITAR-declared. Awarding here does not license export or deemed export of technical data.
          </p>
        )}
        {(fileShipTo || fileOps || fileTermsText) && (
          <section
            aria-label="Carried by the traveler file"
            className="rounded-md border border-warn/40 bg-warn/10 px-3 py-3 text-xs text-foreground"
          >
            <p className="font-medium">Carried by the traveler file — not signed, and not necessarily yours</p>
            <p className="mt-1 text-muted-foreground">
              A ship-to, an ops list or terms in a traveler file are covered by no signature. If this
              traveler was received from someone else, they are that sender&apos;s. Nothing here is
              used unless you copy it in — and then check it against your own records.
            </p>
            <dl className="mt-3 grid gap-2">
              {fileShipTo && (
                <FileRow
                  label="Ship-to"
                  onUse={() => {
                    setName(fileShipTo.name);
                    setLine1(fileShipTo.line1);
                    setCity(fileShipTo.city);
                    setRegion(fileShipTo.region);
                    setPostal(fileShipTo.postal);
                  }}
                >
                  {[fileShipTo.name, fileShipTo.line1, fileShipTo.line2, fileShipTo.city, fileShipTo.region, fileShipTo.postal, fileShipTo.country]
                    .filter(Boolean)
                    .join(", ")}
                </FileRow>
              )}
              {fileOps && (
                <FileRow label="Ops" onUse={() => setOpsText(fileOps)}>
                  {fileOps}
                </FileRow>
              )}
              {fileTerms && fileTermsText && (
                <FileRow
                  label="Terms"
                  onUse={() => {
                    setLaw(fileTerms.governing_law ?? "");
                    setWarranty(fileTerms.warranty ?? "");
                    setPay(fileTerms.payment_terms ?? "");
                  }}
                >
                  {fileTermsText}
                </FileRow>
              )}
            </dl>
          </section>
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
          <p className="-mt-2 text-xs text-muted-foreground" aria-live="polite">
            {opsToRecord.length
              ? `Will be recorded as: ${opsToRecord.map((o) => `${o.seq} ${o.code}`).join(" · ")}`
              : "No ops yet — list at least one."}
          </p>
          <Field label="Governing law (optional)" value={law} onChange={setLaw} />
          <Field label="Warranty (optional)" value={warranty} onChange={setWarranty} />
          <Field label="Payment terms (optional)" value={pay} onChange={setPay} />
        </div>
        <Button type="button" onClick={submit} disabled={!quote || expired}>
          <span>
            Award to <bdi>{quote?.seller.name ?? "seller"}</bdi>
          </span>
        </Button>
      </DialogContent>
    </Dialog>
  );
}

/** One thing the traveler file carries, shown as text, with an explicit "use it". */
function FileRow({
  label,
  onUse,
  children,
}: {
  label: string;
  onUse: () => void;
  children: string;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0">
        <dt className="font-medium">{label}</dt>
        <dd className="break-words text-muted-foreground">
          <bdi>{children}</bdi>
        </dd>
      </div>
      <Button type="button" variant="outline" size="sm" onClick={onUse}>
        Copy in
      </Button>
    </div>
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
