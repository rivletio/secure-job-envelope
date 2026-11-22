import { Fragment } from "react";
import { shortHash } from "@/lib/traveler/hash";
import type { QuoteTerms } from "@/lib/traveler/quote-terms";
import { cn } from "@/lib/utils";

/** Every term of a quote, in the open: nothing here sits in a tooltip or behind a
 *  disclosure. The traveler page's quote cards and the award dialog both render this,
 *  from the same `quoteTerms` model, so the dialog asks the buyer to commit to exactly
 *  what the card showed. Everything a seller wrote is rendered as text — React escapes
 *  it — and the free-form blobs arrive already escaped by `blobText`. */
export function QuoteTermsView({ terms, className }: { terms: QuoteTerms; className?: string }) {
  const { seller, total } = terms;
  return (
    <div className={cn("grid gap-4", className)}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <bdi className="font-medium break-words">{seller.name}</bdi>
            <span
              className={cn(
                "rounded-sm bg-wash px-1.5 py-0.5 font-mono text-xs",
                seller.orgId ? "text-foreground" : "text-warn",
              )}
            >
              {seller.orgId ?? "no org_id"}
            </span>
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            The name is as the quote states it — not verified by this desk.
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {[
              seller.place,
              ...(seller.certs.length ? seller.certs : ["no certs listed"]),
              `ITAR ${seller.itar}`,
              seller.contact,
            ]
              .filter((fact): fact is string => Boolean(fact))
              .map((fact, i) => (
                // Each in its own <bdi>: a direction mark inside one seller-written
                // value cannot reorder the values next to it.
                <Fragment key={i}>
                  {i > 0 && " · "}
                  <bdi>{fact}</bdi>
                </Fragment>
              ))}
          </p>
        </div>
        <p className="font-mono text-sm tabular-nums">
          {terms.unitAtQty ?? "no price"}
          <span className="text-muted-foreground">
            {terms.unitAtQty ? " /ea" : ""} at qty {total.qty}
          </span>
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-3">
        <Term k="Lead time" v={terms.leadTime} />
        <Term
          k="Valid until"
          v={terms.expired ? `${terms.validUntil} — expired` : terms.validUntil}
          tone={terms.expired ? "danger" : undefined}
        />
        <Term k="Need-by" v={terms.needBy} tone={terms.needBy === "not feasible" ? "warn" : undefined} />
        <Term k="Currency" v={terms.currency} />
        <Term k="NRE" v={terms.nre} />
        <Term k="Freight estimate" v={terms.freight} />
        <Term k="Tax" v={terms.tax} />
        <Term k="Quoted on" v={terms.quotedOn} />
        <Term k="Quote id" v={terms.quoteId} mono />
        <Term k="Quoted against hash" v={shortHash(terms.travelerHashQuoted)} mono />
      </dl>

      <div>
        <p className="text-xs text-muted-foreground">Price lines</p>
        <table className="mt-1 w-full max-w-md font-mono text-xs tabular-nums">
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-0.5 pr-3 font-normal">Qty</th>
              <th className="py-0.5 pr-3 text-right font-normal">Unit</th>
              <th className="py-0.5 pr-3 text-right font-normal">Qty × unit</th>
              <th className="py-0.5 font-normal">
                <span className="sr-only">Used in the total</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {terms.lines.map((l) => (
              <tr key={l.qty} className={l.atQty ? "font-medium text-foreground" : "text-muted-foreground"}>
                <td className="py-0.5 pr-3">{l.qty}</td>
                <td className="py-0.5 pr-3 text-right">{l.unit}</td>
                <td className="py-0.5 pr-3 text-right">{l.extended}</td>
                <td className="py-0.5 font-sans font-normal text-muted-foreground">
                  {l.atQty ? "in total below" : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-md bg-wash p-3">
        <p className="text-xs text-muted-foreground">
          Total at qty {total.qty} · {terms.currency}
        </p>
        <table className="mt-1 w-full text-sm tabular-nums">
          <tbody>
            {total.rows.map((row, i) => (
              <tr key={`${row.label}-${i}`}>
                <th scope="row" className="py-0.5 pr-3 text-left font-normal">
                  <bdi className="break-words">{row.label}</bdi>
                  <span className="text-muted-foreground"> · {row.detail}</span>
                </th>
                <td className="py-0.5 text-right font-mono whitespace-nowrap">{row.amount}</td>
              </tr>
            ))}
            <tr className="border-t border-border">
              <th scope="row" className="pt-1.5 pr-3 text-left font-medium">
                Total
              </th>
              <td
                className={cn(
                  "pt-1.5 text-right font-mono font-medium whitespace-nowrap",
                  (total.total === null || total.negative) && "text-danger",
                )}
              >
                {total.total ?? `no price at qty ${total.qty}`}
              </td>
            </tr>
          </tbody>
        </table>
        {total.notes.map((note) => (
          <p key={note} className="mt-2 text-xs text-muted-foreground">
            {note}
          </p>
        ))}
      </div>

      <div>
        <p className="text-xs text-muted-foreground">
          Exceptions{terms.exceptions.length ? ` (${terms.exceptions.length})` : ""}
        </p>
        {terms.exceptions.length === 0 ? (
          <p className="mt-1 text-sm">None.</p>
        ) : (
          <ul className="mt-1 grid gap-2">
            {terms.exceptions.map((ex, i) => (
              <li
                key={`${ex.code}-${i}`}
                className="rounded-sm border border-warn/40 bg-warn/10 px-3 py-2 text-sm"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                  <p className="min-w-0 font-mono text-xs">
                    <bdi className="font-medium break-words">{ex.code}</bdi>
                    <span className="text-muted-foreground"> on </span>
                    <bdi className="break-words">{ex.on ?? "(not stated)"}</bdi>
                  </p>
                  <p className="font-mono text-xs whitespace-nowrap">
                    <span className="text-muted-foreground">price delta </span>
                    <span className="font-medium">{ex.priceDelta ?? "none stated"}</span>
                  </p>
                </div>
                <p className="mt-1 break-words whitespace-pre-wrap">{ex.proposal}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <Blob label="Assumptions" text={terms.assumptions} />
      <Blob label="Capacity" text={terms.capacity} />
    </div>
  );
}

function Term({
  k,
  v,
  tone,
  mono,
}: {
  k: string;
  v: string;
  tone?: "danger" | "warn";
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{k}</dt>
      <dd
        className={cn(
          "text-sm break-words",
          mono && "font-mono text-xs",
          tone === "danger" && "font-medium text-danger",
          tone === "warn" && "font-medium text-warn",
        )}
      >
        {v}
      </dd>
    </div>
  );
}

/** A seller's free-form blob, as escaped JSON text. A long one scrolls inside its own
 *  box (focusable, so the keyboard can scroll it); it is never collapsed. */
function Blob({ label, text }: { label: string; text: string | null }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">
        {label} — free-form, written by the seller, part of what an award commits to
      </p>
      {text === null ? (
        <p className="mt-1 text-sm">None.</p>
      ) : (
        <pre
          tabIndex={0}
          aria-label={label}
          className="mt-1 max-h-48 overflow-auto rounded-sm bg-wash px-3 py-2 font-mono text-xs break-words whitespace-pre-wrap focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {text}
        </pre>
      )}
    </div>
  );
}
