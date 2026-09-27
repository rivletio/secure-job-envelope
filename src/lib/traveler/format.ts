import { format, parseISO } from "date-fns";
import type { PriceLine } from "./types.ts";

function currencyExponent(currency: string): number {
  try {
    return (
      new Intl.NumberFormat("en-US", { style: "currency", currency }).resolvedOptions()
        .maximumFractionDigits ?? 2
    );
  } catch {
    return 2;
  }
}

/** Format an integer amount of a currency's minor unit (e.g. cents) for display. */
export function money(minorUnits: number, currency = "USD"): string {
  const exp = currencyExponent(currency);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    maximumFractionDigits: minorUnits % 10 ** exp === 0 ? 0 : exp,
  }).format(minorUnits / 10 ** exp);
}

/** Convert a user-entered major amount (e.g. dollars) to integer minor units. */
export function toMinorUnits(major: number, currency = "USD"): number {
  return Math.round(major * 10 ** currencyExponent(currency));
}

export function pricedLine(
  lines: PriceLine[],
  pickQty?: number,
): PriceLine | undefined {
  if (pickQty != null) return lines.find((l) => l.qty === pickQty);
  return lines[0];
}

export function quoteTotal(
  lines: PriceLine[],
  nre = 0,
  freight = 0,
  pickQty?: number,
): number {
  const line = pricedLine(lines, pickQty);
  if (!line) return nre + freight;
  return line.qty * line.unit + nre + freight;
}

export function formatDay(iso?: string | null): string {
  if (!iso) return "—";
  try {
    const d = iso.length <= 10 ? parseISO(`${iso}T00:00:00Z`) : parseISO(iso);
    return format(d, "d MMM yyyy");
  } catch {
    return iso;
  }
}

export function processLabel(code: string): string {
  return code.replaceAll("_", " ");
}
