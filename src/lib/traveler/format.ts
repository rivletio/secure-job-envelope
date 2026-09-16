import { format, parseISO } from "date-fns";
import type { PriceLine } from "./types.ts";

export function money(amount: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    maximumFractionDigits: amount % 1 === 0 ? 0 : 2,
  }).format(amount);
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
