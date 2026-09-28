/** Strict ISO-8601 UTC datetime handling, mirrored byte-for-byte by the Rust core
 *  (`rfc3339_millis` / `iso_day_ok` in lib.rs). One shared, strict definition of a
 *  timestamp is what lets the two implementations accept and reject the exact same
 *  dates and agree on the instant used for bind / expiry decisions.
 *
 *  A timestamp is `YYYY-MM-DDTHH:MM:SS(.fraction)?Z` with fixed-width components,
 *  1–9 fractional digits, and a *real* calendar (leap-aware day, hour ≤ 23,
 *  minute/second ≤ 59). Anything a lenient parser would coerce — single-digit
 *  fields, second 60, 2026-02-31, a trailing numeric offset instead of Z — is
 *  refused rather than silently reinterpreted.
 */

const DT_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function isLeap(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

function daysInMonth(y: number, m: number): number {
  return [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1] ?? 0;
}

/** Parse a strict UTC datetime to Unix milliseconds, or null if it is not
 *  canonical. Calendar validity is checked *before* Date.UTC so no out-of-range
 *  component is ever silently rolled over into a different instant. */
export function isoDateTimeMs(s: string): number | null {
  const m = DT_RE.exec(s);
  if (!m) return null;
  const y = +m[1]!;
  const mo = +m[2]!;
  const day = +m[3]!;
  const h = +m[4]!;
  const min = +m[5]!;
  const sec = +m[6]!;
  if (mo < 1 || mo > 12) return null;
  if (day < 1 || day > daysInMonth(y, mo)) return null;
  if (h > 23 || min > 59 || sec > 59) return null;
  const ms = m[7] ? Number((m[7] + "000").slice(0, 3)) : 0;
  return Date.UTC(y, mo - 1, day, h, min, sec, ms);
}

/** A strict ISO calendar day `YYYY-MM-DD` (real calendar, leap-aware). */
export function isoDayOk(s: string): boolean {
  const m = DAY_RE.exec(s);
  if (!m) return false;
  const y = +m[1]!;
  const mo = +m[2]!;
  const day = +m[3]!;
  return mo >= 1 && mo <= 12 && day >= 1 && day <= daysInMonth(y, mo);
}
