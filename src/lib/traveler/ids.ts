import { TRAVELER_ID_RE } from "./types.ts";

const ALPH = "abcdefghijklmnopqrstuvwxyz0123456789";

export function randToken(len = 10): string {
  const out = new Array<string>(len);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    // Rejection sampling — avoid modulo bias against 36.
    const max = 256 - (256 % ALPH.length);
    let i = 0;
    while (i < len) {
      const bytes = new Uint8Array(len - i);
      crypto.getRandomValues(bytes);
      for (const b of bytes) {
        if (b >= max) continue;
        out[i] = ALPH[b % ALPH.length]!;
        i += 1;
        if (i >= len) break;
      }
    }
  } else {
    for (let i = 0; i < len; i++) out[i] = ALPH[Math.floor(Math.random() * ALPH.length)]!;
  }
  return out.join("");
}

export function newTravelerId(): string {
  const id = `tvl_${randToken(10)}`;
  if (!TRAVELER_ID_RE.test(id)) throw new Error("id generation failed");
  return id;
}

export function newQuoteId(): string {
  const id = `qot_${randToken(10)}`;
  if (!TRAVELER_ID_RE.test(id)) throw new Error("id generation failed");
  return id;
}

export function isoNow(): string {
  return new Date().toISOString();
}

export function daysFromNow(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}
