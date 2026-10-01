import { z } from "zod";
import {
  COUNTRY_RE,
  CURRENCY_RE,
  HASH_RE,
  MAX_NAME,
  MAX_TRAVELER_JSON_BYTES,
  MAX_STRING,
  TRAVELER_ID_RE,
  TRAVELER_SPEC,
} from "./types.ts";
import { isoDateTimeMs, isoDayOk } from "./datetime.ts";

// A required, non-empty string that must already be trimmed. We *reject* leading
// or trailing whitespace rather than silently trimming it (the old `.trim()`
// transform): a silent trim means the bytes we hash differ from the bytes we were
// given, and the Rust core — which does not trim — would then hash a different
// string for the "same" document. Rejecting keeps the two implementations
// byte-identical. The desk UI already trims user input before it reaches here.
const trimmedMax = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine((s) => s === s.trim(), "must not have leading or trailing whitespace");
const name = trimmedMax(MAX_NAME);
const longText = z.string().min(1).max(MAX_STRING);
const optName = trimmedMax(MAX_NAME).optional();
const optLong = z.string().min(1).max(MAX_STRING).optional();
const isoDt = z.string().refine((s) => isoDateTimeMs(s) !== null, "ISO-8601 UTC datetime");
const isoDayOrDt = z
  .string()
  .refine((s) => isoDayOk(s) || isoDateTimeMs(s) !== null, "ISO-8601 date or UTC datetime");
/** Values must sit in the canonical numeric range (see canonical.ts): integers
 * or non-integers of magnitude >= 1e-5, so both reference implementations
 * render them identically. */
const canonicalRange = (v: number) => Number.isInteger(v) || Math.abs(v) >= 1e-5;
// Money is an integer count of the currency's minor unit (e.g. cents for USD):
// exact, no IEEE-754 rounding (SPEC 0.1 — "money is integer minor units").
const money = z.number().int().nonnegative().max(1e12);

const jsonBlob = z.record(z.string(), z.unknown()).refine((v) => JSON.stringify(v).length <= 8192, {
  message: "object exceeds 8 KiB",
});

const signature = z
  .object({
    alg: z.literal("ML-DSA-87"),
    kid: z.string().min(1).max(64),
    sig: z
      .string()
      .regex(/^[0-9a-f]+$/, "lowercase hex")
      .max(20000),
  })
  .strict();

const orgSchema = z
  .object({
    org_id: z
      .string()
      .regex(/^[a-z][a-z0-9_]{1,63}$/)
      .optional(),
    name,
    city: optName,
    region: optName,
    contact: trimmedMax(200).optional(),
    certs: z.array(z.string().min(1).max(64)).max(16).optional(),
    itar: z.boolean().optional(),
  })
  .strict();

const priceLineSchema = z
  .object({
    qty: z.number().int().min(1).max(1_000_000),
    unit: money,
  })
  .strict();

export const quoteSchema = z
  .object({
    quote_id: z.string().regex(TRAVELER_ID_RE),
    seller: orgSchema,
    traveler_hash_quoted: z.string().regex(HASH_RE),
    created_at: isoDt,
    valid_until: isoDt,
    lead_time_days: z.number().int().min(0).max(3650),
    need_by_feasible: z.boolean().optional(),
    pricing: z
      .object({
        currency: z.string().regex(CURRENCY_RE),
        nre: money.optional(),
        lines: z.array(priceLineSchema).min(1).max(16),
        freight_estimate: money.optional(),
        tax_excluded: z.boolean().optional(),
      })
      .strict(),
    assumptions: jsonBlob.optional(),
    exceptions: z
      .array(
        z
          .object({
            code: z.string().min(1).max(64),
            on: z.string().min(1).max(128).optional(),
            proposal: longText,
            price_delta: z.number().int().min(-1e12).max(1e12).optional(),
          })
          .strict(),
      )
      .max(16)
      .optional(),
    capacity: jsonBlob.optional(),
    sig: signature.optional(),
  })
  .strict()
  .superRefine((q, ctx) => {
    // Both dates already passed the strict isoDt refinement, so parse them the same
    // way the Rust core does (isoDateTimeMs === rfc3339_millis) and compare instants.
    const created = isoDateTimeMs(q.created_at);
    const until = isoDateTimeMs(q.valid_until);
    if (created !== null && until !== null && until <= created) {
      ctx.addIssue({
        code: "custom",
        path: ["valid_until"],
        message: "valid_until must be after created_at",
      });
    }
  });

const shipToSchema = z
  .object({
    name,
    line1: trimmedMax(200),
    line2: trimmedMax(200).optional(),
    city: name,
    region: name,
    postal: trimmedMax(16),
    country: z.string().regex(COUNTRY_RE),
  })
  .strict();

export const travelerSchema = z
  .object({
    spec: z.literal(TRAVELER_SPEC),
    traveler_id: z.string().regex(TRAVELER_ID_RE),
    revision: z.number().int().min(1).max(10_000),
    created_at: isoDt,
    buyer: orgSchema,
    part: z
      .object({
        family: name,
        part_number: name,
        description: optLong,
        drawing_rev: z.string().min(1).max(32).optional(),
        material: z
          .object({
            spec: name,
            form: optName,
            thickness_mm: z.number().finite().min(0.0001).max(1e6).refine(canonicalRange).optional(),
          })
          .strict(),
        qty: z
          .object({
            target: z.number().int().min(1).max(1_000_000),
            breaks: z.array(z.number().int().min(1).max(1_000_000)).max(16).optional(),
          })
          .strict(),
        processes: z.array(z.string().min(1).max(32)).max(32).optional(),
        finish: optLong,
        tolerances: optLong,
        notes: optLong,
      })
      .strict(),
    need_by: isoDayOrDt.nullable().optional(),
    incoterms: z.string().min(1).max(64).nullable().optional(),
    itar: z.boolean().optional(),
    ship_to: shipToSchema.nullable().optional(),
    ops: z
      .array(
        z
          .object({
            seq: z.number().int().min(1).max(1000),
            code: z.string().min(1).max(32),
            notes: optLong,
          })
          .strict(),
      )
      .max(64)
      .optional(),
    quotes: z.array(quoteSchema).max(64).optional(),
    award: z
      .object({
        quote_id: z.string().regex(TRAVELER_ID_RE),
        awarded_at: isoDt,
        qty: z.number().int().min(1).max(1_000_000),
        terms: z
          .object({
            governing_law: trimmedMax(128).optional(),
            warranty: z.string().min(1).max(MAX_STRING).optional(),
            payment_terms: trimmedMax(128).optional(),
          })
          .strict()
          .optional(),
      })
      .strict()
      .nullable()
      .optional(),
    as_built: jsonBlob.nullable().optional(),
    signatures: z.array(signature).max(8).optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (JSON.stringify(p).length > MAX_TRAVELER_JSON_BYTES) {
      ctx.addIssue({ code: "custom", message: "traveler exceeds 512 KiB" });
    }
    if (p.itar) {
      for (const [i, q] of (p.quotes ?? []).entries()) {
        if (q.seller.itar !== true) {
          ctx.addIssue({
            code: "custom",
            path: ["quotes", i, "seller", "itar"],
            message: "ITAR traveler cannot carry a quote from a non-ITAR seller",
          });
        }
      }
    }
  });

export type QuoteInput = z.infer<typeof quoteSchema>;
export type TravelerInput = z.infer<typeof travelerSchema>;
