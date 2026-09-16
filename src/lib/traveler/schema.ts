import { z } from "zod";
import {
  COUNTRY_RE,
  CURRENCY_RE,
  HASH_RE,
  ISO_DAY_RE,
  ISO_DT_RE,
  MAX_NAME,
  MAX_TRAVELER_JSON_BYTES,
  MAX_STRING,
  TRAVELER_ID_RE,
  TRAVELER_SPEC,
} from "./types.ts";

const name = z.string().trim().min(1).max(MAX_NAME);
const longText = z.string().min(1).max(MAX_STRING);
const optName = z.string().trim().min(1).max(MAX_NAME).optional();
const optLong = z.string().min(1).max(MAX_STRING).optional();
const isoDt = z.string().regex(ISO_DT_RE, "ISO-8601 UTC datetime");
const isoDayOrDt = z.union([z.string().regex(ISO_DAY_RE), isoDt]);
/** Values must sit in the canonical numeric range (see canonical.ts): integers
 * or non-integers of magnitude >= 1e-5, so both reference implementations
 * render them identically. */
const canonicalRange = (v: number) => Number.isInteger(v) || Math.abs(v) >= 1e-5;
const money = z.number().finite().nonnegative().max(1e12).refine(canonicalRange, {
  message: "non-integer values below 0.00001 cannot be hashed canonically",
});

const jsonBlob = z.record(z.string(), z.unknown()).refine((v) => JSON.stringify(v).length <= 8192, {
  message: "object exceeds 8 KiB",
});

const orgSchema = z
  .object({
    org_id: z
      .string()
      .regex(/^[a-z][a-z0-9_]{1,63}$/)
      .optional(),
    name,
    city: optName,
    region: optName,
    contact: z.string().trim().min(1).max(200).optional(),
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
            price_delta: z.number().finite().min(-1e12).max(1e12).refine(canonicalRange).optional(),
          })
          .strict(),
      )
      .max(16)
      .optional(),
    capacity: jsonBlob.optional(),
  })
  .strict()
  .superRefine((q, ctx) => {
    if (Date.parse(q.valid_until) <= Date.parse(q.created_at)) {
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
    line1: z.string().trim().min(1).max(200),
    line2: z.string().trim().min(1).max(200).optional(),
    city: name,
    region: name,
    postal: z.string().trim().min(1).max(16),
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
      })
      .strict()
      .nullable()
      .optional(),
    as_built: jsonBlob.nullable().optional(),
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
