/** Adversarial mutation catalog shared by the differential fuzzer and the corpus
 *  generator. Each mutation nudges one field of a valid traveler to a boundary the
 *  schema cares about; the two implementations must agree on accept/reject either
 *  way. A mix of "should reject" (over a ceiling, malformed) and "should still
 *  accept" (right at the edge) — the harness never assumes which, only that the two
 *  agree.
 *
 *  `jsonSafe: false` marks a mutation whose output cannot round-trip through a JSON
 *  file that Rust's serde reads (a lone surrogate has no UTF-8 encoding). The
 *  differential exercises those in-process; the committed corpus excludes them.
 */
export type Doc = Record<string, any>;
export type Mutation = { name: string; jsonSafe?: boolean; apply: (doc: Doc) => void };

const firstQuote = (d: Doc): Doc | undefined => d.quotes?.[0];

export const MUTATIONS: Mutation[] = [
  { name: "revision-zero", apply: (d) => (d.revision = 0) },
  { name: "revision-over", apply: (d) => (d.revision = 10_001) },
  { name: "revision-huge", apply: (d) => (d.revision = 1_000_000_000) },
  { name: "revision-noninteger", apply: (d) => (d.revision = 1.5) },
  { name: "qty-target-over", apply: (d) => (d.part.qty.target = 1_000_001) },
  { name: "qty-target-zero", apply: (d) => (d.part.qty.target = 0) },
  { name: "qty-break-over", apply: (d) => (d.part.qty.breaks = [1_000_001]) },
  { name: "thickness-below-schema", apply: (d) => (d.part.material.thickness_mm = 0.00005) },
  { name: "thickness-below-canonical", apply: (d) => (d.part.material.thickness_mm = 0.000001) },
  { name: "thickness-over", apply: (d) => (d.part.material.thickness_mm = 2_000_000) },
  { name: "name-whitespace", apply: (d) => (d.buyer.name = `  ${d.buyer.name}\t`) },
  { name: "family-whitespace", apply: (d) => (d.part.family = ` ${d.part.family} `) },
  { name: "name-astral", apply: (d) => (d.buyer.name = `${d.buyer.name} \u{1F600}`) },
  { name: "name-lone-surrogate", jsonSafe: false, apply: (d) => (d.buyer.name = `${d.buyer.name}\uD800`) },
  { name: "notes-lone-surrogate", jsonSafe: false, apply: (d) => (d.part.notes = "note\uDC00end") },
  { name: "name-too-long", apply: (d) => (d.buyer.name = "x".repeat(200)) },
  { name: "unknown-key-top", apply: (d) => (d.surprise = "extra") },
  { name: "unknown-key-part", apply: (d) => (d.part.surprise = 1) },
  { name: "traveler-id-upper", apply: (d) => (d.traveler_id = "TVL_ABCDEF") },
  { name: "traveler-id-short", apply: (d) => (d.traveler_id = "tvl_ab") },
  { name: "created-at-no-ms", apply: (d) => (d.created_at = "2026-05-01T12:00:00Z") },
  { name: "created-at-sec-60", apply: (d) => (d.created_at = "2026-05-01T12:00:60.000Z") },
  { name: "created-at-hour-24", apply: (d) => (d.created_at = "2026-05-01T24:00:00.000Z") },
  { name: "created-at-offset", apply: (d) => (d.created_at = "2026-05-01T12:00:00.000+00:00") },
  { name: "created-at-feb31", apply: (d) => (d.created_at = "2026-02-31T12:00:00.000Z") },
  { name: "as-built-oversize", apply: (d) => (d.as_built = { blob: "x".repeat(9000) }) },
  // ---- quote-targeted (only bite when a quote exists) ----
  { name: "lead-time-over", apply: (d) => firstQuote(d) && (firstQuote(d)!.lead_time_days = 3651) },
  { name: "lead-time-neg", apply: (d) => firstQuote(d) && (firstQuote(d)!.lead_time_days = -1) },
  {
    name: "lines-over-16",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.lines = Array.from({ length: 20 }, () => ({ qty: 1, unit: 100 }));
    },
  },
  {
    name: "line-qty-over",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.lines[0].qty = 1_000_001;
    },
  },
  {
    name: "money-over",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.lines[0].unit = 1_000_000_000_001;
    },
  },
  {
    name: "money-noninteger",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.lines[0].unit = 100.5;
    },
  },
  {
    name: "currency-lower",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.currency = "usd";
    },
  },
  {
    name: "quote-unknown-key",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.surprise = true;
    },
  },
  {
    name: "quote-valid-before-created",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.valid_until = q.created_at;
    },
  },
  {
    name: "quote-assumptions-oversize",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.assumptions = { blob: "x".repeat(9000) };
    },
  },
  {
    name: "quote-exceptions-over",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.exceptions = Array.from({ length: 20 }, (_, i) => ({ code: `c${i}`, proposal: "x" }));
    },
  },
  {
    name: "quote-price-delta-over",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.exceptions = [{ code: "c", proposal: "x", price_delta: 1_000_000_000_001 }];
    },
  },
  {
    name: "quote-freight-over",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.freight_estimate = 1_000_000_000_001;
    },
  },
  {
    name: "quote-nre-negative",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.nre = -1;
    },
  },
  {
    name: "quote-currency-4letter",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.pricing.currency = "USDX";
    },
  },
  {
    name: "seller-org-id-bad-start",
    apply: (d) => {
      const q = firstQuote(d);
      if (q) q.seller.org_id = "1abc";
    },
  },
  // ---- boundary values that must still be ACCEPTED (both sides) ----
  { name: "revision-max-ok", apply: (d) => (d.revision = 10_000) },
  { name: "qty-target-max-ok", apply: (d) => (d.part.qty.target = 1_000_000) },
  { name: "thickness-max-ok", apply: (d) => (d.part.material.thickness_mm = 1_000_000) },
  { name: "thickness-min-ok", apply: (d) => (d.part.material.thickness_mm = 0.0001) },
  { name: "lead-time-max-ok", apply: (d) => firstQuote(d) && (firstQuote(d)!.lead_time_days = 3650) },
  { name: "name-max-ok", apply: (d) => (d.buyer.name = "x".repeat(128)) },
  { name: "processes-empty-ok", apply: (d) => (d.part.processes = []) },
  { name: "breaks-empty-ok", apply: (d) => (d.part.qty.breaks = []) },
  // ---- traveler optional fields ----
  { name: "need-by-day-ok", apply: (d) => (d.need_by = "2027-03-15") },
  { name: "need-by-day-bad", apply: (d) => (d.need_by = "2027-02-30") },
  { name: "need-by-datetime-ok", apply: (d) => (d.need_by = "2027-03-15T09:00:00.000Z") },
  { name: "need-by-null-ok", apply: (d) => (d.need_by = null) },
  { name: "incoterms-ok", apply: (d) => (d.incoterms = "FOB") },
  { name: "incoterms-too-long", apply: (d) => (d.incoterms = "x".repeat(65)) },
  { name: "drawing-rev-too-long", apply: (d) => (d.part.drawing_rev = "x".repeat(33)) },
  { name: "finish-too-long", apply: (d) => (d.part.finish = "x".repeat(2001)) },
  { name: "notes-empty", apply: (d) => (d.part.notes = "") },
  { name: "breaks-count-over", apply: (d) => (d.part.qty.breaks = Array.from({ length: 17 }, (_, i) => i + 1)) },
  { name: "certs-count-over", apply: (d) => (d.buyer.certs = Array.from({ length: 17 }, (_, i) => `c${i}`)) },
  { name: "cert-too-long", apply: (d) => (d.buyer.certs = ["x".repeat(65)]) },
  { name: "processes-count-over", apply: (d) => (d.part.processes = Array.from({ length: 33 }, () => "cnc_mill")) },
  // ---- signatures ----
  { name: "signatures-count-over", apply: (d) => (d.signatures = Array.from({ length: 9 }, (_, i) => ({ alg: "ML-DSA-87", kid: `k${i}`, sig: "ab" }))) },
  { name: "signature-bad-alg", apply: (d) => (d.signatures = [{ alg: "RSA-2048", kid: "k", sig: "ab" }]) },
  { name: "signature-sig-nonhex", apply: (d) => (d.signatures = [{ alg: "ML-DSA-87", kid: "k", sig: "XYZ" }]) },
  // ---- ops / award / ship (bite when present via L1..L3 plans) ----
  { name: "ops-seq-over", apply: (d) => d.ops?.[0] && (d.ops[0].seq = 1001) },
  { name: "ops-code-too-long", apply: (d) => d.ops?.[0] && (d.ops[0].code = "x".repeat(33)) },
  { name: "ops-count-over", apply: (d) => d.ops && (d.ops = Array.from({ length: 65 }, (_, i) => ({ seq: i + 1, code: "op" }))) },
  { name: "award-qty-over", apply: (d) => d.award && (d.award.qty = 1_000_001) },
  { name: "ship-country-lower", apply: (d) => d.ship_to && (d.ship_to.country = "us") },
  { name: "ship-postal-too-long", apply: (d) => d.ship_to && (d.ship_to.postal = "x".repeat(17)) },
  { name: "ship-name-untrimmed", apply: (d) => d.ship_to && (d.ship_to.name = " Dock 4 ") },
];
