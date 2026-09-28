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
];
