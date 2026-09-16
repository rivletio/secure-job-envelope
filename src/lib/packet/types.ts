export const PACKET_SPEC = "rivlet-packet/0.0.1" as const;
export const PACKET_MEDIA = "application/vnd.rivlet.packet+json" as const;
export const HASH_RE = /^sha256:[0-9a-f]{64}$/;
export const PACKET_ID_RE = /^[a-z]{3}_[a-z0-9]{6,24}$/;
export const CURRENCY_RE = /^[A-Z]{3}$/;
export const COUNTRY_RE = /^[A-Z]{2}$/;
export const ISO_DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
export const ISO_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

export const MAX_PACKET_JSON_BYTES = 512 * 1024;
export const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024;
export const MAX_STRING = 2000;
export const MAX_NAME = 128;

export type ConformanceLevel = 0 | 1 | 2 | 3;

export type Org = {
  org_id?: string;
  name: string;
  city?: string;
  region?: string;
  contact?: string;
  certs?: string[];
  itar?: boolean;
};

export type Material = {
  spec: string;
  form?: string;
  thickness_mm?: number;
};

export type Qty = {
  target: number;
  breaks?: number[];
};

export type Part = {
  family: string;
  part_number: string;
  description?: string;
  drawing_rev?: string;
  material: Material;
  qty: Qty;
  processes?: string[];
  finish?: string;
  tolerances?: string;
  notes?: string;
};

export type ShipTo = {
  name: string;
  line1: string;
  line2?: string;
  city: string;
  region: string;
  postal: string;
  country: string;
};

export type Op = {
  seq: number;
  code: string;
  notes?: string;
};

export type PriceLine = {
  qty: number;
  unit: number;
};

export type QuoteException = {
  code: string;
  on?: string;
  proposal: string;
  price_delta?: number;
};

export type QuotePricing = {
  currency: string;
  nre?: number;
  lines: PriceLine[];
  freight_estimate?: number;
  tax_excluded?: boolean;
};

export type Quote = {
  quote_id: string;
  seller: Org;
  packet_hash_quoted: string;
  created_at: string;
  valid_until: string;
  lead_time_days: number;
  need_by_feasible?: boolean;
  pricing: QuotePricing;
  assumptions?: Record<string, unknown>;
  exceptions?: QuoteException[];
  capacity?: Record<string, unknown>;
};

export type Award = {
  quote_id: string;
  awarded_at: string;
  qty: number;
};

export type Packet = {
  spec: typeof PACKET_SPEC;
  packet_id: string;
  revision: number;
  created_at: string;
  buyer: Org;
  part: Part;
  need_by?: string | null;
  incoterms?: string | null;
  itar?: boolean;
  ship_to?: ShipTo | null;
  ops?: Op[];
  quotes?: Quote[];
  award?: Award | null;
  as_built?: Record<string, unknown> | null;
};

/** Buyer-authored body. Quotes bind to the hash of this object. */
export type QuoteableBody = {
  spec: typeof PACKET_SPEC;
  packet_id: string;
  revision: number;
  created_at: string;
  buyer: Org;
  part: Part;
  need_by: string | null;
  incoterms: string | null;
  itar: boolean;
};

export type Shop = Org & {
  org_id: string;
  processes: string[];
  blurb: string;
};

export const PROCESS_OPTIONS = [
  "cnc_mill",
  "cnc_turn",
  "swiss",
  "laser",
  "waterjet",
  "brake",
  "weld",
  "anodize",
  "powder",
  "pem",
  "inspect",
  "plate",
] as const;

export type ProcessCode = (typeof PROCESS_OPTIONS)[number];

export const MATERIAL_PRESETS = [
  "6061-T6",
  "7075-T6",
  "304 SS",
  "303 SS",
  "17-4 PH",
  "A36",
  "CRS 16ga",
  "Delrin",
] as const;
