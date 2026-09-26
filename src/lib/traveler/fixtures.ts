import { travelerHash } from "./hash.ts";
import type { Traveler, Quote, QuoteableBody } from "./types.ts";
import { TRAVELER_SPEC } from "./types.ts";

function withBoundQuotes(traveler: Omit<Traveler, "quotes"> & { quotes?: Quote[] }): Traveler {
  const base: Traveler = { ...traveler, quotes: [] };
  const hash = travelerHash(base);
  return {
    ...base,
    quotes: (traveler.quotes ?? []).map((q) => ({ ...q, traveler_hash_quoted: hash })),
  };
}

const huron = {
  org_id: "org_huron",
  name: "Huron Precision",
  city: "Toledo",
  region: "OH",
  certs: ["ISO 9001"],
  itar: true,
};

const redRiver = {
  org_id: "org_redriver",
  name: "Red River Machine",
  city: "Fort Worth",
  region: "TX",
  certs: ["ISO 9001"],
  itar: false,
};

const cascade = {
  org_id: "org_cascade",
  name: "Cascade Sheet Metal",
  city: "Portland",
  region: "OR",
  certs: ["ISO 9001"],
  itar: false,
};

const lakeshore = {
  org_id: "org_lakeshore",
  name: "Lakeshore Turning",
  city: "Racine",
  region: "WI",
  certs: ["ISO 9001", "AS9100"],
  itar: false,
};

export function seedTravelers(): Traveler[] {
  const bracket = withBoundQuotes({
    spec: TRAVELER_SPEC,
    traveler_id: "tvl_nlbrk4410",
    revision: 1,
    created_at: "2026-09-08T15:12:00.000Z",
    buyer: {
      org_id: "org_northline",
      name: "Northline Equipment",
      city: "Milwaukee",
      region: "WI",
      contact: "buyer@northline.example",
    },
    part: {
      family: "CNC bracket",
      part_number: "NL-BRK-4410",
      drawing_rev: "C",
      description:
        "Motor-mount bracket. 4× Ø5.5 through, 2× M6×1.0. Keep datum A as-machined.",
      material: { spec: "6061-T6", form: "plate", thickness_mm: 9.53 },
      qty: { target: 50, breaks: [10, 50, 200] },
      processes: ["cnc_mill", "anodize", "inspect"],
      finish: "Type II class 2 clear anodize",
      tolerances: "ISO 2768-mK",
      notes: "No paint. Mask threads after anodize.",
    },
    need_by: "2026-10-24",
    incoterms: "FOB",
    itar: false,
    quotes: [
      {
        quote_id: "qot_huron4410",
        seller: huron,
        traveler_hash_quoted: "sha384:pending",
        created_at: "2026-09-09T18:40:00.000Z",
        valid_until: "2026-09-30T00:00:00.000Z",
        lead_time_days: 12,
        need_by_feasible: true,
        pricing: {
          currency: "USD",
          nre: 350,
          lines: [
            { qty: 10, unit: 48 },
            { qty: 50, unit: 29 },
            { qty: 200, unit: 21 },
          ],
          freight_estimate: 85,
          tax_excluded: true,
        },
        assumptions: { anodize: "in-house Type II", fixture: "dedicated aluminum" },
        capacity: { load_pct: 62, hours_open: 80 },
      },
      {
        quote_id: "qot_red4410",
        seller: redRiver,
        traveler_hash_quoted: "sha384:pending",
        created_at: "2026-09-10T13:05:00.000Z",
        valid_until: "2026-09-28T00:00:00.000Z",
        lead_time_days: 18,
        need_by_feasible: true,
        pricing: {
          currency: "USD",
          nre: 500,
          lines: [
            { qty: 10, unit: 44 },
            { qty: 50, unit: 31 },
            { qty: 200, unit: 19.5 },
          ],
          freight_estimate: 110,
          tax_excluded: true,
        },
        exceptions: [
          {
            code: "FINISH_OUTSOURCE",
            on: "part.finish",
            proposal: "Type II anodize at certified vendor, 3 days in queue.",
            price_delta: 2.4,
          },
        ],
        capacity: { load_pct: 41, hours_open: 120 },
      },
    ],
  });

  const enclosure = withBoundQuotes({
    spec: TRAVELER_SPEC,
    traveler_id: "tvl_smenc1601",
    revision: 2,
    created_at: "2026-09-02T11:00:00.000Z",
    buyer: {
      org_id: "org_pacific",
      name: "Pacific Hatch",
      city: "Oakland",
      region: "CA",
    },
    part: {
      family: "Sheet enclosure",
      part_number: "PH-ENC-1601",
      drawing_rev: "B",
      description: "16ga CRS box, 220 × 140 × 80, PEM PEMs on lid, black wrinkle powder.",
      material: { spec: "CRS 16ga", form: "sheet" },
      qty: { target: 200, breaks: [50, 200, 500] },
      processes: ["laser", "brake", "pem", "powder", "inspect"],
      finish: "Black wrinkle powder, interior masked",
      tolerances: "ISO 2768-m",
    },
    need_by: "2026-10-16",
    incoterms: "FOB",
    itar: false,
    ship_to: {
      name: "Pacific Hatch — Receiving",
      line1: "4100 Mandela Pkwy",
      city: "Oakland",
      region: "CA",
      postal: "94608",
      country: "US",
    },
    ops: [
      { seq: 1, code: "LASER", notes: "Nest on 5×10 CRS" },
      { seq: 2, code: "FORM", notes: "Brake sequence on traveler" },
      { seq: 3, code: "PEM", notes: "M4 and M5 as ballooned" },
      { seq: 4, code: "POWDER", notes: "Black wrinkle, mask PEM ID" },
      { seq: 5, code: "INSPECT" },
      { seq: 6, code: "PACK", notes: "Corner protectors, 10 per carton" },
    ],
    quotes: [
      {
        quote_id: "qot_casc1601",
        seller: cascade,
        traveler_hash_quoted: "sha384:pending",
        created_at: "2026-09-04T16:22:00.000Z",
        valid_until: "2026-09-25T00:00:00.000Z",
        lead_time_days: 15,
        need_by_feasible: true,
        pricing: {
          currency: "USD",
          nre: 220,
          lines: [
            { qty: 50, unit: 38 },
            { qty: 200, unit: 24.5 },
            { qty: 500, unit: 19 },
          ],
          freight_estimate: 140,
          tax_excluded: true,
        },
      },
    ],
    award: {
      quote_id: "qot_casc1601",
      awarded_at: "2026-09-05T19:10:00.000Z",
      qty: 200,
    },
  });

  const shaft = withBoundQuotes({
    spec: TRAVELER_SPEC,
    traveler_id: "tvl_shft30325",
    revision: 1,
    created_at: "2026-09-11T09:30:00.000Z",
    buyer: {
      org_id: "org_atlas",
      name: "Atlas Door Systems",
      city: "Grand Rapids",
      region: "MI",
    },
    part: {
      family: "Turned shaft",
      part_number: "ADS-SH-30325",
      drawing_rev: "A",
      description: "Ø18 × 140 303 SS. Two retaining grooves, 32 Ra on journals.",
      material: { spec: "303 SS", form: "bar" },
      qty: { target: 25, breaks: [10, 25, 100] },
      processes: ["cnc_turn", "inspect"],
      finish: "As-turned, passivate",
      tolerances: "h7 on journals",
    },
    need_by: "2026-11-06",
    incoterms: "FOB",
    itar: false,
    quotes: [
      {
        quote_id: "qot_lake303",
        seller: lakeshore,
        traveler_hash_quoted: "sha384:pending",
        created_at: "2026-09-12T20:00:00.000Z",
        valid_until: "2026-10-03T00:00:00.000Z",
        lead_time_days: 21,
        need_by_feasible: true,
        pricing: {
          currency: "USD",
          nre: 180,
          lines: [
            { qty: 10, unit: 62 },
            { qty: 25, unit: 41 },
            { qty: 100, unit: 28 },
          ],
          freight_estimate: 55,
          tax_excluded: true,
        },
        assumptions: { passivate: "citric, included" },
        capacity: { load_pct: 78 },
      },
    ],
  });

  const weldment: Traveler = {
    spec: TRAVELER_SPEC,
    traveler_id: "tvl_wldcart12",
    revision: 1,
    created_at: "2026-09-14T17:00:00.000Z",
    buyer: {
      org_id: "org_northline",
      name: "Northline Equipment",
      city: "Milwaukee",
      region: "WI",
    },
    part: {
      family: "Welded cart frame",
      part_number: "NL-CRT-1200",
      drawing_rev: "A",
      description: "A36 1.5 sq tube cart, 24 × 36 × 36. Casters by buyer.",
      material: { spec: "A36", form: "tube" },
      qty: { target: 12, breaks: [4, 12, 24] },
      processes: ["weld", "cnc_mill", "inspect"],
      finish: "Black enamel, weld spatter removed",
      tolerances: "AWS D1.1, ±1.5 mm envelope",
      notes: "Open RFQ. Need mill pads on the top rails.",
    },
    need_by: "2026-11-20",
    incoterms: "FOB",
    itar: false,
    quotes: [],
  };

  return [bracket, enclosure, shaft, weldment];
}

/** Golden quoteable body — must match crates/secure-job-envelope tests. */
export const GOLDEN_QUOTEABLE: QuoteableBody = {
  spec: TRAVELER_SPEC,
  traveler_id: "tvl_golden0001",
  revision: 1,
  created_at: "2026-09-14T00:00:00.000Z",
  buyer: { name: "Northline Equipment" },
  part: {
    family: "CNC bracket",
    part_number: "NL-BRK-4410",
    material: { spec: "6061-T6" },
    qty: { target: 50 },
  },
  need_by: "2026-10-30",
  incoterms: "FOB",
  itar: false,
};
