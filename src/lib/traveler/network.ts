import type { Shop } from "./types.ts";

export const SHOPS: Shop[] = [
  {
    org_id: "org_huron",
    name: "Huron Precision",
    city: "Toledo",
    region: "OH",
    certs: ["ISO 9001"],
    itar: true,
    processes: ["cnc_mill", "cnc_turn", "inspect", "anodize"],
    blurb: "ITAR mill/turn cell. 3–4 axis, 6061 through 17-4.",
  },
  {
    org_id: "org_redriver",
    name: "Red River Machine",
    city: "Fort Worth",
    region: "TX",
    certs: ["ISO 9001"],
    itar: false,
    processes: ["cnc_mill", "weld", "inspect"],
    blurb: "Job shop mill and weld. Anodize outsourced down the street.",
  },
  {
    org_id: "org_cascade",
    name: "Cascade Sheet Metal",
    city: "Portland",
    region: "OR",
    certs: ["ISO 9001"],
    itar: false,
    processes: ["laser", "brake", "pem", "powder", "inspect"],
    blurb: "Laser, brake, PEM, powder. Overnight to the Bay.",
  },
  {
    org_id: "org_lakeshore",
    name: "Lakeshore Turning",
    city: "Racine",
    region: "WI",
    certs: ["ISO 9001", "AS9100"],
    itar: false,
    processes: ["cnc_turn", "swiss", "inspect"],
    blurb: "Swiss and chucking. 303, 17-4, Delrin.",
  },
  {
    org_id: "org_ironrange",
    name: "Iron Range Fab",
    city: "Duluth",
    region: "MN",
    certs: ["AWS D1.1"],
    itar: false,
    processes: ["weld", "cnc_mill", "inspect"],
    blurb: "A36 weldments. AWS D1.1, carts, frames, guards.",
  },
  {
    org_id: "org_summitfab",
    name: "Summit Fabrication",
    city: "Sparks",
    region: "NV",
    certs: ["ISO 9001"],
    itar: false,
    processes: ["laser", "brake", "cnc_mill", "inspect"],
    blurb: "Laser, brake, and mill. Fast-turn brackets and plates.",
  },
];

export function shopById(id: string): Shop | undefined {
  return SHOPS.find((s) => s.org_id === id);
}

export function opsFromProcesses(processes: string[] = []): { seq: number; code: string; notes?: string }[] {
  const map: Record<string, { code: string; notes?: string }> = {
    cnc_mill: { code: "MILL", notes: "Fixture per drawing rev" },
    cnc_turn: { code: "TURN" },
    swiss: { code: "SWISS" },
    laser: { code: "LASER" },
    waterjet: { code: "JET" },
    brake: { code: "FORM" },
    weld: { code: "WELD", notes: "AWS D1.1 unless noted" },
    anodize: { code: "ANODIZE" },
    powder: { code: "POWDER" },
    pem: { code: "PEM" },
    plate: { code: "PLATE" },
    inspect: { code: "INSPECT", notes: "First article + in-process" },
  };
  const ops = processes
    .map((p) => map[p])
    .filter((x): x is { code: string; notes?: string } => Boolean(x));
  if (!ops.some((o) => o.code === "INSPECT")) {
    ops.push({ code: "INSPECT", notes: "Dimensional per drawing" });
  }
  ops.push({ code: "PACK", notes: "Protect finished faces" });
  return ops.map((o, i) => ({ seq: i + 1, ...o }));
}
