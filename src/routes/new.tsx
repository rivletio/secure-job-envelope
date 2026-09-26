import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { HashChip } from "@/components/hash-chip";
import { LevelBadge } from "@/components/level-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { levelOf } from "@/lib/traveler/conformance";
import { travelerHash } from "@/lib/traveler/hash";
import { isoNow, newTravelerId } from "@/lib/traveler/ids";
import { useTravelerStore } from "@/lib/traveler/store";
import {
  MATERIAL_PRESETS,
  TRAVELER_SPEC,
  PROCESS_OPTIONS,
  type Traveler,
} from "@/lib/traveler/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/new")({ component: Compose });

function Compose() {
  const upsert = useTravelerStore((s) => s.upsert);
  const navigate = useNavigate();
  const [buyer, setBuyer] = useState("Northline Equipment");
  const [city, setCity] = useState("Milwaukee");
  const [region, setRegion] = useState("WI");
  const [family, setFamily] = useState("CNC bracket");
  const [partNumber, setPartNumber] = useState("NL-");
  const [drawingRev, setDrawingRev] = useState("A");
  const [description, setDescription] = useState("");
  const [material, setMaterial] = useState("6061-T6");
  const [form, setForm] = useState("plate");
  const [thickness, setThickness] = useState("9.53");
  const [qty, setQty] = useState("50");
  const [breaks, setBreaks] = useState("10, 50, 200");
  const [finish, setFinish] = useState("");
  const [tolerances, setTolerances] = useState("ISO 2768-mK");
  const [needBy, setNeedBy] = useState("2026-10-30");
  const [itar, setItar] = useState(false);
  const [notes, setNotes] = useState("");
  const [processes, setProcesses] = useState<string[]>(["cnc_mill"]);

  const draft: Traveler = useMemo(() => {
    const target = Math.max(1, Number(qty) || 1);
    const br = breaks
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 1);
    const th = Number(thickness);
    return {
      spec: TRAVELER_SPEC,
      traveler_id: "tvl_draftlive",
      revision: 1,
      created_at: "2026-09-14T00:00:00.000Z",
      buyer: { name: buyer, city, region },
      part: {
        family,
        part_number: partNumber,
        drawing_rev: drawingRev || undefined,
        description: description || undefined,
        material: {
          spec: material,
          form: form || undefined,
          thickness_mm: Number.isFinite(th) && th > 0 ? th : undefined,
        },
        qty: { target, breaks: br.length ? br : undefined },
        processes,
        finish: finish || undefined,
        tolerances: tolerances || undefined,
        notes: notes || undefined,
      },
      need_by: needBy || null,
      incoterms: "FOB",
      itar,
    };
  }, [
    buyer,
    city,
    region,
    family,
    partNumber,
    drawingRev,
    description,
    material,
    form,
    thickness,
    qty,
    breaks,
    finish,
    tolerances,
    needBy,
    itar,
    notes,
    processes,
  ]);

  const info = levelOf(draft);
  const hash = travelerHash(draft);

  function toggleProcess(code: string) {
    setProcesses((p) => (p.includes(code) ? p.filter((x) => x !== code) : [...p, code]));
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (info.code === "D") {
      toast.error(`Not quoteable yet: ${info.missing.join(", ")}`);
      return;
    }
    const traveler: Traveler = {
      ...draft,
      traveler_id: newTravelerId(),
      created_at: isoNow(),
      buyer: {
        name: buyer.trim(),
        ...(city.trim() ? { city: city.trim() } : {}),
        ...(region.trim() ? { region: region.trim() } : {}),
      },
      quotes: [],
    };
    try {
      upsert(traveler);
      toast.success(`${traveler.traveler_id} is L0 quoteable`);
      void navigate({ to: "/t/$travelerId", params: { travelerId: traveler.traveler_id } });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not seal traveler");
    }
  }

  return (
    <AppShell>
      <div className="mb-6">
        <p className="mono-label">Compose</p>
        <h1 className="mt-2 text-3xl tracking-tight text-paper">New traveler</h1>
        <p className="mt-2 max-w-2xl text-sm text-soft">
          Fill material and qty and it is L0 — a shop can price without guessing. The hash
          on the right tracks the quoteable body as you edit; the sealed traveler gets its
          own id and timestamp, so its final bind-to hash is fixed when you seal it.
        </p>
      </div>
      <form onSubmit={submit} className="grid gap-8 lg:grid-cols-[1fr_20rem]">
        <div className="grid gap-6">
          <fieldset className="on-paper traveler-shadow grid gap-3 rounded-sm border-0 p-4">
            <legend className="bg-paper px-2 text-sm font-medium">Buyer</legend>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Shop" value={buyer} onChange={setBuyer} />
              <Field label="City" value={city} onChange={setCity} />
              <Field label="Region" value={region} onChange={setRegion} />
            </div>
          </fieldset>
          <fieldset className="on-paper traveler-shadow grid gap-3 rounded-sm border-0 p-4">
            <legend className="bg-paper px-2 text-sm font-medium">Part family</legend>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Family" value={family} onChange={setFamily} />
              <Field label="Part number" value={partNumber} onChange={setPartNumber} />
              <Field label="Drawing rev" value={drawingRev} onChange={setDrawingRev} />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="desc">Description</Label>
              <Textarea
                id="desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
              />
            </div>
          </fieldset>
          <fieldset className="on-paper traveler-shadow grid gap-3 rounded-sm border-0 p-4">
            <legend className="bg-paper px-2 text-sm font-medium">Material & qty</legend>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="grid gap-1">
                <Label htmlFor="mat">Material spec</Label>
                <Input
                  id="mat"
                  list="mats"
                  value={material}
                  onChange={(e) => setMaterial(e.target.value)}
                />
                <datalist id="mats">
                  {MATERIAL_PRESETS.map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </div>
              <Field label="Form" value={form} onChange={setForm} />
              <Field label="Thickness mm" value={thickness} onChange={setThickness} />
              <Field label="Target qty" value={qty} onChange={setQty} />
              <Field label="Breaks" value={breaks} onChange={setBreaks} className="sm:col-span-2" />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {PROCESS_OPTIONS.map((code) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => toggleProcess(code)}
                  className={cn(
                    "rounded-sm border px-2 py-1 font-mono text-xs",
                    processes.includes(code)
                      ? "border-accent bg-accent/10 text-accent"
                      : "border-border text-muted-foreground",
                  )}
                >
                  {code}
                </button>
              ))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Finish" value={finish} onChange={setFinish} />
              <Field label="Tolerances" value={tolerances} onChange={setTolerances} />
              <Field label="Need by" value={needBy} onChange={setNeedBy} />
              <label className="flex items-end gap-2 pb-2 text-sm">
                <input
                  type="checkbox"
                  checked={itar}
                  onChange={(e) => setItar(e.target.checked)}
                  className="size-4 accent-primary"
                />
                ITAR-controlled technical data (self-declaration)
              </label>
            </div>
            {itar && (
              <p className="rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs leading-relaxed text-foreground">
                Checking this does not implement ITAR, EAR, or deemed-export controls. This desk
                stores travelers in this browser, hashes the quoteable body, and refuses quotes from
                shops that are not marked ITAR. It is not a DDTC-authorized distribution system.
                Do not put actual controlled drawings on a public desk.
              </p>
            )}
            <div className="grid gap-1">
              <Label htmlFor="notes">Notes</Label>
              <Textarea id="notes" rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} />
            </div>
          </fieldset>
          <Button type="submit" className="h-12">
            Seal L0 traveler
          </Button>
        </div>
        <aside className="on-paper traveler-shadow h-fit rounded-sm p-4 lg:sticky lg:top-28">
          <LevelBadge info={info} />
          <p className="mt-3 font-mono text-xs text-muted-foreground">Live hash — preview (fixed on seal)</p>
          <HashChip hash={hash} className="mt-2 w-full justify-between" />
          <dl className="mt-4 grid gap-2 text-sm">
            <Row k="Family" v={family || "—"} />
            <Row k="PN" v={partNumber || "—"} />
            <Row k="Material" v={material || "—"} />
            <Row k="Qty" v={qty || "—"} />
            <Row k="Need by" v={needBy || "—"} />
          </dl>
          {info.code === "D" && (
            <p className="mt-4 text-xs text-warn">Missing {info.missing.join(", ")}</p>
          )}
          {info.code === "L0" && (
            <p className="mt-4 text-xs text-ok">Quoteable. A seller can price this without guessing.</p>
          )}
        </aside>
      </form>
    </AppShell>
  );
}

function Field({
  label,
  value,
  onChange,
  className,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  className?: string;
}) {
  const id = label.replaceAll(" ", "-").toLowerCase();
  return (
    <div className={cn("grid gap-1", className)}>
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="truncate font-medium">{v}</dd>
    </div>
  );
}
