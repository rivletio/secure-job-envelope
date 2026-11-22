import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ImportReviewDialog } from "@/components/import-review-dialog";
import { TravelerCard } from "@/components/traveler-card";
import { Button } from "@/components/ui/button";
import { levelOf } from "@/lib/traveler/conformance";
import { itarExportWarning } from "@/lib/traveler/guards";
import { useKeysStore } from "@/lib/traveler/keys-store";
import { useTravelerStore } from "@/lib/traveler/store";
import { openTravelerDeferred, parseSjeEnvelope } from "@/lib/traveler/transport";
import { MAX_ENVELOPE_JSON_BYTES, type Traveler } from "@/lib/traveler/types";
import { importTravelerFile } from "@/lib/traveler/zip";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({ component: Desk });

type Filter = "all" | "L0" | "L1" | "L2";

/** A received traveler waiting on the reader's acknowledgment. */
type PendingImport = {
  traveler: Traveler;
  /** "Opened" / "Decrypted" — for the confirmation toast. */
  verb: string;
  /** Spends the envelope's one-time key; called only after the traveler is stored. */
  commit?: () => Promise<void>;
  notes: string[];
  statements: string[];
};

function Desk() {
  const travelers = useTravelerStore((s) => s.travelers);
  const role = useTravelerStore((s) => s.role);
  const hydrated = useTravelerStore((s) => s.hydrated);
  const importOne = useTravelerStore((s) => s.importOne);
  const previewImport = useTravelerStore((s) => s.previewImport);
  const resetDesk = useTravelerStore((s) => s.resetDesk);
  const [filter, setFilter] = useState<Filter>("all");
  const [pending, setPending] = useState<PendingImport | null>(null);
  const [resetOpen, setResetOpen] = useState(false);

  const counts = useMemo(() => {
    const c = { all: travelers.length, L0: 0, L1: 0, L2: 0 };
    for (const p of travelers) {
      const code = levelOf(p).code;
      if (code === "L0" || code === "D") c.L0 += 1;
      else if (code === "L1") c.L1 += 1;
      else c.L2 += 1;
    }
    return c;
  }, [travelers]);

  const shown = travelers.filter((p) => {
    if (filter === "all") return true;
    const code = levelOf(p).code;
    if (filter === "L0") return code === "L0" || code === "D";
    if (filter === "L2") return code === "L2" || code === "L3";
    return code === filter;
  });

  /** The trust anchor to verify received travelers against, if one is loaded. */
  function trustNow() {
    const t = useKeysStore.getState().trust;
    return t ? { directory: t.directory, rootPublicKeyHex: t.rootPublicKeyHex } : undefined;
  }

  /** Store an admitted traveler, then — only then — spend the one-time key its envelope
   *  used. Decrypting is not accepting: a refusal or a declined review leaves the
   *  envelope openable again. */
  async function complete(p: PendingImport, acknowledged: boolean) {
    let outcome;
    try {
      outcome = importOne(p.traveler, { trust: trustNow(), acknowledged });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not open traveler");
      return;
    }
    toast.success(`${p.verb} ${outcome.traveler.traveler_id}`, {
      description: outcome.notes.join(" "),
    });
    try {
      await p.commit?.();
    } catch (err) {
      toast.error(
        `The traveler was opened, but its one-time key could not be deleted from this browser's storage (${
          err instanceof Error ? err.message : "write failed"
        }). The same envelope can still be decrypted with this keystore.`,
      );
    }
  }

  /** Run a received traveler through the receive policy: refuse it, ask the reader to
   *  acknowledge what is unproven, or store it. */
  async function admit(traveler: Traveler, verb: string, commit?: () => Promise<void>) {
    let decision;
    try {
      decision = previewImport(traveler, { trust: trustNow() });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not open traveler");
      return;
    }
    if (decision.action === "refuse") {
      toast.error(decision.reason);
      return;
    }
    const itar = itarExportWarning(traveler);
    const statements = [
      ...(itar ? [`${itar} Import it onto this local desk anyway?`] : []),
      ...decision.acknowledge,
    ];
    const p: PendingImport = { traveler, verb, commit, notes: decision.notes, statements };
    if (statements.length > 0) {
      setPending(p);
      return;
    }
    await complete(p, false);
  }

  /** Open a sealed `.sje`: decrypt with the unlocked desk keystore, then run the same
   *  receive policy as a plaintext traveler. Needs an unlocked identity. */
  async function ingestSje(file: File) {
    const unlocked = useKeysStore.getState().unlocked;
    if (!unlocked) {
      toast.error("Unlock your identity in Keys to open a sealed .sje");
      return;
    }
    if (file.size > MAX_ENVELOPE_JSON_BYTES) {
      toast.error("Sealed envelope exceeds size limit");
      return;
    }
    let envelope;
    try {
      // The file's bytes, not `file.text()`: text decoding silently strips a byte-order
      // mark and replaces invalid UTF-8, so the desk would open what another reader of
      // the same file refuses.
      envelope = parseSjeEnvelope(new Uint8Array(await file.arrayBuffer()));
    } catch {
      toast.error("Not a recognized SJE envelope");
      return;
    }
    let opened;
    try {
      opened = await openTravelerDeferred(envelope, unlocked, {
        persistKeystore: (ks) => useKeysStore.getState().persistKeystore(ks),
      });
    } catch {
      toast.error("Could not open envelope (wrong recipient, tampered, or not addressed to this desk)");
      return;
    }
    // Decrypted — which says nothing about who sealed it. The receive policy decides.
    await admit(opened.traveler, "Decrypted", opened.commit);
  }

  async function ingest(file: File) {
    if (file.name.toLowerCase().endsWith(".sje")) {
      await ingestSje(file);
      return;
    }
    let traveler;
    try {
      traveler = await importTravelerFile(file);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not open traveler");
      return;
    }
    await admit(traveler, "Opened");
  }

  function confirmPending() {
    const p = pending;
    setPending(null);
    if (p) void complete(p, true);
  }

  function declinePending() {
    const p = pending;
    setPending(null);
    if (p?.commit) {
      toast.message("Not opened. The envelope was left untouched and can be opened again.");
    }
  }

  return (
    <AppShell>
      <section className="mb-8 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <div>
          <p className="mono-label">US job envelope · not a catalog</p>
          <h1 className="mt-3 max-w-xl text-4xl tracking-tight text-paper md:text-5xl">
            The job object. <em className="font-normal text-accent italic">Between two shops.</em>
          </h1>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-soft md:text-base">
            A SJE is a content-addressed envelope for one part family.
            Quote it without guessing material or qty. Award a structured quote.
            Run it when ops and ship-to are on the traveler.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {role === "buyer" ? (
              <Button asChild>
                <Link to="/new">New traveler</Link>
              </Button>
            ) : (
              <Button variant="outline" asChild>
                <Link to="/spec">Read spec 0.1.0</Link>
              </Button>
            )}
            <Button
              variant="outline"
              type="button"
              onClick={() => {
                const input = document.createElement("input");
                input.type = "file";
                input.accept = ".json,.zip,.traveler.zip,.sje,application/json,application/zip";
                input.addEventListener("change", () => {
                  const f = input.files?.[0];
                  if (f) void ingest(f);
                });
                input.click();
              }}
            >
              Open .traveler / .sje
            </Button>
          </div>
        </div>
        <aside className="on-paper traveler-shadow rounded-sm p-5">
          <p className="font-mono text-xs text-muted-foreground">Conformance</p>
          <ul className="mt-3 grid gap-2 text-sm">
            <LevelRow code="L0" name="Quoteable" hint="Material and qty are known" n={counts.L0} />
            <LevelRow code="L1" name="Awardable" hint="A quote bound to this hash" n={counts.L1} />
            <LevelRow code="L2" name="Executable" hint="Awarded, ops, ship-to" n={counts.L2} />
            <LevelRow code="L3" name="As-built" hint="As-built (grouped under Executable)" n={0} />
          </ul>
        </aside>
      </section>

      <div className="mb-4 flex flex-wrap items-center gap-2" role="tablist" aria-label="Conformance filter">
        {(["all", "L0", "L1", "L2"] as const).map((f) => (
          <Button
            key={f}
            type="button"
            size="sm"
            role="tab"
            aria-selected={filter === f}
            variant={filter === f ? "default" : "outline"}
            onClick={() => setFilter(f)}
          >
            {f === "all" ? `All ${counts.all}` : `${f} ${counts[f]}`}
          </Button>
        ))}
        <Button type="button" size="sm" variant="ghost" className="ml-auto" onClick={() => setResetOpen(true)}>
          Reset seed
        </Button>
      </div>

      {!hydrated ? (
        <p className="on-paper rounded-sm border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
          Loading desk…
        </p>
      ) : shown.length === 0 ? (
        <p className="on-paper rounded-sm border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
          No travelers at this level. Compose one, or reset the seed desk.
        </p>
      ) : (
        <div className="grid gap-3">
          {shown.map((p) => (
            <TravelerCard key={p.traveler_id} traveler={p} />
          ))}
        </div>
      )}

      <ImportReviewDialog
        review={
          pending
            ? { travelerId: pending.traveler.traveler_id, notes: pending.notes, statements: pending.statements }
            : null
        }
        onCancel={declinePending}
        onConfirm={confirmPending}
      />
      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Reset the seed desk?"
        body="This replaces every traveler on this origin with the demo seed. Local audit is kept. It cannot be undone."
        confirmLabel="Reset"
        destructive
        onConfirm={resetDesk}
      />
    </AppShell>
  );
}

function LevelRow({
  code,
  name,
  hint,
  n,
}: {
  code: string;
  name: string;
  hint: string;
  n: number;
}) {
  return (
    <li className="flex items-baseline gap-3">
      <span className={cn("w-8 font-mono text-xs font-medium", n ? "text-accent" : "text-faint")}>
        {code}
      </span>
      <span className="flex-1">
        <span className="font-medium">{name}</span>
        <span className="text-muted-foreground"> — {hint}</span>
      </span>
      <span className="font-mono text-xs tabular-nums text-muted-foreground">{n}</span>
    </li>
  );
}
