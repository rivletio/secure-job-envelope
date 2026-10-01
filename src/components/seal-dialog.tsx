import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { travelerHash } from "@/lib/traveler/hash";
import { useKeysStore } from "@/lib/traveler/keys-store";
import { useTravelerStore } from "@/lib/traveler/store";
import { sealTraveler } from "@/lib/traveler/transport";
import { downloadEnvelope } from "@/lib/traveler/zip";
import type { Traveler } from "@/lib/traveler/types";

/** Seal a traveler to a directory-attested recipient and download the ciphertext
 *  `.sje`. Sealing needs only public keys, so no unlock is required. The recipient
 *  set comes from the loaded, verified trust anchor; the directory is re-verified
 *  inside sealTraveler before any key is used. */
export function SealDialog({
  traveler,
  open,
  onOpenChange,
}: {
  traveler: Traveler;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const trust = useKeysStore((s) => s.trust);
  const logAudit = useTravelerStore((s) => s.logAudit);
  const [org, setOrg] = useState("");
  const [requireFs, setRequireFs] = useState(false);
  const [busy, setBusy] = useState(false);

  const recipients = useMemo(() => {
    if (!trust) return [];
    return trust.directory.entries
      .filter((e) => e.enc_public_key && e.enc_alg === "ML-KEM-1024")
      .map((e) => ({ org_id: e.org_id, hasBundle: Boolean(trust.bundles[e.org_id]) }));
  }, [trust]);

  const chosen = recipients.find((r) => r.org_id === org);
  const canFs = Boolean(chosen?.hasBundle);

  async function seal() {
    if (!trust) {
      toast.error("Load a trust anchor in Keys first.");
      return;
    }
    if (!org) {
      toast.error("Choose a recipient.");
      return;
    }
    setBusy(true);
    try {
      const bundle = canFs ? trust.bundles[org] : undefined;
      const { envelope, forwardSecret } = await sealTraveler(traveler, {
        directory: trust.directory,
        rootPublicKeyHex: trust.rootPublicKeyHex,
        recipientOrg: org,
        ...(bundle ? { prekeyBundle: bundle } : {}),
        ...(requireFs ? { requireForwardSecret: true } : {}),
      });
      downloadEnvelope(envelope);
      logAudit({ act: "export", traveler_id: traveler.traveler_id, hash: travelerHash(traveler) });
      toast.success(`Sealed to ${org} · ${forwardSecret ? "forward-secret" : "static"} — downloaded .sje`);
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not seal");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Seal &amp; send {traveler.part.part_number}</DialogTitle>
          <DialogDescription>
            Encrypts this traveler to a recipient from your trust anchor (ML-KEM-1024 + AES-256-GCM).
            The downloaded <code>.sje</code> is ciphertext — the only artifact meant to be sent.
            The filename is random so it does not leak the traveler id.
          </DialogDescription>
        </DialogHeader>

        {!trust ? (
          <p className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            No trust anchor loaded. Open <span className="font-medium">Keys</span> and load a signed
            directory before sealing.
          </p>
        ) : recipients.length === 0 ? (
          <p className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-sm text-warn">
            The loaded directory has no recipients with an ML-KEM encryption key.
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            {traveler.itar && (
              <p className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
                Self-declared ITAR. Encryption protects confidentiality in transit; it is not
                export-control. Do not transmit to foreign persons.
              </p>
            )}
            <div className="grid gap-1">
              <Label htmlFor="seal-org">Recipient</Label>
              <select
                id="seal-org"
                value={org}
                onChange={(e) => {
                  setOrg(e.target.value);
                  setRequireFs(false);
                }}
                className="h-9 rounded-sm border border-border bg-card-navy px-2 text-sm text-text"
              >
                <option value="">Choose an org…</option>
                {recipients.map((r) => (
                  <option key={r.org_id} value={r.org_id}>
                    {r.org_id}
                    {r.hasBundle ? " · forward-secret available" : " · static only"}
                  </option>
                ))}
              </select>
            </div>

            {org &&
              (canFs ? (
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={requireFs}
                    onChange={(e) => setRequireFs(e.target.checked)}
                    className="size-4 accent-primary"
                  />
                  Require forward secrecy (refuse to send if no prekey is usable)
                </label>
              ) : (
                <p className="text-xs text-muted-foreground">
                  No prekey bundle for this recipient — a static envelope will be sent (reported
                  after sealing).
                </p>
              ))}

            <Button type="button" onClick={seal} disabled={busy || !org}>
              Seal &amp; download .sje
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
