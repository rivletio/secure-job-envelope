import { useMemo, useState } from "react";
import { toast } from "sonner";
import { DemoAnchorBanner, TrustChangeDialog } from "@/components/trust-notices";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { buildDemoTrust, isDemoTrustRoot } from "@/lib/traveler/demo-trust";
import { rootFingerprint } from "@/lib/traveler/fingerprint";
import { travelerHash } from "@/lib/traveler/hash";
import { useKeysStore, type TrustAnchorInput } from "@/lib/traveler/keys-store";
import {
  forwardSecrecyOutlook,
  staticReasonText,
  usedPrekeyIds,
} from "@/lib/traveler/prekey-ledger";
import { projectForRecipient, withheldSummary } from "@/lib/traveler/projection";
import { useTravelerStore } from "@/lib/traveler/store";
import { itarRecipientBasis, sealTraveler } from "@/lib/traveler/transport";
import { downloadEnvelope } from "@/lib/traveler/zip";
import type { Traveler } from "@/lib/traveler/types";
import { visibleText } from "@/lib/traveler/visible-text";

/** Seal a traveler to a directory-attested recipient and download the ciphertext
 *  `.sje`. Sealing needs only public keys, so no unlock is required. The recipient
 *  set comes from the loaded, verified trust anchor; the directory is re-verified
 *  inside sealTraveler before any key is used.
 *
 *  Forward secrecy spends one of the recipient's one-time prekeys per envelope, and a
 *  prekey opens exactly one. This desk remembers which it has sealed to (the prekey
 *  ledger in the keys store) and never picks one twice: the dialog shows how many are
 *  left, and when none are it says so and falls back to a static envelope — instead of
 *  writing an envelope the recipient could never open and calling it forward-secret.
 *
 *  Under the DEMO trust anchor the recipients' decryption keys are public, so sealing
 *  protects nothing; the dialog says so and takes an explicit acknowledgment for every
 *  envelope.
 *
 *  WHAT IS SENT is the recipient's part of the traveler, not all of it: a recipient that
 *  is not the buyer org the traveler names gets the body, its own quotes and — in the
 *  seller view — the quotes of the shop this desk is quoting as; the award travels only
 *  with the quote that won. The dialog says what is left out before anything is sealed.
 *  Sending the whole traveler instead is a choice made per envelope, in so many words.
 *  A traveler marked ITAR is not sealed to an org the directory does not attest for it. */
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
  const ledger = useKeysStore((s) => s.prekeyLedger);
  const recordPrekeyUse = useKeysStore((s) => s.recordPrekeyUse);
  const logAudit = useTravelerStore((s) => s.logAudit);
  const role = useTravelerStore((s) => s.role);
  const sellerOrgId = useTravelerStore((s) => s.sellerOrgId);
  // The quotes that are this desk's own to send: those of the shop it is quoting as.
  // The buyer view has none (a buyer writes no quotes).
  const senderOrg = role === "seller" ? sellerOrgId : undefined;
  const [org, setOrg] = useState("");
  const [requireFs, setRequireFs] = useState(false);
  const [busy, setBusy] = useState(false);
  const [demoAck, setDemoAck] = useState(false);
  const [sendAll, setSendAll] = useState(false);
  const [proposal, setProposal] = useState<TrustAnchorInput | null>(null);

  const demo = trust ? isDemoTrustRoot(trust.rootPublicKeyHex) : false;

  const recipients = useMemo(() => {
    if (!trust) return [];
    const seen = new Set<string>();
    return trust.directory.entries
      .filter((e) => e.status === "active" && e.enc_public_key && e.enc_alg === "ML-KEM-1024")
      .filter((e) => (seen.has(e.org_id) ? false : (seen.add(e.org_id), true)))
      .map((e) => ({ org_id: e.org_id, hasBundle: Object.hasOwn(trust.bundles, e.org_id) }));
  }, [trust]);

  const chosen = recipients.find((r) => r.org_id === org);
  const bundle = trust && chosen?.hasBundle ? trust.bundles[chosen.org_id] : undefined;
  // What a seal to this recipient would do right now: forward-secret (and how many
  // one-time prekeys this desk has left for it), or static — and why.
  const outlook = useMemo(
    () =>
      trust && chosen
        ? forwardSecrecyOutlook({
            ledger,
            bundle,
            directory: trust.directory,
            rootPublicKeyHex: trust.rootPublicKeyHex,
            recipientOrg: chosen.org_id,
          })
        : null,
    [trust, chosen, bundle, ledger],
  );

  // What a seal to this recipient would put in the envelope and what it would leave
  // out — by the functions sealTraveler itself applies, so the two cannot disagree.
  const entitled = useMemo(
    () =>
      chosen
        ? projectForRecipient(traveler, chosen.org_id, senderOrg ? { senderOrg } : {})
        : null,
    [traveler, chosen, senderOrg],
  );
  const leftOut = entitled ? withheldSummary(entitled.withheld) : null;
  const itarBasis = useMemo(
    () => (trust && chosen ? itarRecipientBasis(traveler, trust.directory, chosen.org_id) : "not-itar"),
    [traveler, trust, chosen],
  );
  const itarBlocked = itarBasis === null;

  function close(v: boolean) {
    if (!v) {
      // Both are per envelope, never remembered.
      setDemoAck(false);
      setSendAll(false);
    }
    onOpenChange(v);
  }

  async function seal() {
    if (!trust) {
      toast.error("Load a trust anchor in Keys first.");
      return;
    }
    if (!chosen) {
      toast.error("Choose a recipient.");
      return;
    }
    if (demo && !demoAck) {
      toast.error("Acknowledge the demo warning first.");
      return;
    }
    setBusy(true);
    try {
      const result = await sealTraveler(traveler, {
        directory: trust.directory,
        rootPublicKeyHex: trust.rootPublicKeyHex,
        recipientOrg: chosen.org_id,
        ...(bundle
          ? { prekeyBundle: bundle, excludePrekeyIds: usedPrekeyIds(ledger, bundle) }
          : {}),
        ...(requireFs ? { requireForwardSecret: true } : {}),
        ...(senderOrg ? { senderOrg } : {}),
        ...(sendAll ? { disclose: "everything" as const } : {}),
      });
      // Remember the spent prekey BEFORE the envelope leaves: if that cannot be
      // recorded (storage full, or another tab used the same prekey meanwhile), this
      // throws and nothing is downloaded.
      if (result.forwardSecret && bundle && result.prekeyId !== undefined) {
        recordPrekeyUse(bundle, result.prekeyId);
      }
      downloadEnvelope(result.envelope);
      logAudit({ act: "export", traveler_id: traveler.traveler_id, hash: travelerHash(traveler) });
      const kept = withheldSummary(result.withheld);
      const how =
        (result.forwardSecret
          ? `forward-secret (one-time prekey ${visibleText(result.prekeyId ?? "")})`
          : `static envelope, no forward secrecy — ${staticReasonText(result.staticReason ?? "no-bundle", chosen.org_id)}`) +
        (kept ? ` · not sent: ${kept}` : "");
      if (demo) {
        toast.warning(
          `Sealed to DEMO recipient ${chosen.org_id} · ${how}. Its decryption key is public: anyone can read this file.`,
        );
      } else if (result.forwardSecret) {
        toast.success(`Sealed to ${chosen.org_id} · ${how} — downloaded .sje`);
      } else {
        toast.warning(`Sealed to ${chosen.org_id} · ${how} Downloaded .sje`);
      }
      close(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not seal");
    } finally {
      setDemoAck(false);
      setSendAll(false);
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent data-testid="seal-dialog">
        <DialogHeader>
          <DialogTitle>Seal &amp; send {traveler.part.part_number}</DialogTitle>
          <DialogDescription>
            Encrypts this traveler to a recipient from your trust anchor (ML-KEM-1024 +
            AES-256-GCM). The downloaded <code>.sje</code> is ciphertext — the only artifact meant
            to be sent. The filename is random so it does not leak the traveler id.
          </DialogDescription>
        </DialogHeader>

        {!trust ? (
          <div className="mt-4 flex flex-col items-start gap-3">
            <p className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-sm">
              Sealing needs a <span className="font-medium">trust anchor</span> — the signed list of
              who can receive. Paste your own in <span className="font-medium">Keys</span>, or load
              the demo one to try it (its keys are public: it protects nothing).
            </p>
            <Button type="button" variant="outline" onClick={() => setProposal(buildDemoTrust())}>
              Load the demo trust anchor…
            </Button>
          </div>
        ) : recipients.length === 0 ? (
          <p className="mt-4 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-sm">
            The loaded directory has no recipients with an ML-KEM encryption key.
          </p>
        ) : (
          <div className="mt-4 flex flex-col gap-4">
            {demo && <DemoAnchorBanner />}
            {traveler.itar && (
              <p className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs">
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
                  setDemoAck(false);
                  setSendAll(false);
                }}
                className="h-9 rounded-sm border border-border bg-card-navy px-2 text-sm text-text"
              >
                <option value="">Choose an org…</option>
                {recipients.map((r) => (
                  <option key={r.org_id} value={r.org_id}>
                    {visibleText(r.org_id)}
                    {r.hasBundle ? " · prekey bundle loaded" : " · static only"}
                  </option>
                ))}
              </select>
              <p className="font-mono text-xs text-muted-foreground">
                trust root {rootFingerprint(trust.rootPublicKeyHex)}
                {demo ? " (DEMO)" : ""}
              </p>
            </div>

            {chosen && itarBlocked && (
              <p
                data-testid="itar-blocked"
                role="alert"
                className="rounded-sm border-2 border-ink bg-warn/20 px-3 py-2 text-sm"
              >
                <span className="font-medium">Not sealed to {chosen.org_id}.</span> This traveler
                is marked ITAR and your directory does not attest {chosen.org_id} for ITAR. It is
                sealed only to an ITAR-attested org, or back to the buyer org it names.
              </p>
            )}

            {chosen && !itarBlocked && entitled && (
              <div
                data-testid="seal-disclosure"
                data-withheld-quotes={entitled.withheld.quotes}
                data-withheld-award={entitled.withheld.award ? "yes" : "no"}
                className="grid gap-2 rounded-sm border border-border px-3 py-2 text-sm"
              >
                {leftOut === null ? (
                  <p>
                    <span className="font-medium">The whole traveler is sent</span>
                    {(traveler.quotes?.length ?? 0) > 0 || traveler.award
                      ? `: ${traveler.quotes?.length ?? 0} ${(traveler.quotes?.length ?? 0) === 1 ? "quote" : "quotes"}${traveler.award ? " and the award" : ""}.`
                      : "."}
                  </p>
                ) : (
                  <>
                    <p>
                      <span className="font-medium">Not sent to {chosen.org_id}:</span> {leftOut}.{" "}
                      {chosen.org_id} is not the buyer org this traveler names, so it gets the
                      request, its own quotes
                      {senderOrg ? ` and ${senderOrg}'s` : ""}, and the award only if its quote
                      won.
                    </p>
                    <label className="flex items-start gap-2">
                      <input
                        type="checkbox"
                        checked={sendAll}
                        onChange={(e) => setSendAll(e.target.checked)}
                        className="mt-0.5 size-4 accent-primary"
                        data-testid="send-all"
                      />
                      <span>
                        Send the whole traveler anyway. {chosen.org_id} will be able to read{" "}
                        <strong>every seller&apos;s quote and price</strong>
                        {traveler.award ? ", who won, and where it ships" : ""}.
                      </span>
                    </label>
                  </>
                )}
              </div>
            )}

            {chosen && outlook && (
              <div
                data-testid="fs-outlook"
                data-forward-secret={outlook.forwardSecret ? "yes" : "no"}
                className="grid gap-2 rounded-sm border border-border px-3 py-2 text-sm"
              >
                {outlook.forwardSecret ? (
                  <>
                    <p>
                      <span className="font-medium">Forward-secret.</span>{" "}
                      <span data-testid="prekeys-left">
                        {outlook.unused} of {outlook.total}
                      </span>{" "}
                      one-time prekeys in {chosen.org_id}&apos;s bundle have not been used by this
                      desk. This envelope will use one; each opens exactly one envelope.
                    </p>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={requireFs}
                        onChange={(e) => setRequireFs(e.target.checked)}
                        className="size-4 accent-primary"
                      />
                      Require forward secrecy (refuse to send if no prekey is usable)
                    </label>
                  </>
                ) : (
                  <p>
                    <span className="font-medium">Static envelope — no forward secrecy.</span>{" "}
                    {staticReasonText(outlook.reason, chosen.org_id)}{" "}
                    {outlook.reason === "prekeys-exhausted" && (
                      <>
                        ({outlook.total} of {outlook.total} used.) Sealing to a prekey a second
                        time would produce an envelope that can never be opened, so the desk does
                        not.{" "}
                      </>
                    )}
                    A later compromise of the recipient&apos;s long-term key would expose this
                    envelope.
                  </p>
                )}
                {bundle && (
                  <p className="text-xs text-muted-foreground">
                    The desk only knows the prekeys <em>it</em> has used. Another sender holding
                    the same bundle can pick the same prekey; the envelope the recipient opens
                    second is then lost.
                  </p>
                )}
              </div>
            )}

            {demo && (
              <label
                className="flex items-start gap-2 rounded-sm border-2 border-ink bg-warn/20 px-3 py-2 text-sm"
                data-testid="demo-ack"
              >
                <input
                  type="checkbox"
                  checked={demoAck}
                  onChange={(e) => setDemoAck(e.target.checked)}
                  className="mt-0.5 size-4 accent-primary"
                />
                <span>
                  I understand this envelope is <strong>not confidential</strong>: the demo
                  recipient&apos;s decryption key is public, so anyone can read what I seal to it.
                </span>
              </label>
            )}

            <Button
              type="button"
              onClick={seal}
              disabled={busy || !chosen || itarBlocked || (demo && !demoAck)}
            >
              {demo ? "Seal to DEMO recipient & download .sje" : "Seal & download .sje"}
            </Button>
          </div>
        )}
        <TrustChangeDialog proposal={proposal} onClose={() => setProposal(null)} />
      </DialogContent>
    </Dialog>
  );
}
