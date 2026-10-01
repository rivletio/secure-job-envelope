import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useKeysStore } from "@/lib/traveler/keys-store";
import type { PublicPrekey } from "@/lib/traveler/keystore";

export const Route = createFileRoute("/keys")({ component: KeysPage });

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  return (
    <Button
      type="button"
      size="sm"
      variant="ghost"
      onClick={() => {
        void navigator.clipboard
          ?.writeText(text)
          .then(() => toast.success("Copied"))
          .catch(() => toast.error("Copy failed"));
      }}
    >
      {label}
    </Button>
  );
}

function Json({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2);
  return (
    <div className="mt-2">
      <div className="flex justify-end">
        <CopyButton text={text} label="Copy JSON" />
      </div>
      <pre className="max-h-56 overflow-auto rounded-sm bg-wash p-3 font-mono text-xs leading-relaxed">
        {text}
      </pre>
    </div>
  );
}

function KeysPage() {
  const hydrated = useKeysStore((s) => s.hydrated);
  const identity = useKeysStore((s) => s.identity);
  const trust = useKeysStore((s) => s.trust);
  const unlocked = useKeysStore((s) => s.unlocked);
  const createIdentity = useKeysStore((s) => s.createIdentity);
  const unlock = useKeysStore((s) => s.unlock);
  const lock = useKeysStore((s) => s.lock);
  const clearIdentity = useKeysStore((s) => s.clearIdentity);
  const addPrekeys = useKeysStore((s) => s.addPrekeys);
  const setTrust = useKeysStore((s) => s.setTrust);
  const clearTrust = useKeysStore((s) => s.clearTrust);

  const [pass, setPass] = useState("");
  const [orgId, setOrgId] = useState("");
  const [busy, setBusy] = useState(false);
  const [prekeyN, setPrekeyN] = useState("8");
  const [lastPrekeys, setLastPrekeys] = useState<PublicPrekey[] | null>(null);
  const [anchorText, setAnchorText] = useState("");
  const [clearIdOpen, setClearIdOpen] = useState(false);

  const publicEntry = identity
    ? {
        ...(identity.org_id ? { org_id: identity.org_id } : {}),
        kid: identity.kid,
        enc_alg: identity.enc_alg,
        enc_public_key: identity.enc_public_key,
      }
    : null;

  async function onCreate() {
    setBusy(true);
    try {
      await createIdentity(pass, orgId.trim() || undefined);
      setPass("");
      toast.success("Identity created and unlocked");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not create identity");
    } finally {
      setBusy(false);
    }
  }

  async function onUnlock() {
    setBusy(true);
    try {
      await unlock(pass);
      setPass("");
      toast.success("Unlocked");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Unlock failed");
    } finally {
      setBusy(false);
    }
  }

  function onAddPrekeys() {
    try {
      const n = Math.floor(Number(prekeyN));
      if (!Number.isFinite(n) || n < 1) throw new Error("Enter a prekey count of 1 or more.");
      setLastPrekeys(addPrekeys(n));
      toast.success(`Minted ${n} one-time prekey${n === 1 ? "" : "s"}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not mint prekeys");
    }
  }

  function onLoadAnchor() {
    try {
      const parsed = JSON.parse(anchorText) as {
        root_public_key_hex?: string;
        rootPublicKeyHex?: string;
        directory?: unknown;
        bundles?: unknown;
      };
      const rootPublicKeyHex = parsed.root_public_key_hex ?? parsed.rootPublicKeyHex;
      if (!rootPublicKeyHex || !parsed.directory) {
        throw new Error("Expected { root_public_key_hex, directory, bundles? }.");
      }
      setTrust({
        rootPublicKeyHex,
        directory: parsed.directory as never,
        bundles: (parsed.bundles as never) ?? undefined,
      });
      setAnchorText("");
      toast.success("Trust anchor loaded and verified");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not load trust anchor");
    }
  }

  return (
    <AppShell>
      <div className="mb-6">
        <p className="mono-label">Key custody · encrypted at rest</p>
        <h1 className="mt-2 text-3xl tracking-tight text-paper">Keys &amp; trust</h1>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-soft">
          Your decryption identity is an ML-KEM key stored <strong>encrypted</strong> under a
          passphrase (scrypt + AES-256-GCM). It is decrypted in memory only while unlocked — lock
          when you are done. An XSS on an unlocked desk could read the in-memory secret. This desk
          never holds <strong>signing</strong> keys: sign prekey bundles off the desk.
        </p>
      </div>

      {!hydrated ? (
        <p className="on-paper rounded-sm border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
          Loading keys…
        </p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Identity */}
          <section className="on-paper traveler-shadow rounded-sm p-5">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-medium">This desk&apos;s identity</h2>
              <span
                className={
                  "font-mono text-xs " + (unlocked ? "text-accent" : identity ? "text-warn" : "text-faint")
                }
              >
                {unlocked ? "unlocked" : identity ? "locked" : "none"}
              </span>
            </div>

            {!identity ? (
              <div className="mt-4 grid gap-3">
                <p className="text-sm text-muted-foreground">
                  No identity yet. Create one to receive and open sealed travelers.
                </p>
                <div className="grid gap-1">
                  <Label htmlFor="org">Org id (optional label)</Label>
                  <Input id="org" value={orgId} onChange={(e) => setOrgId(e.target.value)} placeholder="org_yourco" />
                </div>
                <div className="grid gap-1">
                  <Label htmlFor="pass">Passphrase (min 12 chars)</Label>
                  <Input
                    id="pass"
                    type="password"
                    value={pass}
                    onChange={(e) => setPass(e.target.value)}
                    placeholder="a long passphrase"
                  />
                </div>
                <Button type="button" onClick={onCreate} disabled={busy}>
                  Create identity
                </Button>
              </div>
            ) : (
              <div className="mt-4 grid gap-3">
                <p className="font-mono text-xs text-muted-foreground">
                  kid {identity.kid}
                  {identity.org_id ? ` · ${identity.org_id}` : ""}
                </p>
                {!unlocked ? (
                  <div className="grid gap-2">
                    <Label htmlFor="unlock">Passphrase</Label>
                    <Input
                      id="unlock"
                      type="password"
                      value={pass}
                      onChange={(e) => setPass(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void onUnlock();
                      }}
                    />
                    <Button type="button" onClick={onUnlock} disabled={busy}>
                      Unlock
                    </Button>
                  </div>
                ) : (
                  <div className="flex flex-wrap items-center gap-2">
                    <Button type="button" variant="outline" onClick={lock}>
                      Lock
                    </Button>
                    <span className="text-xs text-muted-foreground">Secret is in memory. Lock when done.</span>
                  </div>
                )}

                <div>
                  <p className="text-xs text-muted-foreground">
                    Public directory entry — publish this so others can seal to you:
                  </p>
                  {publicEntry && <Json value={publicEntry} />}
                </div>

                {unlocked && (
                  <div className="grid gap-2 border-t border-border pt-3">
                    <Label htmlFor="pk">One-time prekeys (forward secrecy)</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="pk"
                        inputMode="numeric"
                        className="w-24"
                        value={prekeyN}
                        onChange={(e) => setPrekeyN(e.target.value)}
                      />
                      <Button type="button" variant="outline" onClick={onAddPrekeys}>
                        Mint prekeys
                      </Button>
                    </div>
                    {lastPrekeys && (
                      <div>
                        <p className="text-xs text-muted-foreground">
                          Publish these in a bundle signed by your org directory key (signed off this
                          desk):
                        </p>
                        <Json value={lastPrekeys} />
                      </div>
                    )}
                  </div>
                )}

                <Button
                  type="button"
                  variant="ghost"
                  className="justify-start text-danger"
                  onClick={() => setClearIdOpen(true)}
                >
                  Remove identity from this desk
                </Button>
              </div>
            )}
          </section>

          {/* Trust anchor */}
          <section className="on-paper traveler-shadow rounded-sm p-5">
            <h2 className="text-sm font-medium">Trust anchor</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              The signed directory lets you resolve recipients to verify sealing keys. Obtain the
              root public key out of band and confirm it below — a swapped root lets an attacker
              forge a directory.
            </p>

            {trust ? (
              <div className="mt-4 grid gap-3">
                <div>
                  <p className="text-xs text-muted-foreground">Root public key (verify out of band)</p>
                  <div className="mt-1 flex items-start gap-2">
                    <code className="block flex-1 overflow-x-auto rounded-sm bg-wash p-2 font-mono text-xs">
                      {trust.rootPublicKeyHex}
                    </code>
                    <CopyButton text={trust.rootPublicKeyHex} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">
                    Recipients in this directory ({trust.directory.entries.length})
                  </p>
                  <ul className="mt-1 grid gap-1 text-sm">
                    {trust.directory.entries.map((e) => (
                      <li key={`${e.org_id}-${e.kid}`} className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs">{e.org_id}</span>
                        <span className="text-xs text-muted-foreground">
                          {e.enc_public_key ? "ML-KEM" : "sign-only"}
                          {trust.bundles[e.org_id] ? " · prekeys" : ""}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
                <Button type="button" variant="ghost" className="justify-start text-danger" onClick={clearTrust}>
                  Clear trust anchor
                </Button>
              </div>
            ) : (
              <div className="mt-4 grid gap-2">
                <Label htmlFor="anchor">
                  Paste {"{ root_public_key_hex, directory, bundles? }"}
                </Label>
                <Textarea
                  id="anchor"
                  rows={8}
                  value={anchorText}
                  onChange={(e) => setAnchorText(e.target.value)}
                  placeholder='{"root_public_key_hex":"…","directory":{…}}'
                  className="font-mono text-xs"
                />
                <Button type="button" onClick={onLoadAnchor} disabled={!anchorText.trim()}>
                  Load &amp; verify
                </Button>
              </div>
            )}
          </section>
        </div>
      )}

      <ConfirmDialog
        open={clearIdOpen}
        onOpenChange={setClearIdOpen}
        title="Remove this identity?"
        body="The encrypted keystore (and any one-time prekeys it holds) is deleted from this desk. Sealed travelers addressed to it can no longer be opened here. This cannot be undone."
        confirmLabel="Remove"
        destructive
        onConfirm={clearIdentity}
      />
    </AppShell>
  );
}
