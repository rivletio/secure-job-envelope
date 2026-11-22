import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { CustodyAlerts, CustodyToasts } from "@/components/custody-notices";
import { DemoAnchorBanner, RootFingerprint, TrustChangeDialog } from "@/components/trust-notices";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { parseStrictJson } from "@/lib/traveler/wire";
import { buildDemoTrust, isDemoTrustRoot } from "@/lib/traveler/demo-trust";
import { useKeysStore, type TrustAnchorInput } from "@/lib/traveler/keys-store";
import { keystoreShapeError, type PublicPrekey } from "@/lib/traveler/keystore";
import { visibleText } from "@/lib/traveler/visible-text";

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
    // A one-column grid whose track may shrink to nothing: the <pre> scrolls inside it.
    // Without that, a 3,136-character key on one line is this block's minimum width and
    // stretches the whole page to ~23,000 px.
    <div className="mt-2 grid grid-cols-1">
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
  const knownRoots = useKeysStore((s) => Object.keys(s.trustMarks).length);
  const unlocked = useKeysStore((s) => s.unlocked);
  const createIdentity = useKeysStore((s) => s.createIdentity);
  const unlock = useKeysStore((s) => s.unlock);
  const lock = useKeysStore((s) => s.lock);
  const clearIdentity = useKeysStore((s) => s.clearIdentity);
  const addPrekeys = useKeysStore((s) => s.addPrekeys);
  const clearTrust = useKeysStore((s) => s.clearTrust);

  const [pass, setPass] = useState("");
  const [orgId, setOrgId] = useState("");
  const [busy, setBusy] = useState(false);
  const [prekeyN, setPrekeyN] = useState("8");
  const [lastPrekeys, setLastPrekeys] = useState<PublicPrekey[] | null>(null);
  const [anchorText, setAnchorText] = useState("");
  const [clearIdOpen, setClearIdOpen] = useState(false);
  const [clearTrustOpen, setClearTrustOpen] = useState(false);
  // A trust anchor someone asked to load. Nothing is loaded until it is confirmed in
  // the dialog, which shows the root's fingerprint (old → new for a root change).
  const [proposal, setProposal] = useState<TrustAnchorInput | null>(null);

  // A stored keystore this version cannot read (a newer format, or damaged) is left
  // exactly as it is — and not rendered as if it were one.
  const identityReadable = identity !== undefined && keystoreShapeError(identity) === null;
  // The directory entry to publish comes from the UNLOCKED session, never from the
  // stored blob: a locked blob's header is only what storage says, and whoever can
  // write storage could put their own key there for you to publish.
  const publicEntry = unlocked
    ? {
        ...(unlocked.orgId ? { org_id: unlocked.orgId } : {}),
        kid: unlocked.kid,
        enc_alg: "ML-KEM-1024",
        enc_public_key: unlocked.encPublicKeyHex,
      }
    : null;
  const demo = trust ? isDemoTrustRoot(trust.rootPublicKeyHex) : false;

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
      setLastPrekeys(null);
      toast.error(err instanceof Error ? err.message : "Could not mint prekeys");
    }
  }

  function onReviewAnchor() {
    try {
      // Read strictly, like every other document that crosses a company boundary: a size
      // cap (so a very large paste can't freeze the tab — a real directory + bundles is
      // well under 1 MB), no byte-order mark, and no repeated member name (a second
      // `directory` or `root_public_key_hex` would silently win under JSON.parse).
      const parsed = parseStrictJson(anchorText, { maxBytes: 1_000_000, label: "Trust anchor" }) as {
        root_public_key_hex?: unknown;
        rootPublicKeyHex?: unknown;
        directory?: unknown;
        bundles?: unknown;
      };
      const rootPublicKeyHex = parsed.root_public_key_hex ?? parsed.rootPublicKeyHex;
      if (typeof rootPublicKeyHex !== "string" || !rootPublicKeyHex || !parsed.directory) {
        throw new Error("Expected { root_public_key_hex, directory, bundles? }.");
      }
      // Not loaded yet: the dialog shows the root's fingerprint and what would change,
      // and refuses (with the reason) an anchor that does not verify or goes backwards.
      setProposal({
        rootPublicKeyHex,
        directory: parsed.directory as never,
        bundles: (parsed.bundles as never) ?? undefined,
      });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not read trust anchor");
    }
  }

  const loadAnchor = (
    <div className="grid gap-3">
      <div className="grid gap-2">
        <Label htmlFor="anchor">
          {trust ? "Load another" : "Paste your own"}{" "}
          {"{ root_public_key_hex, directory, bundles? }"}
        </Label>
        <Textarea
          id="anchor"
          rows={trust ? 4 : 8}
          value={anchorText}
          onChange={(e) => setAnchorText(e.target.value)}
          placeholder='{"root_public_key_hex":"…","directory":{…}}'
          className="font-mono text-xs"
        />
        <Button
          type="button"
          variant="outline"
          onClick={onReviewAnchor}
          disabled={!anchorText.trim()}
        >
          Review &amp; load
        </Button>
        <p className="text-xs text-muted-foreground">
          You will be shown the root&apos;s fingerprint to compare before anything is loaded. A
          directory older than one this desk has already accepted under the same root is
          refused.
        </p>
      </div>
      {!demo && (
        <div className="grid gap-1 border-t border-border pt-3">
          <Button
            type="button"
            variant={trust ? "ghost" : "outline"}
            className={trust ? "justify-start" : undefined}
            onClick={() => setProposal(buildDemoTrust())}
          >
            Load the demo trust anchor…
          </Button>
          <p className="text-xs text-muted-foreground">
            Sample shops with real ML-KEM keys, so you can try <strong>Seal &amp; send</strong>{" "}
            right away. Its keys are public: it <strong>proves nothing and protects
            nothing</strong>, and the desk says so everywhere while it is loaded.
          </p>
        </div>
      )}
    </div>
  );

  return (
    <AppShell>
      <CustodyToasts />
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
        <>
          <CustodyAlerts />
          <div className="grid gap-6 lg:grid-cols-2">
            {/* Identity */}
            <section className="on-paper traveler-shadow rounded-sm p-5">
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-sm font-medium">This desk&apos;s identity</h2>
                <span
                  data-testid="identity-state"
                  className={
                    "font-mono text-xs " +
                    (unlocked ? "text-accent" : identity ? "text-warn" : "text-faint")
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
                    <Input
                      id="org"
                      value={orgId}
                      onChange={(e) => setOrgId(e.target.value)}
                      placeholder="org_yourco"
                    />
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
              ) : !identityReadable ? (
                <div className="mt-4 grid gap-3">
                  <p className="rounded-sm border border-warn/40 bg-warn/10 px-3 py-2 text-sm">
                    A keystore is stored here that this version of the desk cannot read — it was
                    written by a newer version, or it is damaged. It has been left exactly as it
                    is.
                  </p>
                  <Button
                    type="button"
                    variant="ghost"
                    className="justify-start text-danger"
                    onClick={() => setClearIdOpen(true)}
                  >
                    Remove identity from this desk
                  </Button>
                </div>
              ) : (
                <div className="mt-4 grid gap-3">
                  <p className="font-mono text-xs text-muted-foreground">
                    kid {visibleText(unlocked?.kid ?? identity.kid)}
                    {(unlocked?.orgId ?? identity.org_id)
                      ? ` · ${visibleText(unlocked?.orgId ?? identity.org_id ?? "")}`
                      : ""}
                    {!unlocked && " · as stored (checked when unlocked)"}
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
                      <span className="text-xs text-muted-foreground">
                        Secret is in memory. Lock when done.
                      </span>
                    </div>
                  )}

                  <div>
                    {publicEntry ? (
                      <>
                        <p className="text-xs text-muted-foreground">
                          Public directory entry — publish this so others can seal to you:
                        </p>
                        <Json value={publicEntry} />
                      </>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Unlock to show the public directory entry to publish. What a locked
                        keystore says about itself is only checked against the encrypted key
                        when it is unlocked.
                      </p>
                    )}
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
                            Publish these in a bundle signed by your org directory key (signed off
                            this desk). Each opens exactly one envelope; a sender that has used
                            them all needs a new bundle.
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
            <section className="on-paper traveler-shadow rounded-sm p-5" data-testid="trust-section">
              <h2 className="text-sm font-medium">Trust anchor</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                The signed directory decides what this desk calls verified and whose keys it seals
                to. Whoever supplies the root supplies all of that — so compare the root&apos;s
                fingerprint with one you obtained out of band.
              </p>

              {trust ? (
                <div className="mt-4 grid gap-3">
                  {demo && <DemoAnchorBanner />}
                  <RootFingerprint
                    rootPublicKeyHex={trust.rootPublicKeyHex}
                    label={demo ? "DEMO root fingerprint" : "Root fingerprint"}
                  />
                  <p className="font-mono text-xs text-muted-foreground">
                    directory issued {trust.directory.issued_at.slice(0, 10)} · valid until{" "}
                    {trust.directory.valid_until.slice(0, 10)} · an older directory under this
                    root is refused
                  </p>
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Recipients in this directory ({trust.directory.entries.length})
                    </p>
                    <ul className="mt-1 grid gap-1 text-sm">
                      {trust.directory.entries.map((e) => (
                        <li
                          key={`${e.org_id}-${e.kid}`}
                          className="flex items-center justify-between gap-2"
                        >
                          <span className="font-mono text-xs">
                            {visibleText(e.org_id)}
                            <span className="text-muted-foreground"> · {visibleText(e.kid)}</span>
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {e.status === "revoked" ? "revoked · " : ""}
                            {e.enc_public_key ? "ML-KEM" : "sign-only"}
                            {e.status === "active" &&
                            e.enc_public_key &&
                            Object.hasOwn(trust.bundles, e.org_id)
                              ? " · prekeys"
                              : ""}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="border-t border-border pt-3">{loadAnchor}</div>
                  <Button
                    type="button"
                    variant="ghost"
                    className="justify-start text-danger"
                    onClick={() => setClearTrustOpen(true)}
                  >
                    Clear trust anchor
                  </Button>
                </div>
              ) : (
                <div className="mt-4 grid gap-3">
                  <p className="text-xs text-muted-foreground" data-testid="trust-memory">
                    {knownRoots === 0
                      ? "No trust anchor is loaded, and this desk has no record of ever accepting one (a first load, or this browser's storage was cleared). It has nothing to compare a directory's age with until one is loaded."
                      : `No trust anchor is loaded. This desk remembers the newest directory it accepted under ${knownRoots} root${knownRoots === 1 ? "" : "s"}, and will refuse an older one.`}
                  </p>
                  {loadAnchor}
                </div>
              )}
            </section>
          </div>
        </>
      )}

      <TrustChangeDialog
        proposal={proposal}
        onClose={() => setProposal(null)}
        onLoaded={() => setAnchorText("")}
      />
      <ConfirmDialog
        open={clearIdOpen}
        onOpenChange={setClearIdOpen}
        title="Remove this identity?"
        body="The encrypted keystore (and any one-time prekeys it holds) is deleted from this desk. Sealed travelers addressed to it can no longer be opened here. This cannot be undone."
        confirmLabel="Remove"
        destructive
        onConfirm={() => {
          try {
            clearIdentity();
            setLastPrekeys(null);
          } catch (err) {
            toast.error(err instanceof Error ? err.message : "Could not remove the identity");
          }
        }}
      />
      <ConfirmDialog
        open={clearTrustOpen}
        onOpenChange={setClearTrustOpen}
        title="Clear the trust anchor?"
        body="Nothing can be verified or sealed until a trust anchor is loaded again, and loading one will ask you to confirm its root fingerprint. The desk keeps its record of the newest directory it accepted under each root, so an older one is still refused."
        confirmLabel="Clear"
        destructive
        onConfirm={clearTrust}
      />
    </AppShell>
  );
}
