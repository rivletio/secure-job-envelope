import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { usePacketStore, type AuditEvent } from "@/lib/packet/store";

export const Route = createFileRoute("/trust")({ component: TrustPage });

function TrustPage() {
  const audit = usePacketStore((s) => s.audit);
  const reversed = [...audit].reverse();

  function exportAudit() {
    const blob = new Blob([JSON.stringify(audit, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "rivlet-packet-audit.json";
    a.rel = "noopener";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <AppShell>
      <p className="mono-label">Trust boundary · 0.0.1</p>
      <h1 className="mt-3 max-w-2xl text-4xl tracking-tight text-paper">
        Built for shops that already have SOC 2.{" "}
        <em className="font-normal text-accent italic">This desk is not that system.</em>
      </h1>
      <p className="mt-4 max-w-2xl text-sm leading-relaxed text-soft">
        Rivlet Packet is a content-addressed job object. Identity, signatures, CUI handling, and
        a production control environment are out of band in 0.0.1. SOC 2 Type II is an org’s
        attestation over <em>their</em> system — it does not transfer to a protocol, a hash, or
        this browser desk.
      </p>

      <section className="on-paper traveler-shadow mt-8 rounded-sm p-5">
        <h2 className="text-lg font-medium">What this desk is</h2>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted-foreground">
          <li>A local, single-browser workbench. Packets live in this origin’s storage.</li>
          <li>
            Buyer / Seller is a <strong className="text-foreground">view</strong>, not login, not
            tenancy, not least-privilege.
          </li>
          <li>
            <code className="font-mono text-foreground">packet_hash</code> is SHA-384 of a closed
            quoteable body. It is integrity, not a signature and not non-repudiation.
          </li>
          <li>
            Import of <code className="font-mono text-foreground">.rivpkt.zip</code> requires
            META.json, allowlisted members, CRC32, size caps, and a matching hash.
          </li>
          <li>
            ITAR is a self-declared bit plus a quote/award consistency check. It is not a
            Technology Control Plan, DDTC registration, or deemed-export screen.
          </li>
        </ul>
      </section>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">SOC 2 TSC — honest mapping</h2>
        <div className="on-paper traveler-shadow mt-3 overflow-x-auto rounded-sm">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-wash text-xs tracking-wide text-muted-foreground uppercase">
              <tr>
                <th className="px-4 py-2 font-medium">TSC</th>
                <th className="px-4 py-2 font-medium">This desk</th>
                <th className="px-4 py-2 font-medium">What a SOC 2 shop still owes</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              <Row
                tsc="CC6 Access"
                here="Local role switch. No identity, session, or MFA."
                owed="SSO / IdP, RBAC, joiner-mover-leaver, session timeout."
              />
              <Row
                tsc="CC6.7 Restrict data"
                here="Origin-isolated localStorage. No encryption at rest."
                owed="CUI boundary, encryption at rest, DLP, media control."
              />
              <Row
                tsc="CC7 Monitoring"
                here="Append-only local audit of compose/quote/award/import/export. Caps at 100 events. No PII in the log."
                owed="Central immutable log, alerting, retention, clock sync."
              />
              <Row
                tsc="CC8 Change"
                here="Hash-bound quotes. Amend bumps revision and stale-marks quotes. L2 packets lock."
                owed="Change tickets, signed packets, dual control on award."
              />
              <Row
                tsc="A1 Availability"
                here="This browser tab."
                owed="HA, backup, RTO/RPO, incident response."
              />
              <Row
                tsc="C1 Confidentiality"
                here="TLS in transit if the host serves HTTPS. Packet JSON is readable."
                owed="Classification, encryption, NDAs, vendor review."
              />
              <Row
                tsc="P1 Privacy"
                here="Ship-to is stored with the packet when awarded. Audit log omits addresses."
                owed="Minimization, retention, DSAR, subprocessors."
              />
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">Export control</h2>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
          Do not put USML / EAR technical data on a public or shared browser desk. localStorage is
          not a CUI system (DFARS 252.204-7012 / NIST 800-171). This demo is for the packet
          envelope, not for controlled drawings.
        </p>
      </section>

      <section className="mt-10">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg font-medium text-paper">Local audit</h2>
          <Button type="button" size="sm" variant="outline" onClick={exportAudit} disabled={!audit.length}>
            Export log
          </Button>
        </div>
        {reversed.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Empty until you compose, quote, award, import, or export. Events stay in this origin.
          </p>
        ) : (
          <ol className="on-paper traveler-shadow divide-y divide-border rounded-sm">
            {reversed.map((ev, i) => (
              <AuditRow key={`${ev.at}-${ev.act}-${i}`} ev={ev} />
            ))}
          </ol>
        )}
      </section>
    </AppShell>
  );
}

function Row({ tsc, here, owed }: { tsc: string; here: string; owed: string }) {
  return (
    <tr className="border-b border-border align-top">
      <td className="px-4 py-3 font-mono text-xs font-medium">{tsc}</td>
      <td className="px-4 py-3 text-muted-foreground">{here}</td>
      <td className="px-4 py-3 text-muted-foreground">{owed}</td>
    </tr>
  );
}

function AuditRow({ ev }: { ev: AuditEvent }) {
  return (
    <li className="grid gap-1 px-4 py-3 sm:grid-cols-[9rem_6rem_1fr] sm:items-baseline">
      <span className="font-mono text-xs text-faint">{ev.at.replace(".000Z", "Z")}</span>
      <span className="font-mono text-xs font-medium uppercase">{ev.act}</span>
      <span className="font-mono text-xs text-muted-foreground">
        {ev.packet_id ?? "—"}
        {ev.hash ? ` · ${ev.hash.slice(0, 14)}…` : ""}
      </span>
    </li>
  );
}
