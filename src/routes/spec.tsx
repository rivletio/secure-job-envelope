import { createFileRoute, Link } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";

export const Route = createFileRoute("/spec")({ component: SpecPage });

function SpecPage() {
  return (
    <AppShell>
      <p className="mono-label">MIT · application/vnd.sje+json</p>
      <h1 className="mt-3 text-4xl tracking-tight text-paper">SJE 0.0.1</h1>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-soft">
        Implementable draft. A traveler is the job object — not the shop OS and not a
        marketplace. Archive name is {"{traveler_id}.traveler.zip"}. Quotes bind to{" "}
        <code className="font-mono text-foreground">traveler_hash_quoted</code>, a SHA-384
        of the canonical quoteable body.
      </p>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">Conformance</h2>
        <div className="on-paper traveler-shadow mt-3 overflow-x-auto rounded-sm">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-wash text-xs tracking-wide text-muted-foreground uppercase">
              <tr>
                <th className="px-4 py-2 font-medium">Level</th>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Meaning</th>
              </tr>
            </thead>
            <tbody>
              <Row code="L0" name="Quoteable" meaning="Can price without guessing material or qty" />
              <Row
                code="L1"
                name="Awardable"
                meaning="At least one structured quote bound to buyer revision"
              />
              <Row code="L2" name="Executable" meaning="Awarded, ops listed, ship-to present" />
              <Row code="L3" name="As-built" meaning="Reserved. as_built may be null in 0.0.1" />
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10 grid gap-6 md:grid-cols-2">
        <article className="on-paper traveler-shadow rounded-sm p-5">
          <h2 className="text-lg font-medium">Hash</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            Canonical JSON (sorted keys, compact, JS number encoding) of a closed field set:
            spec, traveler_id, revision, created_at, buyer, part, need_by, incoterms, itar.
            Extra keys do not enter the hash. Prefixed{" "}
            <code className="font-mono text-foreground">sha384:</code> plus 96 lowercase hex.
            Quotes, award, ops, and ship-to are outside the hash so a traveler can climb L0→L2
            without invalidating quotes. The hash is not a signature.
          </p>
        </article>
        <article className="on-paper traveler-shadow rounded-sm p-5">
          <h2 className="text-lg font-medium">Rust core</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            Protocol crate <code className="font-mono text-foreground">sje</code>{" "}
            hashes, validates quotes, and reports level. Same golden vector as this desk.
            Language-agnostic on the wire; Rust for the verifier.
          </p>
          <pre className="mt-3 overflow-x-auto rounded-md bg-wash p-3 font-mono text-xs text-foreground">
            {`sje hash traveler.json
sje level traveler.json`}
          </pre>
        </article>
      </section>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">Quote schema</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Media schemas live at{" "}
          <a className="underline underline-offset-2" href="/schemas/quote-0.0.1.json">
            /schemas/quote-0.0.1.json
          </a>{" "}
          and{" "}
          <a className="underline underline-offset-2" href="/schemas/traveler-0.0.1.json">
            /schemas/traveler-0.0.1.json
          </a>
          .
        </p>
        <pre className="on-paper traveler-shadow mt-3 overflow-x-auto rounded-sm p-4 font-mono text-xs leading-relaxed">
          {`required: quote_id, seller, traveler_hash_quoted, created_at,
          valid_until, lead_time_days, pricing
pricing.required: currency, lines[]
lines[]: { qty >= 1, unit >= 0 finite }
traveler_hash_quoted: ^sha384:[0-9a-f]{96}$
traveler_id / quote_id: ^[a-z]{3}_[a-z0-9]{6,24}$
currency: ^[A-Z]{3}$`}
        </pre>
      </section>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">Security</h2>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
          <code className="font-mono text-foreground">traveler_hash</code> is SHA-384 of a closed
          field set (spec, traveler_id, revision, created_at, buyer, part, need_by, incoterms, itar).
          Extra keys are ignored. Canonical JSON sorts keys and encodes numbers the way{" "}
          <code className="font-mono text-foreground">JSON.stringify</code> does, so the TypeScript
          desk and the Rust verifier agree — including integer-valued floats such as thickness 10.
        </p>
        <ul className="mt-3 max-w-2xl list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted-foreground">
          <li>
            The hash is integrity of the buyer-authored body, not a signature. Anyone can mint a
            quote that claims to be a named shop. 0.0.1 does not authenticate parties.
          </li>
          <li>
            Quotes are outside the hash so a traveler can climb L0→L2 without invalidating prices.
            That also means a quote’s unit prices are not covered by{" "}
            <code className="font-mono text-foreground">traveler_hash</code>. Treat the archive as
            the document; verify META.json digests on import.
          </li>
          <li>
            Import accepts only root <code className="font-mono text-foreground">traveler.json</code>,
            caps size, refuses path traversal, and checks META.json{" "}
            <code className="font-mono text-foreground">traveler_hash</code> /{" "}
            <code className="font-mono text-foreground">traveler_json_sha384</code> when present.
          </li>
          <li>
            Role on this desk is a local switch. It is not identity, tenancy, or access control.
            See{" "}
            <Link to="/trust" className="underline underline-offset-2">
              Trust
            </Link>{" "}
            for the SOC 2 mapping.
          </li>
        </ul>
      </section>

      <section className="mt-10">
        <h2 className="text-lg font-medium text-paper">Export control & records</h2>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
          <code className="font-mono text-foreground">itar: true</code> is a self-declaration that
          the traveler contains ITAR-controlled technical data. It is not DDTC registration, a
          Technology Control Plan, or an EAR ECCN. This desk will not bind a quote from a seller
          with <code className="font-mono text-foreground">itar !== true</code>, and it warns on
          import/export. That is a consistency check, not compliance.
        </p>
        <ul className="mt-3 max-w-2xl list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted-foreground">
          <li>
            Do not put actual USML/EAR technical data on a public or shared browser desk.
            localStorage is not a CUI system (DFARS 252.204-7012 / NIST 800-171).
          </li>
          <li>
            ITAR is a registration, not a quality cert. Shop{" "}
            <code className="font-mono text-foreground">certs[]</code> is for ISO/AS/AWS; the ITAR
            bit lives on <code className="font-mono text-foreground">org.itar</code>.
          </li>
          <li>
            A bound quote is a structured price. Award is not a PO. 0.0.1 has no governing law,
            warranty, inspection, payment terms, or battle-of-the-forms handling.{" "}
            <code className="font-mono text-foreground">valid_until</code> is enforced at award on
            this desk.
          </li>
          <li>
            Incoterms 2020 FOB requires a named port and is for sea/inland waterway. US domestic
            shops usually mean UCC F.O.B. origin/destination. The field is a string in 0.0.1.
          </li>
          <li>
            Money is IEEE-754. Negative unit/freight/NRE are refused. Prefer integer cents in a
            later spec if this becomes the commercial record.
          </li>
        </ul>
      </section>
    </AppShell>
  );
}

function Row({ code, name, meaning }: { code: string; name: string; meaning: string }) {
  return (
    <tr className="border-b border-border last:border-0">
      <td className="px-4 py-3 font-mono text-xs">{code}</td>
      <td className="px-4 py-3 font-medium">{name}</td>
      <td className="px-4 py-3 text-muted-foreground">{meaning}</td>
    </tr>
  );
}
