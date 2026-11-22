/** What the desk SHOWS about a verification — the wording and the level of each
 *  verdict, decided here (pure, testable) so the panel only draws it.
 *
 *  Three rules, each of which the previous panel broke:
 *
 *  1. The identity a passed check establishes is the one the DIRECTORY binds to the
 *     signing key: an `org_id` and a `kid`. That is what is shown as "who signed".
 *     A document's display names (`buyer.name`, `seller.name`) are typed by whoever
 *     made the file; any enrolled org can sign a traveler under its own org_id and
 *     any name it likes, and it verifies. So names are shown as what they are — the
 *     document's own claim, labelled self-asserted — and never as the row's subject.
 *     (SPEC: "A receiver MUST compare the reported org_id with the org it expects,
 *     and a display name is never evidence.")
 *
 *  2. Under the demo trust anchor nothing is ever "verified". Its keys are public, so
 *     a signature that checks out says only that someone ran the public code. A check
 *     that passes there is shown at WARNING level, as "valid under the DEMO anchor —
 *     proves nothing"; this module never emits a success row for it.
 *
 *  3. Every string that came from a document or a directory goes through
 *     `visibleText`, so a bidi override, a zero-width character or a line break in a
 *     name cannot reorder or hide what is drawn next to the verdict.
 */
import { verificationReport, type SigCheck } from "./authenticity.ts";
import { isDemoTrustRoot } from "./demo-trust.ts";
import type { Directory } from "./directory.ts";
import { rootFingerprint } from "./fingerprint.ts";
import type { Org, Traveler } from "./types.ts";
import { visibleText } from "./visible-text.ts";

export type VerdictStatus = "ok" | "warn" | "bad";

/** What a document says about its own author. */
export type SelfAsserted = { org_id?: string; name: string };

export type VerdictRow = {
  key: string;
  /** What was checked: "Author", "Award", "Quote <quote_id>". Never a name the
   *  document chose for itself. */
  label: string;
  status: VerdictStatus;
  /** What the check established, or why it did not. */
  verdict: string;
  /** Passed checks only: the identity the directory binds to the key that signed. */
  signer?: { org_id: string; kid: string };
  /** The document's own claim about its author. Shown, labelled, never trusted. */
  claimed?: SelfAsserted;
};

export type AuthenticityView = {
  /** The verdicts were computed under the demo trust anchor (public keys). */
  demo: boolean;
  /** The root every verdict here depends on, in its short form. */
  rootFingerprint: string;
  rows: VerdictRow[];
};

export const VERDICT_VERIFIED = "Signature verifies";
export const VERDICT_DEMO = "Valid under the DEMO anchor — proves nothing";
/** What a passed check does and does not mean, for the person reading the panel. */
export const VERDICT_MEANING =
  "A passed check means the org the directory binds to that key signed these bytes. It does not " +
  "mean that org is the company you expect: compare the org_id with the one you are dealing with. " +
  "Names are typed by whoever made the file.";

/** A document's claim about an org, made safe to draw. Undefined for something that is
 *  not an org at all (this function is also reached for documents that failed to
 *  validate). */
function claimOf(org: Org | undefined): SelfAsserted | undefined {
  if (!org || typeof org.name !== "string") return undefined;
  return {
    ...(typeof org.org_id === "string" && org.org_id ? { org_id: visibleText(org.org_id) } : {}),
    name: visibleText(org.name),
  };
}

/** A refusal, with whose key it was when the directory knows. */
function refusal(c: SigCheck): string {
  const reason = c.reason ?? "signature invalid";
  if (c.org_id) return `${reason} (key ${visibleText(c.kid)} belongs to ${visibleText(c.org_id)})`;
  return c.kid ? `${reason} (key ${visibleText(c.kid)})` : reason;
}

export function authenticityView(
  traveler: Traveler,
  trust: { directory: Directory; rootPublicKeyHex: string },
  at?: Date,
): AuthenticityView {
  const demo = isDemoTrustRoot(trust.rootPublicKeyHex);
  const report = verificationReport(traveler, trust.directory, trust.rootPublicKeyHex, at);
  const rows: VerdictRow[] = [];
  const row = (r: Omit<VerdictRow, "claimed">, claimed: SelfAsserted | undefined): void => {
    rows.push(claimed ? { ...r, claimed } : r);
  };

  /** A check that passed: success — unless the anchor is the demo one. */
  const passed = (key: string, label: string, c: SigCheck, claimed: SelfAsserted | undefined): void =>
    row(
      {
        key,
        label,
        status: demo ? "warn" : "ok",
        verdict: demo ? VERDICT_DEMO : VERDICT_VERIFIED,
        signer: { org_id: visibleText(c.org_id ?? ""), kid: visibleText(c.kid) },
      },
      claimed,
    );

  const buyer = claimOf(traveler.buyer);
  const authored = report.authorship.filter((c) => c.ok);
  const refused = report.authorship.filter((c) => !c.ok);
  // Verification could not proceed at all (the directory does not verify against the
  // root, or the document is not a valid traveler): the report then carries a single
  // refused check with no kid — a real signature always names one.
  const blocked = authored.length === 0 && refused.length === 1 && refused[0]!.kid === "";

  // Buyer authorship over the quoteable body: one row per signature that passed.
  authored.forEach((c, i) => passed(`author-${i}`, "Author", c, buyer));
  if (authored.length === 0) {
    if (report.authorship.length === 0) {
      row({ key: "author", label: "Author", status: "warn", verdict: "Not signed" }, buyer);
    } else {
      refused.forEach((c, i) =>
        row({ key: `author-refused-${i}`, label: "Author", status: "bad", verdict: refusal(c) }, buyer),
      );
    }
  } else if (refused.length > 0) {
    // The traveler is authored; other signatures on it failed. Say so — do not hide it.
    row(
      {
        key: "author-others",
        label: "Author",
        status: "warn",
        verdict: `${refused.length} other signature${refused.length === 1 ? "" : "s"} did not verify: ${refusal(refused[0]!)}`,
      },
      undefined,
    );
  }

  // Buyer's award signature (award decision + ship-to). Only when an award exists.
  const award = report.award;
  if (award !== undefined) {
    if (award.ok) {
      passed("award", "Award", award, buyer);
    } else if (!blocked && !traveler.award?.sig) {
      // Present-but-unsigned: a caution, not an invalid signature. Keyed off the award
      // itself, not the reason text. The explicit wording distinguishes a stripped or
      // absent award signature from a merely-unsigned quote — an unsigned award is not
      // buyer-authorized.
      row({ key: "award", label: "Award", status: "warn", verdict: "Unsigned — not buyer-authorized" }, buyer);
    } else {
      row({ key: "award", label: "Award", status: "bad", verdict: refusal(award) }, buyer);
    }
  }

  // Each seller quote signature, in document order. (None when verification could not
  // proceed at all — the Author row already says why.)
  const quotes = traveler.quotes ?? [];
  report.quotes.forEach(({ quote_id, check }, i) => {
    const seller = claimOf(quotes[i]?.seller);
    const key = `quote-${i}`;
    const label = `Quote ${visibleText(quote_id)}`;
    if (check === undefined) {
      row({ key, label, status: "warn", verdict: "Not signed" }, seller);
    } else if (check.ok) {
      passed(key, label, check, seller);
    } else {
      row({ key, label, status: "bad", verdict: refusal(check) }, seller);
    }
  });

  return { demo, rootFingerprint: rootFingerprint(trust.rootPublicKeyHex), rows };
}
