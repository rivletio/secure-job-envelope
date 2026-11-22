/** The receive policy: what to do with a traveler that just arrived, given the copy
 *  already held under the same id and what verification established about each.
 *
 *  An envelope proves nothing about who sealed it — anyone holding the public directory
 *  can encrypt to an org — and a traveler id is not a secret. So a receiver that simply
 *  stores what it decrypts can be made to roll a traveler back to an earlier revision,
 *  swap the part definition under an unchanged revision number, lose the quotes it held,
 *  or "learn" of an award (and a ship-to address) the buyer never made. This module is
 *  the one place those outcomes are decided. It is pure: no storage, no clock, no keys —
 *  the desk and the MCP server both call it, and every rule is tested on its own.
 *
 *  The rules, in the order they are applied:
 *
 *    forged      A signature that is present and FAILS (a changed body, a signer from
 *                another org, an award that does not bind its quote) is refused. An
 *                absent signature, or one that cannot be checked, is "unverified":
 *                admitted only where nothing is replaced, or after the reader has
 *                explicitly acknowledged what is unproven.
 *    buyer       A traveler's buyer org never changes.
 *    floor       Content the held copy has verified as the buyer's is never replaced by
 *                content that is not.
 *    rollback    An older revision is refused.
 *    equivocate  The same revision with different content is refused.
 *    merge       The same revision and content: the incoming copy's quotes are ADDED
 *                (by quote_id; a held quote is never dropped or altered), and its award
 *                is taken through the award gate. A ship-to or ops list that arrives
 *                WITHOUT an award is a draft and is never merged in.
 *    award       A verified award is admitted. An unverified one needs acknowledgment.
 *                A verified held award is immovable; an unverified held award yields to
 *                a verified one, so a forged award cannot lock the genuine one out.
 *    amend       A newer revision replaces the body — refused over an executable
 *                traveler (unless that lock is unverified and the amendment is the
 *                buyer's), and needing acknowledgment when it is not verified. The
 *                quotes held for the earlier revision are kept; they no longer bind.
 */
import { levelOf } from "./conformance.ts";
import { travelerHash } from "./hash.ts";
import type { SigCheck, VerificationReport } from "./authenticity.ts";
import type { Quote, Signature, Traveler } from "./types.ts";

export type ImportContext = {
  /** The copy already held under this traveler_id, if any. */
  held?: Traveler;
  /** Verification of the incoming copy. Omit when there is no trust anchor: nothing
   *  can then be verified, which is not the same as nothing being wrong. */
  incomingReport?: VerificationReport;
  /** Verification of the held copy (same trust anchor, same instant). */
  heldReport?: VerificationReport;
};

export type ImportKind =
  /** Nothing was held under this id. */
  | "new"
  /** Identical to what is held. */
  | "unchanged"
  /** Same revision and content; quotes, signatures or an award were added. */
  | "merged"
  /** A newer revision replaced the body. */
  | "amended";

export type ImportDecision =
  | { action: "refuse"; reason: string }
  | {
      action: "admit";
      kind: ImportKind;
      /** What to store: the incoming copy, or the held copy with the incoming copy's
       *  additions merged in. Always a valid traveler the caller re-validates. */
      traveler: Traveler;
      /** Facts worth showing the reader. */
      notes: string[];
      /** Statements the reader must explicitly acknowledge BEFORE the traveler is
       *  stored. Empty: no confirmation is needed. */
      acknowledge: string[];
    };

/** What verification established about one signed thing. */
type Standing =
  /** Checked, and it holds. */
  | "verified"
  /** Unsigned, or it cannot be checked (no trust anchor, an untrusted or stale
   *  directory, a key the directory does not list). Nothing is established. */
  | "unverified"
  /** Signed, checked, and it FAILS — evidence the content is not its author's. */
  | "invalid";

/** Reasons that mean "cannot tell", as opposed to "checked and wrong". */
const CANNOT_TELL = new Set([
  "directory does not verify against the trust root",
  "no active in-window directory entry for kid",
  "award is present but not signed by the buyer",
]);
const standingOf = (c: SigCheck): Standing =>
  c.ok ? "verified" : CANNOT_TELL.has(c.reason ?? "") ? "unverified" : "invalid";

function authorship(report: VerificationReport | undefined): { standing: Standing; why?: string; by?: string } {
  if (!report) return { standing: "unverified" };
  const ok = report.authorship.find((c) => c.ok);
  if (ok) return { standing: "verified", by: `${ok.org_id} (key ${ok.kid})` };
  const bad = report.authorship.find((c) => standingOf(c) === "invalid");
  return bad ? { standing: "invalid", why: bad.reason } : { standing: "unverified" };
}

function awardStanding(t: Traveler, report: VerificationReport | undefined): { standing: Standing | "none"; why?: string } {
  if (!t.award) return { standing: "none" };
  if (!report?.award) return { standing: "unverified" };
  return { standing: standingOf(report.award), why: report.award.reason };
}

/** Structural equality of two JSON values (member order is not significant). */
function same(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => same(x, b[i]));
  }
  const ka = Object.keys(a).filter((k) => (a as Record<string, unknown>)[k] !== undefined);
  const kb = Object.keys(b).filter((k) => (b as Record<string, unknown>)[k] !== undefined);
  return (
    ka.length === kb.length &&
    ka.every((k) => same((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
  );
}
const withoutSig = <T extends { sig?: Signature }>(x: T): Omit<T, "sig"> => {
  const { sig: _omit, ...rest } = x;
  void _omit;
  return rest;
};
const locked = (t: Traveler): boolean => levelOf(t).level >= 2;
const orgLabel = (t: Traveler): string => t.buyer.org_id ?? "no org_id";

const UNSIGNED_AWARD =
  "The award on this traveler is not verified as the buyer's. Anyone who can encrypt to you could have written it — including the ship-to address. Confirm it with the buyer through a channel you already trust before acting on it.";
const refuse = (reason: string): ImportDecision => ({ action: "refuse", reason });

/** Union of two quote lists by quote_id: `base` first, then quotes only `extra` has.
 *  A quote both carry must have the same content; where only one copy is signed, the
 *  signed one is kept. Returns the offending quote_id on a conflict. */
function mergeQuotes(base: Quote[], extra: Quote[]): { quotes: Quote[]; added: number } | { conflict: string } {
  const out = [...base];
  let added = 0;
  for (const q of extra) {
    const i = out.findIndex((x) => x.quote_id === q.quote_id);
    if (i < 0) {
      out.push(q);
      added += 1;
    } else if (!same(withoutSig(out[i]!), withoutSig(q))) {
      return { conflict: q.quote_id };
    } else if (!out[i]!.sig && q.sig) {
      out[i] = q;
      added += 1;
    } else if (out[i]!.sig && q.sig && !same(out[i]!.sig, q.sig)) {
      return { conflict: q.quote_id };
    }
  }
  return { quotes: out, added };
}

function mergeSignatures(base: Signature[] | undefined, extra: Signature[] | undefined): Signature[] | undefined {
  const out = [...(base ?? [])];
  for (const s of extra ?? []) if (!out.some((x) => same(x, s))) out.push(s);
  return out.length ? out : undefined;
}

export function decideImport(incoming: Traveler, ctx: ImportContext = {}): ImportDecision {
  const { held, incomingReport, heldReport } = ctx;
  const inAuth = authorship(incomingReport);
  const inAward = awardStanding(incoming, incomingReport);
  const notes: string[] = [];
  const acknowledge: string[] = [];

  // forged: present and failing, wherever it is.
  if (inAuth.standing === "invalid") {
    return refuse(`The buyer signature on this traveler does not verify (${inAuth.why}).`);
  }
  if (inAward.standing === "invalid") {
    return refuse(`The award on this traveler does not verify (${inAward.why}). It is not the buyer's.`);
  }
  if (inAuth.standing === "verified") notes.push(`Signed by ${inAuth.by}.`);
  else notes.push("Authorship is not verified: nothing shows who wrote this traveler.");

  if (!held) {
    if (inAward.standing === "verified") notes.push("Award verified as the buyer's.");
    if (inAward.standing === "unverified") acknowledge.push(UNSIGNED_AWARD);
    return { action: "admit", kind: "new", traveler: incoming, notes, acknowledge };
  }

  // buyer
  if ((incoming.buyer.org_id ?? null) !== (held.buyer.org_id ?? null)) {
    return refuse(
      `This traveler is held here as buyer ${orgLabel(held)}; the incoming copy names ${orgLabel(incoming)}. A traveler's buyer does not change.`,
    );
  }
  const heldAuth = authorship(heldReport);
  const heldAward = awardStanding(held, heldReport);
  const heldHash = travelerHash(held);
  const sameContent = incoming.revision === held.revision && travelerHash(incoming) === heldHash;

  // floor
  if (!sameContent && heldAuth.standing === "verified" && inAuth.standing !== "verified") {
    return refuse(
      "The copy held here is signed by its buyer. The incoming copy would replace it with content that is not verified as the buyer's.",
    );
  }
  // rollback
  if (incoming.revision < held.revision) {
    return refuse(
      `This is revision ${incoming.revision}; revision ${held.revision} is already held. An older revision is not accepted.`,
    );
  }
  // equivocate
  if (incoming.revision === held.revision && !sameContent) {
    return refuse(
      `This is revision ${incoming.revision}, the same revision as the copy held, but its content is different. One revision cannot have two contents.`,
    );
  }

  if (sameContent) {
    const merged = mergeQuotes(held.quotes ?? [], incoming.quotes ?? []);
    if ("conflict" in merged) {
      return refuse(`Quote ${merged.conflict} differs from the copy of that quote held here.`);
    }
    let next: Traveler = { ...held, quotes: merged.quotes.length ? merged.quotes : held.quotes };
    let changed = merged.added > 0;
    if (merged.added > 0) notes.push(`${merged.added} quote${merged.added === 1 ? "" : "s"} added.`);

    const signatures = mergeSignatures(held.signatures, incoming.signatures);
    if ((signatures?.length ?? 0) !== (held.signatures?.length ?? 0)) {
      next = { ...next, signatures };
      changed = true;
    }

    const takeAward = (): void => {
      next = { ...next, award: incoming.award, ship_to: incoming.ship_to, ops: incoming.ops };
      if (incoming.as_built) next = { ...next, as_built: incoming.as_built };
      changed = true;
    };
    if (incoming.award && !held.award) {
      // award gate
      if (inAward.standing === "verified") notes.push("Award verified as the buyer's.");
      else acknowledge.push(UNSIGNED_AWARD);
      takeAward();
    } else if (incoming.award && held.award) {
      const identical =
        same(incoming.award, held.award) && same(incoming.ship_to ?? null, held.ship_to ?? null);
      if (!identical) {
        if (heldAward.standing === "verified") {
          return refuse("The award held here is verified as the buyer's and cannot be replaced.");
        }
        if (inAward.standing !== "verified") {
          return refuse(
            "The incoming copy carries a different award from the one held, and neither is verified as the buyer's — they cannot be told apart from a forgery. If you have confirmed the incoming award with the buyer, delete the held copy and open this one again.",
          );
        }
        notes.push("The award held here was never verified; the incoming award is verified as the buyer's and replaces it.");
        takeAward();
      } else if (incoming.as_built && !held.as_built) {
        next = { ...next, as_built: incoming.as_built };
        changed = true;
        notes.push("As-built data added (it is not covered by any signature).");
      } else if (incoming.as_built && !same(incoming.as_built, held.as_built)) {
        notes.push("The incoming as-built data differs from what is held; the held data was kept.");
      }
    } else if (!incoming.award && held.award) {
      notes.push("The incoming copy carries no award; the award held here was kept.");
    } else if (
      (incoming.ship_to && !same(incoming.ship_to, held.ship_to ?? null)) ||
      (incoming.ops?.length && !same(incoming.ops, held.ops ?? []))
    ) {
      // No award on either side. A ship-to or an ops list without an award is somebody's
      // draft, covered by no signature — and "somebody" may be a seller returning a
      // quote. It is never merged in: where the parts ship is stated by the award, by
      // the buyer. (Merged silently, it would sit in the buyer's copy and be offered
      // back as the default when the buyer awards.)
      notes.push("The incoming copy carries a draft ship-to or ops list; it was not taken.");
    }
    if (!changed) notes.push("Identical to the copy held.");
    return { action: "admit", kind: changed ? "merged" : "unchanged", traveler: next, notes, acknowledge };
  }

  // amend: a newer revision.
  if (locked(held)) {
    const lockIsUnverified = heldAward.standing !== "verified";
    if (!(lockIsUnverified && inAuth.standing === "verified")) {
      return refuse(
        heldAward.standing === "verified"
          ? "The copy held here is executable under an award verified as the buyer's. It cannot be amended."
          : "The copy held here is executable (awarded). A newer revision is accepted over it only when that revision is verified as the buyer's.",
      );
    }
    notes.push(
      `The copy held here was awarded, but that award was never verified. The buyer's signed revision ${incoming.revision} replaces it.`,
    );
  }
  if (inAuth.standing !== "verified") {
    acknowledge.push(
      `This replaces revision ${held.revision} of the part with revision ${incoming.revision}, and nothing shows the change came from the buyer. Quotes you hold for revision ${held.revision} will no longer bind.`,
    );
  }
  if (inAward.standing === "verified") notes.push("Award verified as the buyer's.");
  if (inAward.standing === "unverified") acknowledge.push(UNSIGNED_AWARD);

  // Keep the quotes held for the earlier revision: they no longer bind, but they are the
  // reader's record of what was offered. One an ITAR revision cannot carry is dropped.
  const carried = (held.quotes ?? []).filter((q) => !incoming.itar || q.seller.itar === true);
  const dropped = (held.quotes ?? []).length - carried.length;
  const merged = mergeQuotes(incoming.quotes ?? [], carried);
  if ("conflict" in merged) {
    return refuse(`Quote ${merged.conflict} differs from the copy of that quote held here.`);
  }
  if (merged.added > 0) {
    notes.push(
      `${merged.added} quote${merged.added === 1 ? "" : "s"} held for revision ${held.revision} kept as history; ${merged.added === 1 ? "it does" : "they do"} not bind revision ${incoming.revision}.`,
    );
  }
  if (dropped > 0) {
    notes.push(
      `${dropped} held quote${dropped === 1 ? "" : "s"} from a seller without an ITAR declaration could not be kept on an ITAR revision.`,
    );
  }
  const traveler: Traveler = { ...incoming, quotes: merged.quotes.length ? merged.quotes : incoming.quotes };
  return { action: "admit", kind: "amended", traveler, notes, acknowledge };
}
