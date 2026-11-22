/** Sender-side memory of spent one-time prekeys.
 *
 *  A forward-secret envelope is sealed to one of the recipient's one-time prekeys, and
 *  the recipient deletes that prekey after opening it — so a prekey opens exactly ONE
 *  envelope. A sender that seals twice to the same prekey has written a second
 *  envelope nobody can ever open. `sealTraveler` has no memory between calls; this is
 *  that memory, in a form a sender can persist: which one-time keys it has already
 *  sealed to, per recipient org.
 *
 *  A prekey is remembered by its KEY, not by its label. `prekey_id` is whatever the
 *  bundle's author chose, and a recipient that publishes a new bundle of fresh keys may
 *  reuse old labels. Keyed by the key itself:
 *    - a NEW bundle of fresh one-time keys starts fresh — none of it is marked spent;
 *    - a new bundle that re-lists a key this sender already sealed to still has that
 *      key marked spent (sealing to it again would lose one of the two envelopes);
 *    - loading an OLDER bundle again does not make its spent prekeys look unused.
 *
 *  What this cannot know: prekeys spent by OTHER senders, or burned on purpose. Two
 *  senders can still pick the same prekey of a public bundle; that needs a coordinator
 *  (see `sealTraveler`). This removes the loss a sender inflicts on itself.
 */
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "./bytes.ts";
import { ORG_ID_RE, type Directory } from "./directory.ts";
import { prekeyBundleShapeError, verifyPrekeyBundle, type PrekeyBundle } from "./prekeys.ts";
import type { StaticReason } from "./transport.ts";

/** org_id -> marks of the one-time keys this sender has sealed to, oldest first. */
export type PrekeyLedger = Record<string, string[]>;

/** Most marks kept per org: two full bundles' worth (a bundle carries at most 256
 *  prekeys). Beyond that the oldest are forgotten. */
export const MAX_LEDGER_MARKS_PER_ORG = 512;
/** Most orgs tracked; beyond that the org sealed to longest ago is forgotten. */
export const MAX_LEDGER_ORGS = 128;

const MARK_RE = /^[0-9a-f]{16}$/;

/** The mark of a one-time prekey: the first 16 hex characters of SHA-384 over its
 *  public-key bytes. An identifier for bookkeeping, not a commitment — a recipient who
 *  engineered two of its own prekeys to share a mark would only make this sender skip
 *  one of them. */
export function prekeyMark(publicKeyHex: string): string {
  return bytesToHex(sha384(hexToBytes(publicKeyHex))).slice(0, 16);
}

function wellFormed(bundle: PrekeyBundle | undefined): bundle is PrekeyBundle {
  return bundle !== undefined && prekeyBundleShapeError(bundle) === null;
}

/** The `prekey_id`s of `bundle` this sender has already sealed to — what to pass as
 *  `excludePrekeyIds`. Empty for a bundle that is not well-formed (it will not be
 *  sealed to at all). */
export function usedPrekeyIds(ledger: PrekeyLedger, bundle: PrekeyBundle | undefined): string[] {
  if (!wellFormed(bundle)) return [];
  const marks = Object.hasOwn(ledger, bundle.org_id) ? ledger[bundle.org_id]! : [];
  if (marks.length === 0) return [];
  const spent = new Set(marks);
  return bundle.prekeys.filter((p) => spent.has(prekeyMark(p.public_key))).map((p) => p.prekey_id);
}

/** A ledger that also records `prekeyId` of `bundle` as spent. Returns a new ledger
 *  (the input is not modified). Throws if `prekeyId` is not in the bundle — recording
 *  a prekey that was never offered would be a caller's mistake worth hearing about. */
export function recordPrekeyUse(
  ledger: PrekeyLedger,
  bundle: PrekeyBundle,
  prekeyId: string,
): PrekeyLedger {
  const prekey = wellFormed(bundle)
    ? bundle.prekeys.find((p) => p.prekey_id === prekeyId)
    : undefined;
  if (!prekey) throw new Error("recordPrekeyUse: that prekey is not in the bundle");
  const org = bundle.org_id;
  const mark = prekeyMark(prekey.public_key);
  const before = Object.hasOwn(ledger, org) ? ledger[org]! : [];
  if (before.includes(mark)) return ledger;
  const marks = [...before, mark].slice(-MAX_LEDGER_MARKS_PER_ORG);
  // Re-insert the org last, so "sealed to longest ago" is the first key.
  const rest = Object.entries(ledger).filter(([o]) => o !== org);
  return Object.fromEntries([...rest, [org, marks]].slice(-MAX_LEDGER_ORGS));
}

/** Rehydrate defensively: keep only what has the ledger's shape. Anything else
 *  (schema drift, hand-edited or corrupted storage) is dropped, not trusted. */
export function sanitizePrekeyLedger(v: unknown): PrekeyLedger {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return {};
  const out: [string, string[]][] = [];
  for (const [org, marks] of Object.entries(v)) {
    if (!ORG_ID_RE.test(org) || !Array.isArray(marks)) continue;
    const kept = [...new Set(marks.filter((m): m is string => typeof m === "string" && MARK_RE.test(m)))];
    if (kept.length > 0) out.push([org, kept.slice(-MAX_LEDGER_MARKS_PER_ORG)]);
  }
  return Object.fromEntries(out.slice(-MAX_LEDGER_ORGS));
}

/** What sealing to `recipientOrg` would do right now, before doing it. */
export type ForwardSecrecyOutlook =
  | {
      forwardSecret: true;
      /** One-time prekeys of the bundle this sender has not sealed to yet. */
      unused: number;
      total: number;
    }
  | { forwardSecret: false; reason: StaticReason; total: number };

/** Whether a seal to `recipientOrg` would be forward-secret, how many unused one-time
 *  prekeys are left for this sender, and — if it would fall back to the static
 *  envelope — why. The same decision `sealTraveler` makes, without sealing. */
export function forwardSecrecyOutlook(args: {
  ledger: PrekeyLedger;
  bundle: PrekeyBundle | undefined;
  directory: Directory;
  rootPublicKeyHex: string;
  recipientOrg: string;
  at?: Date;
}): ForwardSecrecyOutlook {
  const { bundle } = args;
  if (bundle === undefined) return { forwardSecret: false, reason: "no-bundle", total: 0 };
  const vetted = wellFormed(bundle)
    ? verifyPrekeyBundle(bundle, args.directory, args.rootPublicKeyHex, args.at)
    : undefined;
  if (!vetted || vetted.org_id !== args.recipientOrg) {
    return { forwardSecret: false, reason: "bundle-not-verified", total: 0 };
  }
  const total = vetted.prekeys.length;
  const unused = total - usedPrekeyIds(args.ledger, vetted).length;
  return unused > 0
    ? { forwardSecret: true, unused, total }
    : { forwardSecret: false, reason: "prekeys-exhausted", total };
}

/** Why a seal is (or would be) a static envelope, in words for the person sending. */
export function staticReasonText(reason: StaticReason, recipientOrg: string): string {
  switch (reason) {
    case "no-bundle":
      return `No prekey bundle is loaded for ${recipientOrg}.`;
    case "bundle-not-verified":
      return `The prekey bundle for ${recipientOrg} does not verify (expired, not signed by that org's directory key, or malformed).`;
    case "prekeys-exhausted":
      return `This desk has already used every one-time prekey in ${recipientOrg}'s bundle. Ask them for a fresh prekey bundle.`;
    case "prekey-unavailable":
      return `The requested one-time prekey is not available in ${recipientOrg}'s bundle.`;
  }
}
