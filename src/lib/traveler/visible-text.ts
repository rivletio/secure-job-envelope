/** Show every character of a string that came from somewhere else.
 *
 *  A name or identifier taken from a document or a directory is rendered next to the
 *  verdict a person is about to rely on. Unicode has characters that are not drawn but
 *  change what IS drawn: a right-to-left override makes `Acme <RLO>orp lacitirC` read
 *  "Acme Critical pro"; a zero-width space makes two different names look identical; a
 *  line break pushes text onto a line of its own, where it reads like a separate
 *  statement by the application. `visibleText` replaces each such character with a
 *  placeholder naming its code point, e.g. `[U+202E]`, so nothing in the string can
 *  reorder or hide the rest of it:
 *
 *    - control characters (Cc): C0 and C1, including TAB, LF, CR, DEL
 *    - format characters (Cf): the bidi embeddings/overrides U+202A–U+202E, the bidi
 *      isolates U+2066–U+2069, the marks U+200E/U+200F/U+061C, zero-width space,
 *      joiner and non-joiner, word joiner, U+FEFF, soft hyphen, tag characters, …
 *    - line and paragraph separators (U+2028, U+2029)
 *    - every other default-ignorable code point: variation selectors, the Hangul
 *      fillers that render as nothing, the combining grapheme joiner, …
 *    - a lone surrogate (half of a pair, which has no character of its own)
 *
 *  This is a DISPLAY rule. It changes no document, and what a document may contain is
 *  the schema's business. It does not make a name evidence of anything (look-alike
 *  letters from another script pass straight through) — a display name is never
 *  evidence; the identity a signature establishes is the directory's `org_id`.
 *
 *  (The pattern is built from Unicode properties, so this file contains none of the
 *  characters it is about.)
 */
const NOT_DRAWN = "[\\p{Cc}\\p{Cf}\\p{Cs}\\p{Zl}\\p{Zp}\\p{Default_Ignorable_Code_Point}]";
const EVERY_NOT_DRAWN = new RegExp(NOT_DRAWN, "gu");
const ANY_NOT_DRAWN = new RegExp(NOT_DRAWN, "u");

/** `[U+XXXX]` for one code point: upper-case hex, at least four digits. */
function placeholder(ch: string): string {
  return `[U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}]`;
}

export function visibleText(s: string): string {
  return s.replace(EVERY_NOT_DRAWN, placeholder);
}

/** True iff `visibleText(s)` differs from `s` — the string carries a character that
 *  would not have been drawn. */
export function hasHiddenCharacters(s: string): boolean {
  return ANY_NOT_DRAWN.test(s);
}
