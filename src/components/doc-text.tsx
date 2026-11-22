import { visibleText } from "@/lib/traveler/visible-text";

/** Text that came out of a document — a name, a part number, a note, an address — drawn
 *  so that nothing in it can hide or reorder what is around it.
 *
 *  Everything in a traveler is written by its author, and a traveler arrives from other
 *  companies. Unicode has characters that are not drawn but change what is: a
 *  right-to-left override turned the buyer name `Northline Equipment <RLO>DEIFIREV` into
 *  "Northline Equipment VERIFIED" in this desk's own page header. `visibleText` replaces
 *  each such character with a placeholder naming it (`[U+202E]`), and the text sits in
 *  its own `<bdi>` so its direction cannot leak into the words next to it.
 *
 *  `block` is for a long free-text field (a description, a note, a proposal): its line
 *  breaks are kept and each line is treated on its own. Everywhere else a line break is
 *  shown as a placeholder too — a label is one line. */
export function DocText({ text, block = false }: { text: string; block?: boolean }) {
  return <bdi>{block ? text.split("\n").map(visibleText).join("\n") : visibleText(text)}</bdi>;
}
