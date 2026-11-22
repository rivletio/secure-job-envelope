import JSZip from "jszip";
import { randomBytes } from "./bytes.ts";
import { canonicalJson } from "./canonical.ts";
import { parseTravelerJson } from "./conformance.ts";
import { travelerHash, quoteableBody, sha384Hex } from "./hash.ts";
import { decodeUtf8Strict, exceedsUtf8Bytes, parseStrictJson } from "./wire.ts";
import {
  MAX_ARCHIVE_BYTES,
  MAX_TRAVELER_JSON_BYTES,
  TRAVELER_ID_RE,
  TRAVELER_MEDIA,
  TRAVELER_SPEC,
  type Traveler,
} from "./types.ts";

const ROOT_TRAVELER = "traveler.json";
const ROOT_META = "META.json";
const ROOT_CANONICAL = "quoteable.canonical.json";
const ALLOWED_FILES = new Set([ROOT_TRAVELER, ROOT_META, ROOT_CANONICAL]);
const MAX_ZIP_FILES = 3;
const MAX_META_BYTES = 16_384;
const MAX_CANON_BYTES = 64 * 1024;

function assertSafePath(name: string, entry: JSZip.JSZipObject) {
  // JSZip normalizes member names while loading — "../traveler.json", "a/../traveler.json"
  // and "./traveler.json" all arrive here as "traveler.json" — so the name it hands back
  // can never show a traversal, and checking only that name refused nothing. JSZip keeps
  // the name as stored in the archive in `unsafeOriginalName`; a member whose stored
  // name is not already the plain root name is refused.
  // Fail closed: if a future JSZip stops exposing the stored name, every member is
  // refused (and the archive tests fail) rather than the check silently passing.
  const stored = (entry as unknown as { unsafeOriginalName?: unknown }).unsafeOriginalName;
  if (stored !== name) throw new Error("Archive path is not allowed");
  const n = name.replace(/\\/g, "/");
  // Members are flat root files: refuse any slash, backslash, "..", or NUL
  // (SPEC §Archive: "refuse paths containing / or \ or ..").
  if (n !== name || n.includes("..") || n.includes("/") || n.includes("\0")) {
    throw new Error("Archive path is not allowed");
  }
}

/** How many members the archive's own end-of-central-directory record declares.
 *
 *  A zip may hold two members with the same name. JSZip indexes members by name, so the
 *  later one silently replaces the earlier and the list it returns has no trace of the
 *  other — while a different tool extracting the same file may hand its user the first.
 *  One archive, two travelers, depending on the reader. Comparing JSZip's member count
 *  with the count the archive declares turns a collapsed (or otherwise unlisted) member
 *  into a refusal. The record is located exactly as JSZip locates it: the last
 *  occurrence of its signature. */
function declaredMemberCount(bytes: Uint8Array): number | undefined {
  for (let i = bytes.length - 4; i >= 0; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      // "total number of entries in the central directory": u16 LE at offset 10
      if (i + 12 > bytes.length) return undefined;
      return bytes[i + 10]! | (bytes[i + 11]! << 8);
    }
  }
  return undefined;
}

function archiveName(travelerId: string): string {
  if (!TRAVELER_ID_RE.test(travelerId)) throw new Error("invalid traveler_id");
  return `${travelerId}.traveler.zip`;
}

/** Inflate one entry with a hard ceiling on *decompressed* bytes, aborting
 *  mid-stream the instant it is exceeded. A zip header's declared uncompressed
 *  size is attacker-controlled, so it can't be the gate; this streams the real
 *  output and stops. Prevents a small archive from expanding into a multi-GB
 *  decompression (zip-bomb DoS) before any guard runs. */
function readEntryCapped(
  entry: JSZip.JSZipObject,
  maxBytes: number,
  label: string,
): Promise<Uint8Array> {
  type Stream = {
    on(evt: "data", fn: (chunk: Uint8Array) => void): Stream;
    on(evt: "error", fn: (err: unknown) => void): Stream;
    on(evt: "end", fn: () => void): Stream;
    resume(): Stream;
    pause(): Stream;
  };
  // internalStream works in both the browser and Node (unlike nodeStream) but
  // is absent from jszip's .d.ts, so it is typed locally.
  const stream = (
    entry as unknown as { internalStream(type: "uint8array"): Stream }
  ).internalStream("uint8array");
  return new Promise<Uint8Array>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let settled = false;
    stream
      .on("data", (chunk) => {
        if (settled) return;
        total += chunk.length;
        if (total > maxBytes) {
          settled = true;
          stream.pause();
          reject(new Error(`${label} exceeds ${maxBytes} bytes uncompressed`));
          return;
        }
        chunks.push(chunk);
      })
      .on("error", (err) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err)));
      })
      .on("end", () => {
        if (settled) return;
        settled = true;
        const out = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          out.set(c, off);
          off += c.length;
        }
        resolve(out);
      })
      .resume();
  });
}

async function readEntryText(
  entry: JSZip.JSZipObject,
  maxBytes: number,
  label: string,
): Promise<string> {
  const bytes = await readEntryCapped(entry, maxBytes, label);
  try {
    // Strict: invalid UTF-8 is refused, and a leading byte-order mark is kept (so the
    // JSON parse below refuses it) instead of being silently stripped.
    return decodeUtf8Strict(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

/** The traveler as JSON text for a file or an archive member: pretty-printed for a
 *  human reader when that fits, compact otherwise. Any reader — this one, or the Rust
 *  core — caps the text at 512 KiB of UTF-8, and indentation alone can push a large but
 *  valid traveler over it; an archive this code wrote must always be one it can read
 *  back. */
export function travelerWireJson(traveler: Traveler): string {
  const pretty = JSON.stringify(traveler, null, 2);
  return exceedsUtf8Bytes(pretty, MAX_TRAVELER_JSON_BYTES) ? JSON.stringify(traveler) : pretty;
}

export async function travelerToZip(traveler: Traveler): Promise<Blob> {
  const zip = new JSZip();
  const hash = travelerHash(traveler);
  const travelerJson = travelerWireJson(traveler);
  zip.file(ROOT_TRAVELER, travelerJson, { compression: "DEFLATE" });
  zip.file(
    ROOT_META,
    JSON.stringify(
      {
        media_type: TRAVELER_MEDIA,
        spec: TRAVELER_SPEC,
        traveler_id: traveler.traveler_id,
        traveler_hash: hash,
        traveler_json_sha384: sha384Hex(travelerJson),
        archive: archiveName(traveler.traveler_id),
        itar: Boolean(traveler.itar),
        export_control: traveler.itar ? "ITAR-self-declared" : "none",
        notice:
          "traveler_hash is integrity of the quoteable body, not a signature; authorship is a separate ML-DSA-87 signature verified against the signed key directory (0.1).",
      },
      null,
      2,
    ),
  );
  zip.file(ROOT_CANONICAL, canonicalJson(quoteableBody(traveler)));
  return zip.generateAsync({ type: "blob" });
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function importZip(buf: ArrayBuffer): Promise<Traveler> {
  // No { checkCRC32: true }: it would force JSZip to inflate every entry up
  // front (to verify CRC) before any guard runs, so a ~2 MB archive of
  // compressible bytes could expand to ~1-2 GB first. loadAsync alone only
  // parses headers; each allowlisted member is then inflated through
  // readEntryCapped, which aborts at a hard decompressed-byte ceiling.
  // Integrity comes from the SHA-384 cross-checks below (they supersede CRC32).
  // Normalize the loader's failure: JSZip's raw messages name the library and a
  // help URL ("...is this a zip file? see https://stuk.github.io/jszip/..."), which
  // leaks implementation detail through the MCP/CLI surface. Callers only need to
  // know the bytes were not a valid archive.
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch {
    throw new Error("Not a valid zip archive");
  }
  const names = Object.keys(zip.files);
  if (names.length > MAX_ZIP_FILES) throw new Error("Archive has too many files");
  if (declaredMemberCount(new Uint8Array(buf)) !== names.length) {
    throw new Error("Archive has duplicate or unlisted members");
  }
  for (const name of names) {
    const entry = zip.files[name]!;
    if (entry.dir) throw new Error("Archive directories are not allowed");
    assertSafePath(name, entry);
    if (!ALLOWED_FILES.has(name)) throw new Error("Unexpected archive member");
  }

  const travelerEntry = zip.file(ROOT_TRAVELER);
  const metaEntry = zip.file(ROOT_META);
  if (!travelerEntry) throw new Error("Archive has no traveler.json at the root");
  if (!metaEntry) throw new Error("Archive is missing META.json (required for integrity)");

  // The traveler is parsed from its BYTES by the strict text entry point: the 512 KiB
  // cap, the byte-order-mark and duplicate-member refusals, and the digest below all
  // refer to exactly the bytes in the archive — the same bytes the Rust core would see.
  const travelerBytes = await readEntryCapped(travelerEntry, MAX_TRAVELER_JSON_BYTES, "traveler.json");
  const traveler = parseTravelerJson(travelerBytes);

  // META.json goes through the same strict text boundary: a repeated member name (two
  // `traveler_json_sha384`, say) is refused instead of resolved last-wins.
  const meta = parseStrictJson(await readEntryCapped(metaEntry, MAX_META_BYTES, "META.json"), {
    maxBytes: MAX_META_BYTES,
    label: "META.json",
  });
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    throw new Error("META.json must be an object");
  }
  const rec = meta as Record<string, unknown>;
  if (typeof rec.traveler_id !== "string" || rec.traveler_id !== traveler.traveler_id) {
    throw new Error("META.json traveler_id does not match traveler.json");
  }
  if (typeof rec.traveler_hash !== "string" || rec.traveler_hash !== travelerHash(traveler)) {
    throw new Error("META.json traveler_hash does not match quoteable body");
  }
  if (typeof rec.spec === "string" && rec.spec !== TRAVELER_SPEC) {
    throw new Error(`META.json spec does not match ${TRAVELER_SPEC}`);
  }
  // The full-bytes digest is REQUIRED, not optional. traveler_hash covers only the
  // quoteable body, so without this an importer could tamper the non-quoteable
  // lifecycle fields (award, ship_to, ops, quotes, as_built) and recompute only the
  // quoteable traveler_hash. Requiring the digest over the whole traveler.json means
  // any byte change is refused. (This is unkeyed integrity — it detects corruption
  // and naive tampering; adversarial authenticity is the separate ML-DSA authorship
  // signature, which in 0.1 covers the quoteable body, not the lifecycle fields.)
  if (
    typeof rec.traveler_json_sha384 !== "string" ||
    rec.traveler_json_sha384 !== sha384Hex(travelerBytes)
  ) {
    throw new Error("META.json traveler_json_sha384 is required and must match traveler.json");
  }

  const canonEntry = zip.file(ROOT_CANONICAL);
  if (canonEntry) {
    const canon = await readEntryText(canonEntry, MAX_CANON_BYTES, "quoteable.canonical.json");
    if (canon !== canonicalJson(quoteableBody(traveler))) {
      throw new Error("quoteable.canonical.json does not match traveler.json");
    }
  }

  return traveler;
}

export async function importTravelerFile(file: File): Promise<Traveler> {
  if (file.size > MAX_ARCHIVE_BYTES) throw new Error("File exceeds 2 MB limit");
  const buf = await file.arrayBuffer();
  if (buf.byteLength > MAX_ARCHIVE_BYTES) throw new Error("File exceeds 2 MB limit");
  const lower = file.name.toLowerCase();
  const isZip =
    lower.endsWith(".zip") || lower.endsWith(".traveler.zip") || file.type.includes("zip");
  if (isZip) return importZip(buf);
  return parseTravelerJson(new Uint8Array(buf));
}

export function downloadJson(traveler: Traveler) {
  if (!TRAVELER_ID_RE.test(traveler.traveler_id)) throw new Error("invalid traveler_id");
  const blob = new Blob([travelerWireJson(traveler)], {
    type: TRAVELER_MEDIA,
  });
  downloadBlob(blob, `${traveler.traveler_id}.json`);
}

export async function downloadArchive(traveler: Traveler) {
  const blob = await travelerToZip(traveler);
  downloadBlob(blob, archiveName(traveler.traveler_id));
}

/** Download an encrypted envelope under a RANDOM filename. The name must not embed
 *  the traveler_id (`{traveler_id}.sje`) — that would leak the id of an otherwise
 *  confidential artifact through the filename alone. */
export function downloadEnvelope(envelope: object): void {
  const rand = randomBytes(8);
  const name = Array.from(rand, (b) => b.toString(16).padStart(2, "0")).join("") + ".sje";
  downloadBlob(new Blob([JSON.stringify(envelope)], { type: "application/json" }), name);
}
