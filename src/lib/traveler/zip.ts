import JSZip from "jszip";
import { canonicalJson } from "./canonical.ts";
import { parseTraveler } from "./conformance.ts";
import { travelerHash, quoteableBody, sha384Hex } from "./hash.ts";
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

function assertSafePath(name: string) {
  const n = name.replace(/\\/g, "/");
  // Members are flat root files: refuse any slash, backslash, "..", or NUL
  // (SPEC §Archive: "refuse paths containing / or \ or ..").
  if (n !== name || n.includes("..") || n.includes("/") || n.includes("\0")) {
    throw new Error("Archive path is not allowed");
  }
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
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}

export async function travelerToZip(traveler: Traveler): Promise<Blob> {
  const zip = new JSZip();
  const hash = travelerHash(traveler);
  const travelerJson = JSON.stringify(traveler, null, 2);
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
  for (const name of names) {
    assertSafePath(name);
    const entry = zip.files[name]!;
    if (entry.dir) throw new Error("Archive directories are not allowed");
    if (!ALLOWED_FILES.has(name)) throw new Error(`Unexpected archive member: ${name}`);
  }

  const travelerEntry = zip.file(ROOT_TRAVELER);
  const metaEntry = zip.file(ROOT_META);
  if (!travelerEntry) throw new Error("Archive has no traveler.json at the root");
  if (!metaEntry) throw new Error("Archive is missing META.json (required for integrity)");

  const text = await readEntryText(travelerEntry, MAX_TRAVELER_JSON_BYTES, "traveler.json");
  const traveler = parseTraveler(parseJson(text, "traveler.json"));

  const metaText = await readEntryText(metaEntry, MAX_META_BYTES, "META.json");
  const meta = parseJson(metaText, "META.json");
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
  if (typeof rec.traveler_json_sha384 !== "string" || rec.traveler_json_sha384 !== sha384Hex(text)) {
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
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  if (text.length > MAX_TRAVELER_JSON_BYTES) throw new Error("JSON exceeds 512 KiB");
  return parseTraveler(parseJson(text, "traveler.json"));
}

export function downloadJson(traveler: Traveler) {
  if (!TRAVELER_ID_RE.test(traveler.traveler_id)) throw new Error("invalid traveler_id");
  const blob = new Blob([JSON.stringify(traveler, null, 2)], {
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
  const rand = new Uint8Array(8);
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("a secure random source (crypto.getRandomValues) is required");
  }
  crypto.getRandomValues(rand);
  const name = Array.from(rand, (b) => b.toString(16).padStart(2, "0")).join("") + ".sje";
  downloadBlob(new Blob([JSON.stringify(envelope)], { type: "application/json" }), name);
}
