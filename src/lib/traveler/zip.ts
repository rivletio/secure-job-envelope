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

const ROOT_PACKET = "traveler.json";
const ROOT_META = "META.json";
const ROOT_CANONICAL = "quoteable.canonical.json";
const ALLOWED_FILES = new Set([ROOT_PACKET, ROOT_META, ROOT_CANONICAL]);
const MAX_ZIP_FILES = 3;
const MAX_META_BYTES = 16_384;
const MAX_CANON_BYTES = 64 * 1024;

function assertSafePath(name: string) {
  const n = name.replace(/\\/g, "/");
  if (n !== name || n.includes("..") || n.startsWith("/") || n.includes("\0") || n.includes("//")) {
    throw new Error("Archive path is not allowed");
  }
}

function archiveName(travelerId: string): string {
  if (!TRAVELER_ID_RE.test(travelerId)) throw new Error("invalid traveler_id");
  return `${travelerId}.traveler.zip`;
}

function zipUncompressed(file: JSZip.JSZipObject): number {
  const n = (file as JSZip.JSZipObject & { _data?: { uncompressedSize?: number } })._data
    ?.uncompressedSize;
  if (typeof n !== "number" || n < 0) throw new Error("Archive entry size is unknown");
  return n;
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
  zip.file(ROOT_PACKET, travelerJson, { compression: "DEFLATE" });
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
          "traveler_hash is integrity of the quoteable body, not a signature. 0.0.1 does not authenticate parties or implement export-control.",
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
  const zip = await JSZip.loadAsync(buf, { checkCRC32: true });
  const names = Object.keys(zip.files);
  if (names.length > MAX_ZIP_FILES) throw new Error("Archive has too many files");
  for (const name of names) {
    assertSafePath(name);
    const entry = zip.files[name]!;
    if (entry.dir) throw new Error("Archive directories are not allowed");
    if (!ALLOWED_FILES.has(name)) throw new Error(`Unexpected archive member: ${name}`);
  }

  const travelerEntry = zip.file(ROOT_PACKET);
  const metaEntry = zip.file(ROOT_META);
  if (!travelerEntry) throw new Error("Archive has no traveler.json at the root");
  if (!metaEntry) throw new Error("Archive is missing META.json (required for integrity)");

  if (zipUncompressed(travelerEntry) > MAX_TRAVELER_JSON_BYTES) {
    throw new Error("traveler.json exceeds 512 KiB uncompressed");
  }
  if (zipUncompressed(metaEntry) > MAX_META_BYTES) throw new Error("META.json too large");

  const text = await travelerEntry.async("string");
  if (text.length > MAX_TRAVELER_JSON_BYTES) throw new Error("traveler.json exceeds 512 KiB");
  const traveler = parseTraveler(parseJson(text, "traveler.json"));

  const metaText = await metaEntry.async("string");
  if (metaText.length > MAX_META_BYTES) throw new Error("META.json too large");
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
    throw new Error("META.json spec does not match opentraveler/0.0.1");
  }
  if (typeof rec.traveler_json_sha384 === "string" && rec.traveler_json_sha384 !== sha384Hex(text)) {
    throw new Error("traveler.json does not match archive digest");
  }

  const canonEntry = zip.file(ROOT_CANONICAL);
  if (canonEntry) {
    if (zipUncompressed(canonEntry) > MAX_CANON_BYTES) {
      throw new Error("quoteable.canonical.json too large");
    }
    const canon = await canonEntry.async("string");
    if (canon.length > MAX_CANON_BYTES) throw new Error("quoteable.canonical.json too large");
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

export async function downloadRivpkt(traveler: Traveler) {
  const blob = await travelerToZip(traveler);
  downloadBlob(blob, archiveName(traveler.traveler_id));
}
