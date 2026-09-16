import JSZip from "jszip";
import { canonicalJson } from "./canonical.ts";
import { parsePacket } from "./conformance.ts";
import { packetHash, quoteableBody, sha256Hex } from "./hash.ts";
import {
  MAX_ARCHIVE_BYTES,
  MAX_PACKET_JSON_BYTES,
  PACKET_ID_RE,
  PACKET_MEDIA,
  PACKET_SPEC,
  type Packet,
} from "./types.ts";

const ROOT_PACKET = "packet.json";
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

function archiveName(packetId: string): string {
  if (!PACKET_ID_RE.test(packetId)) throw new Error("invalid packet_id");
  return `${packetId}.rivpkt.zip`;
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

export async function packetToZip(packet: Packet): Promise<Blob> {
  const zip = new JSZip();
  const hash = packetHash(packet);
  const packetJson = JSON.stringify(packet, null, 2);
  zip.file(ROOT_PACKET, packetJson, { compression: "DEFLATE" });
  zip.file(
    ROOT_META,
    JSON.stringify(
      {
        media_type: PACKET_MEDIA,
        spec: PACKET_SPEC,
        packet_id: packet.packet_id,
        packet_hash: hash,
        packet_json_sha256: sha256Hex(packetJson),
        archive: archiveName(packet.packet_id),
        itar: Boolean(packet.itar),
        export_control: packet.itar ? "ITAR-self-declared" : "none",
        notice:
          "packet_hash is integrity of the quoteable body, not a signature. 0.0.1 does not authenticate parties or implement export-control.",
      },
      null,
      2,
    ),
  );
  zip.file(ROOT_CANONICAL, canonicalJson(quoteableBody(packet)));
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

async function importZip(buf: ArrayBuffer): Promise<Packet> {
  const zip = await JSZip.loadAsync(buf, { checkCRC32: true });
  const names = Object.keys(zip.files);
  if (names.length > MAX_ZIP_FILES) throw new Error("Archive has too many files");
  for (const name of names) {
    assertSafePath(name);
    const entry = zip.files[name]!;
    if (entry.dir) throw new Error("Archive directories are not allowed");
    if (!ALLOWED_FILES.has(name)) throw new Error(`Unexpected archive member: ${name}`);
  }

  const packetEntry = zip.file(ROOT_PACKET);
  const metaEntry = zip.file(ROOT_META);
  if (!packetEntry) throw new Error("Archive has no packet.json at the root");
  if (!metaEntry) throw new Error("Archive is missing META.json (required for integrity)");

  if (zipUncompressed(packetEntry) > MAX_PACKET_JSON_BYTES) {
    throw new Error("packet.json exceeds 512 KiB uncompressed");
  }
  if (zipUncompressed(metaEntry) > MAX_META_BYTES) throw new Error("META.json too large");

  const text = await packetEntry.async("string");
  if (text.length > MAX_PACKET_JSON_BYTES) throw new Error("packet.json exceeds 512 KiB");
  const packet = parsePacket(parseJson(text, "packet.json"));

  const metaText = await metaEntry.async("string");
  if (metaText.length > MAX_META_BYTES) throw new Error("META.json too large");
  const meta = parseJson(metaText, "META.json");
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    throw new Error("META.json must be an object");
  }
  const rec = meta as Record<string, unknown>;
  if (typeof rec.packet_id !== "string" || rec.packet_id !== packet.packet_id) {
    throw new Error("META.json packet_id does not match packet.json");
  }
  if (typeof rec.packet_hash !== "string" || rec.packet_hash !== packetHash(packet)) {
    throw new Error("META.json packet_hash does not match quoteable body");
  }
  if (typeof rec.spec === "string" && rec.spec !== PACKET_SPEC) {
    throw new Error("META.json spec does not match rivlet-packet/0.0.1");
  }
  if (typeof rec.packet_json_sha256 === "string" && rec.packet_json_sha256 !== sha256Hex(text)) {
    throw new Error("packet.json does not match archive digest");
  }

  const canonEntry = zip.file(ROOT_CANONICAL);
  if (canonEntry) {
    if (zipUncompressed(canonEntry) > MAX_CANON_BYTES) {
      throw new Error("quoteable.canonical.json too large");
    }
    const canon = await canonEntry.async("string");
    if (canon.length > MAX_CANON_BYTES) throw new Error("quoteable.canonical.json too large");
    if (canon !== canonicalJson(quoteableBody(packet))) {
      throw new Error("quoteable.canonical.json does not match packet.json");
    }
  }

  return packet;
}

export async function importPacketFile(file: File): Promise<Packet> {
  if (file.size > MAX_ARCHIVE_BYTES) throw new Error("File exceeds 2 MB limit");
  const buf = await file.arrayBuffer();
  if (buf.byteLength > MAX_ARCHIVE_BYTES) throw new Error("File exceeds 2 MB limit");
  const lower = file.name.toLowerCase();
  const isZip =
    lower.endsWith(".zip") || lower.endsWith(".rivpkt.zip") || file.type.includes("zip");
  if (isZip) return importZip(buf);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  if (text.length > MAX_PACKET_JSON_BYTES) throw new Error("JSON exceeds 512 KiB");
  return parsePacket(parseJson(text, "packet.json"));
}

export function downloadJson(packet: Packet) {
  if (!PACKET_ID_RE.test(packet.packet_id)) throw new Error("invalid packet_id");
  const blob = new Blob([JSON.stringify(packet, null, 2)], {
    type: PACKET_MEDIA,
  });
  downloadBlob(blob, `${packet.packet_id}.json`);
}

export async function downloadRivpkt(packet: Packet) {
  const blob = await packetToZip(packet);
  downloadBlob(blob, archiveName(packet.packet_id));
}
