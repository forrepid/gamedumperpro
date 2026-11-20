// ----------------------------------------------------------------------------
// DumperPro Online - PE kaynak (resource) agaci + VS_VERSIONINFO + gomulu
// payload sezgisi
//
// Kaynak/teyit: Microsoft "PE Format" - IMAGE_RESOURCE_DIRECTORY (16 B,
// ardindan NamedEntries + IdEntries, her biri 8 B IMAGE_RESOURCE_DIRECTORY_
// ENTRY); data entry = IMAGE_RESOURCE_DATA_ENTRY (16 B).
// VS_VERSIONINFO: "VS_VERSION_INFO" + VS_FIXEDFILEINFO (sig 0xFEEF04BD).
// ----------------------------------------------------------------------------

import type { PeInfo, ResourcesInfo, ResourceEntry, VersionInfo } from "./types";
import { getSectionRaw } from "./pe";

const RT_NAMES: Record<number, string> = {
  1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRINGTABLE",
  7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
  12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 23: "HTML", 24: "MANIFEST",
};

interface DirCtx {
  data: Buffer;
  base: number; // resource bolumu baslangici (data-relative)
  rva0: number;
}

function readUtf16(ctx: DirCtx, off: number, maxWords = 256): string {
  let s = "";
  for (let i = 0; i < maxWords && off + 1 + i * 2 < ctx.data.length; i++) {
    const w = ctx.data.readUInt16LE(off + i * 2);
    if (w === 0) break;
    if (w < 0x20 && w !== 0x0a && w !== 0x0d) break;
    s += String.fromCharCode(w);
  }
  return s;
}

function walkDir(ctx: DirCtx, dirOff: number, level: number, path: string[], out: ResourceEntry[], depth = 0): void {
  if (depth > 4 || out.length > 96) return;
  const d = ctx.base + dirOff;
  if (d + 16 > ctx.data.length) return;
  const namedCount = ctx.data.readUInt16LE(d + 12);
  const idCount = ctx.data.readUInt16LE(d + 14);
  const total = Math.min(namedCount + idCount, 32);
  for (let i = 0; i < total; i++) {
    const e = d + 16 + i * 8;
    if (e + 8 > ctx.data.length) break;
    const nameOrId = ctx.data.readUInt32LE(e);
    const childRva = ctx.data.readUInt32LE(e + 4);
    const isDir = (childRva & 0x80000000) !== 0;
    const child = childRva & 0x7fffffff;
    let label: string;
    if (nameOrId & 0x80000000) {
      label = readUtf16(ctx, ctx.base + (nameOrId & 0x7fffffff)) || `id_${nameOrId & 0x7fffffff}`;
    } else {
      label = String(nameOrId);
    }
    if (!isDir) {
      // data entry
      const de = ctx.base + child;
      if (de + 16 > ctx.data.length) continue;
      const dataRva = ctx.data.readUInt32LE(de);
      const dataSize = ctx.data.readUInt32LE(de + 4);
      const type = path[0] ?? "RCDATA";
      const id = path.slice(1).join("/") || label;
      const fileOff = dataRva - ctx.rva0 + (ctx.base >= 0 ? 0 : 0);
      // data offset: dataRva -> dosya offset i (bolum tablosu haricinde hesaplanamaz
      // burada; index.ts dosya buf u ile rvaToOffset yapar)
      out.push({
        type,
        id: id || label,
        language: level >= 3 ? label : undefined,
        size: dataSize,
        rva: dataRva,
        offset: dataRva, // index.ts cevirir
      });
      void fileOff;
      continue;
    }
    walkDir(ctx, child, level + 1, [...path, label], out, depth + 1);
  }
}

function magicOf(buf: Buffer, off: number, size: number): string | undefined {
  if (off < 0 || off + 8 > buf.length || size < 8) return undefined;
  const m4 = buf.subarray(off, off + 4).toString("latin1");
  if (m4 === "MZ\0\0" || buf[off] === 0x4d && buf[off + 1] === 0x5a) return "PE (gomulu calistirilabilir)";
  if (m4 === "PK\u0003\u0004") return "ZIP konteyner";
  if (m4.startsWith("\x7fELF")) return "ELF ikili";
  if (m4.startsWith("{\\rtf")) return "RTF";
  if (m4.startsWith("<?xml")) return "XML";
  if (buf[off] === 0x89 && buf[off + 1] === 0x50) return "PNG resim";
  if (m4.startsWith("GIF8")) return "GIF resim";
  if (buf[off] === 0xff && buf[off + 1] === 0xd8) return "JPEG resim";
  return undefined;
}

/** VS_VERSIONINFO kaynak verisini zorlamali ayristirir (UTF-16 anahtar/deger). */
function parseVersionInfo(buf: Buffer, off: number, size: number): VersionInfo | null {
  if (off < 0 || off + 64 > buf.length) return null;
  const keys = [
    "CompanyName", "ProductName", "FileDescription", "FileVersion",
    "ProductVersion", "OriginalFilename", "InternalName", "LegalCopyright", "Comments",
  ];
  const keyBufs = keys.map((k) => ({ key: k, buf: Buffer.from(k + "\0", "utf16le") }));
  const out: VersionInfo = {};
  const region = buf.subarray(off, Math.min(off + size, off + 8192, buf.length));
  for (const kb of keyBufs) {
    const idx = region.indexOf(kb.buf);
    if (idx === -1) continue;
    // anahtardan sonra NUL + hizalama (4 bayt), ardindan deger (UTF-16, NUL ile biter)
    let p = idx + kb.buf.length;
    // 4 bayt hizalama
    while (p % 4 !== 0 && p < region.length) p++;
    // deger: UTF-16LE karakterler
    let val = "";
    for (let i = 0; i + 1 < region.length - p && i < 512; i += 2) {
      const w = region.readUInt16LE(p + i);
      if (w === 0) break;
      if (w < 0x20) break;
      val += String.fromCharCode(w);
    }
    if (val) {
      (out as Record<string, string>)[kb.key] = val;
    }
  }
  // VS_FIXEDFILEINFO sayisal surum (StringFileInfo eksikse)
  if (!out.fileVersion) {
    const regionStart = off;
    const limit = Math.min(off + size, buf.length) - 4;
    for (let p = regionStart; p < limit; p += 4) {
      if (buf.readUInt32LE(p) === 0xfeef04bd) {
        const fileVerMS = buf.readUInt32LE(p + 8);
        const fileVerLS = buf.readUInt32LE(p + 12);
        const prodVerMS = buf.readUInt32LE(p + 16);
        const prodVerLS = buf.readUInt32LE(p + 20);
        out.fileVersion = `${(fileVerMS >>> 16)}.${fileVerMS & 0xffff}.${(fileVerLS >>> 16)}.${fileVerLS & 0xffff}`;
        out.productVersion = out.productVersion ?? `${(prodVerMS >>> 16)}.${prodVerMS & 0xffff}.${(prodVerLS >>> 16)}.${prodVerLS & 0xffff}`;
        break;
      }
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function analyzeResources(buf: Buffer, pe: PeInfo, errors: string[]): { resources: ResourcesInfo; versionInfo: VersionInfo | null } {
  const res = pe.dataDirectories.find((d) => d.name === "Resource");
  if (!res || res.size === 0) {
    return { resources: { total: 0, entries: [] }, versionInfo: null };
  }
  // resource bolumunu bul
  const resSec = pe.sections.find(
    (s) => res.va >= s.virtualAddress && res.va < s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
  );
  if (!resSec) {
    errors.push("Resource dizini bir bolume eslenemedi");
    return { resources: { total: 0, entries: [] }, versionInfo: null };
  }
  const secData = getSectionRaw(buf, resSec);
  if (!secData) {
    errors.push("Resource bolumu verisi okunamadi");
    return { resources: { total: 0, entries: [] }, versionInfo: null };
  }
  const ctx: DirCtx = { data: secData, base: 0, rva0: resSec.virtualAddress };
  const dirRel = res.va - resSec.virtualAddress;
  const entries: ResourceEntry[] = [];
  walkDir(ctx, dirRel, 0, [], entries);

  // rva -> dosya offset + magic
  const rvaToOffset = (rva: number): number => {
    for (const s of pe.sections) {
      const span = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
        const off = rva - s.virtualAddress + s.rawPointer;
        return off < buf.length ? off : -1;
      }
    }
    return -1;
  };
  let total = 0;
  for (const e of entries) {
    total++;
    e.offset = rvaToOffset(e.rva);
    e.embedded = magicOf(buf, e.offset, e.size);
  }

  // versiyon bilgisi (type 16)
  let versionInfo: VersionInfo | null = null;
  const verEntry = entries.find((e) => e.type === "VERSION");
  if (verEntry && verEntry.offset >= 0) {
    try {
      versionInfo = parseVersionInfo(buf, verEntry.offset, verEntry.size);
    } catch {
      errors.push("VS_VERSIONINFO ayristirilamadi");
    }
  }

  // en buyuk kaynak
  let biggest: ResourcesInfo["biggest"];
  const sorted = [...entries].sort((a, b) => b.size - a.size);
  if (sorted.length && buf.length > 0) {
    const b = sorted[0];
    biggest = { ...b, pct: Math.round((b.size / buf.length) * 1000) / 10 };
  }

  return {
    resources: {
      total,
      entries: entries.slice(0, 64),
      biggest,
    },
    versionInfo,
  };
}
