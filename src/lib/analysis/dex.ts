// ----------------------------------------------------------------------------
// DumperPro Online - DEX (Dalvik Executable) parser
//
// Kaynak/teyit: Android AOSP "dex-format.md" (dalvik executables 035/037/038/039).
// Yalnizca okuma: header + map_list + string_ids + type_ids + class_defs.
// Sinirli ve guvenli: tum indis okumalari buffer disina tasmaz; cap'ler asagida.
//
// Not: MUTF-8 stringler buffer'dan uzunluk kontrollu okunur (ULEB128 utf16_size),
// bozuk/kesik DEX'te kismi sonuc + hata notu dondurulur.
// ----------------------------------------------------------------------------

import type { DexInfo } from "./types";

const MAX_STRINGS_SCAN = 20000; // paket/motor taramasi icin okunacak string sayisi
const MAX_STRING_BYTES = 4096;  // tek string icin okunacak maksimum bayt
const MAX_CLASSES_SAMPLES = 24;

interface DexHeaderRaw {
  version: string;
  endian: number;
  fileSize: number;
  headerSize: number;
  mapOff: number;
  stringIdsSize: number;
  stringIdsOff: number;
  typeIdsSize: number;
  typeIdsOff: number;
  protoIdsSize: number;
  protoIdsOff: number;
  fieldIdsSize: number;
  fieldIdsOff: number;
  methodIdsSize: number;
  methodIdsOff: number;
  classDefsSize: number;
  classDefsOff: number;
  dataSize: number;
}

function u32(buf: Buffer, off: number): number | undefined {
  if (off < 0 || off + 4 > buf.length) return undefined;
  return buf.readUInt32LE(off);
}

/** ULEB128 okuma - [deger, yeniOffset]; tasma/varsa undefined. */
function uleb128(buf: Buffer, off: number): [number, number] | undefined {
  let result = 0;
  let shift = 0;
  for (let i = 0; i < 5 && off + i < buf.length; i++) {
    const b = buf[off + i];
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result >>> 0, off + i + 1];
    shift += 7;
    if (shift > 28) break;
  }
  return undefined;
}

/** MUTF-8 -> JS string (yaklasik: UTF-8 ile ayni yol, null-terminator'e kadar). */
function decodeMutf8(buf: Buffer, off: number, maxBytes: number): string {
  const end = Math.min(buf.length, off + maxBytes);
  let s = "";
  let i = off;
  for (; i < end; i++) {
    const b = buf[i];
    if (b === 0) break;
    if (b < 0x80) s += String.fromCharCode(b);
    else if ((b & 0xe0) === 0xc0 && i + 1 < end) {
      s += String.fromCharCode(((b & 0x1f) << 6) | (buf[i + 1] & 0x3f));
      i += 1;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < end) {
      const cp = ((b & 0x0f) << 12) | ((buf[i + 1] & 0x3f) << 6) | (buf[i + 2] & 0x3f);
      s += String.fromCharCode(cp);
      i += 2;
    } else {
      s += "?"; // surrogate / 4-bayt dizilim: Cp2 ciftleri onemsiz (rapor amacli)
    }
  }
  return s;
}

/** DEX header checksum: header'daki adler32, govichden sonraki veriye uygulanir. */
function adler32(buf: Buffer, from: number): number {
  let a = 1;
  let b = 0;
  const MOD = 65521;
  for (let i = from; i < buf.length; i++) {
    a = (a + buf[i]) % MOD;
    b = (b + a) % MOD;
  }
  return ((b << 16) | a) >>> 0;
}

function parseHeader(buf: Buffer): DexHeaderRaw | undefined {
  const version = buf.subarray(4, 7).toString("latin1").trim();
  const endian = u32(buf, 0x28);
  if (endian === undefined) return undefined;
  const h: DexHeaderRaw = {
    version,
    endian,
    fileSize: u32(buf, 0x20) ?? 0,
    headerSize: u32(buf, 0x24) ?? 0,
    mapOff: u32(buf, 0x34) ?? 0,
    stringIdsSize: u32(buf, 0x38) ?? 0,
    stringIdsOff: u32(buf, 0x3c) ?? 0,
    typeIdsSize: u32(buf, 0x40) ?? 0,
    typeIdsOff: u32(buf, 0x44) ?? 0,
    protoIdsSize: u32(buf, 0x48) ?? 0,
    protoIdsOff: u32(buf, 0x4c) ?? 0,
    fieldIdsSize: u32(buf, 0x50) ?? 0,
    fieldIdsOff: u32(buf, 0x54) ?? 0,
    methodIdsSize: u32(buf, 0x58) ?? 0,
    methodIdsOff: u32(buf, 0x5c) ?? 0,
    classDefsSize: u32(buf, 0x60) ?? 0,
    classDefsOff: u32(buf, 0x64) ?? 0,
    dataSize: u32(buf, 0x68) ?? 0,
  };
  return h;
}

export function parseDex(buf: Buffer, errors: string[]): DexInfo | undefined {
  if (buf.length < 0x70) {
    errors.push("DEX cok kucuk (header 0x70 bayt olmali)");
    return undefined;
  }
  const h = parseHeader(buf);
  if (!h) {
    errors.push("DEX header okunamadi (kesik dosya)");
    return undefined;
  }

  const checksumOk =
    buf.length >= 0x0c && (adler32(buf, 0x0c) >>> 0) === (u32(buf, 0x08) ?? -1);

  const info: DexInfo = {
    version: h.version,
    endian: h.endian === 0x12345678 ? "LE" : h.endian === 0x78563412 ? "BE" : "bilinmiyor",
    strings: h.stringIdsSize,
    types: h.typeIdsSize,
    protos: h.protoIdsSize,
    fields: h.fieldIdsSize,
    methods: h.methodIdsSize,
    classes: h.classDefsSize,
    checksumOk,
    packages: [],
    topLevelPackages: [],
    engineHints: [],
    classSamples: [],
  };

  // --- string tablosunu tara (cap'li) ---
  // string_id_item: u32 data_off -> string_data_item { uleb16size, mutf8 bytes, 0x00 }
  const scanCount = Math.min(h.stringIdsSize, MAX_STRINGS_SCAN);
  const strings: string[] = [];
  for (let i = 0; i < scanCount; i++) {
    const dataOff = u32(buf, h.stringIdsOff + i * 4);
    if (dataOff === undefined || dataOff >= buf.length) break;
    const len = uleb128(buf, dataOff);
    if (!len) break;
    strings.push(decodeMutf8(buf, len[1], MAX_STRING_BYTES));
  }
  if (h.stringIdsSize > scanCount) {
    errors.push(`DEX string taramasi caplandi: ${scanCount}/${h.stringIdsSize} okundu (sayilar header'dan)`);
  }

  // --- tip tanimlayicilari (type descriptors) ---
  // type_id_item: u32 descriptor_idx (string indis). "Lcom/foo/Bar;" formatinda.
  const typeScan = Math.min(h.typeIdsSize, MAX_STRINGS_SCAN);
  const descriptors: string[] = [];
  for (let i = 0; i < typeScan; i++) {
    const idx = u32(buf, h.typeIdsOff + i * 4);
    if (idx === undefined || idx >= strings.length) break;
    descriptors.push(strings[idx]);
  }

  // paket istatistikleri
  const pkgCount = new Map<string, number>();
  const topCount = new Map<string, number>();
  for (const d of descriptors) {
    if (!d.startsWith("L") || !d.endsWith(";")) continue;
    const parts = d.slice(1, -1).split("/");
    if (parts.length >= 1) {
      const t0 = parts[0];
      topCount.set(t0, (topCount.get(t0) ?? 0) + 1);
    }
    if (parts.length >= 2) {
      const pkg = parts.slice(0, Math.min(parts.length - 1, 3)).join(".");
      pkgCount.set(pkg, (pkgCount.get(pkg) ?? 0) + 1);
    }
  }
  info.packages = [...pkgCount.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 16);
  info.topLevelPackages = [...topCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([k]) => k);

  // sinif ornekleri (class_defs -> class_idx)
  const classScan = Math.min(h.classDefsSize, MAX_CLASSES_SAMPLES);
  for (let i = 0; i < classScan; i++) {
    const classIdx = u32(buf, h.classDefsOff + i * 32); // class_def_item.class_idx @ +0
    if (classIdx === undefined) break;
    const desc = classIdx < descriptors.length ? descriptors[classIdx] : "?";
    info.classSamples.push(desc);
  }

  // motor / oyun ipuclari (string havuzundan)
  const hints = new Set<string>();
  for (const s of strings) {
    const low = s.toLowerCase();
    if (low.includes("com.epicgames")) hints.add("Epic Games paketleri (com.epicgames.*)");
    else if (low.includes("unreal")) hints.add("'unreal' dizeleri");
    else if (low.startsWith("lue") && low.includes("game")) hints.add("LUE* siniflari (UE4/UE5 Activity)");
    if (low.includes("com.unity3d")) hints.add("Unity paketleri (com.unity3d.*)");
    else if (low.includes("il2cpp")) hints.add("IL2CPP referanslari");
    else if (low.includes("godot")) hints.add("Godot referanslari");
    if (low.includes("com.google.android.gms")) hints.add("Google Play Services");
    if (low.includes("anti")) hints.add("'anti*' dizeleri (korumali build olasiligi)");
  }
  info.engineHints = [...hints].slice(0, 12);

  return info;
}
