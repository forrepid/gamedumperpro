// ----------------------------------------------------------------------------
// DumperPro Online - dosya tipi tespiti (magic bytes)
//
// Kaynak/teyit:
//  - PE/COFF: Microsoft "PE Format" spec (IMAGE_DOS_HEADER.e_magic = "MZ")
//  - ZIP/APK: APPNOTE.TXT PK\x03\x04; APK = ZIP + AndroidManifest.xml
//  - ELF:     TIS ELF spec, \x7fELF
//  - DEX:     Android DEX format, "dex\n" + versiyon ("035\0" ...)
// ----------------------------------------------------------------------------

import type { FileKind } from "./types";

export interface DetectedFile {
  kind: FileKind;
  detail: string;
}

export function detectFile(buf: Buffer, fileName: string): DetectedFile {
  // --- PE (MZ) ---
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    // e_lfanew dogrulamasi (sahte MZ'leri ele)
    if (buf.length >= 0x40) {
      const lfanew = buf.readUInt32LE(0x3c);
      if (lfanew > 0 && lfanew + 4 <= buf.length && buf[lfanew] === 0x50 && buf[lfanew + 1] === 0x45) {
        const machine = buf.length >= lfanew + 6 ? buf.readUInt16LE(lfanew + 4) : 0;
        const isDll = buf.length >= lfanew + 0x16 && (buf.readUInt16LE(lfanew + 0x16) & 0x2000) !== 0;
        const ext = fileName.toLowerCase().split(".").pop() ?? "";
        const label = isDll || ext === "dll" || ext === "sys" ? "PE DLL/driver" : "PE calistirilabilir";
        return { kind: "pe", detail: `${label} (machine=0x${machine.toString(16)})` };
      }
    }
    return { kind: "pe", detail: "PE benzeri (MZ imzasi, dogrulanamadi)" };
  }

  // --- ZIP temel ailesi (APK/ZIP) ---
  if (
    buf.length >= 4 &&
    ((buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) ||
      (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x05 && buf[3] === 0x06))
  ) {
    return { kind: "zip", detail: "ZIP konteyner (APK olasiligi - merkezi dizin okunacak)" };
  }

  // --- ELF ---
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { kind: "elf", detail: "ELF (Linux/Android paylasim kutuphanesi veya ikili)" };
  }

  // --- DEX ---
  if (buf.length >= 8 && buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a) {
    const ver = buf.subarray(4, 7).toString("latin1");
    return { kind: "dex", detail: `Dalvik/DEX bytecode (surum ${ver.trim()})` };
  }

  // --- Unity IL2CPP global-metadata.dat (sanity 0xFAB11BAF) ---
  if (buf.length >= 8 && buf.readUInt32LE(0) === 0xfab11baf) {
    const ver = buf.readInt32LE(4);
    if (ver >= 0 && ver <= 100) {
      return { kind: "metadata", detail: `Unity IL2CPP global-metadata.dat (metadata v${ver})` };
    }
  }

  // --- UE .pak (footer magic 0x5A6F12E1; son 1 KB taranir) ---
  if (buf.length >= 64) {
    const scanStart = Math.max(0, buf.length - 1024);
    for (let i = buf.length - 4; i >= scanStart; i--) {
      if (buf.readUInt32LE(i) === 0x5a6f12e1) {
        const ver = buf.readInt32LE(i + 4);
        return { kind: "pak", detail: `Unreal Engine .pak konteyneri (v${ver}, footer @0x${i.toString(16)})` };
      }
    }
  }

  // --- UE .utoc (IoStore TOC) ---
  if (buf.length >= 8 && buf.subarray(0, 4).toString("latin1") === "UTOC") {
    const ver = buf.readInt32LE(4);
    return { kind: "utoc", detail: `Unreal Engine IoStore .utoc (v${ver}) - .ucas veri konteynerini esler` };
  }

  // --- UE .uasset / .umap (PackageFileSummary magic 0x9E2A83C1) ---
  if (buf.length >= 8 && buf.readUInt32LE(0) === 0x9e2a83c1) {
    const isMap = fileName.toLowerCase().endsWith(".umap");
    return { kind: isMap ? "umap" : "uasset", detail: `Unreal Engine ${isMap ? "harita (.umap)" : "varlik (.uasset)"}` };
  }

  // --- Mach-O / fat (iOS ipa / macOS) ---
  if (buf.length >= 32) {
    const m = buf.readUInt32LE(0);
    if (m === 0xcefaedfe || m === 0xcffaedfe) {
      return { kind: "macho", detail: "Mach-O thin (iOS/macOS ikili)" };
    }
    if (m === 0xbebaface || m === 0xbebafacf) {
      return { kind: "macho", detail: `Mach-O fat (${buf.readUInt32BE(4)} mimari)` };
    }
  }

  // --- ART VDEX / OAT / CDEX (Android Runtime derlenmis konteynerler) ---
  if (buf.length >= 8) {
    const magic4 = buf.subarray(0, 4).toString("latin1");
    if (magic4 === "vdex") {
      const ver = buf.subarray(4, 8).toString("latin1").replace(/\0/g, "");
      return { kind: "vdex", detail: `ART VDEX v${ver} (gomulu DEX) - Android Runtime` };
    }
    if (magic4 === "art\n") {
      const ver = buf.subarray(4, 8).toString("latin1").replace(/\0/g, "");
      return { kind: "oat", detail: `ART OAT v${ver} (ELF konteyner + gomulu DEX)` };
    }
    if (magic4 === "cdex") {
      return { kind: "cdex", detail: "Compact DEX (ART cdex varyanti)" };
    }
  }

  // --- UE save game (GVAS / .sav; sifreli varyantlar zlib/ham olabilir) ---
  if (buf.length >= 4 && buf.subarray(0, 4).toString("latin1") === "GVAS") {
    const fv = buf.length >= 8 ? buf.readInt32LE(4) : 0;
    return { kind: "savegame", detail: `Unreal Engine save game (GVAS, fileVersion ${fv})` };
  }
  if (/\.sav$/i.test(fileName) && buf.length > 32) {
    const z = buf[0] === 0x78 && (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda);
    if (z) {
      return { kind: "savegame", detail: "Unreal Engine save game (.sav, zlib sikistirilmis - GVAS zlib sonrasi)" };
    }
    // duz/zlib degilse: sifreli (AES) olabilir - dosya adi guvenli tespit
    return { kind: "savegame", detail: "Save game (.sav) - GVAS imzasi gorunmuyor, sifreli olabilir (AES anahtari ile acilir)" };
  }

  // --- Steam VDF (metin veya ikili - shortcuts.vdf/localconfig.vdf) ---
  if (/\.vdf$/i.test(fileName) && buf.length > 4) {
    const first = buf[0]!;
    const binaryLike = first <= 0x07;
    const head = buf.subarray(0, Math.min(buf.length, 4096)).toString("latin1");
    const textLike = head.includes('"') && (head.includes("{") || head.includes("}"));
    if (binaryLike || textLike) {
      const label = binaryLike && !textLike ? "ikili (shortcuts/remotecache)" : "metin";
      return { kind: "vdf", detail: `Steam VDF (${label})` };
    }
  }

  // --- Minidump (MDMP) ---
  if (buf.length >= 32 && buf.readUInt32LE(0) === 0x504d444d) {
    return { kind: "minidump", detail: "Windows minidump (.dmp) - proses bellegi, moduller, VAD" };
  }

  // --- Kernel crash dump (PAGE + DU64) ---
  if (buf.length >= 0x1000 && buf.readUInt32LE(0) === 0x45474150 && buf.readUInt32LE(4) === 0x34365544) {
    return { kind: "minidump", detail: "Windows kernel crash dump (PAGE/DU64)" };
  }

  // --- memmap tanim dosyasi (LeechCore memmap.txt stili) ---
  if (/\.(memmap|map|txt)$/i.test(fileName) && buf.length < 1024 * 1024 && buf.length > 8) {
    const head = buf.subarray(0, Math.min(buf.length, 4096)).toString("latin1");
    const rangeRe = /^0?x?[0-9a-fA-F]+\s*-\s*0?x?[0-9a-fA-F]+/m;
    if (rangeRe.test(head)) {
      return { kind: "memmap", detail: "Bellek haritasi tanim dosyasi (LeechCore memmap.txt stili)" };
    }
  }

  return { kind: "unknown", detail: "Bilinmeyen format (magic eslesmedi)" };
}
