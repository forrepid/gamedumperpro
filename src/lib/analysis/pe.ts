// ----------------------------------------------------------------------------
// DumperPro Online - PE/COFF parser (sifir bagimlilik)
//
// Kaynak/teyit: Microsoft "PE Format" dokumani (winnt.h yapisalariyla ayni).
//  - IMAGE_DOS_HEADER (64 B), e_lfanew @0x3C
//  - IMAGE_NT_HEADERS: "PE\0\0" + IMAGE_FILE_HEADER (20 B) + OptionalHeader
//  - OptionalHeader magic: 0x20B = PE32+ (imageBase u64), 0x10B = PE32
//  - Section tablosu: 40 B/entry (IMAGE_SECTION_HEADER)
//  - Import: IMAGE_IMPORT_DESCRIPTOR (20 B), thunk 8 B (PE32+) / 4 B (PE32)
//  - Export: IMAGE_EXPORT_DIRECTORY (40 B)
//  - Debug: IMAGE_DEBUG_DIRECTORY (28 B), Type 2 = CODEVIEW (RSDS pdb yolu)
// ----------------------------------------------------------------------------

import type {
  PeInfo,
  PeSection,
  PeImport,
  PeExport,
  PeDataDirectory,
  PeDebugInfo,
  PeDebugEntry,
} from "./types";
import { entropy } from "./util";

const MACHINE: Record<number, string> = {
  0x8664: "AMD64 (x64)",
  0x14c: "i386 (x86)",
  0xaa64: "ARM64",
  0x1c4: "ARMv7 (32-bit)",
  0x1c0: "ARM",
  0x200: "IA-64",
  0x5064: "RISC-V 64",
  0xebc: "EFI Byte Code",
};

const SUBSYSTEM: Record<number, string> = {
  0: "UNKNOWN",
  1: "NATIVE (kernel)",
  2: "WINDOWS GUI",
  3: "WINDOWS CONSOLE",
  5: "OS/2 CUI",
  7: "POSIX CUI",
  8: "NATIVE Win9x",
  9: "WINDOWS CE GUI",
  10: "EFI Application",
  11: "EFI Boot Driver",
  12: "EFI Runtime Driver",
  13: "EFI ROM",
  14: "XBOX",
  16: "WINDOWS BOOT APPLICATION",
};

const CHARACTERISTICS: [number, string][] = [
  [0x0001, "RELOCS_STRIPPED"],
  [0x0002, "EXECUTABLE_IMAGE"],
  [0x0010, "AGGRESSIVE_WS_TRIM"],
  [0x0020, "LARGE_ADDRESS_AWARE"],
  [0x0100, "32BIT_MACHINE"],
  [0x0200, "DEBUG_STRIPPED"],
  [0x0400, "REMOVABLE_RUN_FROM_SWAP"],
  [0x0800, "NET_RUN_FROM_SWAP"],
  [0x1000, "SYSTEM"],
  [0x2000, "DLL"],
  [0x4000, "UP_SYSTEM_ONLY"],
  [0x8000, "BIG_ENDIAN"],
];

const DLL_CHARACTERISTICS: [number, string][] = [
  [0x0020, "HIGH_ENTROPY_VA"],
  [0x0040, "DYNAMIC_BASE (ASLR)"],
  [0x0080, "FORCE_INTEGRITY"],
  [0x0100, "NX_COMPAT (DEP)"],
  [0x0200, "NO_ISOLATION"],
  [0x0400, "NO_SEH"],
  [0x0800, "NO_BIND"],
  [0x1000, "APPCONTAINER"],
  [0x2000, "WDM_DRIVER"],
  [0x4000, "GUARD_CF (CFG)"],
  [0x8000, "TERMINAL_SERVER_AWARE"],
];

const DATA_DIR_NAMES = [
  "Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
  "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
  "IAT", "DelayImport", "COM Runtime", "Reserved",
];

export class PeParseError extends Error {}

export function parsePe(buf: Buffer, errors: string[]): PeInfo {
  if (buf.length < 0x40) throw new PeParseError("dosya PE basligi icin cok kucuk");
  const lfanew = buf.readUInt32LE(0x3c);
  if (lfanew <= 0 || lfanew + 26 > buf.length || buf.readUInt32LE(lfanew) !== 0x00004550) {
    throw new PeParseError("gecersiz PE imzasi");
  }

  // --- IMAGE_FILE_HEADER ---
  const coff = lfanew + 4;
  const machine = buf.readUInt16LE(coff);
  const numSections = buf.readUInt16LE(coff + 2);
  const timestamp = buf.readUInt32LE(coff + 4);
  const sizeOfOpt = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);

  // --- Optional header ---
  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  const is64 = magic === 0x20b;
  if (!is64 && magic !== 0x10b) {
    throw new PeParseError(`desteklenmeyen optional header magic: 0x${magic.toString(16)}`);
  }

  const entryPointRva = buf.readUInt32LE(opt + 16);
  let imageBase: number;
  let sizeOfImage: number;
  let sizeOfHeaders: number;
  let numberOfRvaAndSizes: number;
  if (is64) {
    imageBase = Number(buf.readBigUInt64LE(opt + 24));
    sizeOfImage = buf.readUInt32LE(opt + 56);
    sizeOfHeaders = buf.readUInt32LE(opt + 60);
    numberOfRvaAndSizes = buf.readUInt32LE(opt + 108);
  } else {
    imageBase = buf.readUInt32LE(opt + 28);
    sizeOfImage = buf.readUInt32LE(opt + 56);
    sizeOfHeaders = buf.readUInt32LE(opt + 60);
    numberOfRvaAndSizes = buf.readUInt32LE(opt + 92);
  }
  const dllChars = buf.readUInt16LE(opt + 70);
  const subsystem = buf.readUInt16LE(opt + 68);

  // --- Data directories ---
  const dirsOffset = opt + (is64 ? 112 : 96);
  const dataDirectories: PeDataDirectory[] = [];
  const dirCount = Math.min(16, numberOfRvaAndSizes);
  for (let i = 0; i < dirCount; i++) {
    const off = dirsOffset + i * 8;
    if (off + 8 > buf.length) break;
    const va = buf.readUInt32LE(off);
    const size = buf.readUInt32LE(off + 4);
    if (va !== 0 || size !== 0) dataDirectories.push({ name: DATA_DIR_NAMES[i] ?? `Dir${i}`, va, size });
  }

  // --- Sections ---
  const sections: PeSection[] = [];
  const secTable = opt + sizeOfOpt;
  for (let i = 0; i < Math.min(numSections, 96); i++) {
    const off = secTable + i * 40;
    if (off + 40 > buf.length) break;
    const name = buf.subarray(off, off + 8).toString("latin1").replace(/\0+$/, "");
    const virtualSize = buf.readUInt32LE(off + 8);
    const virtualAddress = buf.readUInt32LE(off + 12);
    const rawSize = buf.readUInt32LE(off + 16);
    const rawPointer = buf.readUInt32LE(off + 20);
    const flags = buf.readUInt32LE(off + 36);
    const fl: string[] = [];
    if (flags & 0x20000000) fl.push("x");
    if (flags & 0x40000000) fl.push("r");
    if (flags & 0x80000000) fl.push("w");
    if (flags & 0x20) fl.push("code");
    if (flags & 0x40) fl.push("data");
    if (flags & 0x02000000) fl.push("discardable");
    let ent = 0;
    if (rawSize > 0 && rawPointer + rawSize <= buf.length) {
      ent = entropy(buf.subarray(rawPointer, rawPointer + rawSize));
    }
    sections.push({ name, virtualSize, virtualAddress, rawSize, rawPointer, entropy: ent, flags: fl });
  }

  const rvaToOffset = (rva: number): number => {
    if (rva < sizeOfHeaders && rva < buf.length) return rva;
    for (const s of sections) {
      const span = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
        const off = rva - s.virtualAddress + s.rawPointer;
        return off < buf.length ? off : -1;
      }
    }
    return -1;
  };

  const readAscii = (off: number, max = 512): string => {
    if (off < 0 || off >= buf.length) return "";
    let end = off;
    while (end < buf.length && end - off < max && buf[end] !== 0) end++;
    return buf.subarray(off, end).toString("latin1");
  };

  // --- Imports ---
  const imports: PeImport[] = [];
  const importDir = dataDirectories.find((d) => d.name === "Import");
  if (importDir && importDir.size > 0) {
    const thunkSize = is64 ? 8 : 4;
    const descOff = rvaToOffset(importDir.va);
    if (descOff >= 0) {
      for (let i = 0; i < 128; i++) {
        const d = descOff + i * 20;
        if (d + 20 > buf.length) break;
        const oft = buf.readUInt32LE(d);
        const nameRva = buf.readUInt32LE(d + 12);
        const ft = buf.readUInt32LE(d + 16);
        if (oft === 0 && nameRva === 0 && ft === 0) break;
        const dllName = readAscii(rvaToOffset(nameRva), 256);
        if (!dllName) continue;
        const thunkRva = oft !== 0 ? oft : ft;
        const funcs: string[] = [];
        let count = 0;
        let tOff = rvaToOffset(thunkRva);
        if (tOff >= 0) {
          for (let j = 0; j < 8192; j++) {
            const t = tOff + j * thunkSize;
            if (t + thunkSize > buf.length) break;
            let val: bigint | number;
            let ordinal = false;
            if (is64) {
              val = buf.readBigUInt64LE(t);
              ordinal = (val & 0x8000000000000000n) !== 0n;
            } else {
              val = buf.readUInt32LE(t);
              ordinal = (val & 0x80000000) !== 0;
            }
            if (!ordinal && val === 0n) break;
            if (ordinal && val === 0) break;
            count++;
            if (funcs.length < 80) {
              if (ordinal) {
                funcs.push(`#${Number(val) & 0xffff} (ordinal)`);
              } else {
                const nameOff = rvaToOffset(Number(val));
                const n = readAscii(nameOff >= 0 ? nameOff + 2 : -1, 256);
                funcs.push(n || "?");
              }
            }
          }
        }
        imports.push({ dll: dllName, count, functions: funcs, truncated: count > 80 });
      }
    } else {
      errors.push("Import dizini RVA'si bolumlere eslenemedi");
    }
  }

  // --- Exports ---
  let exports: PeExport | null = null;
  const exportDir = dataDirectories.find((d) => d.name === "Export");
  if (exportDir && exportDir.size > 0) {
    const eOff = rvaToOffset(exportDir.va);
    if (eOff >= 0 && eOff + 40 <= buf.length) {
      const dllName = readAscii(rvaToOffset(buf.readUInt32LE(eOff + 12)), 256);
      const numberOfFunctions = buf.readUInt32LE(eOff + 20);
      const numberOfNames = buf.readUInt32LE(eOff + 24);
      const namesRva = buf.readUInt32LE(eOff + 32);
      const names: string[] = [];
      const nOff = rvaToOffset(namesRva);
      if (nOff >= 0) {
        for (let i = 0; i < Math.min(numberOfNames, 500); i++) {
          if (nOff + i * 4 + 4 > buf.length) break;
          const nameOff = rvaToOffset(buf.readUInt32LE(nOff + i * 4));
          const n = readAscii(nameOff, 512);
          if (n) names.push(n);
        }
      }
      exports = { dllName, count: numberOfFunctions, names, truncated: numberOfNames > 500 };
    }
  }

  // --- Debug (tam: PDB + GUID + tum kayit tipleri + COFF sembolleri) ---
  let debugPdb: string | undefined;
  let debug: PeDebugInfo | undefined;
  const dbgDir = dataDirectories.find((d) => d.name === "Debug");
  if (dbgDir && dbgDir.size >= 28) {
    const base = rvaToOffset(dbgDir.va);
    if (base >= 0) {
      const entries = Math.floor(dbgDir.size / 28);
      const dbgEntries: PeDebugEntry[] = [];
      let pdbGuid = "";
      let pdbAge = 0;
      let reproducible = false;
      for (let i = 0; i < Math.min(entries, 16); i++) {
        const off = base + i * 28;
        if (off + 28 > buf.length) break;
        const type = buf.readUInt32LE(off + 12);
        const size = buf.readUInt32LE(off + 16);
        const rva = buf.readUInt32LE(off + 20);
        const ptr = buf.readUInt32LE(off + 24);
        const typeNames: Record<number, string> = {
          1: "COFF", 2: "CODEVIEW", 4: "FPO", 5: "_MISC", 6: "EXCEPTION",
          7: "FIXUP", 8: "OMAP_TO_SRC", 9: "OMAP_FROM_SRC", 10: "BOCE",
          11: "XDATA", 12: "POGO", 13: "IPOCG", 14: "MPDC", 15: "SPGO",
          16: "REPRODUCIBLE", 17: "SPGO_PREPGCONFIRM", 18: "LINKOPTS",
          19: "PDBPATH", 20: "REPRO", 21: "SPGO_COMPILE", 22: "CTYPES",
        };
        const typeName = typeNames[type] ?? `T${type}`;
        let detail: string | undefined;
        if (type === 2 && size > 24 && ptr + size <= buf.length) {
          const sig = buf.subarray(ptr, ptr + 4).toString("latin1");
          if (sig === "RSDS") {
            pdbGuid = buf.subarray(ptr + 4, ptr + 20).toString("hex").toUpperCase();
            pdbAge = buf.readUInt32LE(ptr + 20);
            const pathOff = ptr + 24;
            let end = pathOff;
            while (end < ptr + size && buf[end] !== 0 && end - pathOff < 1024) end++;
            const p = buf.subarray(pathOff, end).toString("latin1");
            debugPdb = p;
            detail = p;
          } else {
            detail = `sig=${sig}`;
          }
        } else if (type === 12 && size > 16 && ptr + size <= buf.length) {
          // POGO: birincil Imzali METADATA
          detail = "PGO egitim verisi";
        } else if (type === 16) {
          reproducible = true;
          detail = "reproducible build";
        } else if ((type === 13 || type === 15) && size >= 16 && ptr + size <= buf.length) {
          const count = buf.readUInt32LE(ptr);
          detail = `${count} PGO girisi`;
        } else if (type === 22) {
          detail = "C/C++ tip metadata";
        }
        dbgEntries.push({ index: i, type: typeName, rawType: type, size, rva, detail });
      }
      // COFF sembol tablosu
      const ptrSymTab = buf.readUInt32LE(coff + 12);
      const numSyms = buf.readUInt32LE(coff + 8);
      const coffSamples: string[] = [];
      if (ptrSymTab > 0 && numSyms > 0 && ptrSymTab + numSyms * 18 <= buf.length) {
        const strTabOff = ptrSymTab + numSyms * 18;
        for (let i = 0; i < Math.min(numSyms, 40); i++) {
          const so = ptrSymTab + i * 18;
          const z1 = buf.readUInt32LE(so);
          const z2 = buf.readUInt32LE(so + 4);
          const secNum = buf.readInt16LE(so + 12);
          let name: string;
          if (z1 === 0 && z2 !== 0) {
            const strOff = strTabOff + z2;
            let e = strOff;
            while (e < buf.length && e - strOff < 64 && buf[e] !== 0) e++;
            name = buf.subarray(strOff, e).toString("latin1");
          } else {
            name = buf.subarray(so, so + 8).toString("latin1").replace(/\0+$/, "");
          }
          if (name) coffSamples.push(`${name} (sec ${secNum})`);
        }
      }
      debug = {
        pdb: debugPdb ? { path: debugPdb, guid: pdbGuid, age: pdbAge } : undefined,
        coffSymbols: numSyms,
        coffSymbolSamples: coffSamples,
        reproducible,
        entries: dbgEntries,
        guid: pdbGuid,
      };
    }
  }

  const chars = CHARACTERISTICS.filter(([bit]) => (characteristics & bit) !== 0).map(([, n]) => n);
  const dllFlags = DLL_CHARACTERISTICS.filter(([bit]) => (dllChars & bit) !== 0).map(([, n]) => n);

  return {
    format: is64 ? "PE32+" : "PE32",
    machine: MACHINE[machine] ?? `0x${machine.toString(16)}`,
    arch: machine === 0x8664 || machine === 0xaa64 ? "64-bit" : machine === 0x14c || machine === 0x1c4 ? "32-bit" : "bilinmiyor",
    timestamp,
    buildDate: timestamp > 0 ? new Date(timestamp * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "yok (reproducible build)",
    characteristics: chars,
    subsystem: SUBSYSTEM[subsystem] ?? `0x${subsystem.toString(16)}`,
    entryPointRva,
    imageBase,
    sizeOfImage,
    sizeOfHeaders,
    dllCharacteristics: dllFlags,
    sections,
    imports,
    importDllCount: imports.length,
    exports,
    dataDirectories,
    debugPdb,
    debug,
  };
}

/** section[.raw] verisini dondurur (imza taramasi icin). */
export function getSectionRaw(buf: Buffer, s: PeSection): Buffer | null {
  if (s.rawSize === 0 || s.rawPointer + s.rawSize > buf.length) return null;
  return buf.subarray(s.rawPointer, s.rawPointer + s.rawSize);
}
