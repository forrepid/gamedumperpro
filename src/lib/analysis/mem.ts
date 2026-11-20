// ----------------------------------------------------------------------------
// DumperPro Online - bellek dump modulu (LeechCore + MemProcFS esintili)
//
// Kapsam ve esinlenme:
//   - LeechCore (ufrisk) "file" cihazi: minidump/crashdump, raw dosya,
//     memmap.txt aralik esleme (LcMemMap_AddRange: pa, cb, paRemap mantigi).
//     Cihaz string semantigi: "dump://x.dmp", "raw://x.bin", "memmap://x.map".
//   - MemProcFS (ufrisk) VMM API kavramlari: modul haritasi
//     (VMMDLL_Map_GetModule), VAD/region haritasi (VMMDLL_Map_GetVad),
//     MemReadScatter, bellekten PE kurtarma (modul memdump'i) ve bellek arama.
//
// Neden bu sekilde: DMA/PMEM donanimsal cihazlar Linux sunucuda kullanilamaz;
// burada LEECHCORE'UN DOSYA-BASED CIHAZLARI ve MEMPROCFS'IN DUMP USTU
// OZELLIKLERI TS olarak port edildi. Ayni cihaz string semantigi korunur.
//
// Kaynak/teyit: research/leechcore (device_file.c, memmap.c),
// research/memprocfs (includes/vmmdll.h Map structs), Microsoft minidump spec.
//
// ONEMLI NOTLAR:
//   1) PE kurtarma "bellek gorunumlu" dump uretir (MemProcFS mdel stili):
//      bolum raw ofsetleri = VA ofsetleri; statik analiz hattimiz (RTTI/
//      fonksiyon/struct) bu dosyayi dogrudan parse eder.
//   2) Kernel crash dump (PAGE/DU64) yalnizca baslik + fiziksel aralik
//      tespiti icin cozulur; tam okuma icin memmap eslemesi gerekir.
//   3) Tum okumalar sinir kontrollu; arama penceresi 96 MB.
// ----------------------------------------------------------------------------

import type { MemInfo, MemRegion, MemModuleInfo } from "./types";

const MINIDUMP_MAGIC = 0x504d444d; // "MDMP"
const CRASH_MAGIC32 = 0x45474150; // "PAGE"
const CRASH_MAGIC64 = 0x34365544; // "DU64"

// ---------------------------------------------------------------------------
// cihaz soyutlamasi (LeechCore LcRead/LcMemMap mantigi)
// ---------------------------------------------------------------------------

export interface MemRange2 {
  vaStart: number;
  vaEnd: number;
  fileOff: number; // verinin dosya/dump icindeki offseti (remap dahil)
}

export interface MemDevice {
  device: string;
  totalBytes: number; // erisilebilir bellek toplami
  read(va: number, len: number): Buffer | null;
  readScatter(addrs: number[], len: number): (Buffer | null)[];
  write(va: number, data: Buffer): boolean;
  ranges(): MemRange2[];
  /** bir araligin ne kadarinin bellek icerigi kapsandigi (0..1) */
  coverage(vaStart: number, vaEnd: number): number;
}

function makeDevice(device: string, ranges: MemRange2[], backing: Buffer): MemDevice {
  const sorted = [...ranges].sort((a, b) => a.vaStart - b.vaStart);
  const total = sorted.reduce((s, r) => s + (r.vaEnd - r.vaStart), 0);
  return {
    device,
    totalBytes: total,
    read(va, len) {
      for (const r of sorted) {
        if (va >= r.vaStart && va < r.vaEnd) {
          const inRange = Math.min(len, r.vaEnd - va);
          const off = r.fileOff + (va - r.vaStart);
          if (off < 0 || off + inRange > backing.length) return null;
          return backing.subarray(off, off + inRange);
        }
      }
      return null;
    },
    readScatter(addrs, len) {
      return addrs.map((a) => this.read(a, len));
    },
    write(va, data) {
      for (const r of sorted) {
        if (va >= r.vaStart && va + data.length <= r.vaEnd) {
          const off = r.fileOff + (va - r.vaStart);
          if (off < 0 || off + data.length > backing.length) return false;
          data.copy(backing, off);
          return true;
        }
      }
      return false;
    },
    ranges() {
      return sorted;
    },
    coverage(vaStart, vaEnd) {
      let covered = 0;
      const total0 = Math.max(1, vaEnd - vaStart);
      for (const r of sorted) {
        const s = Math.max(vaStart, r.vaStart);
        const e = Math.min(vaEnd, r.vaEnd);
        if (e > s) covered += e - s;
      }
      return covered / total0;
    },
  };
}

// ---------------------------------------------------------------------------
// minidump parser (Microsoft spec)
// ---------------------------------------------------------------------------

const STREAM_TYPES: Record<number, string> = {
  0: "Unused", 3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception",
  7: "SystemInfo", 8: "ThreadExList", 9: "Memory64List", 10: "CommentA",
  11: "CommentW", 12: "HandleData", 13: "FunctionTable", 14: "UnloadedModuleList",
  15: "MiscInfo", 16: "MemoryInfoList", 17: "ThreadInfoList", 18: "HandleOperationList",
  19: "Token", 22: "SystemMemoryInfo", 23: "ProcessVmCounters", 24: "IptTrace",
};

const PROTECTION: Record<number, string> = {
  0x01: "--", 0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x10: "--x",
  0x20: "r-x", 0x40: "rwx", 0x80: "rwx",
};
const STATES: Record<number, string> = { 0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE" };
const MTYPES: Record<number, string> = { 0x20000: "MEM_PRIVATE", 0x40000: "MEM_MAPPED", 0x1000000: "MEM_IMAGE" };

interface MiniDumpData {
  device: MemDevice;
  arch: string;
  os?: string;
  modules: MemModuleInfo[];
  regions: MemRegion[];
  regionCount: number;
  memoryRangeCount: number;
  notes: string[];
  streamNames: string[];
  exception?: { code: string; address: string };
}

function readMiniDumpString(buf: Buffer, rva: number): string | null {
  if (rva <= 0 || rva + 4 > buf.length) return null;
  const len = buf.readUInt32LE(rva);
  if (len <= 0 || len > 8192 || rva + 4 + len > buf.length) return null;
  const raw = buf.subarray(rva + 4, rva + 4 + len);
  let s = "";
  for (let i = 0; i + 1 < raw.length; i += 2) s += String.fromCharCode(raw[i]);
  return s.replace(/\0+$/, "");
}

const WIN_ARCH: Record<number, string> = {
  0: "x86", 5: "ARM", 9: "x86_64", 12: "ARM64",
};

export function parseMiniDump(buf: Buffer): MiniDumpData | null {
  if (buf.length < 32) return null;
  if (buf.readUInt32LE(0) !== MINIDUMP_MAGIC) return null;
  const streamCount = buf.readUInt32LE(8);
  const dirRva = buf.readUInt32LE(12);
  if (streamCount > 256 || dirRva + streamCount * 12 > buf.length) return null;

  const notes: string[] = [];
  const streamNames: string[] = [];
  const ranges: MemRange2[] = [];
  const regions: MemRegion[] = [];
  const modules: MemModuleInfo[] = [];
  let arch = "bilinmiyor";
  let os: string | undefined;
  let regionCount = 0;
  let exception: MiniDumpData["exception"];

  for (let i = 0; i < streamCount; i++) {
    const rec = dirRva + i * 12;
    const type = buf.readUInt32LE(rec);
    const size = buf.readUInt32LE(rec + 4);
    const rva = buf.readUInt32LE(rec + 8);
    streamNames.push(STREAM_TYPES[type] ?? `0x${type.toString(16)}`);
    void size;

    if (type === 9 /* Memory64List */ && rva + 16 <= buf.length) {
      const nRanges = Number(buf.readBigUInt64LE(rva));
      let baseRva = Number(buf.readBigUInt64LE(rva + 8));
      let pos = rva + 16;
      for (let k = 0; k < Math.min(nRanges, 200_000); k++) {
        if (pos + 16 > buf.length) break;
        const start = Number(buf.readBigUInt64LE(pos));
        const dataSize = Number(buf.readBigUInt64LE(pos + 8));
        pos += 16;
        if (dataSize > 0 && baseRva + dataSize <= buf.length) {
          ranges.push({ vaStart: start, vaEnd: start + dataSize, fileOff: baseRva });
        }
        baseRva += dataSize;
      }
    } else if (type === 4 /* ModuleList */ && rva + 4 <= buf.length) {
      const nMods = buf.readUInt32LE(rva);
      for (let k = 0; k < Math.min(nMods, 512); k++) {
        const m = rva + 4 + k * 108;
        if (m + 108 > buf.length) break;
        const base = Number(buf.readBigUInt64LE(m));
        const sizeImg = buf.readUInt32LE(m + 8);
        const stamp = buf.readUInt32LE(m + 16);
        const nameRva = buf.readUInt32LE(m + 24);
        const name = readMiniDumpString(buf, nameRva) ?? `modul_${k}`;
        modules.push({
          name,
          base,
          size: sizeImg,
          timestamp: stamp > 0 ? new Date(stamp * 1000).toISOString().slice(0, 19) + "Z" : undefined,
          recoverable: false,
          recoveredRangePct: 0,
        });
      }
    } else if (type === 16 /* MemoryInfoList */ && rva + 16 <= buf.length) {
      const sizeOfHeader = buf.readUInt32LE(rva);
      const sizeOfEntry = buf.readUInt32LE(rva + 4);
      const nEntries = Number(buf.readBigUInt64LE(rva + 8));
      const eBase = rva + sizeOfHeader;
      for (let k = 0; k < Math.min(nEntries, 100_000); k++) {
        const e = eBase + k * sizeOfEntry;
        if (e + 48 > buf.length) break;
        const baseAddr = Number(buf.readBigUInt64LE(e));
        const regionSize = Number(buf.readBigUInt64LE(e + 16));
        const state = buf.readUInt32LE(e + 24);
        const prot = buf.readUInt32LE(e + 28);
        const mtype = buf.readUInt32LE(e + 32);
        regionCount++;
        if (regions.length < 400 && regionSize > 0) {
          regions.push({
            vaStart: baseAddr,
            vaEnd: baseAddr + regionSize,
            protection: PROTECTION[prot] ?? `0x${prot.toString(16)}`,
            state: STATES[state] ?? `0x${state.toString(16)}`,
            type: MTYPES[mtype] ?? `0x${mtype.toString(16)}`,
            file: "-",
          });
        }
      }
    } else if (type === 7 /* SystemInfo */ && rva + 56 <= buf.length) {
      const procArch = buf.readUInt16LE(rva);
      const major = buf.readUInt32LE(rva + 10);
      const minor = buf.readUInt32LE(rva + 14);
      const build = buf.readUInt32LE(rva + 18);
      const platform = buf.readUInt32LE(rva + 22);
      arch = WIN_ARCH[procArch] ?? `0x${procArch.toString(16)}`;
      if (major > 0 && platform === 2) os = `Windows ${major}.${minor} (build ${build})`;
    } else if (type === 6 /* Exception */ && rva + 32 <= buf.length) {
      const code = buf.readUInt32LE(rva + 8);
      const addr = Number(buf.readBigUInt64LE(rva + 24));
      exception = {
        code: `0x${code.toString(16).padStart(8, "0").toUpperCase()}`,
        address: `0x${addr.toString(16).toUpperCase()}`,
      };
    }
  }

  if (ranges.length === 0) {
    notes.push("Memory64List yok/okunamadi - bellek icerigi okunamaz (yalnizca metadata)");
    return {
      device: makeDevice("dump://minidump", [], buf),
      arch,
      os,
      modules,
      regions,
      regionCount,
      memoryRangeCount: 0,
      notes,
      streamNames,
      exception,
    };
  }
  notes.push(`Memory64List: ${ranges.length} aralik (MemoryList/64List)`);
  const device = makeDevice("dump://minidump", ranges, buf);
  return { device, arch, os, modules, regions, regionCount, memoryRangeCount: ranges.length, notes, streamNames, exception };
}

// ---------------------------------------------------------------------------
// kernel crash dump (PAGE/DU64) - baslik + fiziksel aralik tespiti
// ---------------------------------------------------------------------------

export function parseKernelCrashDump(buf: Buffer): MiniDumpData | null {
  if (buf.length < 0x1000) return null;
  if (buf.readUInt32LE(0) !== CRASH_MAGIC32 || buf.readUInt32LE(4) !== CRASH_MAGIC64) return null;
  const notes: string[] = [];
  const machine = buf.readUInt32LE(0x30);
  const major = buf.readUInt32LE(0x38);
  const minor = buf.readUInt32LE(0x3c);
  const dumpType = buf.readUInt32LE(0xf98);
  notes.push(`Kernel crash dump (64-bit): tip ${dumpType === 1 ? "FULL" : dumpType === 5 ? "BITMAP FULL" : dumpType === 6 ? "ACTIVE" : dumpType}`);
  notes.push("Tam bellek okuma icin memmap eslemesi gerekir (LeechCore file cihazi davranisi)");
  const runs: MemRange2[] = [];
  const nRuns = buf.readUInt32LE(0x88);
  if (nRuns > 0 && nRuns <= 0x80) {
    for (let i = 0; i < nRuns; i++) {
      const rec = 0xa0 + i * 16;
      if (rec + 16 > buf.length) break;
      const basePage = Number(buf.readBigUInt64LE(rec));
      const pageCount = Number(buf.readBigUInt64LE(rec + 8));
      notes.push(`fiziksel run #${i}: 0x${basePage.toString(16)} + ${pageCount} sayfa`);
      void basePage; void pageCount;
    }
  }
  return {
    device: makeDevice("crashdump://kernel", runs, buf),
    arch: machine === 0x8664 ? "x86_64" : machine === 0xaa64 ? "ARM64" : machine === 0x14c ? "x86" : `0x${machine.toString(16)}`,
    os: major > 0 ? `Windows ${major}.${minor}` : undefined,
    modules: [],
    regions: [],
    regionCount: 0,
    memoryRangeCount: runs.length,
    notes,
    streamNames: ["DUMP_HEADER"],
  };
}

// ---------------------------------------------------------------------------
// memmap.txt (LeechCore MemMap_AddRange / MemProcFS memmap stili)
// ---------------------------------------------------------------------------

export interface MemMapEntry {
  vaStart: number;
  vaEnd: number;
  remap: number; // veri offseti (0 = dogrudan)
  label?: string;
}

export function parseMemMapText(text: string): MemMapEntry[] {
  const out: MemMapEntry[] = [];
  for (const lineRaw of text.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line || line.startsWith("#")) continue;
    // formatlar: "a-b:label" | "a-b : label" | "a-b -> remap" | "a-b"
    const m = line.match(/^0?x?([0-9a-fA-F]+)\s*-\s*0?x?([0-9a-fA-F]+)\s*(?::\s*([^->]+?))?(?:\s*->\s*0?x?([0-9a-fA-F]+))?\s*$/);
    if (!m) continue;
    const start = parseInt(m[1], 16);
    const end = parseInt(m[2], 16);
    const remap = m[4] ? parseInt(m[4], 16) : start;
    if (!isFinite(start) || !isFinite(end) || end <= start) continue;
    out.push({ vaStart: start, vaEnd: end, remap, label: m[3]?.trim() || undefined });
  }
  return out;
}

export function openRawWithMemmap(raw: Buffer, memmapText: string): MemDevice | null {
  const entries = parseMemMapText(memmapText);
  if (entries.length === 0) return null;
  const ranges: MemRange2[] = [];
  for (const e of entries) {
    const size = e.vaEnd - e.vaStart;
    if (e.remap + size <= raw.length) {
      ranges.push({ vaStart: e.vaStart, vaEnd: e.vaEnd, fileOff: e.remap });
    }
  }
  if (ranges.length === 0) return null;
  return makeDevice("memmap://raw", ranges, raw);
}

// ---------------------------------------------------------------------------
// bellek arama (AOB; LeechCore/MemProcFS "find" esintili)
// ---------------------------------------------------------------------------

export interface MemSearchHit {
  va: number;
  hex: string;
}

export function searchMemory(
  device: MemDevice,
  pattern: (number | null)[],
  limit = 256,
  maxScanBytes = 96 * 1024 * 1024,
): MemSearchHit[] {
  const hits: MemSearchHit[] = [];
  let scanned = 0;
  const plen = pattern.length;
  const first = pattern.findIndex((p) => p !== null);
  if (first === -1 || plen === 0) return hits;
  for (const r of device.ranges()) {
    if (hits.length >= limit || scanned >= maxScanBytes) break;
    const size = r.vaEnd - r.vaStart;
    if (size <= 0) continue;
    const data = device.read(r.vaStart, Math.min(size, maxScanBytes - scanned));
    if (!data) continue;
    scanned += data.length;
    let idx = 0;
    while (idx <= data.length - plen && hits.length < limit) {
      // ilk sabit bayta hizli atlama
      const fb = pattern[first]!;
      idx = data.indexOf(fb, idx + (idx === 0 ? 0 : 1));
      if (idx === -1 || idx + plen > data.length) break;
      let ok = true;
      for (let k = 0; k < plen; k++) {
        const p = pattern[k];
        if (p === null) continue;
        if (data[idx + k] !== p) { ok = false; break; }
      }
      if (ok) {
        hits.push({
          va: r.vaStart + idx,
          hex: data.subarray(idx, idx + Math.min(plen, 32)).toString("hex"),
        });
      }
      idx += 1;
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// PE kurtarma (MemProcFS modul memdump mantigi)
// ---------------------------------------------------------------------------

export function recoverModulePe(device: MemDevice, base: number, size: number, notes: string[]): Buffer | null {
  if (size <= 0 || size > 64 * 1024 * 1024) {
    notes.push(`kurtarma iptal: boyut gecersiz/cok buyuk (${size})`);
    return null;
  }
  const cov = device.coverage(base, base + size);
  if (cov < 0.5) {
    notes.push(`kurtarma iptal: bellek kapsamasi %${Math.round(cov * 100)} (< %50)`);
    return null;
  }
  // DOS header
  const dos = device.read(base, 64);
  if (!dos || dos.readUInt16LE(0) !== 0x5a4d) {
    notes.push("kurtarma iptal: MZ imzasi yok (modul dump edilmis/sifreli olabilir)");
    return null;
  }
  const lfanew = dos.readUInt32LE(0x3c);
  if (lfanew <= 0 || lfanew > 0x400) {
    notes.push("kurtarma iptal: e_lfanew gecersiz");
    return null;
  }
  const nt = device.read(base + lfanew, 264);
  if (!nt || nt.readUInt32LE(0) !== 0x00004550) {
    notes.push("kurtarma iptal: PE imzasi yok");
    return null;
  }
  const machine = nt.readUInt16LE(4);
  const nSections = nt.readUInt16LE(6);
  const optSize = nt.readUInt16LE(20);
  const optOff = lfanew + 24;
  const opt = device.read(base + optOff, Math.max(64, Math.min(optSize, 240)));
  if (!opt) {
    notes.push("kurtarma iptal: optional header okunamadi");
    return null;
  }
  const magic = opt.readUInt16LE(0);
  const is64 = magic === 0x20b;
  const sizeOfImage = is64 ? opt.readUInt32LE(56) : opt.readUInt32LE(56);
  const sectTableOff = optOff + optSize;
  const sect = device.read(base + sectTableOff, nSections * 40);
  if (!sect || nSections <= 0 || nSections > 96) {
    notes.push("kurtarma iptal: bolum tablosu okunamadi");
    return null;
  }

  const outSize = Math.max(sizeOfImage, size);
  const out = Buffer.alloc(outSize);
  // headerlari kopyala
  const headers = device.read(base, Math.min(0x1000, outSize));
  if (headers) headers.copy(out, 0);

  let copied = 0;
  for (let i = 0; i < nSections; i++) {
    const rec = i * 40;
    const vSize = sect.readUInt32LE(rec + 8);
    const vAddr = sect.readUInt32LE(rec + 12);
    if (vAddr + vSize > outSize) continue;
    const mem = device.read(base + vAddr, vSize);
    if (mem) {
      mem.copy(out, vAddr);
      copied += vSize;
    }
    // bellek gorunumlu dump: raw pointer = virtualAddress, raw size = virtual size
    sect.writeUInt32LE(vAddr, rec + 20); // PointerToRawData
    sect.writeUInt32LE(vSize, rec + 16); // SizeOfRawData
    sect.copy(out, sectTableOff + rec); // tabloyu guncelle
  }
  // e_lfanew + NT headeri yeniden yaz (guncellenmis bolum tablosu ile)
  const ntBuf = device.read(base + lfanew, 24 + optSize + nSections * 40);
  if (ntBuf) ntBuf.copy(out, lfanew);
  // checksum sifirla
  const chkOff = optOff + (is64 ? 64 : 64);
  if (chkOff + 4 <= outSize) out.writeUInt32LE(0, chkOff);

  notes.push(
    `PE kurtarildi: ${nSections} bolum, ${copied} bayt bolum verisi, kapsama %${Math.round(cov * 100)}` +
      ` (machine 0x${machine.toString(16)}, ${is64 ? "PE32+" : "PE32"})`,
  );
  return out;
}

// ---------------------------------------------------------------------------
// analiz hatti girisi
// ---------------------------------------------------------------------------

export interface MemoryAnalysisOptions {
  /** raw + memmap eslemesi icin harita metni (yukleme eslesmesi) */
  memmapText?: string;
}

export function analyzeMemoryDump(
  buf: Buffer,
  fileName: string,
  opts: MemoryAnalysisOptions = {},
): { info: MemInfo; device: MemDevice; minidump?: MiniDumpData } | undefined {
  const notes: string[] = [];
  let md: MiniDumpData | null = null;
  let device: MemDevice | null = null;
  let deviceLabel = "";

  if (buf.readUInt32LE(0) === MINIDUMP_MAGIC) {
    md = parseMiniDump(buf);
    if (md) {
      device = md.device;
      deviceLabel = `minidump (${fileName})`;
      notes.push(...md.notes);
      if (md.exception) notes.push(`Exception: kod ${md.exception.code} @ ${md.exception.address}`);
    }
  } else if (buf.readUInt32LE(0) === CRASH_MAGIC32 && buf.readUInt32LE(4) === CRASH_MAGIC64) {
    md = parseKernelCrashDump(buf);
    if (md) {
      device = md.device;
      deviceLabel = `kernel crashdump (${fileName})`;
      notes.push(...md.notes);
    }
  } else if (opts.memmapText) {
    device = openRawWithMemmap(buf, opts.memmapText);
    if (device) {
      deviceLabel = `raw + memmap (${fileName})`;
      notes.push(`memmap: ${device.ranges().length} aralik eslesti (LeechCore memmap:// semantigi)`);
    } else {
      notes.push("memmap metni eslesmedi (araliklar dosya boyutunu asiyor)");
    }
  } else {
    notes.push("Raw dump icin memmap eslemesi gerekir; .memmap/.map dosyasini ayri yukleyin");
  }

  if (!device) return undefined;

  // modul kurtarilabilirlik kontrolu
  const modules = md?.modules ?? [];
  for (const m of modules) {
    const cov = device.coverage(m.base, m.base + m.size);
    m.recoveredRangePct = Math.round(cov * 100);
    m.recoverable = cov >= 0.5 && m.size > 0 && m.size <= 64 * 1024 * 1024;
  }
  if (modules.some((m) => m.recoverable)) {
    notes.push("Modul(lere) PE kurtarma uygulanabilir - panel'den 'Dump & Analiz' kullanin (RTTI/fonksiyon analizi otomatik calisir)");
  }

  const regions = md?.regions ?? [];
  const info: MemInfo = {
    device: deviceLabel,
    arch: md?.arch ?? "bilinmiyor",
    os: md?.os,
    moduleCount: modules.length,
    modules: modules.slice(0, 64),
    regionCount: md?.regionCount ?? device.ranges().length,
    regions,
    memoryRangeCount: device.ranges().length,
    totalMemoryBytes: device.totalBytes,
    notes,
  };
  return { info, device, minidump: md ?? undefined };
}

export function isMiniDump(buf: Buffer): boolean {
  return buf.length >= 32 && buf.readUInt32LE(0) === MINIDUMP_MAGIC;
}

export function isKernelCrashDump(buf: Buffer): boolean {
  return buf.length >= 0x1000 && buf.readUInt32LE(0) === CRASH_MAGIC32 && buf.readUInt32LE(4) === CRASH_MAGIC64;
}
