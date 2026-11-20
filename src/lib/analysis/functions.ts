// ----------------------------------------------------------------------------
// DumperPro Online - fonksiyon tablosu (x64 .pdata / x86 heuristik) + referans
// analizi
//
// Kaynak/teyit:
//  - x64: IMAGE_RUNTIME_FUNCTION (12 B: Begin, End, UnwindInfo) - Microsoft
//    "PE Format" Exception dizini; MSVC/MinGW x64 derleyicileri zoralimli
//    tablo uretir (kapsam = butun fonksiyonlar, kesin sinirlar).
//  - x86: .pdata yok -> fonksiyon giris kalibi (prologue) heuristigi.
//  - E8/E9 rel32 = cagri atlama; FF 15 = call [rip+disp32] (IAT);
//    48 8D xx = lea rip (string/veri referansi).
// ----------------------------------------------------------------------------

import type { PeSection, PeInfo, FunctionsInfo, FunctionEntry, PeExportEntry } from "./types";
import { getSectionRaw } from "./pe";

interface RawFn {
  start: number; // RVA
  end: number; // RVA
}

const PROLOGUES_X86: number[][] = [
  [0x55, 0x8b, 0xec], // push ebp; mov ebp,esp
  [0x8b, 0xff, 0x55, 0x8b, 0xec], // mov edi,edi; push ebp; ...
  [0x55, 0x89, 0xe5],
  // x64 (bellek dump'inda .pdata olmayan PE'ler icin; MemProcFS PE kurtarma hattı)
  [0x55, 0x48, 0x89, 0xe5], // push rbp; mov rbp,rsp
  [0x48, 0x89, 0x5c, 0x24], // mov [rsp+X],rbx (MSVC x64 hot prolog)
];

function sectionOf(sections: PeSection[], rva: number): PeSection | null {
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + span) return s;
  }
  return null;
}

/** .pdata tablosunu okur (x64). Dogrulama image genelinde yapilir. */
function parsePdata(buf: Buffer, pe: PeInfo): RawFn[] {
  const exc = pe.dataDirectories.find((d) => d.name === "Exception");
  if (!exc || exc.size === 0) return [];
  for (const s of pe.sections) {
    if (exc.va >= s.virtualAddress && exc.va < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
      const data = getSectionRaw(buf, s);
      if (!data) return [];
      const rel = exc.va - s.virtualAddress;
      const out: RawFn[] = [];
      const count = Math.min(Math.floor(exc.size / 12), 60000);
      for (let i = 0; i < count; i++) {
        const o = rel + i * 12;
        if (o + 12 > data.length) break;
        const start = data.readUInt32LE(o);
        const end = data.readUInt32LE(o + 4);
        // GIRISLER .text ICINDIR (bolum farkli olabilir) - image genelinde dogrula:
        // end > start, boyut makul (< 1 MB), image araliginda
        if (end > start && end - start < 0x100000 && end <= pe.sizeOfImage) {
          out.push({ start, end });
        }
      }
      // sirali ve cakismayan tablo beklenir
      out.sort((a, b) => a.start - b.start);
      return out;
    }
  }
  return [];
}

/** x86 icin prologue heuristigi. */
function heuristicX86(buf: Buffer, pe: PeInfo): RawFn[] {
  const text = pe.sections.find((s) => s.name === ".text");
  if (!text) return [];
  const data = getSectionRaw(buf, text);
  if (!data) return [];
  const starts: number[] = [];
  for (let i = 0; i < data.length - 8; i++) {
    for (const p of PROLOGUES_X86) {
      let ok = true;
      for (let j = 0; j < p.length; j++) {
        if (data[i + j] !== p[j]) { ok = false; break; }
      }
      if (ok) { starts.push(text.virtualAddress + i); break; }
    }
  }
  // tekil ve en az 8 bayt aralikli girisler
  const out: RawFn[] = [];
  let last = -100;
  for (const st of starts) {
    if (st - last < 8) continue;
    out.push({ start: st, end: st + 64 }); // sonraki girise kadar duzeltilir
    last = st;
  }
  for (let i = 0; i < out.length - 1; i++) {
    out[i].end = out[i + 1].start;
  }
  if (out.length) out[out.length - 1].end = out[out.length - 1].start + 256;
  return out;
}

function readLeaStringAt(buf: Buffer, off: number, max = 160): string | null {
  if (off < 0 || off >= buf.length) return null;
  let end = off;
  while (end < buf.length && end - off < max) {
    const b = buf[end];
    if (b === 0) break;
    if (b < 0x20 || b > 0x7e) return null;
    end++;
  }
  if (end - off < 4) return null;
  const s = buf.subarray(off, end).toString("latin1");
  // kod benzeri gurultuyu ele
  if (!/[a-zA-Z]/.test(s)) return null;
  if (/^[A-Za-z0-9_]+$/.test(s) && s.length < 8) return null;
  return s;
}

export function analyzeFunctions(buf: Buffer, pe: PeInfo, errors: string[]): FunctionsInfo | undefined {
  const is64 = pe.format === "PE32+";
  let raw = is64 ? parsePdata(buf, pe) : [];
  let source: "pdata" | "heuristic" = "pdata";
  if (raw.length === 0) {
    raw = heuristicX86(buf, pe);
    source = "heuristic";
  }
  if (raw.length === 0) {
    return { total: 0, source, is64, detailed: 0, disassembled: 0, functions: [], note: "Fonksiyon tablosu bulunamadi" };
  }

  // text bolumu + ham veri
  const text = pe.sections.find((s) => s.name === ".text");
  const textData = text ? getSectionRaw(buf, text) : null;

  // IAT haritasi: IAT slot VA -> "dll!fonksiyon"
  const iatMap = buildIatMap(buf, pe);

  // etiketler: exportlar + entry point
  const labelByRva = new Map<number, string>();
  if (pe.exports?.entries) {
    for (const e of pe.exports.entries) labelByRva.set(e.rva, e.name);
  }
  const ep = sectionOf(pe.sections, pe.entryPointRva);
  if (ep) {
    if (!labelByRva.has(pe.entryPointRva)) labelByRva.set(pe.entryPointRva, "EntryPoint");
  }

  // cagri grafi: hedef RVA -> gelen sayisi
  const xrefIn = new Map<number, number>();

  const detailedCap = Math.min(raw.length, 400);
  const out: FunctionEntry[] = [];
  let detailed = 0;

  for (let i = 0; i < raw.length; i++) {
    const f = raw[i];
    const size = f.end - f.start;
    const sec = sectionOf(pe.sections, f.start);
    const relStart = f.start - (sec ? sec.virtualAddress : 0) + (sec ? sec.rawPointer : 0);
    const first = relStart >= 0 && relStart + 12 <= buf.length
      ? buf.subarray(relStart, relStart + 12)
      : null;

    const entry: FunctionEntry = {
      idx: i,
      rva: f.start,
      va: pe.imageBase + f.start,
      size,
      section: sec ? sec.name : "?",
      prologue: first ? Array.from(first).map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ") : "-",
      strings: [],
      apiCalls: [],
      callsOut: 0,
      xrefsIn: xrefIn.get(f.start) ?? 0,
    };
    const lbl = labelByRva.get(f.start);
    if (lbl) entry.label = lbl;

    // referans analizi (ilk detailedCap fonksiyon, boyut < 64KB)
    if (i < detailedCap && size > 0 && size < 65536) {
      const off0 = relStart;
      const off1 = relStart + size;
      if (off0 >= 0 && off1 <= buf.length) {
        detailed++;
        for (let p = off0; p + 6 <= off1; p++) {
          const op = buf[p];
          // E8 rel32 (call) / E9 rel32 (jmp)
          if (op === 0xe8 || op === 0xe9) {
            const rel = buf.readInt32LE(p + 1);
            const targetRva = f.start + (p - off0) + 5 + rel;
            if (text && targetRva >= text.virtualAddress && targetRva < text.virtualAddress + text.virtualSize) {
              if (op === 0xe8) {
                entry.callsOut++;
                xrefIn.set(targetRva, (xrefIn.get(targetRva) ?? 0) + 1);
              }
            }
            p += 4;
            continue;
          }
          // FF 15 rel32 -> call [IAT]
          if (op === 0xff && buf[p + 1] === 0x15) {
            const rel = buf.readInt32LE(p + 2);
            const slotRva = f.start + (p - off0) + 6 + rel;
            const api = iatMap.get(slotRva);
            if (api && entry.apiCalls.length < 8) entry.apiCalls.push(api);
            p += 5;
            continue;
          }
          // 48/4C 8D /r -> lea r64, [rip+disp32]; ModRM = mod=00, rm=101
          if (
            (op === 0x48 || op === 0x4c) &&
            buf[p + 1] === 0x8d &&
            (buf[p + 2] & 0xc7) === 0x05
          ) {
            const rel = buf.readInt32LE(p + 3);
            const dataRva = f.start + (p - off0) + 7 + rel;
            const dsec = sectionOf(pe.sections, dataRva);
            if (dsec && dsec.name !== ".text") {
              const dOff = dataRva - dsec.virtualAddress + dsec.rawPointer;
              const s = readLeaStringAt(buf, dOff);
              if (s && entry.strings.length < 8) entry.strings.push(s);
            }
            p += 6;
            continue;
          }
        }
      }
    }

    out.push(entry);
  }

  const cap = Math.min(out.length, 500);
  const topBySize = [...out]
    .sort((a, b) => b.size - a.size)
    .slice(0, 12)
    .map((f) => ({ rva: f.rva, size: f.size, label: f.label }));

  return {
    total: out.length,
    source,
    is64,
    detailed,
    disassembled: 0, // attachDecompilation doldurur (index.ts)
    functions: out.slice(0, cap),
    topBySize,
    note:
      source === "pdata"
        ? `.pdata zorunluluk tablosundan ${out.length} fonksiyon (kesin sinirlar, MSVC x64 uretimi)`
        : "x86 modu: prologue heuristigi ile yaklasik fonksiyon sinirlari",
  };
}

/** IAT slot RVA -> "dll!func" haritasi (import thunk tablosundan). */
export function buildIatMap(buf: Buffer, pe: PeInfo): Map<number, string> {
  const map = new Map<number, string>();
  const readAscii = (off: number, max = 256): string => {
    if (off < 0 || off >= buf.length) return "";
    let end = off;
    while (end < buf.length && end - off < max && buf[end] !== 0) end++;
    return buf.subarray(off, end).toString("latin1");
  };
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
  const imp = pe.dataDirectories.find((d) => d.name === "Import");
  if (!imp || imp.size === 0) return map;
  const is64 = pe.format === "PE32+";
  const thunkSize = is64 ? 8 : 4;
  const descOff = rvaToOffset(imp.va);
  if (descOff < 0) return map;
  for (let i = 0; i < 128; i++) {
    const d = descOff + i * 20;
    if (d + 20 > buf.length) break;
    const oft = buf.readUInt32LE(d);
    const nameRva = buf.readUInt32LE(d + 12);
    const ft = buf.readUInt32LE(d + 16);
    if (oft === 0 && nameRva === 0 && ft === 0) break;
    const dllName = readAscii(rvaToOffset(nameRva)).toLowerCase();
    if (!dllName) continue;
    const thunkRva = oft !== 0 ? oft : ft;
    const tOff = rvaToOffset(thunkRva);
    if (tOff < 0) continue;
    for (let j = 0; j < 4096; j++) {
      const t = tOff + j * thunkSize;
      if (t + thunkSize > buf.length) break;
      let val: bigint;
      let ordinal = false;
      if (is64) {
        val = buf.readBigUInt64LE(t);
        ordinal = (val & 0x8000000000000000n) !== 0n;
      } else {
        val = BigInt(buf.readUInt32LE(t));
        ordinal = (val & 0x80000000n) !== 0n;
      }
      if (val === 0n) break;
      let fn: string;
      if (ordinal) {
        fn = `#${is64 ? Number(val & 0xffffn) : Number(val & 0xffffn)} (ordinal)`;
      } else {
        const nameOff = rvaToOffset(Number(val));
        fn = readAscii(nameOff >= 0 ? nameOff + 2 : -1) || "?";
      }
      // IAT slotu = FT thunk RVA (yuklenmis IAT adresleri)
      map.set(thunkRva + j * thunkSize, `${dllName}!${fn}`);
    }
  }
  return map;
}

/** Export girişlerini RVA tablosuyla zenginleştirir (pe.ts sonrasi). */
export function collectExportEntries(buf: Buffer, pe: PeInfo): PeExportEntry[] {
  const out: PeExportEntry[] = [];
  if (!pe.exports) return out;
  const exp = pe.dataDirectories.find((d) => d.name === "Export");
  if (!exp || exp.size === 0) return out;
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
  const readAscii = (off: number, max = 256): string => {
    if (off < 0 || off >= buf.length) return "";
    let end = off;
    while (end < buf.length && end - off < max && buf[end] !== 0) end++;
    return buf.subarray(off, end).toString("latin1");
  };
  const eOff = rvaToOffset(exp.va);
  if (eOff < 0) return out;
  const numberOfFunctions = buf.readUInt32LE(eOff + 20);
  const numberOfNames = buf.readUInt32LE(eOff + 24);
  const addrRva = buf.readUInt32LE(eOff + 28);
  const namesRva = buf.readUInt32LE(eOff + 32);
  const ordRva = buf.readUInt32LE(eOff + 36);
  const aOff = rvaToOffset(addrRva);
  const nOff = rvaToOffset(namesRva);
  const oOff = rvaToOffset(ordRva);
  if (aOff < 0) return out;
  for (let i = 0; i < Math.min(numberOfFunctions, 500); i++) {
    if (aOff + i * 4 + 4 > buf.length) break;
    const fnRva = buf.readUInt32LE(aOff + i * 4);
    let name = "";
    if (nOff >= 0 && i < numberOfNames && oOff >= 0) {
      const nameIdx = buf.readUInt16LE(oOff + i * 2);
      const nameRva = buf.readUInt32LE(nOff + nameIdx * 4);
      name = readAscii(rvaToOffset(nameRva));
    }
    out.push({ name: name || `#${i + 1}`, ordinal: i + 1, rva: fnRva, va: pe.imageBase + fnRva });
  }
  return out;
}
