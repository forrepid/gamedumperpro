// ----------------------------------------------------------------------------
// DumperPro Online - IL2CPP binary taraf analizi (GameAssembly.dll / libil2cpp.so)
//
// Il2CppDumper (Perfare) Il2Cpp.cs + SectionHelper.cs algoritmasinin portudur:
//   1) Veri bolumlerinde "mscorlib.dll\0" string VA'si bulunur.
//   2) Bu VA'yi deger olarak tutan QWORD'ler = Il2CppCodeGenModule baslari
//      (moduleName ilk alan oldugu icin struct adresi = string referansi).
//   3) Module adreslerini deger olarak tutan QWORD'ler = codeGenModules
//      dizisinin eleman slotlari; slot - i*ps dizinin TABANIDIR (i tarama
//      ile bulunur), tabani deger olarak tutan QWORD = CodeRegistration
//      icindeki codeGenModules alani, onundeki QWORD = codeGenModulesCount
//      (== imageCount) dogrulanir.
//   4) CodeRegistration tabani: codeGenModules alanindan geriye dogru
//      {count, ptr} ciftleri gezilir (oz-dogrulamali; Il2CppDumper'in sabit
//      alan aritmetigi yerine guvenli yuruyus kullanilir).
//   5) MetadataRegistration: Il2CppDumper "V21" deseninin portudur:
//      data'da [x]==typeDefCount ve [x+2ps]==typeDefCount ve [x+3ps] gecerli
//      bir data isaretcisi -> x = fieldOffsetsCount, x+2ps =
//      typeDefinitionsSizesCount, base = x - 10ps.
//
// Kaynak/teyit:
//   - research/il2cppdumper/.../Il2Cpp/Il2CppClass.cs  (struct layoutlari)
//   - research/il2cppdumper/.../Utils/SectionHelper.cs (FindCodeRegistration2019,
//     FindMetadataRegistrationV21, CheckPointerRange*)
//   - Il2CppCodeGenModule alan sayilari surume gore (v24.2..v31) tablodadir.
//
// ONEMLI NOTLAR:
//   1) Surum belirlemesi metadata tarafindan gelir (metadata v27 <=> il2cpp v27).
//      Metadata bagli degilse modul parser'i 27 varsayar + dogrulama notu ekler.
//   2) 32-bit (PE32/ELF32) de desteklenir (ps=4); arrasta fieldOffsets u32
//      isaretcileri denenir.
//   3) Tum okumalar sinir kontrolludur; bulgular dogrulanmadan rapor edilmez.
// ----------------------------------------------------------------------------

import type { AnalysisResult, Il2CppBinaryInfo, PeInfo } from "./types";
import type { Il2CppCore } from "./metadata";
import { parseIl2CppMetadataCore } from "./metadata";
import { getSectionRaw } from "./pe";

// ---------------------------------------------------------------------------
// bolum haritasi (LeechCore "memmap" mantiginda VA <-> file offset)
// ---------------------------------------------------------------------------

interface MemRange {
  offStart: number;
  offEnd: number; // dosya ici bitis (raw veri)
  vaStart: number;
  vaEnd: number; // VA (PE: imageBase+rva; ELF: p_vaddr)
  exec: boolean;
  name: string;
}

interface SectionMap {
  pointerSize: number;
  imageBase: number;
  ranges: MemRange[];
  execRanges: MemRange[];
  dataRanges: MemRange[];
  isPe: boolean;
}

function buildPeMap(buf: Buffer, pe: PeInfo): SectionMap {
  const ranges: MemRange[] = [];
  for (const s of pe.sections) {
    const raw = getSectionRaw(buf, s);
    if (!raw || s.rawSize === 0) continue;
    ranges.push({
      offStart: s.rawPointer,
      offEnd: s.rawPointer + Math.min(s.rawSize, buf.length - s.rawPointer),
      vaStart: pe.imageBase + s.virtualAddress,
      vaEnd: pe.imageBase + s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
      exec: s.flags.includes("x"),
      name: s.name,
    });
  }
  return {
    pointerSize: pe.format === "PE32+" ? 8 : 4,
    imageBase: pe.imageBase,
    ranges,
    execRanges: ranges.filter((r) => r.exec),
    dataRanges: ranges.filter((r) => !r.exec),
    isPe: true,
  };
}

function buildElfMap(buf: Buffer): SectionMap {
  // program header tablosu (Android .so'da section header'lar kopuk olabilir)
  const is64 = buf[4] === 2;
  const ps = is64 ? 8 : 4;
  const phOff = is64 ? Number(buf.readBigUInt64LE(0x20)) : buf.readUInt32LE(0x1c);
  const phEnt = buf.readUInt16LE(is64 ? 0x36 : 0x2a);
  const phNum = buf.readUInt16LE(is64 ? 0x38 : 0x2c);
  const ranges: MemRange[] = [];
  for (let i = 0; i < Math.min(phNum, 32); i++) {
    const rec = phOff + i * phEnt;
    if (rec + (is64 ? 56 : 32) > buf.length) break;
    const pType = buf.readUInt32LE(rec);
    if (pType !== 1 /* PT_LOAD */) continue;
    let pFlags = 0;
    let pOffset: number, pFilesz: number, pVaddr: number, pMemsz: number;
    if (is64) {
      pFlags = buf.readUInt32LE(rec + 4);
      pOffset = Number(buf.readBigUInt64LE(rec + 8));
      pVaddr = Number(buf.readBigUInt64LE(rec + 16));
      pFilesz = Number(buf.readBigUInt64LE(rec + 32));
      pMemsz = Number(buf.readBigUInt64LE(rec + 40));
    } else {
      pOffset = buf.readUInt32LE(rec + 4);
      pVaddr = buf.readUInt32LE(rec + 8);
      pFilesz = buf.readUInt32LE(rec + 16);
      pMemsz = buf.readUInt32LE(rec + 20);
      pFlags = buf.readUInt32LE(rec + 24);
    }
    if (pFilesz <= 0) continue;
    ranges.push({
      offStart: pOffset,
      offEnd: pOffset + Math.min(pFilesz, Math.max(0, buf.length - pOffset)),
      vaStart: pVaddr,
      vaEnd: pVaddr + pMemsz,
      exec: (pFlags & 1) !== 0,
      name: `PT_LOAD#${i}`,
    });
  }
  return {
    pointerSize: ps,
    imageBase: 0,
    ranges,
    execRanges: ranges.filter((r) => r.exec),
    dataRanges: ranges.filter((r) => !r.exec),
    isPe: false,
  };
}

function vaToOff(map: SectionMap, va: number): number | null {
  for (const r of map.ranges) {
    if (va >= r.vaStart && va < r.vaEnd) {
      const off = va - r.vaStart + r.offStart;
      if (off >= r.offStart && off < r.offEnd) return off;
      return null;
    }
  }
  return null;
}

function offToVa(map: SectionMap, off: number): number | null {
  for (const r of map.ranges) {
    if (off >= r.offStart && off < r.offEnd) return off - r.offStart + r.vaStart;
  }
  return null;
}

function inRanges(rs: MemRange[], va: number): boolean {
  for (const r of rs) if (va >= r.vaStart && va < r.vaEnd) return true;
  return false;
}

function readCstr(buf: Buffer, off: number, cap = 260): string | null {
  if (off < 0 || off >= buf.length) return null;
  const max = Math.min(buf.length - off, cap);
  let end = 0;
  while (end < max && buf[off + end] !== 0) end++;
  if (end === 0 || end >= max) return end > 0 ? buf.subarray(off, off + end).toString("latin1") : null;
  const s = buf.subarray(off, off + end).toString("latin1");
  return /^[\x20-\x7e]+$/.test(s) ? s : null;
}

// ---------------------------------------------------------------------------
// tarama motorlari
// ---------------------------------------------------------------------------

/** data bolumlerinde tek ge cisle hedef VA'leri deger olarak tutsan konumlari bulur. */
function findPtrRefs(map: SectionMap, buf: Buffer, targets: Set<number>): Map<number, number[]> {
  const out = new Map<number, number[]>();
  if (targets.size === 0) return out;
  const ps = map.pointerSize;
  for (const r of map.dataRanges) {
    const end = Math.min(r.offEnd, buf.length - ps);
    for (let off = r.offStart; off < end; off += ps) {
      const va = ps === 8 ? Number(buf.readBigUInt64LE(off)) : buf.readUInt32LE(off);
      if (targets.has(va)) {
        const targetVa = offToVa(map, off);
        if (targetVa === null) continue;
        const arr = out.get(va);
        if (arr) arr.push(targetVa);
        else out.set(va, [targetVa]);
      }
    }
  }
  return out;
}

/** data bolumlerinde needle arar (file offsetleri doner). */
function findNeedles(map: SectionMap, buf: Buffer, needle: Buffer, cap = 256): number[] {
  const out: number[] = [];
  for (const r of map.dataRanges) {
    let idx = buf.indexOf(needle, r.offStart);
    while (idx !== -1 && idx < r.offEnd && out.length < cap) {
      out.push(idx);
      idx = buf.indexOf(needle, idx + 1);
    }
    if (out.length >= cap) break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Il2CppCodeGenModule (surume gore alan sayisi; Il2CppClass.cs kaynakli)
// ---------------------------------------------------------------------------

const CODEGEN_MODULE_FIELDS = (ver: number): number => {
  // Il2CppCodeGenModule alan sayisi (Il2CppClass.cs):
  //   v24.2-24.4: moduleName,cnt,mptr,invokerIdx,revCnt,revIdx,rgctxR*,rgctxS*,debuggerMeta = 11
  //   v24.5:      + adjustorThunkCount/adjustorThunks = 13
  //   v27-27.2:   + customAttributeCacheGenerator, moduleInitializer,
  //                 staticConstructorTypeIndices, metadataRegistration, codeRegistaration = 16
  //   v28+:       customAttributeCacheGenerator kalkar = 15
  if (ver >= 28) return 15;
  if (ver >= 27) return 16;
  if (ver === 24.5) return 13;
  return 11;
};

interface CodeGenModule {
  name: string;
  nameOff: number;
  methodPointerCount: number;
  pointersOff: number; // methodPointers dizisinin dosya offseti
  pointersVa: number;
  structOff: number;
}

function parseCodeGenModules(
  map: SectionMap,
  buf: Buffer,
  arrayBaseVa: number,
  count: number,
  ver: number,
): CodeGenModule[] | null {
  const ps = map.pointerSize;
  const modules: CodeGenModule[] = [];
  for (let i = 0; i < Math.min(count, 4096); i++) {
    // dizi slotu bir ISARETCI tutar; once dereference et
    const slotOff = vaToOff(map, arrayBaseVa + i * ps);
    if (slotOff === null) return null;
    const structPtr = readPtrAt(map, buf, slotOff);
    if (structPtr === null || structPtr === 0) return null;
    const structOff = vaToOff(map, structPtr);
    if (structOff === null) return null;
    // Il2CppCodeGenModule: moduleName ptr, methodPointerCount (i64/i32), methodPointers ptr
    let namePtr: number, cnt: number, pointersPtr: number;
    if (ps === 8) {
      namePtr = Number(buf.readBigUInt64LE(structOff));
      const cLo = buf.readInt32LE(structOff + 8);
      const cHi = buf.readInt32LE(structOff + 12);
      if (cHi !== 0 && cHi !== -1) return null;
      cnt = cLo;
      pointersPtr = Number(buf.readBigUInt64LE(structOff + 16));
    } else {
      namePtr = buf.readUInt32LE(structOff);
      cnt = buf.readInt32LE(structOff + 4);
      pointersPtr = buf.readUInt32LE(structOff + 8);
    }
    if (cnt < 0 || cnt > 600_000) return null;
    const nameOff = vaToOff(map, namePtr);
    const name = nameOff !== null ? readCstr(buf, nameOff) : null;
    if (!name || !/\.(dll|so|a)$/.test(name)) return null;
    const pointersOff = vaToOff(map, pointersPtr);
    if (pointersOff === null && cnt > 0) return null;
    modules.push({
      name,
      nameOff: nameOff ?? -1,
      methodPointerCount: cnt,
      pointersOff: pointersOff ?? -1,
      pointersVa: pointersPtr,
      structOff,
    });
  }
  return modules;
}

function readPtrAt(map: SectionMap, buf: Buffer, off: number): number | null {
  const ps = map.pointerSize;
  if (off < 0 || off + ps > buf.length) return null;
  if (ps === 8) {
    const v = Number(buf.readBigUInt64LE(off));
    return v > 0xffffffffffff ? null : v;
  }
  return buf.readUInt32LE(off);
}

/** CodeRegistration tabani: {count, ptr} ciftleriyle geriye oz-dogrulamali yuruyus. */
function walkBackCodeRegistration(
  map: SectionMap,
  buf: Buffer,
  codeGenModulesFieldVa: number,
): { baseVa: number; pairs: number } | null {
  const ps = map.pointerSize;
  const fieldOff = vaToOff(map, codeGenModulesFieldVa);
  if (fieldOff === null) return null;
  // Struct son alan cifti: {count@F-ps, ptr@F}. Onceki ciftler 2ps adimla geride.
  // k=0 -> codeGenModulesCount/ptr; k=1 -> windowsRuntimeFactory; ...
  let pairs = 0;
  let baseVa = codeGenModulesFieldVa;
  for (let k = 0; k < 14; k++) {
    const cntVa = codeGenModulesFieldVa - ps * (2 * k + 1);
    const ptrVa = codeGenModulesFieldVa - ps * (2 * k);
    const cntOff = vaToOff(map, cntVa);
    const ptrOff = vaToOff(map, ptrVa);
    if (cntOff === null || ptrOff === null) break;
    const cnt = buf.readInt32LE(cntOff);
    const hi = ps === 8 ? buf.readInt32LE(cntOff + 4) : 0;
    if (ps === 8 && hi !== 0 && hi !== -1) break;
    const ptr = readPtrAt(map, buf, ptrOff);
    if (cnt < 0 || cnt > 0x50000) break;
    if (ptr === null || (ptr !== 0 && !inRanges(map.dataRanges, ptr))) break;
    pairs = k + 1;
    baseVa = cntVa;
  }
  if (pairs < 3) return null; // en az reversePInvoke+genericMethod+invoker ciftleri
  return { baseVa, pairs };
}

// ---------------------------------------------------------------------------
// ana giris
// ---------------------------------------------------------------------------

export interface Il2CppLinkOptions {
  /** bagli global-metadata.dat cekirdegi (yukleme rotasi eslestirirse) */
  metadata?: Il2CppCore;
  /** tespit ipuclari icin dosya adi (GameAssembly.dll / libil2cpp.so) */
  fileName?: string;
}

export interface Il2CppBinaryAnalysis {
  info: Il2CppBinaryInfo;
  /** bagli metadata ile uretilen dump.cs (Il2CppDumper stili) */
  dumpCs: string | null;
  /** bagli metadata ile uretilen script.json (Il2CppDumper benzeri) */
  scriptJson: string | null;
}

const IL2_METHOD_CAP = 60_000; // dump.cs metod satiri butcesi
const IL2_CLASS_CAP = 3000;

function findUnityVersion(buf: Buffer): string | undefined {
  const re = /20(1[5-9]|2[0-9]|3[0-9])\.\d{1,2}\.\d{1,2}[fpba]\d+/g;
  const counts = new Map<string, number>();
  const text = buf.subarray(0, Math.min(buf.length, 96 * 1024 * 1024)).toString("latin1");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    counts.set(m[0], (counts.get(m[0]) ?? 0) + 1);
    if (counts.size > 40) break;
  }
  let best: string | undefined;
  let bestN = 0;
  for (const [k, n] of counts) if (n > bestN) { best = k; bestN = n; }
  return best;
}

export function looksLikeIl2CppBinary(buf: Buffer, fileName: string, pe?: PeInfo): boolean {
  const low = fileName.toLowerCase();
  if (low.includes("gameassembly") || low.includes("libil2cpp")) return true;
  if (pe?.exports?.names.some((n) => n.startsWith("il2cpp_"))) return true;
  if (buf.indexOf(Buffer.from("global-metadata.dat", "latin1")) !== -1 &&
      buf.indexOf(Buffer.from("mscorlib.dll", "latin1")) !== -1) return true;
  return false;
}

export function analyzeIl2CppBinary(
  buf: Buffer,
  kind: "pe" | "elf",
  pe: PeInfo | undefined,
  opts: Il2CppLinkOptions = {},
): Il2CppBinaryAnalysis {
  const notes: string[] = [];
  const info: Il2CppBinaryInfo = {
    detected: false,
    reason: "",
    pointerSize: 8,
    methodPointersResolved: 0,
    linked: !!opts.metadata,
    notes,
  };

  const hinted = looksLikeIl2CppBinary(buf, opts.fileName ?? "", pe);
  if (!hinted && kind !== "elf") {
    info.reason = "IL2CPP ipucu bulunamadi (il2cpp export / GameAssembly / mscorlib.dll)";
    return { info, dumpCs: null, scriptJson: null };
  }
  info.detected = true;
  info.reason = pe?.exports?.names.some((n) => n.startsWith("il2cpp_"))
    ? `il2cpp_* exportlari bulundu (${pe.exports.count} export)`
    : hinted
      ? "dosya adi / buffer ipuclari (GameAssembly, mscorlib.dll + global-metadata.dat)"
      : "mscorlib.dll referanslari (ELF)";
  info.unityVersion = findUnityVersion(buf);

  let map: SectionMap;
  try {
    map = kind === "pe" && pe ? buildPeMap(buf, pe) : buildElfMap(buf);
  } catch (e) {
    info.reason = `bolum haritasi kurulamadi: ${e instanceof Error ? e.message : String(e)}`;
    return { info, dumpCs: null, scriptJson: null };
  }
  info.pointerSize = map.pointerSize;
  if (map.dataRanges.length === 0 || map.execRanges.length === 0) {
    info.reason = "bolum haritasi bos (veri/kod araligi yok)";
    return { info, dumpCs: null, scriptJson: null };
  }

  const ps = map.pointerSize;
  const ver = opts.metadata ? (opts.metadata.effVersion >= 24.2 ? opts.metadata.effVersion : 24.2) : 27;

  // --- 1) mscorlib.dll stringleri ---
  const strOffs = findNeedles(map, buf, Buffer.from("mscorlib.dll\0", "latin1"));
  if (strOffs.length === 0) {
    info.reason = "mscorlib.dll referansi bulunamadi (obfuscate/sansurlu build olabilir)";
    return { info, dumpCs: null, scriptJson: null };
  }
  const strVas = new Set<number>();
  for (const off of strOffs) {
    const va = offToVa(map, off);
    if (va !== null) strVas.add(va);
  }
  notes.push(`mscorlib.dll string: ${strOffs.length} konum (VA: ${[...strVas].slice(0, 3).map((v) => "0x" + v.toString(16)).join(", ")})`);

  // --- 2) module struct baslari (moduleName ptr -> string VA) ---
  const modStarts = findPtrRefs(map, buf, strVas);
  const modStartVas = new Set<number>();
  for (const arr of modStarts.values()) for (const va of arr) modStartVas.add(va);
  if (modStartVas.size === 0) {
    info.reason = "mscorlib.dll VA'sini tasiyan QWORD bulunamadi (CodeGenModule yok)";
    return { info, dumpCs: null, scriptJson: null };
  }
  notes.push(`CodeGenModule adayi: ${modStartVas.size} konum`);

  // --- 3) dizi slotlari (module adreslerini tasiyan QWORD'ler) ---
  const slots = findPtrRefs(map, buf, modStartVas);
  const slotVas = new Set<number>();
  for (const arr of slots.values()) for (const va of arr) slotVas.add(va);
  notes.push(`dizi slotu adayi: ${slotVas.size} konum`);

  // --- 4) codeGenModules dizisi tabani + count dogrulamasi ---
  const imageCountHint = opts.metadata?.images.length ?? 0;
  const bound = imageCountHint > 0 ? Math.min(imageCountHint, 4096) : 64;
  const targets = new Set<number>();
  for (const s of slotVas) {
    for (let i = 0; i < bound; i++) targets.add(s - i * ps);
  }
  const fieldRefs = findPtrRefs(map, buf, targets);
  let codeGenFieldVa: number | null = null;
  let arrayBaseVa = 0;
  let moduleCount = 0;
  outer: for (const [targetVa, positions] of fieldRefs) {
    for (const posVa of positions) {
      const cntOff = vaToOff(map, posVa - ps);
      if (cntOff === null) continue;
      const cnt = map.pointerSize === 8 ? buf.readInt32LE(cntOff) : buf.readInt32LE(cntOff);
      const hi = map.pointerSize === 8 ? buf.readInt32LE(cntOff + 4) : 0;
      if (map.pointerSize === 8 && hi !== 0 && hi !== -1) continue;
      if (cnt <= 0 || cnt > 4096) continue;
      if (imageCountHint > 0 && cnt !== imageCountHint && cnt !== imageCountHint - 1) continue;
      const parsed = parseCodeGenModules(map, buf, targetVa, cnt, ver);
      if (!parsed || parsed.length === 0) continue;
      codeGenFieldVa = posVa;
      arrayBaseVa = targetVa;
      moduleCount = cnt;
      break outer;
    }
  }
  if (codeGenFieldVa === null) {
    info.reason = "codeGenModules dizisi dogrulanamadi (count == imageCount eslesmedi)";
    return { info, dumpCs: null, scriptJson: null };
  }
  const parsedModules = parseCodeGenModules(map, buf, arrayBaseVa, moduleCount, ver)!;
  notes.push(`codeGenModules: ${moduleCount} modul (dizi VA 0x${arrayBaseVa.toString(16)})`);

  // --- 5) CodeRegistration tabani ---
  const cr = walkBackCodeRegistration(map, buf, codeGenFieldVa);
  const base = map.imageBase;
  if (cr) {
    info.codeRegistration = {
      rva: cr.baseVa - base,
      va: cr.baseVa,
      fieldNote: `${cr.pairs} {count,ptr} cifti dogrulandi (geriye yuruyus)`,
    };
    notes.push(`CodeRegistration @ 0x${(cr.baseVa - base).toString(16)} RVA`);
  }
  const fieldRva = codeGenFieldVa - base;
  info.codeGenModules = {
    count: moduleCount,
    rva: fieldRva,
    va: codeGenFieldVa,
    modules: parsedModules.slice(0, 128).map((m) => ({
      name: m.name,
      methodCount: m.methodPointerCount,
      resolved: 0,
      pointersRva: m.pointersVa - base,
    })),
  };

  // methodPointer dogrulama + sayim
  let resolvedTotal = 0;
  const modulePointers = new Map<string, number[]>(); // isim -> VA listesi
  for (const m of parsedModules) {
    const arr: number[] = [];
    if (m.pointersOff >= 0) {
      for (let i = 0; i < m.methodPointerCount && i < 600_000; i++) {
        const p = readPtrAt(map, buf, m.pointersOff + i * ps);
        if (p === null) break;
        if (p !== 0 && inRanges(map.execRanges, p)) {
          arr.push(p);
          resolvedTotal++;
        } else if (p !== 0) {
          arr.push(0);
        } else {
          arr.push(0);
        }
      }
    }
    modulePointers.set(m.name, arr);
    const entry = info.codeGenModules.modules.find((x) => x.name === m.name);
    if (entry) entry.resolved = arr.filter((p) => p !== 0).length;
  }
  info.methodPointersResolved = resolvedTotal;
  notes.push(`${resolvedTotal} metod isaretcisi kod bolumune eslesti`);

  // --- 6) MetadataRegistration (bagli metadata ile; Il2CppDumper V21 deseni) ---
  let fieldOffsetsByType: number[][] | null = null;
  let typesByTypedefIdx: Map<number, { name: string; isValueType: boolean }> | null = null;
  const meta = opts.metadata;
  if (meta) {
    const typeDefCount = meta.types.length;
    const eqCount = new Set<number>([typeDefCount]);
    const hits = findPtrRefs(map, buf, eqCount); // deger == typeDefCount olan konumlar
    mrScan: for (const [, positions] of hits) {
      for (const posVa of positions) {
        const p2Off = vaToOff(map, posVa + 2 * ps);
        const p3Off = vaToOff(map, posVa + 3 * ps);
        if (p2Off === null || p3Off === null) continue;
        const v2 = map.pointerSize === 8 ? Number(buf.readBigUInt64LE(p2Off)) : buf.readUInt32LE(p2Off);
        if (v2 !== typeDefCount) continue;
        const sizesPtr = readPtrAt(map, buf, p3Off);
        if (sizesPtr === null || sizesPtr === 0 || !inRanges(map.dataRanges, sizesPtr)) continue;
        const sizesOff = vaToOff(map, sizesPtr);
        if (sizesOff === null || sizesOff + typeDefCount * ps > buf.length) continue;
        const baseVa = posVa - 10 * ps;
        if (vaToOff(map, baseVa) === null) continue;
        // tam struct dogrulamasi: 8 cift (count,ptr) makul olmali
        let ok = 0;
        for (let k = 0; k < 14; k++) {
          const cOff = vaToOff(map, baseVa + k * 2 * ps);
          const pOff = vaToOff(map, baseVa + k * 2 * ps + ps);
          if (cOff === null || pOff === null) break;
          const c = map.pointerSize === 8 ? buf.readInt32LE(cOff) : buf.readInt32LE(cOff);
          if (c < 0 || c > 4_000_000) continue;
          const p = readPtrAt(map, buf, pOff);
          if (p !== null && (p === 0 || inRanges(map.dataRanges, p))) ok++;
        }
        if (ok < 8) continue;
        info.metadataRegistration = {
          rva: baseVa - base,
          va: baseVa,
          fieldNote: `${ok} alan dogrulandi (typesCount/fieldOffsets/typeDefSizes)`,
        };
        notes.push(`MetadataRegistration @ 0x${(baseVa - base).toString(16)} RVA`);

        // --- fieldOffsets tablosu ---
        const foPtrOff = vaToOff(map, baseVa + 10 * ps + ps);
        if (foPtrOff !== null) {
          const foPtr = readPtrAt(map, buf, foPtrOff);
          if (foPtr && inRanges(map.dataRanges, foPtr)) {
            const foOff = vaToOff(map, foPtr);
            if (foOff !== null) {
              const byType: number[][] = [];
              let okTypes = 0;
              for (let t = 0; t < Math.min(typeDefCount, 200_000); t++) {
                const p = readPtrAt(map, buf, foOff + t * ps);
                if (p === null) break;
                if (p === 0) { byType.push([]); continue; }
                const o = vaToOff(map, p);
                if (o === null) { byType.push([]); continue; }
                const t2 = meta.types[t];
                const n = Math.min(t2.fieldCount, 512);
                const offs: number[] = [];
                let good = n > 0;
                for (let f = 0; f < n; f++) {
                  const v = buf.readUInt32LE(o + f * 4);
                  if (v > 0x20000) { good = false; break; }
                  offs.push(v);
                }
                if (good) { byType.push(offs); okTypes++; } else byType.push([]);
              }
              if (okTypes > typeDefCount * 0.3) {
                fieldOffsetsByType = byType;
                info.fieldOffsetsTypes = okTypes;
                notes.push(`fieldOffsets: ${okTypes}/${typeDefCount} tip icin offset tablosu okundu`);
              }
            }
          }
        }

        // --- types dizisi (parent cozumu icin): Il2CppMetadataRegistration.types = pair 3 ptr (field 7) ---
        const typesPtrOff = vaToOff(map, baseVa + 7 * ps);
        if (typesPtrOff !== null) {
          const typesPtr = readPtrAt(map, buf, typesPtrOff);
          if (typesPtr && inRanges(map.dataRanges, typesPtr)) {
            const arrOff = vaToOff(map, typesPtr);
            if (arrOff !== null) {
              typesByTypedefIdx = new Map();
              for (let t = 0; t < Math.min(typeDefCount, 200_000); t++) {
                const tp = readPtrAt(map, buf, arrOff + t * ps);
                if (!tp) continue;
                const to = vaToOff(map, tp);
                if (to === null || to + 12 > buf.length) continue;
                const datapoint = map.pointerSize === 8
                  ? Number(buf.readBigUInt64LE(to))
                  : buf.readUInt32LE(to);
                const bits = buf.readUInt32LE(to + (map.pointerSize === 8 ? 8 : 4));
                const ty = (bits >> 16) & 0xff;
                // 0x11 VALUETYPE / 0x12 CLASS -> data = typedef indeksi
                if (ty === 0x11 || ty === 0x12) {
                  const idx = datapoint >>> 0;
                  const td = meta.types[idx];
                  if (td) typesByTypedefIdx.set(idx, { name: td.name, isValueType: ty === 0x11 });
                }
              }
            }
          }
        }
        break mrScan;
      }
    }
  }

  // --- 7) bagli mod: dump.cs + script.json ---
  let dumpCs: string | null = null;
  let scriptJson: string | null = null;
  if (meta && parsedModules.length > 0) {
    const built = buildLinkedOutput(map, buf, meta, parsedModules, modulePointers, {
      imageBase: base,
      fieldOffsetsByType,
      typesByTypedefIdx,
      crRva: cr?.baseVa ? cr.baseVa - base : undefined,
      mrRva: info.metadataRegistration?.rva,
    });
    dumpCs = built.dumpCs;
    scriptJson = built.scriptJson;
    info.dumpCs = dumpCs !== null;
  }

  if (!opts.metadata) {
    notes.push("Metadata bagli degil: metod RVA eslestirmesi ve dump.cs icin global-metadata.dat dosyasini da yukleyin (eslestirme otomatik yapilir)");
  }

  return { info, dumpCs, scriptJson };
}

function resolveParentName(
  parentIndex: number,
  typesByTypedefIdx: Map<number, { name: string; isValueType: boolean }> | null,
): string | null {
  if (!typesByTypedefIdx || parentIndex < 0) return null;
  return typesByTypedefIdx.get(parentIndex)?.name ?? null;
}

function buildLinkedOutput(
  map: SectionMap,
  buf: Buffer,
  meta: Il2CppCore,
  modules: CodeGenModule[],
  modulePointers: Map<string, number[]>,
  ctx: {
    imageBase: number;
    fieldOffsetsByType: number[][] | null;
    typesByTypedefIdx: Map<number, { name: string; isValueType: boolean }> | null;
    crRva?: number;
    mrRva?: number;
  },
): { dumpCs: string | null; scriptJson: string | null } {
  const ps = map.pointerSize;
  const base = ctx.imageBase;
  const moduleByName = new Map(modules.map((m) => [m.name, m]));
  const lines: string[] = [];
  const scriptMethods: { Name: string; Rva: string; Va: string; Offset: string }[] = [];
  const usedModules = new Set<string>();
  let methodLines = 0;
  let classCount = 0;
  let truncated = false;

  lines.push("// ============================================================================");
  lines.push("// DumperPro Online - dump.cs (Il2CppDumper benzeri, bagli metadata + binary)");
  lines.push(`// Metadata v${meta.effVersion} | binary pointerSize ${ps} | ImageBase 0x${base.toString(16)}`);
  if (ctx.crRva !== undefined) lines.push(`// CodeRegistration RVA: 0x${ctx.crRva.toString(16)}`);
  if (ctx.mrRva !== undefined) lines.push(`// MetadataRegistration RVA: 0x${ctx.mrRva.toString(16)}`);
  lines.push("// Yalnizca arastirma amacli; ofsetler statik eslestirmeden gelir.");
  lines.push("// ============================================================================");
  lines.push("");

  for (const img of meta.images) {
    const mod = moduleByName.get(img.name);
    if (mod) usedModules.add(img.name);
    const pointers = mod ? modulePointers.get(img.name) ?? [] : [];
    lines.push(`// Image: ${img.name} (${img.typeCount} tip)`);
    lines.push("");
    if (!mod) {
      lines.push(`// (bu image icin codeGenModules modulu bulunamadi)`);
      lines.push("");
      continue;
    }
    const typeEnd = Math.min(img.typeStart + img.typeCount, meta.types.length);
    for (let ti = img.typeStart; ti < typeEnd; ti++) {
      if (classCount >= IL2_CLASS_CAP) { truncated = true; break; }
      const t = meta.types[ti];
      if (!t) continue;
      const kind = t.isInterface ? "interface" : t.isEnum ? "enum" : t.isValueType ? "struct" : "class";
      const parentName = resolveParentName(t.parentIndex, ctx.typesByTypedefIdx);
      lines.push(`// Namespace: ${t.ns || "(global)"}`);
      lines.push(`${kind} ${t.name}${parentName ? ` : ${parentName}` : ""} // TypeDefIndex: ${ti}`);
      lines.push("{");

      // alanlar (+fieldOffsets varsa offset yorumu)
      const fo = ctx.fieldOffsetsByType?.[ti];
      lines.push("\t// Fields");
      let fieldCursor = 0;
      for (let k = 0; k < Math.min(t.fieldCount, 96); k++) {
        const fname = meta.fieldNames[t.fieldStart + k] ?? `field_${k}`;
        if (fname === "value__") continue;
        const off = fo?.[k];
        lines.push(`\t${fname};${off !== undefined ? ` // 0x${off.toString(16).toUpperCase()}` : " // 0x??"}`);
        fieldCursor++;
      }
      if (t.fieldCount > 96) lines.push(`\t// ... ${t.fieldCount - 96} alan daha (kesildi)`);
      void fieldCursor;

      // metodlar (token rid -> methodPointers)
      lines.push("\t// Methods");
      for (let k = 0; k < Math.min(t.methodCount, 96); k++) {
        const gIdx = t.methodStart + k;
        if (methodLines >= IL2_METHOD_CAP) { truncated = true; break; }
        const mname = meta.methodNames[gIdx] ?? `method_${k}`;
        const token = meta.methodTokens[gIdx] ?? 0;
        const rid = (token & 0xffffff) - 1;
        let rva = -1;
        if (rid >= 0 && rid < pointers.length) {
          const va = pointers[rid];
          if (va > 0) rva = va - base;
        }
        const sig = mname;
        if (rva >= 0) {
          const off = vaToOff(map, rva + base);
          lines.push(`\t${sig}; // RVA: 0x${rva.toString(16).toUpperCase()} Offset: 0x${(off ?? 0).toString(16).toUpperCase()} VA: 0x${(rva + base).toString(16).toUpperCase()}`);
          if (scriptMethods.length < 40_000) {
            scriptMethods.push({
              Name: `${img.name}${t.ns ? t.ns + "." : ""}${t.name}.${sig}`,
              Rva: `0x${rva.toString(16).toUpperCase()}`,
              Va: `0x${(rva + base).toString(16).toUpperCase()}`,
              Offset: `0x${(off ?? 0).toString(16).toUpperCase()}`,
            });
          }
        } else {
          lines.push(`\t${sig}; // RVA: -1 Offset: -1 VA: 0`);
        }
        methodLines++;
      }
      if (t.methodCount > 96) lines.push(`\t// ... ${t.methodCount - 96} metod daha (kesildi)`);
      lines.push("}");
      lines.push("");
      classCount++;
    }
    if (truncated) break;
  }

  if (truncated) {
    lines.push(`// NOT: cikti butceye takildi (${classCount} sinif, ${methodLines} metod satiri);`);
    lines.push("// tam SDK icin Il2CppDumper kullanin veya butceleri yukseltin.");
  }
  // modul-eslesme ozeti
  const unmatched = [...moduleByName.keys()].filter((n) => !usedModules.has(n));
  if (unmatched.length) {
    lines.push(`// codeGenModules'te olup metadata image ile eslesmeyen moduller: ${unmatched.slice(0, 12).join(", ")}`);
  }

  const dumpCsOut = lines.join("\n");
  const script = {
    Generator: "DumperPro Online (Il2CppDumper script.json benzeri)",
    MetadataVersion: meta.effVersion,
    Addresses: {
      CodeRegistration: ctx.crRva !== undefined ? `0x${ctx.crRva.toString(16)}` : null,
      MetadataRegistration: ctx.mrRva !== undefined ? `0x${ctx.mrRva.toString(16)}` : null,
      ImageBase: `0x${base.toString(16)}`,
    },
    MethodCount: scriptMethods.length,
    Methods: scriptMethods,
  };
  return { dumpCs: dumpCsOut, scriptJson: JSON.stringify(script, null, 1) };
}

/** PE/ELF hattina Il2CppBinary eklemek icin index.ts cagirir. */
export function maybeAnalyzeIl2CppBinary(
  buf: Buffer,
  kind: "pe" | "elf",
  pe: PeInfo | undefined,
  opts: Il2CppLinkOptions = {},
): Il2CppBinaryAnalysis | undefined {
  if (kind !== "pe" && kind !== "elf") return undefined;
  if (kind === "pe" && !looksLikeIl2CppBinary(buf, opts.fileName ?? "", pe)) return undefined;
  try {
    return analyzeIl2CppBinary(buf, kind, pe, opts);
  } catch {
    return undefined;
  }
}

/** yukleme rotasi icin: metadata + binary cifti -> dump.cs/script.json SDK dosyalari. */
export function analyzeIl2CppPair(
  metadataBuf: Buffer,
  binBuf: Buffer,
  binKind: "pe" | "elf",
  binPe: PeInfo | undefined,
  notes: string[],
): { info: Il2CppBinaryInfo; dumpCs: string | null; scriptJson: string | null; metadataInfo?: AnalysisResult["il2cpp"] } | undefined {
  const mdNotes: string[] = [];
  let core: ReturnType<typeof parseIl2CppMetadataCore>;
  try {
    core = parseIl2CppMetadataCore(metadataBuf, mdNotes);
  } catch (e) {
    notes.push(`metadata core parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
    return undefined;
  }
  if (!core?.core) {
    notes.push("IL2CPP eslestirme: metadata tam parse edilemedi");
    return undefined;
  }
  return analyzeIl2CppBinary(binBuf, binKind, binPe, { metadata: core.core });
}
