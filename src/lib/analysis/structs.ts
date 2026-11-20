// ----------------------------------------------------------------------------
// DumperPro Online - struct kurtarma (RTTI + kod erisim analizi)
//
// Yontem (statik, tahminsel - "structure recovery" yaygin yaklasimi):
//  1) RTTI vftable'li siniflar (rtti.ts) -> temel struct taslaklari
//     (offset 0 = vptr, metodlar vftable'dan).
//  2) Her fonksiyon x86-64 olarak cozulur; icerisinde bir sinifin vftable'ina
//     `lea reg,[rip+X]` ile referans verilirse o fonksiyon sinifin metodu
//     kabul edilir ve fonksiyondaki `[reg+disp]` bellek erisimleri sinifin
//     uye alan adaylari olarak toplanir (genislik -> uint8/16/32/64/xmm).
//  3) Alanlar offset'e gore birlestirilir; max(offset+size) tahmini struct
//     boyutunu verir. Dumper-7'deki UnknownData_XX dolgu mantigi SDK
//     ureticisinde (sdkgen.ts) uygulanir.
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) Alan TURLERI tahminidir: isaretci/float ayrisimi yapilmaz; genislige
//      gore isaretsiz tamsayi varsayilir (float olasiligi not ile bildirilir).
//   2) `this` takibi tam register veri akisi analizi degildir; vftable
//      referansi bulunan fonksiyondaki tum [reg+disp] erisimleri ayni sinifa
//      yazilir (kabalama = yanlis pozitif olasiligi; reads sayisi guven verir).
//   3) Sozu etme durustlugu: raporda ve SDK basliklarinda "tahmini/recovered"
//      etiketleri zorunlu tutulur; gercek semantik canli dogrulama ister.
//   4) Kapsam: x64 PE (PE32+) icin tam; x86 icin yalnizca RTTI taslaklari.
// ----------------------------------------------------------------------------

import type {
  PeInfo,
  FunctionsInfo,
  RttiInfo,
  StructsInfo,
  RecoveredStruct,
  StructField,
} from "./types";
import { getSectionRaw } from "./pe";
import { disassemble, type AsmInsn } from "./disasm";

export interface DeepCodeOutput {
  structs: StructsInfo;
  /** fonksiyon RVA -> sinif adi (kod vftable referansi) */
  fnClassHints: Map<number, string>;
  /** lea rip hedef VA -> fonksiyon RVA (switch tablo atama icin) */
  leaTargets: Map<number, number>;
  /** xref sayilari: hedef fn RVA -> cagri sayisi */
  callTargets: Map<number, number>;
}

interface ClassAcc {
  offsets: Map<number, { size: number; reads: number }>;
  fnCount: number;
  maxSize: number;
}

const MAX_DECODE_INSNS = 2500;
const MAX_TOTAL_INSNS = 1_600_000;
const MAX_FIELD_OFFSET = 0x2000;

export function analyzeStructs(
  buf: Buffer,
  pe: PeInfo,
  functions: FunctionsInfo | undefined,
  rtti: RttiInfo | undefined,
): DeepCodeOutput {
  const fnClassHints = new Map<number, string>();
  const leaTargets = new Map<number, number>();
  const callTargets = new Map<number, number>();

  const vftableToClass = new Map<number, { name: string; base?: string; methodCount: number; methods: { rva: number }[] }>();
  if (rtti?.available) {
    for (const c of rtti.classes) {
      if (c.vftableRva !== undefined) {
        vftableToClass.set(c.vftableRva, { name: c.name, base: c.base, methodCount: c.methodCount, methods: c.methods });
      }
    }
  }

  const classAcc = new Map<string, ClassAcc>();
  const codeOnly = new Map<number, ClassAcc>(); // vftablesiz fonksiyon alanlari

  const text = pe.sections.find((s) => s.name === ".text");
  if (!text) {
    return { structs: { total: rtti?.classes.length ?? 0, structs: rttiSkeleton(pe, rtti), }, fnClassHints, leaTargets, callTargets };
  }
  const textData = getSectionRaw(buf, text);
  if (!textData) {
    return { structs: { total: rtti?.classes.length ?? 0, structs: rttiSkeleton(pe, rtti) }, fnClassHints, leaTargets, callTargets };
  }

  // ---- fonksiyon secimi (butce kontrollu) ----
  const allFns = functions?.functions ?? [];
  const priority = (f: { label?: string; size: number; strings: string[]; apiCalls: string[] }) =>
    (f.label ? 3 : 0) + (f.strings.length ? 2 : 0) + (f.apiCalls.length ? 1 : 0);
  const sorted = [...allFns].sort((a, b) => priority(b) - priority(a) || b.size - a.size);
  const chosen = sorted.slice(0, 600);
  const sizeCap = 64 * 1024;

  let decodedTotal = 0;
  for (const f of chosen) {
    if (decodedTotal >= MAX_TOTAL_INSNS) break;
    if (f.size <= 0 || f.size > sizeCap) continue;
    const sec = pe.sections.find((s) => s.virtualAddress <= f.rva && f.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
    if (!sec || sec.name !== ".text") continue;
    const rel = f.rva - sec.virtualAddress + sec.rawPointer;
    if (rel < 0 || rel + f.size > buf.length) continue;

    const budget = Math.min(MAX_DECODE_INSNS, Math.floor((MAX_TOTAL_INSNS - decodedTotal)));
    const res = disassemble(buf, rel, f.size, pe.imageBase + f.rva, budget);
    decodedTotal += res.insns.length;

    let ownerClass: { name: string } | null = null;
    for (const ins of res.insns) {
      const m = ins.text.match(/^(lea|mov) (r[a-z0-9]+), \[0x([0-9A-F]+)\]/);
      if (m) {
        const targetVa = parseInt(m[3], 16);
        leaTargets.set(targetVa, f.rva);
        // rip hedefi mutlak VA; vftable anahtari RVA
        const clsByVa = vftableToClass.get(targetVa - pe.imageBase);
        if (clsByVa && m[1] === "lea") {
          ownerClass = clsByVa;
          fnClassHints.set(f.rva, clsByVa.name);
        }
      }
      // cagri grafika
      const cm = ins.text.match(/^call 0x([0-9A-F]+)/);
      if (cm) {
        const t = parseInt(cm[1], 16) - pe.imageBase;
        callTargets.set(t, (callTargets.get(t) ?? 0) + 1);
      }
      // uye erisimi: [reg+disp] / [reg]
      const mm = ins.text.match(/\[([a-z0-9]+)(\+0x[0-9A-F]+|-0x[0-9A-F]+)?\]/);
      if (mm) {
        const base = mm[1];
        const dispStr = mm[2];
        if (!dispStr) continue; // [reg] = offset 0 (cok gurultulu) - vptr hariç atla
        let disp = parseInt(dispStr.replace("+", ""), 16);
        if (dispStr.startsWith("-")) disp = -disp;
        if (base === "rsp" || base === "rbp") continue; // yerel yigin - uye degil
        if (disp < 0 || disp > MAX_FIELD_OFFSET) continue;
        const size = accessWidth(ins.text);
        if (!size) continue;
        const acc = ownerClass
          ? classAcc.get(ownerClass.name) ?? { offsets: new Map(), fnCount: 0, maxSize: 0 }
          : codeOnly.get(f.rva) ?? { offsets: new Map(), fnCount: 0, maxSize: 0 };
        const cur = acc.offsets.get(disp);
        if (cur) {
          cur.reads++;
          if (size > cur.size) cur.size = size;
        } else {
          acc.offsets.set(disp, { size, reads: 1 });
        }
        acc.maxSize = Math.max(acc.maxSize, disp + size);
        if (ownerClass) classAcc.set(ownerClass.name, acc);
        else codeOnly.set(f.rva, acc);
      }
    }
    if (ownerClass) {
      const acc = classAcc.get(ownerClass.name);
      if (acc) acc.fnCount++;
    }
  }

  // ---- structlari kur ----
  const structs: RecoveredStruct[] = [];

  for (const c of rtti?.classes ?? []) {
    const acc = classAcc.get(c.name);
    const fields: StructField[] = [];
    fields.push({ name: "vftable", offset: 0, size: 8, type: "void*", reads: acc ? acc.fnCount : 0 });
    if (acc) {
      for (const [off, v] of [...acc.offsets.entries()].sort((a, b) => a[0] - b[0]).slice(0, 63)) {
        if (off === 0) continue; // vptr zaten var
        fields.push({ name: `field_0x${off.toString(16).padStart(2, "0")}`, offset: off, size: v.size, type: widthType(v.size), reads: v.reads });
      }
    }
    structs.push({
      name: c.name,
      kind: c.kind,
      size: acc ? align8(acc.maxSize) : undefined,
      base: c.base,
      vftableRva: c.vftableRva,
      vftableVa: c.vftableVa,
      methodCount: c.methodCount,
      fields: fields.slice(0, 64),
      source: acc ? "mixed" : "rtti",
    });
  }

  // kod-ile kurtarilan structlar (RTTI'siz fonksiyonlar)
  const codeEntries = [...codeOnly.entries()]
    .filter(([, acc]) => acc.offsets.size >= 3)
    .sort((a, b) => b[1].offsets.size - a[1].offsets.size)
    .slice(0, 40);
  for (const [fnRva, acc] of codeEntries) {
    const fields: StructField[] = [...acc.offsets.entries()]
      .sort((a, b) => a[0] - b[0])
      .slice(0, 64)
      .map(([off, v]) => ({ name: `field_0x${off.toString(16).padStart(2, "0")}`, offset: off, size: v.size, type: widthType(v.size), reads: v.reads }));
    structs.push({
      name: `sub_${(pe.imageBase + fnRva).toString(16).toUpperCase()}_struct`,
      kind: "struct",
      size: align8(acc.maxSize),
      methodCount: 0,
      fields,
      source: "code",
    });
  }

  // sinif vftable'i var ama kod erisimi bulunmayanlar (skelet)
  for (const s of rttiSkeleton(pe, rtti)) {
    if (!structs.find((x) => x.name === s.name)) structs.push(s);
  }

  const total = structs.length;
  const note =
    total === 0
      ? "Struct kurtarma icin yeterli RTTI/kod erisimi bulunamadi"
      : `${total} struct: ${structs.filter((s) => s.source === "mixed").length} kod-erisimli, ${structs.filter((s) => s.source === "code").length} kod-kaynakli, ${structs.filter((s) => s.source === "rtti").length} RTTI-skelet (tahminsel; turler genislige gore)`;

  return {
    structs: { total, structs: structs.slice(0, 200), note },
    fnClassHints,
    leaTargets,
    callTargets,
  };
}

function rttiSkeleton(pe: PeInfo, rtti: RttiInfo | undefined): RecoveredStruct[] {
  return (rtti?.classes ?? []).map((c) => ({
    name: c.name,
    kind: c.kind,
    base: c.base,
    vftableRva: c.vftableRva,
    vftableVa: c.vftableVa,
    methodCount: c.methodCount,
    fields: [{ name: "vftable", offset: 0, size: 8, type: "void*", reads: 0 }],
    source: "rtti" as const,
  }));
}

/** insandin metninden erisim genisligi (bayt) cikarir. */
function accessWidth(text: string): number | undefined {
  if (/^(movsd|movups|movupd|movaps|movapd|movdqa|movdqu)( \(store\))?\b/.test(text)) return 16;
  if (/^movss\b/.test(text)) return 4;
  const body = text.replace(/;.*$/, "").trim();
  const sp = body.indexOf(" ");
  if (sp < 0) return undefined;
  const operands = body.slice(sp).split(",").map((s) => s.trim());
  for (const op of operands) {
    const w = regWidth(op);
    if (w) return w;
  }
  return 4; // yalnizca-imm islenen: dword varsayimi
}

function regWidth(r: string): number | undefined {
  const clean = r.replace(/;.*$/, "").trim();
  if (/^xmm[0-9]+$/.test(clean)) return 16;
  if (/^r(1[0-5]|[8-9])$/.test(clean)) return 8;
  if (/^r(1[0-5]|[8-9])d$/.test(clean)) return 4;
  if (/^r(1[0-5]|[8-9])w$/.test(clean)) return 2;
  if (/^r(1[0-5]|[8-9])b$/.test(clean)) return 1;
  if (/^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp)$/.test(clean)) return 8;
  if (/^(eax|ebx|ecx|edx|esi|edi|ebp|esp)$/.test(clean)) return 4;
  if (/^(ax|bx|cx|dx|si|di|bp|sp)$/.test(clean)) return 2;
  if (/^(al|bl|cl|dl|sil|dil|bpl|spl|ah|bh|ch|dh)$/.test(clean)) return 1;
  return undefined;
}

function widthType(size: number): string {
  switch (size) {
    case 1: return "uint8";
    case 2: return "uint16";
    case 4: return "uint32"; // float olasiligi
    case 8: return "uint64"; // ptr/float64 olasiligi
    case 16: return "uint8[16]";
    default: return `uint8[${size}]`;
  }
}

function align8(n: number): number {
  return Math.ceil(n / 8) * 8;
}

// asm ciktisini ileride kullanmak icin yardimci (sse dizi referanslari)
export function insnsText(insns: AsmInsn[]): string[] {
  return insns.map((i) => `${i.va.toString(16).padStart(8, "0")}  ${i.text}`);
}
