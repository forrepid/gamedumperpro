// ----------------------------------------------------------------------------
// DumperPro Online - MSVC RTTI cozumleyici (x64)
//
// Kaynak/teyit: Microsoft "Under the hood" RTTI dokumani + winnt.h:
//  - TypeDescriptor: [vftable_ptr 8B][spare 8B][".?AV<isim>\0" ...]
//  - CompleteObjectLocator (x64): sig(4) offset(4) cdOffset(4)
//      pTypeDescriptor(4,RVA) pClassDescriptor(4,RVA) pSelf(4,RVA)
//  - ClassHierarchyDescriptor: attributes(4) numBaseClasses(4) pBase(4,RVA)
//  - BaseClassDescriptor: pTypeDescriptor(4,RVA) numContainedBases(4)
//      PMD(12) flags(4)
//  - vftable: [.COL isaretcisi][metod isaretcileri...]; COL'dan geriye
//    vftable RVA bulunur, ardindan .text isaretci metodlari okunur.
// ----------------------------------------------------------------------------

import type { PeInfo, PeSection, RttiClass, RttiInfo } from "./types";
import { getSectionRaw } from "./pe";

interface SectionView {
  name: string;
  data: Buffer;
  rva: number;
  rawPointer: number;
  virtualSize: number;
}

function loadSections(buf: Buffer, sections: PeSection[]): SectionView[] {
  const out: SectionView[] = [];
  for (const s of sections) {
    const data = getSectionRaw(buf, s);
    if (data && data.length > 0 && data.length <= 96 * 1024 * 1024) {
      out.push({
        name: s.name,
        data,
        rva: s.virtualAddress,
        rawPointer: s.rawPointer,
        virtualSize: s.virtualSize || s.rawSize,
      });
    }
  }
  return out;
}

function rvaToSection(views: SectionView[], rva: number): SectionView | null {
  for (const v of views) {
    const span = Math.max(v.virtualSize, v.data.length);
    if (rva >= v.rva && rva < v.rva + span) return v;
  }
  return null;
}

function rvaToOffset(v: SectionView, rva: number): number {
  return rva - v.rva;
}

/** ".?AV..." adindan okunabilir sinif adi uretir (demangle).
 *  MSVC sirasi: ic-icene dogru yazilir (".?AVbad_exception@std@@" =
 *  std::bad_exception) - ilk tanimlayici EN ICI sinif adidir. */
function demangle(raw: string): { name: string; kind: "class" | "struct" } {
  // .?AV<class>@@ | .?AU<struct>@@ | .?AW4<enum>@@ | .?AV?<method>@@
  const kind: "class" | "struct" = raw.startsWith(".?AU") ? "struct" : "class";
  let body = raw.replace(/^\.\?A[VUW4]/, "");
  body = body.replace(/@+$/, "");
  const parts = body.split("@").filter((p) => p.length > 0);
  // ilk parca = sinif adi (en ici), sonrakiler = kapsayan sinif/namespace
  // (MSVC ic-icene yazar); gorunum disaridan-ice olmali -> ters cevir
  let name = parts.length > 0 ? parts[0] : body;
  if (parts.length > 1) {
    const ns = parts.slice(1).map((p) => (p.startsWith("?A0x") ? "" : p)).filter(Boolean).reverse();
    if (ns.length) name = `${ns.join("::")}::${name}`;
  }
  // ? ile baslayanlar metod/opsiyonel tipler
  if (name.startsWith("?")) name = body;
  return { name, kind };
}

export function analyzeRtti(buf: Buffer, pe: PeInfo, errors: string[]): RttiInfo | undefined {
  if (pe.format !== "PE32+") {
    return { available: false, total: 0, classes: [], enumNames: [], note: "x86 (PE32) RTTI destegi sinirlidir - atlandi" };
  }

  const views = loadSections(buf, pe.sections);
  const dataViews = views.filter((v) => v.name === ".rdata" || v.name === ".data" || v.name === ".rodata");

  // --- 1) tip descriptor taramasi (.?AV / .?AU sinif, .?AW4 enum) ---
  const descByName = new Map<string, number>(); // ham ad -> descriptor RVA
  const enumNames: string[] = [];
  const avNeedles = [Buffer.from(".?AV", "latin1"), Buffer.from(".?AU", "latin1"), Buffer.from(".?AW4", "latin1")];
  for (const v of dataViews) {
    for (const needle of avNeedles) {
      let idx = v.data.indexOf(needle);
      while (idx !== -1) {
        let end = idx + 4;
        while (end < v.data.length && end - idx < 160) {
          const b = v.data[end];
          if (b === 0) break;
          // tanimlayici/disaretci karakterleri
          if (!((b >= 0x20 && b < 0x7f) || b > 0x80)) break;
          end++;
        }
        const raw = v.data.subarray(idx, end).toString("latin1");
        const valid = /^\.\?A[VUW4][A-Za-z0-9_?<>:$@\\,-]*$/.test(raw);
        if (valid) {
          const descRva = v.rva + idx - 16; // vftable(8) + spare(8)
          if (descRva >= 0) descByName.set(raw, descRva);
          if (raw.startsWith(".?AW4") && enumNames.length < 128) {
            const dem = demangle(raw);
            if (!enumNames.includes(dem.name)) enumNames.push(dem.name);
          }
        }
        idx = v.data.indexOf(needle, idx + 4);
      }
    }
  }

  if (descByName.size === 0) {
    return {
      available: false,
      total: 0,
      classes: [],
      enumNames: [],
      note: "RTTI tip descriptor bulunamadi (RTTI kapali, obfuscate veya C derlemesi olabilir)",
    };
  }

  // --- 2) COL isaretcilerini bul: .rdata'daki 8B deger == imageBase + COL_RVA ---
  // COL yapisindan sinif adini coz; vftable = isaretcinin bulundugu yer.
  const classes: RttiClass[] = [];
  const seen = new Set<string>();
  const imageBase = pe.imageBase;

  for (const v of dataViews) {
    for (let p = 0; p + 8 <= v.data.length; p += 8) {
      const ptr = Number(v.data.readBigUInt64LE(p));
      if (ptr < imageBase || ptr > imageBase + 0x10000000) continue;
      const colRva = ptr - imageBase;
      const colSec = rvaToSection(views, colRva);
      if (!colSec || (colSec.name !== ".rdata" && colSec.name !== ".data")) continue;
      const co = rvaToOffset(colSec, colRva);
      if (co < 0 || co + 24 > colSec.data.length) continue;
      const sig = colSec.data.readInt32LE(co);
      if (sig !== 1 && sig !== 0) continue; // x64: 1, x86: 0
      const tdRva = colSec.data.readUInt32LE(co + 12);
      const chdRva = colSec.data.readUInt32LE(co + 16);
      // self-referans dogrulamasi (COL icerisindeki pSelf)
      const selfRva = colSec.data.readUInt32LE(co + 20);
      if (selfRva !== colRva) continue;

      const tdSec = rvaToSection(views, tdRva);
      if (!tdSec) continue;
      const tOff = rvaToOffset(tdSec, tdRva);
      if (tOff < 0 || tOff + 24 > tdSec.data.length) continue;
      // descriptor+16 = ad
      let nameEnd = tOff + 16;
      while (nameEnd < tdSec.data.length && nameEnd - (tOff + 16) < 160 && tdSec.data[nameEnd] !== 0) nameEnd++;
      const raw = tdSec.data.subarray(tOff + 16, nameEnd).toString("latin1");
      if (!descByName.has(raw)) continue;

      const { name, kind } = demangle(raw);
      if (seen.has(name)) continue;

      // vftable = bu COL isaretcisinin bulundugu RVA
      const vftableRva = v.rva + p;
      const methods: { rva: number; va: number }[] = [];
      let methodCount = 0;
      for (let m = p + 8; m + 8 <= v.data.length && methodCount < 64; m += 8) {
        const mp = Number(v.data.readBigUInt64LE(m));
        if (mp === 0) break;
        if (mp < imageBase || mp > imageBase + 0x10000000) break;
        const mrva = mp - imageBase;
        const mSec = rvaToSection(views, mrva);
        if (!mSec || mSec.name !== ".text") break;
        if (methods.length < 48) methods.push({ rva: mrva, va: mp });
        methodCount++;
      }

      // taban sinif: ClassHierarchyDescriptor -> BaseClassDescriptor[0]
      let base: string | undefined;
      const chdSec = rvaToSection(views, chdRva);
      if (chdSec) {
        const chOff = rvaToOffset(chdSec, chdRva);
        if (chOff >= 0 && chOff + 12 <= chdSec.data.length) {
          const numBases = chdSec.data.readUInt32LE(chOff + 4);
          const bcdRva = chdSec.data.readUInt32LE(chOff + 8);
          if (numBases >= 2 && bcdRva !== 0) {
            const bSec = rvaToSection(views, bcdRva);
            if (bSec) {
              const bOff = rvaToOffset(bSec, bcdRva);
              if (bOff >= 0 && bOff + 4 <= bSec.data.length) {
                const baseTdRva = bSec.data.readUInt32LE(bOff);
                const btSec = rvaToSection(views, baseTdRva);
                if (btSec) {
                  const btOff = rvaToOffset(btSec, baseTdRva);
                  if (btOff >= 0 && btOff + 24 <= btSec.data.length) {
                    let ne = btOff + 16;
                    while (ne < btSec.data.length && ne - (btOff + 16) < 160 && btSec.data[ne] !== 0) ne++;
                    const baseRaw = btSec.data.subarray(btOff + 16, ne).toString("latin1");
                    if (/^\.\?A[VU]/.test(baseRaw)) base = demangle(baseRaw).name;
                  }
                }
              }
            }
          }
        }
      }

      seen.add(name);
      classes.push({
        name,
        kind,
        rttiRva: tdRva,
        vftableRva,
        vftableVa: imageBase + vftableRva,
        base,
        methodCount,
        methods,
      });
      if (classes.length >= 256) break;
    }
    if (classes.length >= 256) break;
  }

  // COL'suz descriptorlar icin say (tam liste bilgisi)
  const total = descByName.size;

  if (classes.length === 0) {
    return {
      available: true,
      total,
      classes: [],
      enumNames,
      note: `${total} tip descriptor bulundu ancak COL/vftable baglantisi kurulamadi`,
    };
  }

  classes.sort((a, b) => (a.base ? 0 : -1) - (b.base ? 0 : -1) || a.name.localeCompare(b.name));

  return {
    available: true,
    total,
    classes,
    enumNames,
    note: `MSVC x64 RTTI: ${total} tip descriptor, ${classes.length} sinifin vftable baglantisi cozuldu${enumNames.length ? `, ${enumNames.length} enum adi` : ""}`,
  };
}
