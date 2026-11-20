// ----------------------------------------------------------------------------
// DumperPro Online - enum kurtarma (RTTI .?AW4 + switch atlama tablolari)
//
// Yontem:
//  1) RTTI: .?AW4 tip descriptorlari enum adlarini verir (rtti.ts). Degerler
//     semboller olmadan statik olarak kurtarilamaz (not ile bildirilir).
//  2) Switch tablolari: MSVC x64 derleyicisi yogun switch'leri .rdata'ya
//     int32 relatif atlama tablosu yazar: her giriÅ (tabloVA + delta) bir
//     case hedefini gosterir. Tablo bulunursa case adetleri ve hedef
//     fonksiyonlar kurtarilir; indeks degerleri enum benzeri uye seti uretir.
//     Kaynak: MSVC CodeGen "jump table" uretimi + IDA switch tespiti yaklasimi.
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) Switch tablo uye degerleri TABLO INDEKSIDIR (0..n-1); derleyici
//      `case 10..20` gibi kaydirma yaparsa gercek etiketler indeks+taban
//      olur; taban kurtarilamazsa 0 varsayilir (not ile).
//   2) .rdata taramasi hizli sezgisel filtrelerle yapilir (tum giriÅler
//      .text icine isaret etmeli, uzunluk 3..128, 4-bayt hizali) - yanlis
//      pozitifler dusuk; yine de "aday" etiketlenir.
//   3) Enum deger kurtarmanin kesin yolu sembol/ metadata okumaktir:
//      Unity icin global-metadata.dat (il2cpp.ts/ metadata.ts) tam deger
//      verir; PE-tek basina modda bu modul yalnizca aday uretir.
// ----------------------------------------------------------------------------

import type { PeInfo, RttiInfo, EnumsInfo, RecoveredEnum } from "./types";
import { getSectionRaw } from "./pe";

export interface JumpTable {
  tableRva: number;
  tableVa: number;
  entries: number; // case adedi
  ownerFnRva?: number; // lea referansi bulunan fonksiyon
  targets: number[]; // hedef RVA'lar (cap 64)
}

const MAX_TABLES = 48;
const MIN_ENTRIES = 3;
const MAX_ENTRIES = 128;

export function analyzeEnums(
  buf: Buffer,
  pe: PeInfo,
  rtti: RttiInfo | undefined,
  leaTargets: Map<number, number>,
): { enums: EnumsInfo; jumpTables: JumpTable[] } {
  const enums: RecoveredEnum[] = [];

  // --- 1) RTTI enum adlari ---
  for (const name of rtti?.enumNames ?? []) {
    enums.push({
      name,
      source: "rtti",
      members: [],
      note: "RTTI descriptor: ad kurtarildi; degerler semboller/metadata gerektirir",
    });
  }

  // --- 2) switch atlama tablolari (.rdata) ---
  const jumpTables = findJumpTables(buf, pe);
  for (const jt of jumpTables) {
    const ownerRva = leaTargets.get(jt.tableVa);
    if (ownerRva !== undefined) jt.ownerFnRva = ownerRva;
    const members = jt.targets.map((_, i) => ({
      name: `case_${i}`,
      value: i,
    }));
    enums.push({
      name: `switch_${jt.tableVa.toString(16).toUpperCase()}${ownerRva !== undefined ? `_fn${(pe.imageBase + ownerRva).toString(16).toUpperCase()}` : ""}`,
      source: "switch",
      members,
      note: `atlama tablosu: ${jt.entries} dal, tablo RVA 0x${jt.tableRva.toString(16).toUpperCase()} (indeks degerleri adaydir)`,
    });
    if (enums.length >= 200) break;
  }

  return {
    enums: {
      total: enums.length,
      enums: enums.slice(0, 200),
      note:
        enums.length === 0
          ? "Enum adayi bulunamadi (RTTI yok, switch tablosu yok)"
          : `${enums.length} enum adayi: ${enums.filter((e) => e.source === "rtti").length} RTTI adi, ${enums.filter((e) => e.source === "switch").length} switch tablosu`,
    },
    jumpTables,
  };
}

/** .rdata icinde .text'e isaret eden int32 relatif atlama tablolarini bulur. */
export function findJumpTables(buf: Buffer, pe: PeInfo): JumpTable[] {
  const out: JumpTable[] = [];
  const text = pe.sections.find((s) => s.name === ".text");
  const rdata = pe.sections.find((s) => s.name === ".rdata" || s.name === ".data");
  if (!text || !rdata) return out;
  const rdataData = getSectionRaw(buf, rdata);
  if (!rdataData) return out;

  const textStart = text.virtualAddress;
  const textEnd = text.virtualAddress + Math.max(text.virtualSize, text.rawSize);

  let i = 0;
  while (i + 12 <= rdataData.length && out.length < MAX_TABLES) {
    // 4-bayt hizaya jumple
    if (i % 4 !== 0) {
      i += 4 - (i % 4);
      continue;
    }
    const d0 = rdataData.readInt32LE(i);
    // ilk giris: .text'e isaret etmeli (signed delta, tablo VA'ya gore)
    const tableVa = pe.imageBase + rdata.virtualAddress + i;
    const t0 = tableVa + d0;
    const t0Rva = rdata.virtualAddress + i + d0;
    if (d0 !== 0 && t0Rva >= textStart && t0Rva < textEnd && Math.abs(d0) < 0x100000) {
      // tablo uzunlugunu tespit: giriÅler .text'e isaret etmeye devam etmeli
      let n = 1;
      const targets: number[] = [t0Rva];
      while (n < MAX_ENTRIES && i + (n + 1) * 4 + 4 <= rdataData.length) {
        const dn = rdataData.readInt32LE(i + n * 4);
        const tnRva = rdata.virtualAddress + i + n * 4 + dn;
        if (dn === 0 && n >= MIN_ENTRIES) break; // delta 0 = kendine isaret = tablo sonu ihtimali
        if (Math.abs(dn) >= 0x100000 || tnRva < textStart || tnRva >= textEnd) break;
        targets.push(tnRva);
        n++;
      }
      if (n >= MIN_ENTRIES) {
        // yanlis pozitif filtre: en az 3 girisin farkli hedefi olmali
        const uniq = new Set(targets);
        if (uniq.size >= Math.min(3, Math.floor(n * 0.5))) {
          out.push({
            tableRva: rdata.virtualAddress + i,
            tableVa,
            entries: n,
            targets: targets.slice(0, 64),
          });
          i += n * 4; // tabloyu atla
          continue;
        }
      }
    }
    i += 4;
  }
  return out;
}
