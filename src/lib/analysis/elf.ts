// ----------------------------------------------------------------------------
// DumperPro Online - ELF parser (sifir bagimlilik)
//
// Kaynak/teyit: TIS ELF spec / man elf(5).
//  - e_ident: \x7fELF + class(1=32,2=64) + data(1=LE,2=BE)
//  - ehdr64: e_machine @0x12 (u16 LE/BE'ye gore), e_entry @0x18
//  - section header 64 B (sh64) / 40 B (sh32), isim tablosu shstrtab
// ----------------------------------------------------------------------------

import type { ElfInfo, ElfSection, ElfDynSym } from "./types";

const MACHINE: Record<number, string> = {
  0xb7: "AArch64 (ARM64)",
  0x3e: "x86-64",
  0x28: "ARM (32-bit)",
  0x03: "x86",
  0x8b: "LoongArch64",
  0xf3: "RISC-V",
  0x14: "PowerPC",
  0x15: "PowerPC64",
  0x02: "SPARC",
  0x3b: "SPARC v9",
};

const SHT: Record<number, string> = {
  0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
  6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
  14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x6ffffff6: "GNU_HASH",
  0x6ffffffe: "VERNEED", 0x6fffffff: "VERSYM", 0x6ffffffd: "GNU VERDEF",
};

const ET: Record<number, string> = {
  0: "NONE", 1: "REL (relocatable)", 2: "EXEC (executable)",
  3: "DYN (shared object)", 4: "CORE",
};

export function parseElf(buf: Buffer, errors: string[]): ElfInfo {
  if (buf.length < 64) throw new Error("ELF basligi icin cok kucuk");
  const eiClass = buf[4]; // 1=32, 2=64
  const eiData = buf[5]; // 1=LE, 2=BE
  const is64 = eiClass === 2;
  const le = eiData !== 2;
  const rd16 = le ? (o: number) => buf.readUInt16LE(o) : (o: number) => buf.readUInt16BE(o);
  const rd32 = le ? (o: number) => buf.readUInt32LE(o) : (o: number) => buf.readUInt32BE(o);
  const rd64 = le
    ? (o: number) => Number(buf.readBigUInt64LE(o))
    : (o: number) => Number(buf.readBigUInt64BE(o));

  const machine = rd16(0x12);
  const eType = rd16(0x10);
  let entry = 0;
  let eShoff = 0;
  let eShentsize = 0;
  let eShnum = 0;
  let eShstrndx = 0;
  if (is64) {
    entry = rd64(0x18);
    eShoff = rd64(0x28);
    eShentsize = rd16(0x3a);
    eShnum = rd16(0x3c);
    eShstrndx = rd16(0x3e);
  } else {
    entry = rd32(0x18);
    eShoff = rd32(0x20);
    eShentsize = rd16(0x2e);
    eShnum = rd16(0x30);
    eShstrndx = rd16(0x32);
  }

  // bolum isim tablosu
  let strTab: Buffer | null = null;
  const shSize = is64 ? 64 : 40;
  if (eShoff > 0 && eShnum > 0 && eShstrndx < eShnum) {
    const shOff = eShoff + eShstrndx * eShentsize;
    if (shOff + shSize <= buf.length) {
      const strOff = is64 ? rd64(shOff + 24) : rd32(shOff + 16);
      const strSize = is64 ? rd64(shOff + 32) : rd32(shOff + 20);
      if (strOff + strSize <= buf.length) strTab = buf.subarray(strOff, strOff + strSize);
    }
  }

  const sections: ElfSection[] = [];
  for (let i = 0; i < Math.min(eShnum, 64); i++) {
    const off = eShoff + i * eShentsize;
    if (off + shSize > buf.length) break;
    const nameIdx = rd32(off);
    const sType = rd32(off + 4);
    const addr = is64 ? rd64(off + 16) : rd32(off + 12);
    const size = is64 ? rd64(off + 32) : rd32(off + 20);
    let name = "";
    if (strTab && nameIdx < strTab.length) {
      let end = nameIdx;
      while (end < strTab.length && strTab[end] !== 0 && end - nameIdx < 128) end++;
      name = strTab.subarray(nameIdx, end).toString("latin1");
    }
    sections.push({ name, type: SHT[sType] ?? `0x${sType.toString(16)}`, addr, size });
  }
  if (eShnum > 64) errors.push(`ELF bolum sayisi 64'u asiyor (${eShnum}); ilk 64 listelendi`);

  // --- dynamic symbol tablosu (.dynsym + .dynstr): disa aktarilan semboller ---
  const dynsyms: ElfDynSym[] = [];
  let dynsymCount = 0;
  const symSec = sections.find((s) => s.type === "DYNSYM");
  if (symSec) {
    // bolum header'larindan raw offset'leri al (sections listesi addr/size tutuyor)
    const symEnt = is64 ? 24 : 16;
    let symOff = 0;
    let symSize = 0;
    let strRaw = 0;
    for (let i = 0; i < Math.min(eShnum, 64); i++) {
      const off = eShoff + i * eShentsize;
      if (off + shSize > buf.length) break;
      const sTypeRaw = rd32(off + 4);
      const raw = is64 ? rd64(off + 24) : rd32(off + 16);
      if (sTypeRaw === 11 && symOff === 0) {
        symOff = raw;
        symSize = is64 ? rd64(off + 32) : rd32(off + 20);
      } else {
        const nmIdx = rd32(off);
        let nm = "";
        if (strTab && nmIdx < strTab.length) {
          let en = nmIdx;
          while (en < strTab.length && strTab[en] !== 0 && en - nmIdx < 128) en++;
          nm = strTab.subarray(nmIdx, en).toString("latin1");
        }
        if (nm === ".dynstr" && strRaw === 0) strRaw = raw;
      }
    }
    if (symOff > 0 && symSize >= symEnt && symOff + symSize <= buf.length) {
      dynsymCount = Math.floor(symSize / symEnt);
      const capN = Math.min(dynsymCount, 65536);
      for (let i = 0; i < capN && dynsyms.length < 96; i++) {
        const e = symOff + i * symEnt;
        let stName = 0;
        let stInfo = 0;
        let stValue = 0;
        let stSize2 = 0;
        if (is64) {
          stName = rd32(e);
          stInfo = buf[e + 4];
          stValue = rd64(e + 8);
          stSize2 = rd64(e + 16);
        } else {
          stName = rd32(e);
          stValue = rd32(e + 4);
          stSize2 = rd32(e + 8);
          stInfo = buf[e + 12];
        }
        const bind = stInfo >> 4;
        const sType2 = stInfo & 0xf;
        if (bind !== 1 && bind !== 2) continue; // GLOBAL / WEAK
        if (sType2 !== 1 && sType2 !== 2) continue; // OBJECT / FUNC
        if (!stValue) continue;
        let name = "";
        if (strRaw > 0 && strRaw + stName < buf.length) {
          let end = strRaw + stName;
          while (end < buf.length && buf[end] !== 0 && end - (strRaw + stName) < 256) end++;
          name = buf.subarray(strRaw + stName, end).toString("latin1");
        }
        dynsyms.push({
          name,
          type: sType2 === 2 ? "FUNC" : "OBJECT",
          bind: bind === 1 ? "GLOBAL" : "WEAK",
          value: stValue,
          size: stSize2,
        });
      }
    }
  }

  return {
    class: is64 ? "ELF64" : "ELF32",
    endian: le ? "LE" : "BE",
    machine: MACHINE[machine] ?? `0x${machine.toString(16)}`,
    type: ET[eType] ?? `0x${eType.toString(16)}`,
    entryPoint: entry,
    sectionCount: eShnum,
    sections,
    dynsymCount: dynsymCount || undefined,
    dynsyms: dynsyms.length > 0 ? dynsyms : undefined,
  };
}
