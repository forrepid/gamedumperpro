import fs from "node:fs";

const buf = fs.readFileSync("/home/z/my-project/storage/uploads/a5930196-1534-4ac5-bf81-486c33fb1aec__ROB_RUN.exe");
const lfanew = buf.readUInt32LE(0x3c);
const coff = lfanew + 4;
const numSections = buf.readUInt16LE(coff + 2);
const sizeOfOpt = buf.readUInt16LE(coff + 16);
const opt = coff + 20;
const is64 = buf.readUInt16LE(opt) === 0x20b;
const numberOfRvaAndSizes = is64 ? buf.readUInt32LE(opt + 108) : buf.readUInt32LE(opt + 92);
const dirsOffset = opt + (is64 ? 112 : 96);
const dirNames = ["Export","Import","Resource","Exception","Security","BaseReloc","Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","COM","Rsv"];
const dirs: {name:string;va:number;size:number}[] = [];
for (let i = 0; i < Math.min(16, numberOfRvaAndSizes); i++) {
  const va = buf.readUInt32LE(dirsOffset + i*8);
  const size = buf.readUInt32LE(dirsOffset + i*8 + 4);
  if (va || size) dirs.push({name: dirNames[i], va, size});
}
const secTable = opt + sizeOfOpt;
const sections: {name:string;vs:number;va:number;rs:number;rp:number}[] = [];
for (let i = 0; i < numSections; i++) {
  const off = secTable + i * 40;
  sections.push({
    name: buf.subarray(off, off+8).toString("latin1").replace(/\0+$/, ""),
    vs: buf.readUInt32LE(off+8), va: buf.readUInt32LE(off+12),
    rs: buf.readUInt32LE(off+16), rp: buf.readUInt32LE(off+20),
  });
}
const rvaToOffset = (rva: number): number => {
  for (const s of sections) {
    const span = Math.max(s.vs, s.rs);
    if (rva >= s.va && rva < s.va + span) return rva - s.va + s.rp;
  }
  return -1;
};
const readAscii = (off: number, max = 256): string => {
  if (off < 0 || off >= buf.length) return "";
  let end = off;
  while (end < buf.length && end - off < max && buf[end] !== 0) end++;
  return buf.subarray(off, end).toString("latin1");
};

// --- Exports ---
const exp = dirs.find(d => d.name === "Export");
if (exp) {
  const eOff = rvaToOffset(exp.va);
  const dllName = readAscii(rvaToOffset(buf.readUInt32LE(eOff + 12)));
  const nFuncs = buf.readUInt32LE(eOff + 20), nNames = buf.readUInt32LE(eOff + 24);
  const addrRva = buf.readUInt32LE(eOff + 28), namesRva = buf.readUInt32LE(eOff + 32), ordRva = buf.readUInt32LE(eOff + 36);
  console.log("EXPORT dll:", dllName, "funcs:", nFuncs, "names:", nNames);
  const nOff = rvaToOffset(namesRva);
  for (let i = 0; i < Math.min(nNames, 20); i++) {
    const nameRva = buf.readUInt32LE(nOff + i*4);
    const fnRva = buf.readUInt32LE(rvaToOffset(addrRva) + i*4);
    console.log(`  export "${readAscii(rvaToOffset(nameRva))}" -> RVA 0x${fnRva.toString(16)} VA 0x${(0x140000000 + fnRva).toString(16)}`);
  }
}

// --- COFF symbol table ---
const ptrSymTab = buf.readUInt32LE(coff + 12);
const numSyms = buf.readUInt32LE(coff + 8);
console.log("\nCOFF symbol table:", ptrSymTab === 0 ? "YOK (stripped)" : `var, ${numSyms} sembol @0x${ptrSymTab.toString(16)}`);

// --- Debug dir (PDB) ---
const dbg = dirs.find(d => d.name === "Debug");
if (dbg) {
  const base = rvaToOffset(dbg.va);
  for (let i = 0; i < Math.floor(dbg.size/28); i++) {
    const off = base + i*28;
    const type = buf.readUInt32LE(off+12), size = buf.readUInt32LE(off+16), ptr = buf.readUInt32LE(off+24);
    const sig = buf.subarray(ptr, ptr+4).toString("latin1");
    console.log(`debug[${i}] type=${type} sig=${sig} size=${size}`);
    if (sig === "RSDS") {
      const guid = buf.subarray(ptr+4, ptr+20).toString("hex");
      const age = buf.readUInt32LE(ptr+20);
      console.log("  PDB:", readAscii(ptr+24), "guid:", guid, "age:", age);
    }
  }
}

// --- Resource tree ---
const res = dirs.find(d => d.name === "Resource");
const resTypes = ["CURSOR","BITMAP","ICON","MENU","DIALOG","STRINGTABLE","FONTDIR","FONT","ACCELERATOR","RCDATA","MESSAGETABLE","GROUP_CURSOR","GROUP_ICON","VERSION","DLGINCLUDE","PLAIN","VFT","MANIFEST"];
if (res) {
  const baseOff = rvaToOffset(res.va);
  const typeCount = buf.readUInt16LE(baseOff + 12);
  console.log("\nRESOURCE tree, root types:", typeCount);
  for (let t = 0; t < typeCount; t++) {
    const tOff = baseOff + 16 + t*8;
    const typeId = buf.readUInt32LE(tOff) & 0x7fffffff;
    const tEntryRva = buf.readUInt32LE(tOff+4) & 0x7fffffff;
    const tEntryOff = rvaToOffset(tEntryRva);
    const nameCount = buf.readUInt16LE(tEntryOff + 12);
    const typeName = typeId < 0x10 ? (resTypes[typeId-1] ?? `T${typeId}`) : `CUSTOM_${typeId}`;
    console.log(`  type ${typeName} (${typeId}), names: ${nameCount}`);
    for (let n = 0; n < Math.min(nameCount, 12); n++) {
      const nOff2 = tEntryOff + 16 + n*8;
      const nameId = buf.readUInt32LE(nOff2) & 0x7fffffff;
      const lEntryRva = buf.readUInt32LE(nOff2+4) & 0x7fffffff;
      const lOff = rvaToOffset(lEntryRva);
      const dataRva = buf.readUInt32LE(lOff), dataSize = buf.readUInt32LE(lOff+4);
      const dataOff = rvaToOffset(dataRva);
      const head = dataOff >= 0 ? buf.subarray(dataOff, dataOff+8).toString("latin1") : "";
      console.log(`    id=${nameId} rva=0x${dataRva.toString(16)} size=${dataSize} head="${head}"`);
    }
  }
}

// --- Image strings (tum dosya, min 5) ---
console.log("\n--- ASCII strings (offset, ilk 60) ---");
let start = -1, found = 0;
for (let i = 0; i < buf.length && found < 60; i++) {
  const b = buf[i];
  const printable = (b >= 0x20 && b <= 0x7e);
  if (printable) { if (start === -1) start = i; }
  else {
    if (start !== -1 && i - start >= 5) {
      const s = buf.subarray(start, i).toString("latin1");
      console.log(`0x${start.toString(16)}: ${s.slice(0, 120)}`);
      found++;
    }
    start = -1;
  }
}

// --- UTF-16 strings ---
console.log("\n--- UTF-16LE strings (ilk 40) ---");
const u16 = Buffer.from([0x00]);
start = -1; found = 0;
for (let i = 0; i + 1 < buf.length && found < 40; i += 2) {
  const b = buf[i], z = buf[i+1];
  const printable = (b >= 0x20 && b <= 0x7e) && z === 0x00;
  if (printable) { if (start === -1) start = i; }
  else {
    if (start !== -1 && (i - start) >= 10) {
      let s = "";
      for (let j = start; j < i; j += 2) s += String.fromCharCode(buf[j]);
      console.log(`0x${start.toString(16)}: ${s.slice(0, 120)}`);
      found++;
    }
    start = -1;
  }
}
