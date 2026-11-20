import fs from "node:fs";

const buf = fs.readFileSync("/home/z/my-project/storage/uploads/a5930196-1534-4ac5-bf81-486c33fb1aec__ROB_RUN.exe");

console.log("size:", buf.length);
const lfanew = buf.readUInt32LE(0x3c);
console.log("lfanew:", lfanew, "sig:", buf.subarray(lfanew, lfanew + 4).toString("latin1"));
const coff = lfanew + 4;
const machine = buf.readUInt16LE(coff);
const numSections = buf.readUInt16LE(coff + 2);
const sizeOfOpt = buf.readUInt16LE(coff + 16);
const characteristics = buf.readUInt16LE(coff + 18);
console.log("machine:", machine.toString(16), "sections:", numSections, "optSize:", sizeOfOpt, "chars:", characteristics.toString(16));

const opt = coff + 20;
const magic = buf.readUInt16LE(opt);
const is64 = magic === 0x20b;
console.log("magic:", magic.toString(16), "is64:", is64);
const imageBase = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
const numberOfRvaAndSizes = is64 ? buf.readUInt32LE(opt + 108) : buf.readUInt32LE(opt + 92);
const dirsOffset = opt + (is64 ? 112 : 96);
const dirNames = ["Export","Import","Resource","Exception","Security","BaseReloc","Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","COM","Rsv"];
const dirs: {name:string;va:number;size:number}[] = [];
for (let i = 0; i < Math.min(16, numberOfRvaAndSizes); i++) {
  const va = buf.readUInt32LE(dirsOffset + i*8);
  const size = buf.readUInt32LE(dirsOffset + i*8 + 4);
  if (va || size) dirs.push({name: dirNames[i], va, size});
}
console.log("dirs:", JSON.stringify(dirs));

const secTable = opt + sizeOfOpt;
const sections: {name:string;vs:number;va:number;rs:number;rp:number;ch:number}[] = [];
for (let i = 0; i < numSections; i++) {
  const off = secTable + i * 40;
  const name = buf.subarray(off, off+8).toString("latin1").replace(/\0+$/, "");
  const vs = buf.readUInt32LE(off+8), va = buf.readUInt32LE(off+12), rs = buf.readUInt32LE(off+16), rp = buf.readUInt32LE(off+20), ch = buf.readUInt32LE(off+36);
  sections.push({name,vs,va,rs,rp,ch});
  console.log(`sec ${name.padEnd(9)} VA=0x${va.toString(16)} VSZ=0x${vs.toString(16)} RAW=0x${rs.toString(16)}@0x${rp.toString(16)} ch=0x${ch.toString(16)}`);
}

const rvaToOffset = (rva: number): number => {
  for (const s of sections) {
    const span = Math.max(s.vs, s.rs);
    if (rva >= s.va && rva < s.va + span) {
      const off = rva - s.va + s.rp;
      return off < buf.length ? off : -1;
    }
  }
  return -1;
};

// .pdata parse (Exception dir)
const exc = dirs.find(d => d.name === "Exception");
if (exc) {
  const off = rvaToOffset(exc.va);
  const count = Math.floor(exc.size / 12);
  console.log("\n.pdata: entries =", count);
  const fns: {start:number;end:number}[] = [];
  for (let i = 0; i < Math.min(count, 100000); i++) {
    const o = off + i*12;
    if (o+12 > buf.length) break;
    const start = buf.readUInt32LE(o), end = buf.readUInt32LE(o+4);
    if (end > start) fns.push({start,end});
  }
  console.log("valid funcs:", fns.length, "first:", fns.slice(0,5).map(f=>`0x${f.start.toString(16)}-0x${f.end.toString(16)}`).join(" "));
}

// RTTI scan: ".?AV" ve ".?AU" tip descriptor isimleri (MSVC 64-bit)
console.log("\nRTTI .?AV (class) isimleri:");
const av = Buffer.from(".?AV", "latin1");
let idx = buf.indexOf(av);
let names: string[] = [];
while (idx !== -1 && names.length < 200) {
  let end = idx + 4;
  while (end < buf.length && end - idx < 120) {
    const b = buf[end];
    if ((b >= 0x20 && b < 0x7f) || b > 0x80) end++; else break;
  }
  const n = buf.subarray(idx, end).toString("latin1");
  if (n.length > 4 && !names.includes(n)) names.push(n);
  idx = buf.indexOf(av, idx + 4);
}
console.log(names.length, "adet:", names.slice(0, 60).join("\n  "));

console.log("\nRTTI .?AU (struct) isimleri:");
const au = Buffer.from(".?AU", "latin1");
idx = buf.indexOf(au);
let snames: string[] = [];
while (idx !== -1 && snames.length < 100) {
  let end = idx + 4;
  while (end < buf.length && end - idx < 120) {
    const b = buf[end];
    if ((b >= 0x20 && b < 0x7f) || b > 0x80) end++; else break;
  }
  const n = buf.subarray(idx, end).toString("latin1");
  if (n.length > 4 && !snames.includes(n)) snames.push(n);
  idx = buf.indexOf(au, idx + 4);
}
console.log(snames.length, "adet:", snames.slice(0, 40).join("\n  "));

// IL2CPP / Unity / UE marker kontrolu
for (const m of ["global-metadata", "il2cpp", "UnityPlayer", "UE4", "UE5", "Roblox", "roblox", "EAC", "BattlEye", "Denuvo", "vmprotect", "electron", "node.js", "Python", "pyi", "Mz"]) {
  const c = buf.indexOf(Buffer.from(m, "latin1"));
  console.log(`marker "${m}":`, c === -1 ? "YOK" : `0x${c.toString(16)}`);
}
