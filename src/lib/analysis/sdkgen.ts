// ----------------------------------------------------------------------------
// UnrealDumperX - SDK cikti uretici (Dumper-7 / Il2CppDumper benzeri)
//
// Dumper-7 cikti stili (referans: Dumper-7/Source/SDKGenerator):
//   SDK/{Oyun}_classes.h   -> siniflar + ofset yorumlari + fonksiyonlar
//   SDK/{Oyun}_structs.h   -> struct tanimlari (UnknownData_XX dolgulu)
//   SDK/{Oyun}_enums.h     -> enum tanimlari
//   SDK/SDK.hpp            -> ana baslik
// Il2CppDumper cikti stili:
//   dump.cs                -> C# iskeleti (namespace/class/fields/methods)
// Ilave DumperPro ciktilari:
//   Functions.txt (tam fonksiyon tablosu + disassembly + pseudo),
//   Debug.txt (debug dizini/PDB), Offsets.txt (adres haritasi)
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) Alan turleri tahminidir (genislige gore isaretsiz tamsayi); gercek
//      tip bilgisi canli mode veya metadata ile gelir. Basliklarda
//      "recovered (tahmini)" etiketi zorunludur - iddia suistimali olmasin.
//   2) Bilinmeyen araliklar Dumper-7 usulu uint8 UnknownData_0xXX[0xYY]
//      dolgusu ile yazilir (offset haritasi bozulmadan).
//   3) Ciktilar diskte storage/sdk/<uploadId>/ altina yazilir; web UI'den
//      tek tek indirilebilir.
// ----------------------------------------------------------------------------

import type { AnalysisResult, SdkFile } from "./types";

export interface GeneratedSdk {
  files: SdkFile[];
  contents: { name: string; content: string }[];
}

function fmtHex(n: number): string {
  return `0x${n.toString(16).padStart(2, "0").toUpperCase()}`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function safeBase(name: string): string {
  return (
    name
      .replace(/\.(exe|dll|sys|apk|so|bin|dat|pak|obb)$/i, "")
      .replace(/[^A-Za-z0-9_-]/g, "_")
      .slice(0, 48) || "Target"
  );
}

const HEADER = (r: AnalysisResult, what: string): string[] => {
  const L: string[] = [];
  L.push("// ============================================================================");
  L.push(`// UnrealDumperX - ${what}`);
  L.push(`// Hedef dosya : ${r.file.name} (${fmtBytes(r.file.size)})`);
  L.push(`// Motor       : ${r.engine.detected}${r.engine.version ? " " + r.engine.version : ""}`);
  L.push(`// Tarih       : ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC`);
  L.push("// NOT: alan turleri/offsetler statik kurtarmadir (tahmini); canli");
  L.push("// modda (--process/--pid) dogrulanmalidir. Yalnizca arastirma amacli.");
  L.push("// ============================================================================");
  L.push("");
  return L;
};

/** Dumper-7 stilinde UnknownData dolgulariyla C++ struct govdesi. */
function structBodyCpp(
  fields: { name: string; offset: number; size: number; type: string; reads: number }[],
  totalSize?: number,
  indent = "    ",
): string[] {
  const L: string[] = [];
  let cursor = 0;
  const sorted = [...fields].sort((a, b) => a.offset - b.offset);
  for (const f of sorted) {
    if (f.offset > cursor) {
      const gap = f.offset - cursor;
      L.push(`${indent}uint8 UnknownData_0x${cursor.toString(16).padStart(2, "0")}[0x${gap.toString(16).toUpperCase()}]; // dolgu`);
    }
    const type = cppType(f.type);
    L.push(`${indent}${type} ${f.name}; // 0x${f.offset.toString(16).toUpperCase()} (erisim: ${f.reads} fn)`);
    cursor = f.offset + f.size;
  }
  if (totalSize && totalSize > cursor) {
    const gap = totalSize - cursor;
    L.push(`${indent}uint8 UnknownData_0x${cursor.toString(16).padStart(2, "0")}[0x${gap.toString(16).toUpperCase()}]; // son dolgu`);
  }
  return L;
}

function cppType(t: string): string {
  switch (t) {
    case "uint8": return "uint8_t";
    case "uint16": return "uint16_t";
    case "uint32": return "uint32_t";
    case "uint64": return "uint64_t";
    case "void*": return "void*";
    case "float": return "float";
    default:
      if (t.startsWith("uint8[")) return `uint8_t[${t.slice(6, -1)}]`;
      return t;
  }
}

function cppIdent(name: string): string {
  const clean = name.replace(/[^A-Za-z0-9_]/g, "_");
  return /^[0-9]/.test(clean) ? `_${clean}` : clean || "unnamed";
}

export function buildSdkFiles(r: AnalysisResult): GeneratedSdk {
  const files: SdkFile[] = [];
  const contents: { name: string; content: string }[] = [];
  const base = safeBase(r.file.name);
  const isPe = r.kind === "pe" && !!r.pe;

  // ---------------- classes.h (RTTI siniflari) ----------------
  if (isPe && r.rtti && r.rtti.classes.length > 0) {
    const L = HEADER(r, `SDK siniflari - ${base}_classes.h (Dumper-7 stili)`);
    L.push("#pragma once");
    L.push("#include <cstdint>");
    L.push("");
    L.push("namespace DumperSDK {");
    for (const c of r.rtti.classes.slice(0, 256)) {
      L.push(`    // ${c.kind} ${c.name}${c.base ? ` : ${c.base}` : ""} - vftable ${c.vftableVa ? fmtHex(c.vftableVa) : "-"} (${c.methodCount} metod)`);
      L.push(`    ${c.kind === "struct" ? "struct" : "class"} ${cppIdent(c.name)}${c.base ? ` : ${cppIdent(c.base)}` : ""} {`);
      L.push(`    public:`);
      L.push(`        void* vftable; // ${fmtHex(0)} - ${c.vftableVa ? fmtHex(c.vftableVa) : ""}`);
      for (const m of c.methods.slice(0, 48)) {
        L.push(`        // metod: ${fmtHex(m.va)} (${fmtHex(m.rva)} RVA)`);
      }
      L.push(`    };`);
      L.push("");
    }
    L.push("} // namespace DumperSDK");
    const classesContent = L.join("\n");
    files.push({ name: `${base}_classes.h`, kind: "classes.h", size: classesContent.length });
    contents.push({ name: `${base}_classes.h`, content: classesContent });
  }

  // ---------------- structs.h (kurtarilan structlar) ----------------
  if (isPe && r.structs && r.structs.structs.length > 0) {
    const L = HEADER(r, `kurtarilan structlar - ${base}_structs.h (Dumper-7 stili)`);
    L.push("#pragma once");
    L.push("#include <cstdint>");
    L.push("");
    L.push("namespace DumperSDK {");
    for (const s of r.structs.structs.slice(0, 200)) {
      const cmt: string[] = [];
      if (s.size) cmt.push(`boyut ~${fmtHex(s.size)}`);
      if (s.vftableVa) cmt.push(`vftable ${fmtHex(s.vftableVa)}`);
      cmt.push(`kaynak: ${s.source}`);
      L.push(`    // ${s.name} - ${cmt.join(", ")}`);
      L.push(`    ${s.kind === "class" ? "class" : "struct"} ${cppIdent(s.name)} {`);
      L.push(`    public:`);
      for (const line of structBodyCpp(s.fields, s.size)) L.push(line);
      L.push(`    };`);
      L.push("");
    }
    L.push("} // namespace DumperSDK");
    const structsContent = L.join("\n");
    files.push({ name: `${base}_structs.h`, kind: "structs.h", size: structsContent.length });
    contents.push({ name: `${base}_structs.h`, content: structsContent });
  }

  // ---------------- enums.h ----------------
  const enumLines: string[] = [];
  if (isPe && r.enums) {
    const L = HEADER(r, `enumlar - ${base}_enums.h`);
    L.push("#pragma once");
    L.push("");
    L.push("namespace DumperSDK {");
    let idx = 0;
    for (const e of r.enums.enums.slice(0, 200)) {
      if (e.source === "rtti" && e.members.length === 0) {
        L.push(`    // enum ${e.name} (RTTI adi; degerler metadata/sembol gerektirir)`);
        L.push(`    enum ${cppIdent(e.name)} { };`);
        L.push("");
        idx++;
        continue;
      }
      L.push(`    // ${e.source} kaynagi${e.note ? ` - ${e.note}` : ""}`);
      L.push(`    enum ${cppIdent(e.name) || `enum_${idx}`} {`);
      for (const m of e.members.slice(0, 64)) {
        L.push(`        ${cppIdent(m.name)} = ${m.value},`);
      }
      L.push(`    };`);
      L.push("");
      idx++;
    }
    L.push("} // namespace DumperSDK");
    const enumsContent = L.join("\n");
    files.push({ name: `${base}_enums.h`, kind: "enums.h", size: enumsContent.length });
    contents.push({ name: `${base}_enums.h`, content: enumsContent });
  }

  // ---------------- dump.cs (IL2CPP metadata) ----------------
  if (r.il2cpp && r.il2cpp.sanityOk && r.il2cpp.classes.length > 0) {
    const L: string[] = [];
    L.push("// ============================================================================");
    L.push("// UnrealDumperX - dump.cs (Il2CppDumper benzeri)");
    L.push(`// Hedef: ${r.file.name} | IL2CPP metadata v${r.il2cpp.version} (${r.il2cpp.unityHint})`);
    L.push("// NOT: metodlarin RVA/adresleri GameAssembly.dll / libil2cpp.so analizi ister.");
    L.push("// ============================================================================");
    L.push("");
    for (const img of r.il2cpp.images.slice(0, 48)) {
      L.push(`// Image: ${img}`);
    }
    L.push("");
    for (const c of r.il2cpp.classes.slice(0, 500)) {
      const scope = c.namespace ? `namespace ${c.namespace}` : "namespace (global)";
      L.push(`// ${scope}`);
      L.push(`${c.kind === "struct" ? "struct" : c.kind === "interface" ? "interface" : "class"} ${c.name}${c.base ? ` : ${c.base}` : ""} // TypeDefIndex: n/a (metadata-yalniz)`);
      L.push("{");
      for (const f of c.fields) L.push(`\t/* field */ ${f}; // offset yok (binary eslestirmesi gerekir)`);
      for (const m of c.methods) L.push(`\tvoid ${m}(); // RVA: 0x0 (GameAssembly.dll gerekli)`);
      L.push("}");
      L.push("");
    }
    const dumpCsContent = L.join("\n");
    files.push({ name: "dump.cs", kind: "dump.cs", size: dumpCsContent.length });
    contents.push({ name: "dump.cs", content: dumpCsContent });

    // il2cpp enumlari dump.cs icinde - ayri dosya
    if (r.il2cpp.enums.length > 0) {
      const E: string[] = [];
      E.push("// IL2CPP enumlari (degerler fieldDefaultValues tablosundan)");
      E.push("");
      for (const e of r.il2cpp.enums.slice(0, 300)) {
        E.push(`// ${e.namespace ? `namespace ${e.namespace} - ` : ""}enum ${e.name}`);
        E.push("public enum " + e.name);
        E.push("{");
        for (const m of e.members.slice(0, 32)) {
          E.push(`\t${m.name} = ${m.value === null ? 0 : m.value},`);
        }
        E.push("}");
        E.push("");
      }
      const enumsCsContent = E.join("\n");
      files.push({ name: "il2cpp_enums.cs", kind: "enums.cs", size: enumsCsContent.length });
      contents.push({ name: "il2cpp_enums.cs", content: enumsCsContent });
      }
  }

  // ---------------- Functions.txt ----------------
  if (isPe && r.functions && r.functions.functions.length > 0) {
    const L: string[] = [];
    L.push("=".repeat(72));
    L.push(`UnrealDumperX - Fonksiyon tablosu: ${r.file.name}`);
    L.push(`Kaynak: ${r.functions.source} | toplam: ${r.functions.total} | analizli: ${r.functions.detailed}`);
    L.push("=".repeat(72));
    L.push("");
    for (const f of r.functions.functions.slice(0, 500)) {
      const lbl = f.label ?? f.structHint ? `${f.label ?? ""}${f.structHint ? ` [${f.structHint}]` : ""}` : "";
      L.push(`#${f.idx} ${fmtHex(f.va)} (RVA ${fmtHex(f.rva)}) boyut=${f.size} ${f.section}${lbl ? ` | ${lbl.trim()}` : ""}`);
      if (f.apiCalls.length) L.push(`    API: ${f.apiCalls.join(", ")}`);
      if (f.strings.length) L.push(`    Dizeler: ${f.strings.map((s) => `"${s.slice(0, 40)}"`).join(", ")}`);
      if (f.callsOut || f.xrefsIn) L.push(`    cikis cagri: ${f.callsOut} | gelen xref: ${f.xrefsIn}`);
      L.push(`    prologue: ${f.prologue}`);
      L.push("");
    }
    const functionsContent = L.join("\n");
    files.push({ name: "Functions.txt", kind: "Functions.txt", size: functionsContent.length });
    contents.push({ name: "Functions.txt", content: functionsContent });

    // Decompile.txt: asm + pseudo olan fonksiyonlar
    const D: string[] = [];
    D.push("=".repeat(72));
    D.push(`UnrealDumperX - Disassembly + tahmini pseudo-C: ${r.file.name}`);
    D.push("// x86-64 cozucu yaygin komut alt kumesini cozer; bilinmeyenler 'db'.");
    D.push("// Pseudo-C yaklasiktir (veri akisi tam takip edilmez) - dogrulama canli modda.");
    D.push("=".repeat(72));
    D.push("");
    for (const f of r.functions.functions) {
      if (!f.asm && !f.pseudo) continue;
      D.push("-".repeat(72));
      D.push(`FONKSIYON ${f.label ?? `sub_${f.va.toString(16).toUpperCase()}`} @ ${fmtHex(f.va)} (RVA ${fmtHex(f.rva)}, ${f.size} bayt)`);
      if (f.structHint) D.push(`  Sinif ipucu: ${f.structHint}`);
      if (f.asm) {
        D.push("  --- assembly ---");
        for (const line of f.asm.split("\n")) D.push("  " + line);
      }
      if (f.pseudo) {
        D.push("  --- tahmini pseudo-C ---");
        for (const line of f.pseudo.split("\n")) D.push("  " + line);
      }
      D.push("");
    }
    const decompileContent = D.join("\n");
    files.push({ name: "Decompile.txt", kind: "Decompile.txt", size: decompileContent.length });
    contents.push({ name: "Decompile.txt", content: decompileContent });
  }

  // ---------------- Debug.txt ----------------
  if (isPe && r.pe?.debug) {
    const L: string[] = [];
    L.push("=".repeat(72));
    L.push(`UnrealDumperX - Debug bilgisi: ${r.file.name}`);
    L.push("=".repeat(72));
    L.push("");
    if (r.pe.debug.pdb) {
      L.push(`PDB yolu : ${r.pe.debug.pdb.path}`);
      L.push(`PDB GUID : ${r.pe.debug.pdb.guid}`);
      L.push(`PDB Age  : ${r.pe.debug.pdb.age}`);
      L.push("");
      L.push("Microsoft sembol sunucusuna sorgu icin:");
      const pdbName = r.pe.debug.pdb.path.split(/[\\/]/).pop() ?? "";
      L.push(`  ${pdbName}/${r.pe.debug.pdb.guid}${r.pe.debug.pdb.age}/${pdbName}`);
      L.push("");
    } else {
      L.push("PDB (CODEVIEW) kaydi yok.");
      L.push("");
    }
    for (const e of r.pe.debug.entries) {
      L.push(`debug[${e.index}] ${e.type} (type=${e.rawType}) size=${e.size} rva=${fmtHex(e.rva)}${e.detail ? ` | ${e.detail}` : ""}`);
    }
    if (r.pe.debug.coffSymbols === 0) {
      L.push("");
      L.push("COFF sembol tablosu: YOK (stripped)");
    } else {
      L.push("");
      L.push(`COFF sembol tablosu: ${r.pe.debug.coffSymbols} sembol`);
      for (const s of r.pe.debug.coffSymbolSamples.slice(0, 40)) L.push(`  ${s}`);
    }
    if (r.pe.debug.reproducible) L.push("\nREPRODUCIBLE build kaydi mevcut (derleme zamani gercek degil).");
    const debugContent = L.join("\n");
    files.push({ name: "Debug.txt", kind: "Debug.txt", size: debugContent.length });
    contents.push({ name: "Debug.txt", content: debugContent });
  }

  // ---------------- Offsets.txt ----------------
  if (isPe && r.pe) {
    const L: string[] = [];
    L.push("=".repeat(72));
    L.push(`UnrealDumperX - Adres haritasi: ${r.file.name}`);
    L.push("=".repeat(72));
    L.push("");
    L.push(`ImageBase   : ${fmtHex(r.pe.imageBase)}`);
    L.push(`Entry (RVA) : ${fmtHex(r.pe.entryPointRva)}`);
    L.push(`Entry (VA)  : ${fmtHex(r.pe.imageBase + r.pe.entryPointRva)}`);
    L.push(`SizeOfImage : ${fmtHex(r.pe.sizeOfImage)}`);
    L.push("");
    for (const s of r.pe.sections) {
      L.push(`section ${s.name.padEnd(10)} VA=${fmtHex(s.virtualAddress)} VSZ=${fmtHex(s.virtualSize)} raw=${fmtHex(s.rawSize)}`);
    }
    if (r.pe.exports && r.pe.exports.entries?.length) {
      L.push("");
      L.push("Disa aktarma:");
      for (const e of r.pe.exports.entries) {
        L.push(`  ${e.name.padEnd(48)} RVA=${fmtHex(e.rva)} VA=${fmtHex(e.va)}`);
      }
    }
    if (r.rtti?.classes.length) {
      L.push("");
      L.push("vftable'lar (RTTI):");
      for (const c of r.rtti.classes.slice(0, 128)) {
        L.push(`  ${c.name.padEnd(48)} ${c.vftableVa ? fmtHex(c.vftableVa) : "-"}`);
      }
    }
    const offsetsContent = L.join("\n");
    files.push({ name: "Offsets.txt", kind: "Offsets.txt", size: offsetsContent.length });
    contents.push({ name: "Offsets.txt", content: offsetsContent });
  }

  // ---------------- SDK.hpp ----------------
  if (files.some((f) => f.kind === "classes.h" || f.kind === "structs.h")) {
    const L: string[] = [];
    L.push("// UnrealDumperX SDK ana basligi (Dumper-7 SDK.hpp stili)");
    L.push("#pragma once");
    L.push(`#include "${base}_classes.h"`);
    L.push(`#include "${base}_structs.h"`);
    L.push(`#include "${base}_enums.h"`);
    const sdkHppContent = L.join("\n");
    files.push({ name: "SDK.hpp", kind: "SDK.hpp", size: sdkHppContent.length });
    contents.push({ name: "SDK.hpp", content: sdkHppContent });
  }

  return { files, contents };
}
