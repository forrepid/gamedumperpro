// ----------------------------------------------------------------------------
// DumperPro Online - analiz orkestratoru
//
// Hatt: magic tespit -> format parser (PE/ELF/ZIP-APK/DEX/metadata) ->
// motor/guvenlik taramasi -> derin statik analiz (fonksiyon tablosu +
// disassembly + tahmini pseudo-C, RTTI, struct/enum kurtarma, kaynak agaci,
// IL2CPP metadata) -> imza adaylari -> string cikarimi -> SDK uretimi
// (Dumper-7 / Il2CppDumper stili) -> rapor + games.ini
// ----------------------------------------------------------------------------

import crypto from "node:crypto";

import { detectFile } from "./detect";
import { parsePe } from "./pe";
import { parseElf } from "./elf";
import { parseDex } from "./dex";
import {
  parseZipCentralDirectory,
  extractZipEntry,
  parseAxmlManifest,
  type ZipEntryRaw,
} from "./zipapk";
import { scanEngineAndSecurity, pickInterestingStrings } from "./engine";
import { scanSignatureCandidates } from "./sigs";
import { buildReport, buildGamesIniSuggestion } from "./report";
import { entropy, extractAsciiStrings, findUeVersionStrings, ciContains } from "./util";
import { analyzeFunctions, buildIatMap, collectExportEntries } from "./functions";
import { analyzeRtti } from "./rtti";
import { analyzeResources } from "./resources";
import { analyzeStructs } from "./structs";
import { analyzeEnums } from "./enums";
import { disassemble, buildPseudo } from "./disasm";
import { parseIl2CppMetadata, looksLikeMetadata, parseIl2CppMetadataCore } from "./metadata";
import { maybeAnalyzeIl2CppBinary } from "./il2cppbin";
import { parseGameFiles } from "./gamefiles";
import { parseVdex, parseOat, extractDex } from "./vdex";
import { parsePdb } from "./pdb";
import { analyzeMemoryDump } from "./mem";
// NOT: savegame/vdf ozetleri queue.ts tarafindan dinamik yuklenir (bellek limiti)
import { buildSdkFiles } from "./sdkgen";
import { buildExtractors, claimExtractorFiles } from "./extractors";
import { getSectionRaw } from "./pe";
import type { AnalysisResult, FileKind, ApkEntry } from "./types";

export interface FullAnalysis {
  result: AnalysisResult;
  report: string;
  /** SDK ciktilari icerigi (upload route diske yazar; manifest result.sdk'te) */
  sdkContents: { name: string; content: string }[];
}

// ---- decompile/asm butcesi (DB satiri sismemesin) ----
const MAX_PSEUDO_FNS = 48; // DB'de asm+pseudo tutulacak fonksiyon adedi
const MAX_ASM_LINES = 320;
const MAX_PSEUDO_LINES = 120;

export interface AnalyzeOptions {
  /** bagli global-metadata.dat (IL2CPP binary eslestirmesi icin) */
  il2cppMetadata?: Buffer;
  /** bagli memmap metni (raw bellege esleme icin) */
  memmapText?: string;
  /** eslesen .pdb dosyasi (sembol cikarma icin; pdb modulu kullanir) */
  pdbBuffer?: Buffer;
}

export function analyzeBuffer(buf: Buffer, fileName: string, opts: AnalyzeOptions = {}): FullAnalysis {
  const notes: string[] = [];
  const errors: string[] = [];

  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
  const overallEntropy = entropy(buf, 8 * 1024 * 1024);

  const det = detectFile(buf, fileName);
  let kind: FileKind = det.kind;
  notes.push(`Format tespiti: ${det.detail}`);

  // engine/security icin string havuzu
  const asciiStrings = extractAsciiStrings(buf, 8, 4000);

  // --- motor + guvenlik taramasi (TDZ kurali: once engine!) ---
  const scan = scanEngineAndSecurity(buf, asciiStrings);
  const engine = scan.engine;
  const security = scan.security;

  // --- PE ---
  let pe: AnalysisResult["pe"];
  if (kind === "pe") {
    try {
      pe = parsePe(buf, errors);
    } catch (e) {
      errors.push(`PE parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- ELF ---
  let elf: AnalysisResult["elf"];
  if (kind === "elf") {
    try {
      elf = parseElf(buf, errors);
      notes.push(
        elf.machine.includes("ARM")
          ? "ARM/AArch64 ikili - Windows canli moduna uymaz; statik tarama uygundur."
          : "x86-64 ELF - statik tarama uygundur.",
      );
    } catch (e) {
      errors.push(`ELF parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- DEX (standalone classes.dex / .odex yuklemesi) ---
  let dex: AnalysisResult["dex"];
  if (kind === "dex") {
    try {
      dex = parseDex(buf, errors);
      if (dex) {
        notes.push(
          `DEX v${dex.version} (${dex.endian}): ${dex.classes} sinif, ${dex.methods} metod, ${dex.strings} string` +
            (dex.checksumOk ? " - checksum gecerli" : " - checksum UYUSMUYOR"),
        );
        if (dex.engineHints.length) {
          notes.push(`DEX string havuzunda ipuclari: ${dex.engineHints.slice(0, 4).join(", ")}`);
        }
        if (engine.detected === "Bilinmiyor") {
          const hints = dex.engineHints.join(" ").toLowerCase();
          if (hints.includes("epic") || hints.includes("unreal")) {
            engine.detected = "Unreal Engine";
            engine.confidence = "dusuk";
          } else if (hints.includes("unity") || hints.includes("il2cpp")) {
            engine.detected = "Unity";
            engine.confidence = "dusuk";
          } else if (hints.includes("godot")) {
            engine.detected = "Godot";
            engine.confidence = "dusuk";
          }
        }
      }
    } catch (e) {
      errors.push(`DEX parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- Unity IL2CPP global-metadata.dat ---
  let il2cpp: AnalysisResult["il2cpp"];
  if (kind === "metadata" || looksLikeMetadata(buf)) {
    try {
      il2cpp = parseIl2CppMetadata(buf, notes);
      if (il2cpp) {
        if (kind === "unknown") kind = "metadata";
        notes.push(
          `IL2CPP metadata v${il2cpp.version} (${il2cpp.unityHint}): ${il2cpp.classCount} sinif, ${il2cpp.methodCount} metod, ${il2cpp.enums.length} enum - Il2CppDumper benzeri dump.cs uretilecek`,
        );
        engine.detected = "Unity (IL2CPP)";
        engine.confidence = "yuksek";
      }
    } catch (e) {
      errors.push(`IL2CPP metadata parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- ZIP / APK ---
  let apk: AnalysisResult["apk"];
  let zip: AnalysisResult["zip"];
  if (kind === "zip" || kind === "unknown") {
    try {
      const zipEntries = parseZipCentralDirectory(buf);
      const hasManifest = zipEntries.some((e) => e.name === "AndroidManifest.xml");
      const hasDex = zipEntries.some((e) => e.name.endsWith(".dex"));
      if (hasManifest) {
        kind = "apk";
        apk = analyzeApk(buf, zipEntries, errors, notes);
        notes.push(`APK yapisi: ${hasDex ? "AndroidManifest.xml + dex dogrulandi" : "manifest bulundu (dex yok)"}`);
      } else if (zipEntries.length > 0) {
        zip = analyzeZip(zipEntries);
        notes.push("ZIP konteyneri (Android manifest yok)");
      }
    } catch (e) {
      // ZIP degilse sessiz gec (unknown kalir)
      if (kind === "zip") {
        errors.push(`ZIP parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  // --- derin PE analizi: fonksiyonlar + disassembly + pseudo-C ---
  let functions: AnalysisResult["functions"];
  let rtti: AnalysisResult["rtti"];
  let structs: AnalysisResult["structs"];
  let enums: AnalysisResult["enums"];
  let resources: AnalysisResult["resources"];
  let il2cppBin: AnalysisResult["il2cppBin"];
  let gameFiles: AnalysisResult["gameFiles"];
  let art: AnalysisResult["art"];
  let pdb: AnalysisResult["pdb"];
  let mem: AnalysisResult["mem"];

  // --- ortak oyun dosyalari (pak/utoc/uasset/macho) ---
  if (kind === "pak" || kind === "utoc" || kind === "ucas" || kind === "uasset" || kind === "umap" || kind === "macho") {
    try {
      const gf = parseGameFiles(buf, kind, fileName, notes);
      if (gf) {
        gameFiles = gf;
        if (kind === "pak" || kind === "utoc" || kind === "uasset" || kind === "umap") {
          if (engine.detected === "Bilinmiyor") {
            engine.detected = "Unreal Engine";
            engine.confidence = "yuksek";
          }
        } else if (kind === "macho" && engine.detected === "Bilinmiyor") {
          engine.detected = "iOS/macOS hedefi";
          engine.confidence = "orta";
        }
      }
    } catch (e) {
      errors.push(`Oyun dosyasi analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- bellek dump (LeechCore/MemProcFS benzeri) ---
  // raw dump (kind unknown) + memmap eslesmesi reverse-pairing ile gelir;
  // bu durumda da cihaz kurulup modul/bolge haritasi uretilir.
  if (kind === "minidump" || kind === "memmap" || (kind === "unknown" && opts.memmapText)) {
    try {
      const mres = analyzeMemoryDump(buf, fileName, { memmapText: opts.memmapText });
      if (mres) {
        mem = mres.info;
        notes.push(`Bellek cihazi: ${mem.device} - ${mem.moduleCount} modul, ${mem.regionCount} bolge, ${(mem.totalMemoryBytes / 1024 / 1024).toFixed(1)} MB erisilebilir bellek`);
      } else if (kind === "memmap") {
        notes.push("memmap tanim dosyasi okundu ancak eslesme icin raw dump cifti gerekir");
      }
    } catch (e) {
      errors.push(`Bellek dump analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (pe) {
    // export entries (RVA tablosu) zenginlestir
    try {
      const exportEntries = collectExportEntries(buf, pe);
      if (pe.exports && exportEntries.length) pe.exports.entries = exportEntries;
    } catch (e) {
      errors.push(`Export tablosu genisletilemedi: ${e instanceof Error ? e.message : String(e)}`);
    }

    // fonksiyon tablosu
    try {
      functions = analyzeFunctions(buf, pe, errors);
    } catch (e) {
      errors.push(`Fonksiyon analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }

    // RTTI
    try {
      rtti = analyzeRtti(buf, pe, errors);
    } catch (e) {
      errors.push(`RTTI analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }

    // kaynak agaci + versiyon bilgisi
    try {
      const res = analyzeResources(buf, pe, errors);
      resources = res.resources;
      if (res.versionInfo) pe.versionInfo = res.versionInfo;
    } catch (e) {
      errors.push(`Kaynak analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- struct/enum kurtarma + secili fonksiyonlar icin decompile ---
  let sdkContents: { name: string; content: string }[] = [];
  if (pe && functions) {
    try {
      const deep = analyzeStructs(buf, pe, functions, rtti);
      structs = deep.structs;

      // enum kurtarma (switch tablolari + RTTI adlari)
      const enumRes = analyzeEnums(buf, pe, rtti, deep.leaTargets);
      enums = enumRes.enums;

      // fonksiyon ipuclarini yaz
      for (const f of functions.functions) {
        const hint = deep.fnClassHints.get(f.rva);
        if (hint) f.structHint = hint;
      }

      // secili fonksiyonlar icin disassembly + pseudo-C uretir
      attachDecompilation(buf, pe, functions, deep.fnClassHints, rtti);
    } catch (e) {
      errors.push(`Struct/enum kurtarma hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- IL2CPP binary tarafi (GameAssembly.dll / libil2cpp.so) ---
  let il2cppBinFiles: { dumpCs: string | null; scriptJson: string | null } | null = null;
  if (kind === "pe" || kind === "elf") {
    try {
      const lowName = fileName.toLowerCase();
      const isIl2cpp =
        lowName.includes("gameassembly") ||
        lowName.includes("libil2cpp") ||
        buf.indexOf(Buffer.from("mscorlib.dll", "latin1")) !== -1;
      if (isIl2cpp) {
        let metaCore;
        if (opts.il2cppMetadata) {
          const mdNotes: string[] = [];
          metaCore = parseIl2CppMetadataCore(opts.il2cppMetadata, mdNotes)?.core;
          if (!metaCore) notes.push("IL2CPP eslestirme: metadata cekirdegi okunamadi");
        }
        const res = maybeAnalyzeIl2CppBinary(buf, kind, pe, { metadata: metaCore, fileName });
        if (res) {
          il2cppBin = res.info;
          il2cppBinFiles = { dumpCs: res.dumpCs, scriptJson: res.scriptJson };
          if (res.info.detected) {
            notes.push(
              `IL2CPP binary: ${res.info.methodPointersResolved} metod isaretcisi eslesti` +
                (res.info.linked ? " - metadata baglandi, dump.cs + script.json uretildi" : ""),
            );
          }
        }
      }
    } catch (e) {
      errors.push(`IL2CPP binary analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- ART VDEX/OAT gomulu DEX (vdexExtractor mantigi; Gorev 4) ---
  if (kind === "vdex" || kind === "oat" || kind === "cdex") {
    try {
      if (kind === "cdex") {
        notes.push("Compact DEX (cdex): cikarma kapsamda degil - yalnizca dogrulama");
      } else {
        const info = kind === "vdex" ? parseVdex(buf) : parseOat(buf);
        if (info) {
          const dexSummaries: NonNullable<AnalysisResult["art"]>["dexes"] = info.dexes.slice(0, 8).map((e) => {
            const slice = extractDex(buf, e);
            const dres = slice.length >= 64 ? parseDex(slice, errors) : null;
            return {
              index: e.index,
              offset: e.offset,
              size: e.size,
              classes: dres?.classes,
              methods: dres?.methods,
              strings: dres?.strings,
            };
          });
          art = {
            kind: info.kind === "vdex" ? "vdex" : "oat",
            version: info.version,
            apiHint: info.apiHint,
            dexSectionVersion: info.kind === "vdex" ? info.dexSectionVersion : undefined,
            dexCount: info.dexes.length,
            dexes: dexSummaries,
            notes: info.notes,
            error: info.error,
          };
          notes.push(
            `ART ${info.kind.toUpperCase()} v${info.version} (${info.apiHint}): ${info.dexes.length} gomulu DEX bulundu` +
              (info.error ? ` [${info.error}]` : ""),
          );
        } else {
          errors.push(`${kind.toUpperCase()} parse hatasi: baslik gecerli ama icerik cozulemedi`);
        }
      }
    } catch (e) {
      errors.push(`ART analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- eslesen .pdb sembolleri (MSF/DBI/S_PUB32/S_UDT; Gorev 3) ---
  if (opts.pdbBuffer) {
    try {
      const p = parsePdb(opts.pdbBuffer);
      if (p) {
        pdb = {
          valid: p.valid,
          version: p.version,
          signature: p.signature,
          age: p.age,
          guid: p.guid,
          machine: p.machine,
          streamCount: p.streamCount,
          sectionCount: p.sectionCount,
          funcCount: p.funcCount,
          dataCount: p.dataCount,
          udtCount: p.udtCount,
          symbols: p.symbols.slice(0, 500),
          symbolsTotal: p.symbols.length,
          udtNames: p.udtNames.slice(0, 300),
          udtTotal: p.udtNames.length,
          sections: p.sections.slice(0, 96),
          notes: p.notes,
          error: p.error,
        };
        if (p.valid && (p.funcCount + p.dataCount > 0)) {
          notes.push(
            `PDB sembolleri: ${p.funcCount} fonksiyon + ${p.dataCount} veri + ${p.udtCount} UDT (GUID ${p.guid}, age ${p.age})`,
          );
        } else {
          notes.push(`PDB eslesti ancak sembol cikarilamadi${p.error ? `: ${p.error}` : ""}`);
        }
      }
    } catch (e) {
      errors.push(`PDB sembol analizi hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- PE il2cpp ipuclari (exe tek basina: launcher stub tespiti) ---
  if (pe && !il2cpp) {
    const pdbName = (pe.debugPdb ?? "").toLowerCase();
    const stringsJoined = asciiStrings.slice(0, 800).join(" ").toLowerCase();
    const il2cppHint =
      pdbName.includes("il2cpp") ||
      stringsJoined.includes("gameassembly.dll") ||
      stringsJoined.includes("global-metadata.dat");
    if (il2cppHint && engine.detected.startsWith("Unity")) {
      engine.detected = "Unity (IL2CPP)";
      engine.confidence = "yuksek";
    }
    if (il2cppHint || engine.detected === "Unity" || engine.detected === "Unity (IL2CPP)") {
      notes.push(
        "Unity IL2CPP hedefi: sinif/enum/struct verileri GameAssembly.dll + global-metadata.dat icindedir. " +
          "Bu dosyalari da yukleyin: metadata tam parse edilir, dump.cs + enum/struct degerleri uretilir.",
      );
    }
  }

  // APK icinde .so taramasindan gelen motor bilgiyi birlestir
  if (apk?.scannedLibs.length) {
    for (const lib of apk.scannedLibs) {
      if (lib.engine && engine.detected === "Bilinmiyor") {
        engine.detected = lib.engine;
        engine.version = lib.version;
        engine.confidence = "orta";
      }
      for (const v of lib.versionStrings) {
        if (!engine.versionStrings.includes(v)) engine.versionStrings.push(v);
      }
      if (lib.engine && (lib.engine === "UE4" || lib.engine === "UE5") && !engine.version && lib.version) {
        engine.version = lib.version;
      }
    }
  }

  if (pe) {
    const text = pe.sections.find((s) => s.name === ".text");
    if (text && text.entropy > 7.2) {
      security.packedHint = true;
      notes.push(`.text entropy ${text.entropy} - paketleyici (packer) olasiligi yuksek.`);
    }
  }

  // --- imza adaylari (PE only) ---
  let signatureCandidates: AnalysisResult["signatureCandidates"] = [];
  if (pe) {
    signatureCandidates = scanSignatureCandidates(buf, pe.sections, pe.imageBase);
    const withHits = signatureCandidates.filter((c) => c.hits.length > 0);
    if (withHits.length) {
      notes.push(
        `${withHits.length} desen icin imza adayi bulundu. Statik adaylar dogrulanmamistir; ` +
        `canli modda (--process/--pid) RIP-relative cozumlemeyle teyit edilir.`,
      );
    } else {
      notes.push(
        "Bilinen desenlerde eslesme yok - ozel/obfuscate build olabilir; games.ini'ye manuel adres girilebilir.",
      );
    }
  } else {
    notes.push("Imza aday taramasi RVA/VA uretimi icin PE formatinda yapilir.");
  }

  const strings = pickInterestingStrings(asciiStrings, 250);

  const result: AnalysisResult = {
    kind,
    file: { name: fileName, size: buf.length, sha256 },
    overallEntropy,
    pe,
    elf,
    dex,
    apk,
    zip,
    engine,
    security,
    signatureCandidates,
    strings,
    functions,
    rtti,
    resources,
    structs,
    enums,
    il2cpp,
    il2cppBin,
    gameFiles,
    art,
    pdb,
    mem,
    // savegame/vdf: queue.ts dinamik zenginlestirme ile doldurulur (bellek limiti)
    gamesIniSuggestion: buildGamesIniSuggestion({ file: { name: fileName, size: buf.length, sha256 }, kind, engine } as AnalysisResult),
    notes,
    errors,
  };

  // --- SDK uretimi (Dumper-7 / Il2CppDumper stili) ---
  try {
    const sdk = buildSdkFiles(result);
    sdkContents = sdk.contents;
    // bagli IL2CPP ciktilari: dump.cs (RVA'li) + script.json
    if (il2cppBinFiles?.dumpCs) {
      sdkContents.push({ name: "dump.cs", content: il2cppBinFiles.dumpCs });
    }
    if (il2cppBinFiles?.scriptJson) {
      sdkContents.push({ name: "script.json", content: il2cppBinFiles.scriptJson });
    }
    // eslesen .pdb sembol ciktisi (Gorev 3)
    if (pdb && pdb.valid && pdb.symbols.length > 0) {
      const base = fileName.replace(/\.[^.]+$/, "");
      const lines: string[] = [
        `// PDB sembolleri - ${base}`,
        `// GUID ${pdb.guid} age ${pdb.age} machine ${pdb.machine}`,
        `// ${pdb.symbolsTotal} sembol (func ${pdb.funcCount} / data ${pdb.dataCount}), ${pdb.udtTotal} UDT`,
        "",
        "# Fonksiyonlar (S_PUB32: RVA = VA - ImageBase)",
        ...pdb.symbols
          .filter((s) => s.kind === "func")
          .map((s) => `FUNC rva=0x${(s.rva ?? 0).toString(16).padStart(8, "0")} seg=${s.seg} off=0x${s.off.toString(16)} ${s.name}`),
        "",
        "# Veri sembolleri (S_PUB32 data + S_GDATA32)",
        ...pdb.symbols
          .filter((s) => s.kind === "data")
          .map((s) => `DATA rva=0x${(s.rva ?? 0).toString(16).padStart(8, "0")} seg=${s.seg} off=0x${s.off.toString(16)} ${s.name}`),
        "",
        "# UDT (sinif/struct tip adlari)",
        ...pdb.udtNames.map((u) => `UDT ${u}`),
      ];
      sdkContents.push({ name: `PDB_${base}_symbols.txt`, content: lines.join("\n") });
    }
    const seenSdk = new Set<string>();
    sdkContents = sdkContents.filter((c) => (seenSdk.has(c.name) ? false : (seenSdk.add(c.name), true)));

    // --- coklu cikarici ciktilari (Dumper-7 / Il2CppDumper / UnrealCEDumper /
    //     MemProcFS / LeechCore) + model ortak verileri ---
    try {
      const ex = buildExtractors(result);
      result.extractors = ex.info;
      for (const f of ex.files) {
        if (!seenSdk.has(f.name)) {
          sdkContents.push({ name: f.name, content: f.content });
          seenSdk.add(f.name);
        }
      }
      claimExtractorFiles(result.extractors, fileName, sdkContents.map((c) => ({ name: c.name, kind: c.name, size: c.content.length })));
      notes.push(`Coklu cikarici: ${result.extractors.extractors.filter((e) => e.available).length}/6 model cikti uretti (Dumper-7, DumperPro, Il2CppDumper, UnrealCEDumper, MemProcFS, LeechCore)`);
    } catch (e) {
      errors.push(`Cikarici modulu hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }

    if (sdkContents.length > 0) {
      result.sdk = {
        generator: il2cppBinFiles?.dumpCs
          ? "Il2CppDumper dump.cs + script.json (bagli eslestirme)"
          : il2cpp
            ? "Dumper-7 C++ + Il2CppDumper dump.cs karisik"
            : "Dumper-7 benzeri C++ SDK",
        files: sdkContents.map((c) => ({ name: c.name, kind: c.name, size: c.content.length })),
        note: "Dosyalar sunucuda storage/sdk/ altinda; panel'den goruntuleyin veya indirin. Cikarici gruplari Cikaricilar sekmesinde.",
      };
    }
  } catch (e) {
    errors.push(`SDK uretimi hatasi: ${e instanceof Error ? e.message : String(e)}`);
  }

  const report = buildReport(result);
  return { result, report, sdkContents };
}

// ----------------------------------------------------------------------------
// Secili fonksiyonlara disassembly + tahmini pseudo-C ekler.
// Secim: export'lar, EntryPoint, en buyuk 16, string/API referansli 24,
// RTTI metodu olan 12 - toplam MAX_PSEUDO_FNS.
// ----------------------------------------------------------------------------
function attachDecompilation(
  buf: Buffer,
  pe: NonNullable<AnalysisResult["pe"]>,
  functions: NonNullable<AnalysisResult["functions"]>,
  fnClassHints: Map<number, string>,
  rtti: AnalysisResult["rtti"],
): void {
  const iatMap = buildIatMap(buf, pe);

  // string havuzu: rdata'daki yazilabilir diziler (decompile yorumlari icin)
  const stringsVa = new Map<number, string>();
  const fnLabels = new Map<number, string>();
  const rdataLabels = new Map<number, string>();

  for (const s of pe.sections) {
    const data = getSectionRaw(buf, s);
    if (!data) continue;
    if (s.name === ".rdata" || s.name === ".data") {
      let start = -1;
      const cap = Math.min(data.length, 4 * 1024 * 1024);
      for (let i = 0; i < cap; i++) {
        const b = data[i];
        const printable = b >= 0x20 && b <= 0x7e;
        if (printable) {
          if (start === -1) start = i;
        } else {
          if (start !== -1 && i - start >= 6) {
            const va = pe.imageBase + s.virtualAddress + start;
            if (stringsVa.size < 4000) stringsVa.set(va, data.subarray(start, i).toString("latin1"));
          }
          start = -1;
        }
      }
    }
  }

  // vftable etiketleri (RTTI) + fonksiyon etiketleri
  for (const c of rtti?.classes ?? []) {
    if (c.vftableVa !== undefined) rdataLabels.set(c.vftableVa, `${c.name}::vftable`);
  }
  if (functions.functions.length) {
    for (const f of functions.functions) {
      if (f.label) fnLabels.set(f.va, f.label);
    }
  }

  // secim: oncelik sirasiyla
  const all = functions.functions;
  const selected = new Set<number>();
  const addIdx = (pred: (f: (typeof all)[number]) => boolean, cap: number): void => {
    for (const f of all) {
      if (selected.size >= MAX_PSEUDO_FNS) return;
      if (pred(f)) selected.add(f.idx);
      if (selected.size >= cap) return;
    }
  };
  addIdx((f) => !!f.label, 8);
  addIdx((f) => (f.strings.length > 0 || f.apiCalls.length > 0) && f.size < 32768, 20);
  addIdx((f) => fnClassHints.has(f.rva) && f.size < 32768, 34);
  const bySize = [...all].sort((a, b) => b.size - a.size);
  for (const f of bySize) {
    if (selected.size >= MAX_PSEUDO_FNS) break;
    if (f.size > 0 && f.size < 65536) selected.add(f.idx);
  }

  let disassembled = 0;
  for (const f of all) {
    if (!selected.has(f.idx)) continue;
    const sec = pe.sections.find((s) => s.virtualAddress <= f.rva && f.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
    if (!sec || sec.name !== ".text") continue;
    const rel = f.rva - sec.virtualAddress + sec.rawPointer;
    if (rel < 0 || rel + f.size > buf.length || f.size === 0) continue;

    const res = disassemble(buf, rel, Math.min(f.size, 32768), f.va, MAX_ASM_LINES, iatMap, (va) => stringsVa.get(va) ?? null, (va) => rdataLabels.get(va) ?? null);
    const lines = res.insns.map((i) => {
      const target = i.text.match(/^(call|jmp) 0x([0-9A-F]+)/);
      if (target) {
        const tVa = parseInt(target[2], 16);
        const lbl = fnLabels.get(tVa);
        if (lbl) return `${i.va.toString(16).toUpperCase()}  ${i.text}  ; ${lbl}`;
        return `${i.va.toString(16).toUpperCase()}  ${i.text}  ; sub_${tVa.toString(16).toUpperCase()}`;
      }
      return `${i.va.toString(16).toUpperCase()}  ${i.text}`;
    });

    const pseudo = buildPseudo(res.insns, f.va, {
      strings: stringsVa,
      iatMap,
      fnLabels,
      rdataLabels,
    }, MAX_PSEUDO_LINES);

    f.asm = lines.slice(0, MAX_ASM_LINES).join("\n");
    f.pseudo = pseudo;
    disassembled++;
    if (disassembled >= MAX_PSEUDO_FNS) break;
  }
  functions.disassembled = disassembled;
}

// --- APK icerik analizi ---
function analyzeApk(
  buf: Buffer,
  entries: ZipEntryRaw[],
  errors: string[],
  notes: string[],
): NonNullable<AnalysisResult["apk"]> {
  const apk: NonNullable<AnalysisResult["apk"]> = {
    abis: [],
    mainLibs: [],
    dexCount: 0,
    entryCount: entries.length,
    groups: [],
    notableFiles: [],
    pakFiles: [],
    scannedLibs: [],
  };

  // manifest (binary AXML)
  const manifestEntry = entries.find((e) => e.name === "AndroidManifest.xml");
  if (manifestEntry) {
    const extracted = extractZipEntry(buf, manifestEntry);
    if (extracted) {
      const manifest = parseAxmlManifest(extracted.data);
      if (manifest) {
        apk.packageName = manifest.packageName;
        apk.versionName = manifest.versionName;
        apk.versionCode = manifest.versionCode;
        apk.minSdk = manifest.minSdk;
        apk.targetSdk = manifest.targetSdk;
      } else {
        errors.push("AndroidManifest.xml (binary AXML) cozumlenemedi");
      }
    }
  }

  // gruplar
  const groupMap = new Map<string, { count: number; totalSize: number }>();
  for (const e of entries) {
    const dir = e.name.includes("/") ? e.name.slice(0, e.name.lastIndexOf("/")) : "(kok)";
    const g = groupMap.get(dir) ?? { count: 0, totalSize: 0 };
    g.count++;
    g.totalSize += e.size;
    groupMap.set(dir, g);
  }
  apk.groups = [...groupMap.entries()]
    .map(([dir, v]) => ({ dir, ...v }))
    .sort((a, b) => b.totalSize - a.totalSize)
    .slice(0, 24);

  // dex + so + pak + dikkat ceken dosyalar
  const abis = new Set<string>();
  const libs: ApkEntry[] = [];
  for (const e of entries) {
    if (e.name.endsWith(".dex")) apk.dexCount++;
    if (e.name.startsWith("lib/") && e.name.endsWith(".so")) {
      const parts = e.name.split("/");
      if (parts.length >= 3) abis.add(parts[1]);
      libs.push({ path: e.name, size: e.size, compressed: e.compressedSize, method: e.method === 0 ? "STORE" : "DEFLATE" });
    }
    if (e.name.endsWith(".pak")) apk.pakFiles.push({ path: e.name, size: e.size });
    const low = e.name.toLowerCase();
    if (
      low.includes("global-metadata.dat") ||
      low.includes("unityplayer") ||
      (low.includes(".obb")) ||
      low.includes("winmetadata") ||
      low.includes("resources.assets")
    ) {
      apk.notableFiles.push(`${e.name} (${e.size} B)`);
    }
  }
  apk.abis = [...abis];
  apk.pakFiles.sort((a, b) => b.size - a.size);
  if (apk.pakFiles.length) {
    notes.push(`APK icinde ${apk.pakFiles.length} adet UE .pak bulundu (assets) - motor icerigi burada.`);
  }

  // motor ipucu isimlendirme
  const hintOf = (path: string): string | undefined => {
    const low = path.toLowerCase();
    if (low.includes("ue5") || low.includes("unreal5")) return "Unreal Engine 5";
    if (low.includes("ue4") || low.includes("unreal")) return "Unreal Engine 4";
    if (low.includes("il2cpp")) return "Unity IL2CPP";
    if (low.includes("unity")) return "Unity";
    if (low.includes("godot")) return "Godot";
    return undefined;
  };
  apk.mainLibs = libs
    .sort((a, b) => b.size - a.size)
    .slice(0, 32)
    .map((l) => ({ ...l, engineHint: hintOf(l.path) }));

  // en buyuk "ilginc" .so'leri buffer'dan cikarip motor string taramasi yap
  const interesting = libs
    .filter((l) => hintOf(l.path) !== undefined || l.size > 8 * 1024 * 1024)
    .sort((a, b) => b.size - a.size)
    .slice(0, 2);
  for (const lib of interesting) {
    const raw = entries.find((e) => e.name === lib.path);
    if (!raw) continue;
    const extracted = extractZipEntry(buf, raw);
    if (!extracted) {
      errors.push(`${lib.path} acilamadi (yontem/boyut siniri)`);
      continue;
    }
    const ueVersions = findUeVersionStrings(extracted.data, 8);
    const libStrings = extractAsciiStrings(extracted.data, 10, 600);
    const libEngine =
      ueVersions.length > 0
        ? ueVersions[0].raw.startsWith("++UE5")
          ? "UE5"
          : "UE4"
        : guessEngineFromStrings(libStrings, hintOf(lib.path));
    apk.scannedLibs.push({
      path: lib.path,
      engine: libEngine,
      version: ueVersions[0]?.version,
      versionStrings: ueVersions.map((v) => v.raw).slice(0, 6),
    });
    if (ueVersions.length) {
      apk.notableFiles.unshift(`${lib.path} icinde UE surum stringi: ${ueVersions[0].raw}`);
    }
  }

  return apk;
}

function guessEngineFromStrings(strings: string[], hint: string | undefined): string | undefined {
  if (hint) return hint;
  const joined = strings.slice(0, 400).join(" ").toLowerCase();
  if (ciContains(joined, "global-metadata") || ciContains(joined, "il2cpp")) return "Unity";
  if (ciContains(joined, "unreal")) return "Unreal Engine";
  return undefined;
}

// --- sade ZIP ---
function analyzeZip(entries: ZipEntryRaw[]): NonNullable<AnalysisResult["zip"]> {
  const groupMap = new Map<string, { count: number; totalSize: number }>();
  const notable: string[] = [];
  const libs: (ApkEntry & { engineHint?: string })[] = [];
  for (const e of entries) {
    const dir = e.name.includes("/") ? e.name.slice(0, e.name.lastIndexOf("/")) : "(kok)";
    const g = groupMap.get(dir) ?? { count: 0, totalSize: 0 };
    g.count++;
    g.totalSize += e.size;
    groupMap.set(dir, g);
    const low = e.name.toLowerCase();
    if (low.endsWith(".so") || low.endsWith(".exe") || low.endsWith(".dll")) {
      libs.push({
        path: e.name,
        size: e.size,
        compressed: e.compressedSize,
        method: e.method === 0 ? "STORE" : "DEFLATE",
        engineHint:
          low.includes("ue4") || low.includes("unreal")
            ? "Unreal Engine"
            : low.includes("il2cpp") || low.includes("unity")
              ? "Unity"
              : undefined,
      });
    }
    if (low.includes("global-metadata.dat") || low.includes("winmetadata")) {
      notable.push(`${e.name} (${e.size} B)`);
    }
  }
  const groups = [...groupMap.entries()]
    .map(([dir, v]) => ({ dir, ...v }))
    .sort((a, b) => b.totalSize - a.totalSize)
    .slice(0, 24);
  return {
    entryCount: entries.length,
    groups,
    notableFiles: notable,
    mainLibs: libs.sort((a, b) => b.size - a.size).slice(0, 24),
  };
}

export { buildReport };
