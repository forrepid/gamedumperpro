// ----------------------------------------------------------------------------
// UnrealDumperX - TXT rapor uretici + games.ini onerisi
// ----------------------------------------------------------------------------

import type { AnalysisResult } from "./types";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function section(title: string): string {
  const line = "=".repeat(64);
  return `${line}\n${title}\n${line}`;
}

function sub(title: string): string {
  return `-- ${title}`;
}

export function buildReport(r: AnalysisResult): string {
  const L: string[] = [];
  L.push(section("UnrealDumperX - Dosya Analiz Raporu"));
  L.push(`Dosya           : ${r.file.name}`);
  L.push(`Boyut           : ${fmtBytes(r.file.size)} (${r.file.size} bayt)`);
  L.push(`Tip             : ${r.kind.toUpperCase()}`);
  L.push(`SHA-256 (ilk 16): ${r.file.sha256.slice(0, 16)}`);
  L.push(`Genel Entropy   : ${r.overallEntropy} / 8.00`);
  L.push(`Rapor zamani    : ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC`);
  L.push("");

  L.push(section("MOTOR TESPITI"));
  L.push(`Tespit          : ${r.engine.detected}`);
  L.push(`Surum           : ${r.engine.version ?? "-"}`);
  L.push(`Guven           : ${r.engine.confidence}`);
  if (r.engine.versionStrings.length) {
    L.push(sub("Surum stringleri"));
    for (const v of r.engine.versionStrings.slice(0, 12)) L.push(`  ${v}`);
  }
  if (r.engine.markers.length) {
    L.push(sub("Imza eslesmeleri"));
    for (const m of r.engine.markers.slice(0, 16)) L.push(`  ${m.name}: ${m.hits} eslesme`);
  }
  L.push("");

  if (r.pe) {
    L.push(section("PE BILGILERI"));
    L.push(`Format          : ${r.pe.format} | ${r.pe.machine} | ${r.pe.arch}`);
    L.push(`Build zamani    : ${r.pe.buildDate}`);
    L.push(`SubSystem       : ${r.pe.subsystem}`);
    L.push(`Entry (RVA)     : 0x${r.pe.entryPointRva.toString(16).toUpperCase()}`);
    L.push(`ImageBase       : 0x${r.pe.imageBase.toString(16).toUpperCase()}`);
    L.push(`SizeOfImage     : 0x${r.pe.sizeOfImage.toString(16).toUpperCase()}`);
    if (r.pe.debugPdb) L.push(`PDB yolu        : ${r.pe.debugPdb}`);
    if (r.pe.dllCharacteristics.length) L.push(`Guvenlik ozel.  : ${r.pe.dllCharacteristics.join(", ")}`);
    L.push("");
    L.push(sub("Bolumler"));
    for (const s of r.pe.sections) {
      L.push(
        `  ${s.name.padEnd(10)} VA=0x${s.virtualAddress.toString(16).padStart(8, "0")} ` +
        `VSZ=0x${s.virtualSize.toString(16).padStart(8, "0")} ` +
        `RAW=0x${s.rawSize.toString(16).padStart(8, "0")} ` +
        `entropy=${s.entropy.toFixed(2).padStart(5)} [${s.flags.join("")}]`,
      );
    }
    L.push("");
    L.push(sub(`Ice aktarma (${r.pe.importDllCount} DLL)`));
    for (const imp of r.pe.imports.slice(0, 40)) {
      L.push(`  ${imp.dll} (${imp.count} fn)`);
      for (const f of imp.functions.slice(0, 6)) L.push(`    . ${f}`);
      if (imp.truncated) L.push(`    . ... +${imp.count - imp.functions.length} daha`);
    }
    if (r.pe.exports) {
      L.push("");
      L.push(sub(`Disa aktarma (${r.pe.exports.count})`));
      for (const e of r.pe.exports.names.slice(0, 30)) L.push(`  ${e}`);
      if (r.pe.exports.truncated) L.push(`  ... +${r.pe.exports.count - r.pe.exports.names.length} daha`);
    }
    L.push("");
  }

  if (r.pe?.debug) {
    L.push(section("DEBUG BILGISI"));
    if (r.pe.debug.pdb) {
      L.push(`PDB yolu        : ${r.pe.debug.pdb.path}`);
      L.push(`PDB GUID        : ${r.pe.debug.pdb.guid}`);
      L.push(`PDB Age         : ${r.pe.debug.pdb.age}`);
      const pdbName = r.pe.debug.pdb.path.split(/[\\/]/).pop() ?? "";
      L.push(sub("Microsoft sembol sunucusu yolu"));
      L.push(`  ${pdbName}/${r.pe.debug.pdb.guid}${r.pe.debug.pdb.age}/${pdbName}`);
    } else {
      L.push("PDB (CODEVIEW) kaydi yok");
    }
    for (const e of r.pe.debug.entries) {
      L.push(`  debug[${e.index}] ${e.type} (type=${e.rawType}) size=${e.size} rva=0x${e.rva.toString(16).toUpperCase()}${e.detail ? ` | ${e.detail}` : ""}`);
    }
    L.push(`COFF sembol     : ${r.pe.debug.coffSymbols === 0 ? "YOK (stripped)" : `${r.pe.debug.coffSymbols} sembol`}`);
    if (r.pe.debug.reproducible) L.push("REPRODUCIBLE build: evet (build zamani gercek degil)");
    L.push("");
  }

  if (r.functions && r.functions.total > 0) {
    L.push(section(`FONKSIYONLAR (${r.functions.total})`));
    L.push(`Kaynak          : ${r.functions.source} | analizli: ${r.functions.detailed} | decompile: ${r.functions.disassembled}`);
    L.push(`Not             : ${r.functions.note ?? ""}`);
    L.push("");
    for (const f of r.functions.functions.slice(0, 60)) {
      const lbl = f.label ?? (f.structHint ? `[${f.structHint}]` : "sub_" + f.va.toString(16).toUpperCase());
      L.push(`  #${f.idx} ${lbl}`);
      L.push(`     VA=${f.va.toString(16).toUpperCase()} RVA=${f.rva.toString(16).toUpperCase()} boyut=${f.size} bolum=${f.section} xref=${f.xrefsIn}`);
      if (f.apiCalls.length) L.push(`     API: ${f.apiCalls.join(", ")}`);
      if (f.strings.length) L.push(`     Dizeler: ${f.strings.slice(0, 3).map((s) => `"${s.slice(0, 44)}"`).join(" | ")}`);
    }
    if (r.functions.total > 60) L.push(`  ... +${r.functions.total - 60} fonksiyon (Functions.txt'te tam liste)`);
    // decompile ornegi
    const sample = r.functions.functions.find((f) => f.pseudo);
    if (sample?.pseudo) {
      L.push("");
      L.push(sub(`Tahmini pseudo-C ornegi: ${sample.label ?? "sub_" + sample.va.toString(16).toUpperCase()}`));
      for (const line of sample.pseudo.split("\n").slice(0, 24)) L.push(`  ${line}`);
      L.push("  ... (Decompile.txt'te tamami)");
    }
    L.push("");
  }

  if (r.structs && r.structs.structs.length > 0) {
    L.push(section(`STRUCTLAR (kurtarilan: ${r.structs.total})`));
    L.push(`Not             : ${r.structs.note ?? ""}`);
    for (const s of r.structs.structs.slice(0, 40)) {
      L.push(`  ${s.kind} ${s.name}${s.base ? ` : ${s.base}` : ""}${s.size ? ` ~0x${s.size.toString(16).toUpperCase()}` : ""} [${s.source}]`);
      for (const fld of s.fields.slice(0, 12)) {
        L.push(`     +0x${fld.offset.toString(16).padStart(2, "0")} ${fld.type.padEnd(8)} ${fld.name} (erisim ${fld.reads})`);
      }
      if (s.fields.length > 12) L.push(`     ... +${s.fields.length - 12} alan`);
      if (s.methodCount) L.push(`     metodlar: ${s.methodCount}`);
    }
    if (r.structs.total > 40) L.push(`  ... +${r.structs.total - 40} struct`);
    L.push("");
  }

  if (r.enums && r.enums.enums.length > 0) {
    L.push(section(`ENUMLAR (kurtarilan: ${r.enums.total})`));
    L.push(`Not             : ${r.enums.note ?? ""}`);
    for (const e of r.enums.enums.slice(0, 30)) {
      L.push(`  enum ${e.name} [${e.source}]${e.note ? ` - ${e.note}` : ""}`);
      for (const m of e.members.slice(0, 10)) L.push(`     ${m.name} = ${m.value}`);
      if (e.members.length > 10) L.push(`     ... +${e.members.length - 10} uye`);
    }
    if (r.enums.total > 30) L.push(`  ... +${r.enums.total - 30} enum`);
    L.push("");
  }

  if (r.il2cpp) {
    L.push(section("UNITY IL2CPP METADATA"));
    L.push(`Metadata surumu : v${r.il2cpp.version} (${r.il2cpp.unityHint})`);
    L.push(`Sanity          : ${r.il2cpp.sanityOk ? "gecerli (0xFAB11BAF)" : "UYUSMUYOR"}`);
    L.push(`Tip/Metod       : ${r.il2cpp.classCount} / ${r.il2cpp.methodCount}`);
    L.push(`Alan            : ${r.il2cpp.fieldCount}`);
    L.push(`String literal  : ${r.il2cpp.literalCount} | string havuz: ${r.il2cpp.stringCount} bayt`);
    if (r.il2cpp.images.length) {
      L.push(sub("Imagelar (assembly)"));
      for (const i of r.il2cpp.images.slice(0, 24)) L.push(`  ${i}`);
    }
    if (r.il2cpp.classes.length) {
      L.push(sub(`Sinif ornekleri (ilk ${Math.min(r.il2cpp.classes.length, 40)})`));
      for (const c of r.il2cpp.classes.slice(0, 40)) {
        L.push(`  ${c.namespace ? c.namespace + "." : ""}${c.name} (${c.kind}, ${c.fieldCount} alan, ${c.methodCount} metod)`);
      }
    }
    if (r.il2cpp.enums.length) {
      L.push(sub(`Enumlar (ilk ${Math.min(r.il2cpp.enums.length, 30)})`));
      for (const e of r.il2cpp.enums.slice(0, 30)) {
        const ms = e.members.slice(0, 8).map((m) => `${m.name}=${m.value ?? "?"}`).join(", ");
        L.push(`  ${e.namespace ? e.namespace + "." : ""}${e.name}: ${ms}${e.memberCount > 8 ? " ..." : ""}`);
      }
    }
    L.push("  Not: metod RVA'ları GameAssembly.dll / libil2cpp.so analizi ister.");
    L.push("");
  }

  if (r.elf) {
    L.push(section("ELF BILGILERI"));
    L.push(`Sinif/Makine    : ${r.elf.class} ${r.elf.endian} | ${r.elf.machine}`);
    L.push(`Tip             : ${r.elf.type}`);
    L.push(`Entry           : 0x${r.elf.entryPoint.toString(16)}`);
    L.push(`Bolum sayisi    : ${r.elf.sectionCount}`);
    for (const s of r.elf.sections.slice(0, 40)) {
      L.push(`  ${s.name.padEnd(20)} ${s.type.padEnd(12)} size=0x${s.size.toString(16)}`);
    }
    if (r.elf.dynsyms && r.elf.dynsyms.length > 0) {
      L.push(sub(`Dynamic semboller (.dynsym, ilk ${Math.min(48, r.elf.dynsyms.length)} / ${r.elf.dynsymCount ?? r.elf.dynsyms.length})`));
      for (const s of r.elf.dynsyms.slice(0, 48)) {
        L.push(`  ${s.type.padEnd(6)} ${s.bind.padEnd(6)} 0x${s.value.toString(16).padStart(8, "0")}  ${s.name}`);
      }
      const jni = r.elf.dynsyms.some((s) => s.name.startsWith("JNI_OnLoad"));
      const il2 = r.elf.dynsyms.some((s) => s.name.startsWith("il2cpp_"));
      if (jni) L.push("  -> JNI_OnLoad var (Android native kutuphane)");
      if (il2) L.push("  -> il2cpp_* API sembolleri var (Unity IL2CPP)");
    }
    L.push("");
  }

  if (r.dex) {
    L.push(section("DEX BILGILERI"));
    L.push(`Surum/Endian    : ${r.dex.version} (${r.dex.endian})`);
    L.push(`Checksum        : ${r.dex.checksumOk ? "gecerli (adler32 uyuyor)" : "UYUSMUYOR (bozuk/degistirilmis)"}`);
    L.push(`String havuzu   : ${r.dex.strings}`);
    L.push(`Tip/Proto       : ${r.dex.types} / ${r.dex.protos}`);
    L.push(`Alan/Metod      : ${r.dex.fields} / ${r.dex.methods}`);
    L.push(`Sinif tanimi    : ${r.dex.classes}`);
    if (r.dex.packages.length) {
      L.push(sub("En cok sinif iceren paketler"));
      for (const p of r.dex.packages.slice(0, 12)) L.push(`  ${p.name} (${p.count} sinif)`);
    }
    if (r.dex.classSamples.length) {
      L.push(sub("Sinif ornekleri"));
      for (const c of r.dex.classSamples.slice(0, 16)) L.push(`  ${c}`);
    }
    if (r.dex.engineHints.length) {
      L.push(sub("Motor / oyun ipuclari"));
      for (const h of r.dex.engineHints) L.push(`  - ${h}`);
    }
    L.push("  Android hedefi: canli dump icin Windows istemcisi + emulator/saglama gerekir");
    L.push("");
  }

  if (r.apk) {
    L.push(section("APK BILGILERI"));
    if (r.apk.packageName) L.push(`Paket           : ${r.apk.packageName}`);
    if (r.apk.versionName) L.push(`versionName     : ${r.apk.versionName}`);
    if (r.apk.versionCode) L.push(`versionCode     : ${r.apk.versionCode}`);
    if (r.apk.minSdk) L.push(`minSdk          : ${r.apk.minSdk}`);
    if (r.apk.targetSdk) L.push(`targetSdk       : ${r.apk.targetSdk}`);
    L.push(`Kayit sayisi    : ${r.apk.entryCount}`);
    L.push(`DEX sayisi      : ${r.apk.dexCount}`);
    if (r.apk.abis.length) L.push(`ABI'ler         : ${r.apk.abis.join(", ")}`);
    if (r.apk.mainLibs.length) {
      L.push(sub("Ana kutuphaneler (lib/*/*.so)"));
      for (const m of r.apk.mainLibs.slice(0, 24)) {
        L.push(`  ${m.path}  ${fmtBytes(m.size)} ${m.engineHint ? `[${m.engineHint}]` : ""}`);
      }
    }
    if (r.apk.pakFiles.length) {
      L.push(sub("UE .pak dosyalari"));
      for (const p of r.apk.pakFiles.slice(0, 12)) L.push(`  ${p.path}  ${fmtBytes(p.size)}`);
    }
    if (r.apk.notableFiles.length) {
      L.push(sub("Dikkat ceken dosyalar"));
      for (const n of r.apk.notableFiles.slice(0, 16)) L.push(`  ${n}`);
    }
    if (r.apk.scannedLibs.length) {
      L.push(sub("Taranan .so icerikleri"));
      for (const s of r.apk.scannedLibs) {
        L.push(`  ${s.path}: ${s.engine ?? "-"} ${s.version ?? ""}`);
        for (const v of s.versionStrings.slice(0, 4)) L.push(`    ${v}`);
      }
    }
    L.push("");
  }

  if (r.zip) {
    L.push(section("ZIP BILGILERI"));
    L.push(`Kayit sayisi    : ${r.zip.entryCount}`);
    if (r.zip.mainLibs.length) {
      for (const m of r.zip.mainLibs.slice(0, 16)) {
        L.push(`  ${m.path}  ${fmtBytes(m.size)} ${m.engineHint ? `[${m.engineHint}]` : ""}`);
      }
    }
    if (r.zip.notableFiles.length) {
      L.push(sub("Dikkat ceken dosyalar"));
      for (const n of r.zip.notableFiles.slice(0, 16)) L.push(`  ${n}`);
    }
    L.push("");
  }

  if (r.security.antiCheat.length || r.security.drm.length || r.security.packer.length) {
    L.push(section("GUVENLIK / KORUMA"));
    if (r.security.antiCheat.length) L.push(`Anti-cheat      : ${r.security.antiCheat.join(" | ")}`);
    if (r.security.drm.length) L.push(`DRM/Platform    : ${r.security.drm.join(" | ")}`);
    if (r.security.packer.length) L.push(`Packer          : ${r.security.packer.join(" | ")}`);
    L.push(`Packed sezgisi  : ${r.security.packedHint ? "EVET (yuksek entropy)" : "hayir"}`);
    if (r.security.notableStrings.length) {
      L.push(sub("Dikkat ceken dizeler"));
      for (const s of r.security.notableStrings.slice(0, 10)) L.push(`  ${s}`);
    }
    L.push("");
  }

  if (r.signatureCandidates.length) {
    L.push(section("IMZA ADAYLARI (statik - dogrulanmadi)"));
    for (const c of r.signatureCandidates) {
      L.push(`  ${c.name} [${c.pattern}]`);
      if (c.hits.length === 0) L.push("    eslesme yok");
      for (const h of c.hits) L.push(`    RVA=${h.rva}  VA=${h.va}  file=0x${h.offset.replace("0x", "").toUpperCase()}`);
    }
    L.push("");
  }

  if (r.strings.length) {
    L.push(section(`ILGINC DIZELER (ilk ${Math.min(r.strings.length, 120)})`));
    for (const s of r.strings.slice(0, 120)) L.push(`  ${s.value}`);
    L.push("");
  }

  if (r.resources && r.resources.total > 0) {
    L.push(section(`KAYNAKLAR (${r.resources.total})`));
    for (const e of r.resources.entries.slice(0, 32)) {
      L.push(`  ${e.type}/${e.id} size=${e.size} rva=0x${e.rva.toString(16).toUpperCase()}${e.embedded ? ` [gomulu: ${e.embedded}]` : ""}`);
    }
    if (r.resources.biggest) {
      L.push(`  En buyuk: ${r.resources.biggest.type}/${r.resources.biggest.id} (${fmtBytes(r.resources.biggest.size)}, %${r.resources.biggest.pct.toFixed(1)})`);
    }
    L.push("");
  }

  if (r.extractors) {
    const avail = r.extractors.extractors.filter((e) => e.available);
    L.push(section(`CIKARICILER (coklu dumper ciktilari - ${avail.length}/${r.extractors.extractors.length})`));
    for (const ex of r.extractors.extractors) {
      L.push(`  ${ex.name} [${ex.id}] ${ex.version} - ${ex.available ? "cikti uretti" : "uygulanamaz"}`);
      L.push(`    ${ex.reason}`);
      for (const sec of ex.sections) {
        L.push(`    ${sec.title}: ${sec.total.toLocaleString("tr-TR")} oge`);
      }
      for (const f of ex.files) {
        L.push(`    dosya: ${f.name} (${fmtBytes(f.size)})`);
      }
    }
    if (r.extractors.common.length > 0) {
      L.push(sub("Model ortak verileri (>= 2 cikaricida ayni isim)"));
      for (const group of r.extractors.common) {
        L.push(`  ${group.title} (${group.entries.length}):`);
        for (const e of group.entries.slice(0, 12)) {
          L.push(`    ${e.name}  <-  ${e.foundIn.join(", ")}`);
        }
        if (group.entries.length > 12) L.push(`    ... +${group.entries.length - 12} daha`);
      }
    }
    L.push("");
  }

  if (r.sdk && r.sdk.files.length > 0) {
    L.push(section(`SDK CIKTILARI (${r.sdk.files.length} dosya)`));
    L.push(`Uretici         : ${r.sdk.generator}`);
    for (const f of r.sdk.files) {
      L.push(`  ${f.name.padEnd(40)} ${fmtBytes(f.size)}`);
    }
    L.push("");
  }

  if (r.gamesIniSuggestion) {
    L.push(section("GAMES.INI ONERISI"));
    L.push(r.gamesIniSuggestion);
    L.push("");
  }

  if (r.art) {
    L.push(section(`ART ${r.art.kind.toUpperCase()} v${r.art.version} - GOMULU DEX`));
    L.push(`API bilgis      : ${r.art.apiHint}`);
    if (r.art.dexSectionVersion) L.push(`Dex bolum surumu: ${r.art.dexSectionVersion}`);
    L.push(`Gomulu DEX      : ${r.art.dexCount} adet`);
    for (const d of r.art.dexes) {
      L.push(
        `  dex[${d.index}] off=0x${d.offset.toString(16).padStart(8, "0")} size=${d.size}` +
          (d.classes !== undefined ? ` classes=${d.classes} methods=${d.methods} strings=${d.strings}` : ""),
      );
    }
    for (const n of r.art.notes.slice(0, 6)) L.push(`  * ${n}`);
    if (r.art.error) L.push(`  ! ${r.art.error}`);
    L.push("  Not: gomulu DEX'ler cocuk yukleme olarak otomatik analiz edilir.");
    L.push("");
  }

  if (r.pdb) {
    L.push(section("PDB SEMBOLLERI (eslesen .pdb)"));
    L.push(`Durum           : ${r.pdb.valid ? "cozuldu" : " cozulemedi"}`);
    if (r.pdb.error) L.push(`Hata            : ${r.pdb.error}`);
    L.push(`GUID / Age      : ${r.pdb.guid} / ${r.pdb.age}`);
    L.push(`Mimari          : ${r.pdb.machine}`);
    L.push(`Akis sayisi     : ${r.pdb.streamCount}`);
    L.push(`Semboller       : ${r.pdb.symbolsTotal} toplam (func ${r.pdb.funcCount} / data ${r.pdb.dataCount})`);
    L.push(`UDT tipleri     : ${r.pdb.udtTotal}`);
    if (r.pdb.symbols.length) {
      L.push(sub("Fonksiyon sembolleri (ilk 30)"));
      for (const s of r.pdb.symbols.filter((x) => x.kind === "func").slice(0, 30)) {
        L.push(`  rva=0x${(s.rva ?? 0).toString(16).padStart(8, "0")} ${s.name}`);
      }
      L.push("");
      L.push(sub("Veri sembolleri (ilk 20)"));
      for (const s of r.pdb.symbols.filter((x) => x.kind === "data").slice(0, 20)) {
        L.push(`  rva=0x${(s.rva ?? 0).toString(16).padStart(8, "0")} ${s.name}`);
      }
    }
    if (r.pdb.udtNames.length) {
      L.push("");
      L.push(sub("UDT tipleri (ilk 30)"));
      for (const u of r.pdb.udtNames.slice(0, 30)) L.push(`  ${u}`);
    }
    L.push("");
  }

  if (r.notes.length) {
    L.push(section("NOTLAR"));
    for (const n of r.notes) L.push(`  - ${n}`);
    L.push("");
  }

  if (r.errors.length) {
    L.push(section("UYARILAR"));
    for (const e of r.errors) L.push(`  ! ${e}`);
    L.push("");
  }

  L.push(section("SORUMLULUK REDDI"));
  L.push("Bu rapor yalnizca offline analiz, tek oyunculu modding, interop ve motor");
  L.push("arastirmasi icindir. Cok oyunculu/hile amacli kullanim kapsam disidir.");
  return L.join("\n");
}

export function buildGamesIniSuggestion(r: AnalysisResult): string | undefined {
  const base = r.file.name
    .replace(/\.(exe|dll|sys|apk|so|bin)$/i, "")
    .replace(/-Win64-Shipping$/i, "")
    .replace(/-Shipping$/i, "")
    .replace(/[^A-Za-z0-9_-]/g, "");
  if (!base) return undefined;
  const lines: string[] = [`[${base}]`];
  if (r.engine.version) {
    const ver = r.engine.version.split(".");
    lines.push(`version = ${ver[0]}.${ver[1] ?? "0"}`);
  }
  if (r.kind === "apk") {
    lines.push("; APK hedefi: canli dump icin Windows istemcisi gerekir (emulator/saglama).");
    lines.push("; libUE*.so'yi cikarip --file moduyla statik tarama yapabilirsiniz.");
  }
  lines.push("; adresler canli dump sonrasi <Oyun>_sigs.txt ciktisindan eklenir:");
  lines.push(";   DumperPro.exe --process " + (r.kind === "pe" ? r.file.name : "Game.exe"));
  lines.push("; gobjects = 0x...   gnames = 0x...");
  return lines.join("\n");
}
