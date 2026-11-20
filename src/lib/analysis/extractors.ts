// ----------------------------------------------------------------------------
// DumperPro Online - coklu cikarici (multi-dumper) modulu
//
// Ayni dosya farkli dumper "modelleri" ile ayrilir ve her modelin ciktilari
// ayrisolgu olarak sunulur + model ortak verileri (kesisim) hesaplanir:
//
//   Dumper-7       : RTTI/struct/enum kurtarma -> C++ SDK (classes/structs/enums.h, SDK.hpp)
//   DumperPro      : yerel derin analiz -> Functions.txt / Decompile.txt / Debug.txt / Offsets.txt
//   Il2CppDumper   : metadata + GameAssembly eslestirmesi -> dump.cs / script.json
//   UnrealCEDumper : UE imza adaylari + vtable haritasi -> offsets/vtables ciktilari
//   MemProcFS      : modul / VAD bolge / cihaz gorunumu (bellek dump veya PE modul haritasi)
//   LeechCore      : fiziksel bellek/dosya haritasi (lc memmap uyumlu cikti)
//
// OrtakVeri: en az 2 cikaricida ayni isimle bulunan ogeler listelenir
// (ornek: RTTI sinifi hem Dumper-7 hem UnrealCEDumper ciktilarinda var).
// ----------------------------------------------------------------------------

import type {
  AnalysisResult,
  CommonEntry,
  ExtractorEntry,
  ExtractorId,
  ExtractorOutput,
  ExtractorSection,
  ExtractorSectionKind,
  ExtractorsInfo,
} from "./types";

const SECTION_CAP = 300; // bolum basina en fazla oge
const COMMON_CAP = 400; // ortak listede en fazla oge

function hx(n: number): string {
  return `0x${n.toString(16).toUpperCase()}`;
}

function normName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9_]/g, "");
}

function cap(entries: ExtractorEntry[]): { entries: ExtractorEntry[]; total: number; truncated: boolean } {
  const total = entries.length;
  const truncated = total > SECTION_CAP;
  return { entries: entries.slice(0, SECTION_CAP), total, truncated };
}

// ---------------------------------------------------------------------------
// yardimcilar: result uzerinden bolum kurma
// ---------------------------------------------------------------------------

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function peFlagsToProt(flags: string[]): string {
  const has = (f: string) => flags.includes(f);
  return `${has("r") ? "r" : "-"}${has("w") ? "w" : "-"}${has("x") ? "x" : "-"}`;
}

// ---------------------------------------------------------------------------
// 1) Dumper-7 benzeri C++ SDK cikarici
// ---------------------------------------------------------------------------

function buildDumper7(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];

  const classEntries: ExtractorEntry[] = (r.rtti?.classes ?? []).map((c) => ({
    name: c.name,
    value: c.vftableVa ? hx(c.vftableVa) : undefined,
    note: `${c.methodCount} metod${c.base ? ` : ${c.base}` : ""}`,
  }));
  if (classEntries.length > 0) {
    const c = cap(classEntries);
    sections.push({ key: "classes", title: "Siniflar (RTTI)", kind: "class", ...c });
  }

  const structEntries: ExtractorEntry[] = (r.structs?.structs ?? []).map((s) => ({
    name: s.name,
    value: s.size ? `~${hx(s.size)}` : undefined,
    note: `${s.fields.length} alan${s.base ? ` : ${s.base}` : ""}`,
  }));
  if (structEntries.length > 0) {
    const c = cap(structEntries);
    sections.push({ key: "structs", title: "Structlar", kind: "struct", ...c });
  }

  const enumEntries: ExtractorEntry[] = (r.enums?.enums ?? []).map((e) => ({
    name: e.name,
    value: e.members.length > 0 ? `${e.members.length} uye` : undefined,
    note: e.members.slice(0, 4).map((m) => `${m.name}=${m.value}`).join(", ") || undefined,
  }));
  if (enumEntries.length > 0) {
    const c = cap(enumEntries);
    sections.push({ key: "enums", title: "Enumlar", kind: "enum", ...c });
  }

  const fnEntries: ExtractorEntry[] = (r.functions?.functions ?? [])
    .slice()
    .sort((a, b) => b.size - a.size)
    .slice(0, 48)
    .map((f) => ({
      name: f.label ?? `sub_${f.va.toString(16).toUpperCase()}`,
      value: hx(f.va),
      note: `${f.size} B${f.structHint ? ` · ${f.structHint}` : ""}`,
    }));
  if (fnEntries.length > 0) {
    const c = cap(fnEntries);
    sections.push({ key: "functions", title: "Fonksiyonlar (en buyuk 48)", kind: "function", ...c });
  }

  const available = sections.length > 0;
  return {
    id: "dumper7",
    name: "Dumper-7",
    version: "v1.3.2 benzeri",
    generatorNote: "MSVC RTTI + kod erisimi ile C++ SDK uretimi (UnknownData dolgulu)",
    available,
    reason: available
      ? "RTTI/struct/enum kurtarma ciktilari uretildi"
      : "RTTI/struct/enum verisi bulunamadi - C++ SDK uretilemedi",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// 2) DumperPro yerel derin analiz cikarici
// ---------------------------------------------------------------------------

function buildDumperPro(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];

  const fnEntries: ExtractorEntry[] = (r.functions?.functions ?? []).slice(0, SECTION_CAP).map((f) => ({
    name: f.label ?? `sub_${f.va.toString(16).toUpperCase()}`,
    value: `${hx(f.va)} (${f.size} B)`,
    note: f.structHint ?? (f.apiCalls.length ? `api: ${f.apiCalls.slice(0, 3).join(",")}` : undefined),
  }));
  if (fnEntries.length > 0) {
    const c = cap(fnEntries);
    sections.push({ key: "functions", title: "Fonksiyon tablosu", kind: "function", ...c, note: r.functions?.source === "pdata" ? ".pdata kesin sinirlar" : "heuristik sinirlar" });
  }

  const offEntries: ExtractorEntry[] = [];
  if (r.pe) {
    offEntries.push({ name: "ImageBase", value: hx(r.pe.imageBase) });
    offEntries.push({ name: "EntryPoint", value: `RVA ${hx(r.pe.entryPointRva)}` });
    offEntries.push({ name: "SizeOfImage", value: hx(r.pe.sizeOfImage) });
    for (const s of r.pe.sections) {
      offEntries.push({ name: `section:${s.name}`, value: `VA ${hx(s.virtualAddress)} RAW ${hx(s.rawSize)}` });
    }
  }
  if (offEntries.length > 0) {
    const c = cap(offEntries);
    sections.push({ key: "offsets", title: "Temel adresler", kind: "offset", ...c });
  }

  const available = sections.length > 0;
  return {
    id: "dumperpro",
    name: "DumperPro (yerel)",
    version: "v1.1.0",
    generatorNote: "Fonksiyon tablosu + disassembly + debug dizini + temel adresler",
    available,
    reason: available ? "Derin statik analiz ciktilari uretildi" : "Yerel analiz icin yeterli veri yok",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// 3) Il2CppDumper benzeri cikarici
// ---------------------------------------------------------------------------

function buildIl2CppDumper(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];

  const classEntries: ExtractorEntry[] = (r.il2cpp?.classes ?? []).map((c) => ({
    name: c.namespace ? `${c.namespace}.${c.name}` : c.name,
    value: c.kind,
    note: `${c.fieldCount} alan / ${c.methodCount} metod${c.base ? ` : ${c.base}` : ""}`,
  }));
  if (classEntries.length > 0) {
    const c = cap(classEntries);
    sections.push({
      key: "classes",
      title: "Siniflar (metadata)",
      kind: "class",
      ...c,
      note: `metadata v${r.il2cpp?.version} - toplam ${r.il2cpp?.classCount}`,
    });
  }

  const enumEntries: ExtractorEntry[] = (r.il2cpp?.enums ?? []).map((e) => ({
    name: e.namespace ? `${e.namespace}.${e.name}` : e.name,
    value: `${e.memberCount} uye`,
    note: e.members.slice(0, 4).map((m) => `${m.name}=${m.value ?? "?"}`).join(", ") || undefined,
  }));
  if (enumEntries.length > 0) {
    const c = cap(enumEntries);
    sections.push({ key: "enums", title: "Enumlar (metadata)", kind: "enum", ...c });
  }

  const offEntries: ExtractorEntry[] = [];
  if (r.il2cppBin?.codeRegistration) {
    offEntries.push({ name: "CodeRegistration", value: `RVA ${hx(r.il2cppBin.codeRegistration.rva)} / VA ${hx(r.il2cppBin.codeRegistration.va)}` });
  }
  if (r.il2cppBin?.metadataRegistration) {
    offEntries.push({ name: "MetadataRegistration", value: `RVA ${hx(r.il2cppBin.metadataRegistration.rva)} / VA ${hx(r.il2cppBin.metadataRegistration.va)}` });
  }
  if (r.il2cppBin?.codeGenModules) {
    offEntries.push({
      name: "codeGenModules[]",
      value: `RVA ${hx(r.il2cppBin.codeGenModules.rva)} · ${r.il2cppBin.codeGenModules.count} modul`,
    });
  }
  if (r.il2cppBin?.unityVersion) {
    offEntries.push({ name: "UnityVersion", value: r.il2cppBin.unityVersion });
  }
  if (offEntries.length > 0) {
    const c = cap(offEntries);
    sections.push({ key: "offsets", title: "IL2CPP kayit adresleri", kind: "offset", ...c });
  }

  const available = sections.length > 0;
  return {
    id: "il2cppdumper",
    name: "Il2CppDumper",
    version: "v6.7.2 benzeri",
    generatorNote: "global-metadata.dat parse + GameAssembly il2cpp kayit yapisi taramasi",
    available,
    reason: available
      ? r.il2cppBin?.linked
        ? "metadata + binary eslestirildi - dump.cs uretildi"
        : "metadata/binary verisi bulundu"
      : "IL2CPP metadata veya GameAssembly bulunamadi - bu cikarici uygulanamaz",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// 4) UnrealCEDumper benzeri cikarici
// ---------------------------------------------------------------------------

function isUnrealEngine(r: AnalysisResult): boolean {
  const e = r.engine.detected.toLowerCase();
  return e.startsWith("ue4") || e.startsWith("ue5") || e.includes("unreal");
}

function buildUnrealCEDumper(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];

  // imza adaylari -> ofsetler (GObjects / GNames / GWorld / ProcessEvent)
  const offEntries: ExtractorEntry[] = r.signatureCandidates
    .filter((c) => c.hits.length > 0)
    .map((c) => ({
      name: c.name,
      value: `RVA ${c.hits[0].rva} / VA ${c.hits[0].va}`,
      note: `${c.hits.length} eslesme · ${c.pattern.slice(0, 24)}...`,
    }));
  if (r.engine.version) {
    offEntries.unshift({ name: "EngineVersion", value: r.engine.version });
  }
  if (offEntries.length > 0) {
    const c = cap(offEntries);
    sections.push({ key: "offsets", title: "Imza ofsetleri (GObjects/GNames/...)", kind: "offset", ...c });
  }

  // vtable haritasi (UE stilinde vftable tablosu)
  const vtEntries: ExtractorEntry[] = (r.rtti?.classes ?? [])
    .filter((c) => c.vftableVa !== undefined)
    .map((c) => ({
      name: c.name,
      value: hx(c.vftableVa ?? 0),
      note: `${c.methodCount} slot`,
    }));
  if (vtEntries.length > 0) {
    const c = cap(vtEntries);
    sections.push({ key: "classes", title: "Vtable haritasi", kind: "class", ...c });
  }

  // vftable referans eden fonksiyonlar (ProcessEvent benzeri adaylar)
  const fnEntries: ExtractorEntry[] = (r.functions?.functions ?? [])
    .filter((f) => f.structHint)
    .slice(0, 60)
    .map((f) => ({
      name: `${f.structHint}::sub_${f.va.toString(16).toUpperCase()}`,
      value: hx(f.va),
      note: `${f.size} B`,
    }));
  if (fnEntries.length > 0) {
    const c = cap(fnEntries);
    sections.push({ key: "functions", title: "Uye fonksiyon adaylari", kind: "function", ...c });
  }

  const ue = isUnrealEngine(r);
  const available = sections.length > 0 && ue;
  return {
    id: "unrealcedumper",
    name: "UnrealCEDumper",
    version: "UE4.20-4.27 / UE5.0-5.3",
    generatorNote: "GObjects/GNames imza taramasi + vtable haritasi (UE hedefleri)",
    available,
    reason: available
      ? "UE hedefi: imza ofsetleri + vtable haritasi uretildi"
      : ue
        ? "UE hedefi ancak imza/vtable eslesmesi yok - adresler games.ini ile girilebilir"
        : "Hedef Unreal Engine degil - bu cikarici uygulanamaz",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// 5) MemProcFS benzeri cikarici (modul / VAD / surec gorunumu)
// ---------------------------------------------------------------------------

function buildMemProcFs(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];

  const modEntries: ExtractorEntry[] = [];
  const regEntries: ExtractorEntry[] = [];
  let deviceNote = "";

  if (r.mem) {
    deviceNote = `cihaz: ${r.mem.device} (${r.mem.arch})`;
    for (const m of r.mem.modules) {
      modEntries.push({
        name: m.name,
        value: `base ${hx(m.base)} · size ${hx(m.size)}`,
        note: `${m.timestamp ?? "-"} · kapsama %${m.recoveredRangePct}`,
      });
    }
    for (const rg of r.mem.regions) {
      regEntries.push({
        name: `${hx(rg.vaStart)}-${hx(rg.vaEnd)}`,
        value: rg.protection,
        note: `${rg.state} · ${rg.type}${rg.file && rg.file !== "-" ? ` · ${rg.file}` : ""}`,
      });
    }
    modEntries.unshift({
      name: r.mem.pid !== undefined ? `Process PID ${r.mem.pid}` : "Process (dump)",
      value: `${r.mem.moduleCount} modul`,
      note: deviceNote,
    });
  } else if (r.pe) {
    // statik PE -> MemProcFS "modul haritasi" usuluyle sentezleme
    deviceNote = "statik PE modul haritasi (canli dump degil)";
    modEntries.push({
      name: r.file.name,
      value: `base ${hx(r.pe.imageBase)} · size ${hx(r.pe.sizeOfImage)}`,
      note: `${r.pe.format} · ${r.pe.machine}`,
    });
    for (const imp of r.pe.imports.slice(0, 48)) {
      modEntries.push({
        name: imp.dll,
        value: "bagimlilik (import)",
        note: `${imp.count} fn`,
      });
    }
    for (const s of r.pe.sections) {
      regEntries.push({
        name: `${hx(r.pe.imageBase + s.virtualAddress)}-${hx(r.pe.imageBase + s.virtualAddress + s.virtualSize)}`,
        value: peFlagsToProt(s.flags),
        note: `MEM_IMAGE · ${s.name}`,
      });
    }
  }

  if (modEntries.length > 0) {
    const c = cap(modEntries);
    sections.push({ key: "modules", title: "Moduller", kind: "module", ...c, note: deviceNote });
  }
  if (regEntries.length > 0) {
    const c = cap(regEntries);
    sections.push({ key: "regions", title: "Bellek bolgeleri (VAD)", kind: "region", ...c });
  }

  const available = sections.length > 0;
  return {
    id: "memprocfs",
    name: "MemProcFS",
    version: "v5.9 benzeri",
    generatorNote: r.mem
      ? "minidump/memmap bellek analizi: modul + VAD bolgeleri"
      : "statik PE modul haritasi sentezleme (imports -> modul, sections -> VAD)",
    available,
    reason: available
      ? r.mem
        ? `Bellek cihazi okundu: ${deviceNote}`
        : "Statik PE modul/VAD haritasi uretildi"
      : "Bellek cihazi veya PE yapisi bulunamadi",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// 6) LeechCore benzeri cikarici (fiziksel bellek / dosya haritasi)
// ---------------------------------------------------------------------------

function buildLeechCore(r: AnalysisResult): ExtractorOutput {
  const sections: ExtractorSection[] = [];
  const mapEntries: ExtractorEntry[] = [];
  let device = "";

  if (r.mem) {
    device = `lc_device=${r.mem.device}`;
    mapEntries.push({ name: "device", value: r.mem.device, note: `${r.mem.arch}${r.mem.os ? ` · ${r.mem.os}` : ""}` });
    mapEntries.push({
      name: "memory",
      value: `${fmtBytes(r.mem.totalMemoryBytes)} erisilebilir`,
      note: `${r.mem.memoryRangeCount} aralik`,
    });
    // VAD bolgelerini lc memmap araliklarina cevir
    for (const rg of r.mem.regions.slice(0, 128)) {
      if (rg.state !== "MEM_FREE") {
        mapEntries.push({
          name: `${hx(rg.vaStart)},${hx(rg.vaEnd)}`,
          value: rg.type,
          note: rg.protection,
        });
      }
    }
  } else if (r.pe) {
    device = `lc_device=file://${r.file.name}`;
    mapEntries.push({ name: "device", value: `file://${r.file.name}`, note: fmtBytes(r.file.size) });
    for (const s of r.pe.sections) {
      mapEntries.push({
        name: `${hx(s.rawPointer)},${hx(s.rawPointer + s.rawSize)}`,
        value: s.name,
        note: `VA ${hx(s.virtualAddress)} · ${peFlagsToProt(s.flags)}`,
      });
    }
  }

  if (mapEntries.length > 0) {
    const c = cap(mapEntries);
    sections.push({ key: "map", title: "Fiziksel harita (memmap)", kind: "map", ...c, note: device });
  }

  const available = sections.length > 0;
  return {
    id: "leechcore",
    name: "LeechCore",
    version: "v2.16 benzeri",
    generatorNote: r.mem
      ? "bellek aralik haritasi (lc memmap uyumlu)"
      : "PE bolumlerinin fiziksel dosya haritasi (lc memmap uyumlu)",
    available,
    reason: available ? `Cihaz haritasi uretildi: ${device}` : "Haritalanabilir bellek/dosya yapisi yok",
    sections,
    files: [],
  };
}

// ---------------------------------------------------------------------------
// ortak veri (kesisim) hesabi
// ---------------------------------------------------------------------------

function buildCommon(extractors: ExtractorOutput[]): ExtractorsInfo["common"] {
  const byKindName = new Map<string, { entry: ExtractorEntry; kind: ExtractorSectionKind; ids: Set<ExtractorId> }>();

  for (const ex of extractors) {
    if (!ex.available) continue;
    for (const sec of ex.sections) {
      // module/region/map haritalarda ad aralik benzerligi dusuk olur; yine de
      // ayni isimle ikinci kez bulunursa ortak sayilir (orn. ana modul adlari)
      for (const e of sec.entries) {
        const key = `${sec.kind}:${normName(e.name)}`;
        const existing = byKindName.get(key);
        if (existing) {
          existing.ids.add(ex.id);
        } else {
          byKindName.set(key, { entry: e, kind: sec.kind, ids: new Set([ex.id]) });
        }
      }
    }
  }

  const commonByKind = new Map<ExtractorSectionKind, CommonEntry[]>();
  for (const { entry, kind, ids } of byKindName.values()) {
    if (ids.size < 2) continue;
    const list = commonByKind.get(kind) ?? [];
    list.push({ name: entry.name, kind, foundIn: [...ids], value: entry.value });
    commonByKind.set(kind, list);
  }

  const TITLES: Record<ExtractorSectionKind, string> = {
    class: "Ortak Siniflar",
    struct: "Ortak Structlar",
    enum: "Ortak Enumlar",
    function: "Ortak Fonksiyonlar",
    offset: "Ortak Ofsetler / Adresler",
    module: "Ortak Moduller",
    region: "Ortak Bellek Bolgeleri",
    map: "Ortak Harita Kayitlari",
  };

  const out: ExtractorsInfo["common"] = [];
  for (const [kind, list] of commonByKind) {
    list.sort((a, b) => b.foundIn.length - a.foundIn.length || a.name.localeCompare(b.name));
    out.push({ kind, title: TITLES[kind], entries: list.slice(0, COMMON_CAP) });
  }
  out.sort((a, b) => b.entries.length - a.entries.length);
  return out;
}

// ---------------------------------------------------------------------------
// cikarici dosya uretimi (diskte storage/sdk/<uploadId> altina yazilir)
// ---------------------------------------------------------------------------

export interface ExtractorGeneratedFile {
  name: string;
  content: string;
}

function buildExtractorFiles(r: AnalysisResult, extractors: ExtractorOutput[]): ExtractorGeneratedFile[] {
  const files: ExtractorGeneratedFile[] = [];
  const stamp = new Date().toISOString().replace("T", " ").slice(0, 19);
  const header = (what: string): string[] => [
    "================================================================",
    `  DumperPro Online - ${what}`,
    `  Hedef : ${r.file.name} (${fmtBytes(r.file.size)})`,
    `  Tarih : ${stamp} UTC`,
    "  NOT: statik kurtarma - canli modda dogrulanmalidir.",
    "================================================================",
    "",
  ];

  // --- UnrealCEDumper: offsets + vtables ---
  const ue = extractors.find((e) => e.id === "unrealcedumper");
  if (ue?.available) {
    const offSec = ue.sections.find((s) => s.key === "offsets");
    if (offSec && offSec.entries.length > 0) {
      const L = header("UnrealCEDumper tarzi ofsetler (unrealcedumper_offsets.txt)");
      L.push("[OFFSETS]");
      for (const e of offSec.entries) {
        L.push(`${e.name} = ${e.value}${e.note ? `  ; ${e.note}` : ""}`);
      }
      L.push("", "; games.ini ile kullanim: adresleri games.ini'ye kopyalayin.");
      files.push({ name: "unrealcedumper_offsets.txt", content: L.join("\n") });
    }
    const vtSec = ue.sections.find((s) => s.key === "classes");
    if (vtSec && vtSec.entries.length > 0) {
      const L = header("UnrealCEDumper tarzi vtable haritasi (unrealcedumper_vtables.txt)");
      L.push("[VTABLES]");
      for (const e of vtSec.entries) {
        L.push(`${e.name} : ${e.value}${e.note ? `  ; ${e.note}` : ""}`);
      }
      files.push({ name: "unrealcedumper_vtables.txt", content: L.join("\n") });
    }
  }

  // --- MemProcFS: modules + regions ---
  const mp = extractors.find((e) => e.id === "memprocfs");
  if (mp?.available) {
    const modSec = mp.sections.find((s) => s.key === "modules");
    if (modSec && modSec.entries.length > 0) {
      const L = header("MemProcFS tarzi modul listesi (memprocfs_modules.txt)");
      L.push(`; gorunum: ${mp.generatorNote}`);
      L.push("");
      L.push("Volume  | Module     | Base          | Size");
      L.push("--------|------------|---------------|-----");
      for (const e of modSec.entries) {
        L.push(`-       | ${e.name.padEnd(24)} | ${(e.value ?? "-").padEnd(28)} | ${e.note ?? ""}`);
      }
      files.push({ name: "memprocfs_modules.txt", content: L.join("\n") });
    }
    const regSec = mp.sections.find((s) => s.key === "regions");
    if (regSec && regSec.entries.length > 0) {
      const L = header("MemProcFS tarzi VAD bolgeleri (memprocfs_regions.txt)");
      L.push("Start          - End            | Prot | State | Type       | File");
      L.push("---------------|----------------|------|-------|------------|-----");
      for (const e of regSec.entries) {
        const [start, end] = e.name.split("-");
        L.push(`${start} - ${end} | ${(e.value ?? "-").padEnd(4)} | ${(e.note ?? "-").padEnd(28)}`);
      }
      files.push({ name: "memprocfs_regions.txt", content: L.join("\n") });
    }
  }

  // --- LeechCore: lc memmap uyumlu harita ---
  const lc = extractors.find((e) => e.id === "leechcore");
  if (lc?.available) {
    const mapSec = lc.sections.find((s) => s.key === "map");
    if (mapSec && mapSec.entries.length > 0) {
      const L = header("LeechCore tarzi bellek/dosya haritasi (leechcore_memmap.txt)");
      L.push(`; ${mapSec.note ?? ""}`);
      L.push("; format: lc_memmap uyumlu 'start,end' satirlari (hex)");
      L.push("");
      for (const e of mapSec.entries) {
        if (e.name.includes(",")) {
          L.push(`${e.name}${e.value ? ` ; ${e.value}` : ""}`);
        } else {
          L.push(`; ${e.name}: ${e.value ?? ""}${e.note ? ` · ${e.note}` : ""}`);
        }
      }
      files.push({ name: "leechcore_memmap.txt", content: L.join("\n") });
    }
  }

  return files;
}

// ---------------------------------------------------------------------------
// ana giris
// ---------------------------------------------------------------------------

export function buildExtractors(r: AnalysisResult): {
  info: ExtractorsInfo;
  files: ExtractorGeneratedFile[];
} {
  const extractors: ExtractorOutput[] = [
    buildDumper7(r),
    buildDumperPro(r),
    buildIl2CppDumper(r),
    buildUnrealCEDumper(r),
    buildMemProcFs(r),
    buildLeechCore(r),
  ];

  // cikaricilarin kendi urettigi ek dosyalar (unrealcedumper_* / memprocfs_* / leechcore_*)
  const files = buildExtractorFiles(r, extractors);

  const common = buildCommon(extractors);
  const availableCount = extractors.filter((e) => e.available).length;

  const info: ExtractorsInfo = {
    extractors,
    common,
    note:
      availableCount === 0
        ? "Bu dosya icin hicbir cikarici cikti uretemedi."
        : `${availableCount} cikarici cikti uretti - ortak veriler ${common.reduce((a, c) => a + c.entries.length, 0)} oge.`,
  };

  return { info, files };
}

// ---------------------------------------------------------------------------
// SDK manifest'i cikaricilara dagit (hangi dosya hangi cikaricinin ciktisi)
// ---------------------------------------------------------------------------

const EXTRACTOR_FILE_LABELS: Record<ExtractorId, string> = {
  dumper7: "Dumper-7 stilinde C++ SDK",
  dumperpro: "DumperPro yerel analiz",
  il2cppdumper: "Il2CppDumper stilinde C#/meta cikti",
  unrealcedumper: "UnrealCEDumper stilinde ofset/vtable",
  memprocfs: "MemProcFS tarzi modul/bolge listesi",
  leechcore: "LeechCore tarzi bellek haritasi",
};

export function claimExtractorFiles(info: ExtractorsInfo, baseName: string, manifest: { name: string; kind: string; size: number }[]): void {
  const lowerBase = baseName.replace(/\.(exe|dll|sys|apk|so|bin|dat|pak|obb)$/i, "").toLowerCase();
  for (const ex of info.extractors) {
    const claimed = manifest.filter((f) => {
      const n = f.name.toLowerCase();
      switch (ex.id) {
        case "dumper7":
          return n.startsWith(`${lowerBase}_classes`) || n.startsWith(`${lowerBase}_structs`) || n.startsWith(`${lowerBase}_enums`) || n === "sdk.hpp";
        case "dumperpro":
          return ["functions.txt", "decompile.txt", "debug.txt", "offsets.txt"].includes(n);
        case "il2cppdumper":
          return n === "dump.cs" || n === "il2cpp_enums.cs" || n === "script.json";
        case "unrealcedumper":
          return n.startsWith("unrealcedumper_");
        case "memprocfs":
          return n.startsWith("memprocfs_");
        case "leechcore":
          return n.startsWith("leechcore_");
        default:
          return false;
      }
    });
    ex.files = claimed.map((f) => ({ name: f.name, kind: f.name, size: f.size }));
    if (claimed.length > 0 && !ex.available) {
      // dosya uretildiyse cikarici kullanilabilir sayilir
      ex.available = true;
      if (ex.reason.startsWith("Bu dosya icin")) ex.reason = "SDK ciktilari uretildi";
    }
    void EXTRACTOR_FILE_LABELS;
  }
}
