// ----------------------------------------------------------------------------
// DumperPro Online - analiz sonuc tipleri (frontend ile paylasilir)
// ----------------------------------------------------------------------------

export type FileKind =
  | "pe" | "apk" | "zip" | "elf" | "dex" | "metadata" | "unknown"
  | "pak" | "utoc" | "ucas" | "uasset" | "umap" | "macho"
  | "vdex" | "oat" | "cdex"
  | "minidump" | "memmap"
  | "savegame" | "vdf";

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawPointer: number;
  entropy: number;
  flags: string[]; // "r","w","x","code","data","reloc","discardable"
}

export interface PeImport {
  dll: string;
  count: number;
  functions: string[]; // cap 80, kesilirse "+N more" notu
  truncated: boolean;
}

export interface PeExport {
  dllName: string;
  count: number;
  names: string[]; // cap 500
  truncated: boolean;
  entries?: PeExportEntry[]; // ad + RVA tablosu (fonksiyon etiketleme icin)
}

export interface PeExportEntry {
  name: string;
  ordinal: number;
  rva: number;
  va: number;
}

export interface PeDataDirectory {
  name: string;
  va: number;
  size: number;
}

export interface PeInfo {
  format: "PE32+" | "PE32";
  machine: string;
  arch: string;
  timestamp: number;
  buildDate: string;
  characteristics: string[];
  subsystem: string;
  entryPointRva: number;
  imageBase: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  dllCharacteristics: string[];
  sections: PeSection[];
  imports: PeImport[];
  importDllCount: number;
  exports: PeExport | null;
  dataDirectories: PeDataDirectory[];
  debugPdb?: string;
  debug?: PeDebugInfo;
  versionInfo?: VersionInfo | null;
  tlsCallbacks?: string[];
  richTools?: string[];
  checksumOk?: boolean | null;
}

export interface PeDebugInfo {
  pdb?: { path: string; guid: string; age: number };
  coffSymbols: number; // 0 = stripped
  coffSymbolSamples: string[]; // cap 40
  reproducible: boolean; // debug[1] type=12 (REPRODUCIBLE)
  entries: PeDebugEntry[]; // tum debug dizin kayitlari (cap 16)
  guid: string; // PDB GUID (kodview), yoksa ""
}

export interface PeDebugEntry {
  index: number;
  type: string; // CODEVIEW | POGO | IPOCG | MPDC | REPRODUCIBLE | SPGO | CTYPES | EX DLLNAME | ...
  rawType: number;
  size: number;
  rva: number;
  detail?: string; // pdb yolu / pgo adi vb.
}

export interface VersionInfo {
  companyName?: string;
  productName?: string;
  fileVersion?: string;
  productVersion?: string;
  fileDescription?: string;
  originalFilename?: string;
  internalName?: string;
  legalCopyright?: string;
  comments?: string;
}

export interface ResourceEntry {
  type: string;
  id: string;
  language?: string;
  size: number;
  rva: number;
  offset: number; // dosya ici offset
  embedded?: string; // "PE" | "ZIP" | ... (magic sezgisi)
}

export interface ResourcesInfo {
  total: number;
  entries: ResourceEntry[]; // cap 64
  biggest?: ResourceEntry & { pct: number }; // dosyanin yuzdesi
}

export interface ElfSection {
  name: string;
  type: string;
  addr: number;
  size: number;
}

// disa aktarilan dynamic sembol (.dynsym)
export interface ElfDynSym {
  name: string;
  type: string; // FUNC | OBJECT
  bind: string; // GLOBAL | WEAK
  value: number; // sanal adres
  size: number;
}

export interface ElfInfo {
  class: "ELF32" | "ELF64";
  endian: "LE" | "BE";
  machine: string;
  type: string;
  entryPoint: number;
  sectionCount: number;
  sections: ElfSection[]; // cap 64
  dynsymCount?: number; // toplam .dynsym girdisi
  dynsyms?: ElfDynSym[]; // disa aktarilanlar (cap 96)
}

export interface DexInfo {
  version: string; // "035" / "037" / "038" / "039"
  endian: string; // LE | BE
  strings: number;
  types: number;
  protos: number;
  fields: number;
  methods: number;
  classes: number;
  checksumOk: boolean;
  packages: { name: string; count: number }[]; // top 16 paket
  topLevelPackages: string[]; // ilk segment sayimi (com, org ...)
  engineHints: string[];
  classSamples: string[]; // ilk 24 sinif tanimlayicisi
}

export interface ApkEntry {
  path: string;
  size: number; // uncompressed
  compressed: number;
  method: string; // STORE / DEFLATE
}

export interface ApkGroup {
  dir: string;
  count: number;
  totalSize: number;
}

export interface ApkInfo {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: number;
  targetSdk?: number;
  abis: string[];
  mainLibs: (ApkEntry & { engineHint?: string })[]; // lib/<abi>/*.so
  dexCount: number;
  entryCount: number;
  groups: ApkGroup[]; // cap 24
  notableFiles: string[]; // global-metadata.dat, *.pak ...
  pakFiles: { path: string; size: number }[]; // UE .pak
  scannedLibs: { path: string; engine?: string; version?: string; versionStrings: string[] }[];
}

export interface EngineInfo {
  detected: string; // UE4 | UE5 | Unity | Godot | Source | CryEngine | Frostbite | Bilinmiyor
  version?: string;
  versionStrings: string[]; // ham "++UE4+Release-..." eslesmeleri
  markers: { name: string; hits: number }[]; // bulunmayanlar listelenmez
  confidence: string; // yuksek | orta | dusuk
}

export interface SecurityInfo {
  antiCheat: string[];
  drm: string[];
  packer: string[];
  packedHint: boolean; // yuksek entropy sezgisel sonucu
  notableStrings: string[];
}

export interface SigCandidate {
  name: string; // GObjects / GNames / ProcessEvent ...
  pattern: string;
  hits: { rva: string; va: string; offset: string }[];
  note: string;
}

export interface InterestingString {
  value: string;
  kind: "ascii" | "utf16";
}

// ------------------------- derin statik analiz -------------------------

export interface FunctionEntry {
  idx: number;
  rva: number;
  va: number;
  size: number;
  label?: string; // export adi / EntryPoint / WinMain tahmini
  section: string;
  prologue: string; // ilk 12 bayt hex
  strings: string[]; // lea/mov rip referanslari (cap 8)
  apiCalls: string[]; // FF 15 IAT referanslari (cap 8)
  callsOut: number; // E8/E9 rel32 cikis cagrilari
  xrefsIn: number; // diger fonksiyonlardan gelen cagri sayisi
  asm?: string; // cap'li disassembly listing (secili fonksiyonlar)
  pseudo?: string; // tahmini pseudo-C (secili fonksiyonlar)
  structHint?: string; // kodda vftable referansi varsa sinif adi
}

export interface FunctionsInfo {
  total: number;
  source: "pdata" | "heuristic";
  is64: boolean;
  detailed: number; // referans analizi yapilan fonksiyon sayisi
  disassembled: number; // asm/pseudo uretilen fonksiyon sayisi
  functions: FunctionEntry[]; // cap 500
  topBySize?: { rva: number; size: number; label?: string }[]; // cap 12
  note?: string;
}

export interface RttiClass {
  name: string; // demangled (std::exception seklinde)
  kind: "class" | "struct";
  rttiRva: number; // TypeDescriptor RVA
  vftableRva?: number;
  vftableVa?: number;
  base?: string; // 1 seviye taban sinif
  methodCount: number;
  methods: { rva: number; va: number }[]; // cap 48
}

export interface RttiInfo {
  available: boolean;
  total: number;
  classes: RttiClass[]; // cap 256
  enumNames: string[]; // .?AW4 tip descriptorlari (cap 128)
  note?: string;
}

export interface Il2CppClassInfo {
  name: string;
  namespace: string;
  image: string; // Assembly-CSharp.dll ...
  kind: "class" | "struct" | "interface" | "enum";
  base?: string;
  fields: string[]; // cap 24
  methods: string[]; // cap 24
  fieldCount: number;
  methodCount: number;
}

export interface Il2CppEnumInfo {
  name: string;
  namespace: string;
  image: string;
  members: { name: string; value: number | null }[]; // cap 32
  memberCount: number;
}

export interface Il2CppInfo {
  version: string; // "24.2" / "27" / "29" ...
  unityHint: string; // "Unity ~2019.3-2019.4"
  sanityOk: boolean;
  stringCount: number;
  literalCount: number;
  images: string[]; // cap 48
  classCount: number;
  methodCount: number;
  fieldCount: number;
  classes: Il2CppClassInfo[]; // cap 500
  enums: Il2CppEnumInfo[]; // cap 300
  literalSamples: string[]; // cap 60
  notes: string[];
}

// ------------------------- struct / enum kurtarma -------------------------

export interface StructField {
  name: string;
  offset: number;
  size: number;
  type: string; // uint8/uint16/uint32/uint64/float/vptr...
  reads: number; // kac fonksiyonda erisildi (guven)
}

export interface RecoveredStruct {
  name: string;
  kind: "class" | "struct";
  size?: number;
  base?: string;
  vftableRva?: number;
  vftableVa?: number;
  methodCount: number;
  fields: StructField[]; // ofset sirali, cap 64
  source: "rtti" | "code" | "mixed";
}

export interface StructsInfo {
  total: number;
  structs: RecoveredStruct[]; // cap 200
  note?: string;
}

export interface RecoveredEnum {
  name: string;
  source: "rtti" | "switch" | "il2cpp";
  members: { name: string; value: number }[]; // cap 64
  note?: string;
}

export interface EnumsInfo {
  total: number;
  enums: RecoveredEnum[]; // cap 200
  note?: string;
}

// ------------------------- IL2CPP binary eslestirme (CodeRegistration) -------------------------

export interface Il2CppBinaryInfo {
  detected: boolean;
  reason: string; // nasil tespit edildi / neden edilmedi
  unityVersion?: string; // binary icinde bulunan "2019.4.39f1" tarzi surum
  pointerSize: number;
  codeRegistration?: { rva: number; va: number; fieldNote: string };
  metadataRegistration?: { rva: number; va: number; fieldNote: string };
  codeGenModules?: {
    count: number;
    rva: number; // codeGenModules dizi isaretcisinin saklandigi alan (CodeRegistration ici)
    va: number;
    modules: { name: string; methodCount: number; resolved: number; pointersRva: number }[];
  };
  methodPointersResolved: number; // gecerli .text adresine eslenen metod isaretcisi
  fieldOffsetsTypes?: number; // fieldOffsets tablosu cozulen tip sayisi
  linked: boolean; // metadata ile eslestirme yapildi mi
  dumpCs?: boolean; // dump.cs uretildi mi (bagli metadata ile)
  notes: string[];
}

// ------------------------- ortak oyun dosyalari (pak/utoc/uasset/macho) -------------------------

export interface PakEntryInfo {
  name: string | null;
  offset: number; // pak icinde kesin offset (cozulmuse)
  size: number;
  compressed?: number;
  method: string; // None / Oodle / Zlib ... (v8+ isim tablosundan)
  hash?: string; // SHA-1 (ilk baytlar)
}

export interface PakFileInfo {
  version: number;
  indexOffset: number;
  indexSize: number;
  encryptedIndex: boolean;
  compressionMethods: string[]; // v8+ 5 adet 32B isim
  mountPoint?: string;
  entryCount: number;
  namedEntries: number;
  entries: PakEntryInfo[]; // cap 400
}

export interface UtocInfo {
  version: number;
  tocHeaderSize: number;
  entryCount: number;
  blockEntryCount: number;
  compressionMethods: string[];
  partitions: number;
  entries: { chunkId: string; chunkType: string; offset: number; size: number }[]; // cap 400
}

export interface UassetInfo {
  legacyVersion: number; // -8 => UE5 hizasi
  ue4Version?: number;
  ue5Version?: number;
  licenseeVersion: number;
  totalHeaderSize?: number;
  packageFlags?: number;
  nameCount: number;
  nameOffset?: number;
  importCount?: number;
  exportCount?: number;
  names: string[]; // cap 200
  note?: string;
}

export interface MachoArch {
  cpu: string;
  offset: number;
  size: number;
}

export interface MachoInfo {
  format: "thin" | "fat";
  archs: MachoArch[];
  fileType: string;
  segments: { name: string; vmaddr: number; vmsize: number; filesize: number; nsects: number }[];
  sections: { seg: string; name: string; addr: number; size: number }[];
  dylibs: string[]; // cap 48
  entry?: number;
  ncmds: number;
}

export interface GameFilesInfo {
  type: "pak" | "utoc" | "ucas" | "uasset" | "umap" | "macho";
  pak?: PakFileInfo;
  utoc?: UtocInfo;
  uasset?: UassetInfo;
  macho?: MachoInfo;
  notes: string[];
}

// ------------------------- memory dump (LeechCore/MemProcFS benzeri) -------------------------

export interface MemRegion {
  vaStart: number;
  vaEnd: number;
  protection: string; // "rw-" / "r-x" ...
  state: string; // MEM_COMMIT / MEM_RESERVE / MEM_FREE / -
  type: string; // MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED / -
  file?: string; // MemoryInfoList'te bagli dosya yoksa "-"
  note?: string;
}

export interface MemModuleInfo {
  name: string;
  base: number;
  size: number;
  timestamp?: string; // TimeDateStamp
  recoverable: boolean; // PE'den kurtarilabilir mi (bellek araligi kapsiyor mu)
  recoveredRangePct: number; // bellekte kac yuzde kapsama
  note?: string;
}

export interface MemInfo {
  device: string; // "minidump" | "kernel-crashdump" | "raw+memmap"
  arch: string;
  os?: string;
  pid?: number;
  moduleCount: number;
  modules: MemModuleInfo[];
  regionCount: number;
  regions: MemRegion[]; // cap 400
  memoryRangeCount: number;
  totalMemoryBytes: number;
  notes: string[];
}

// ------------------------- SDK cikti dosyalari -------------------------

export interface SdkFile {
  name: string;
  kind: string; // classes.h | structs.h | enums.h | Functions.txt | Debug.txt | dump.cs | ...
  size: number;
}

export interface SdkInfo {
  generator: string; // "Dumper-7 benzeri C++ SDK" / "Il2CppDumper benzeri dump.cs"
  files: SdkFile[];
  note?: string;
}

// ------------------------- coklu cikarici (multi-dumper) ciktilari -------------------------
//
// Ayni dosya farkli dumper "modelleri" ile ayrilir: Dumper-7, Il2CppDumper,
// UnrealCEDumper, MemProcFS, LeechCore... Her cikaricinin kendi bolumleri
// (sinif/struct/enum/fonksiyon/offset/modul/bolge) ve kendi SDK ciktilari olur.
// OrtakVeri: en az 2 cikaricida ayni isimle bulunan ogeler (kesisim).

export type ExtractorId = "dumper7" | "il2cppdumper" | "unrealcedumper" | "memprocfs" | "leechcore" | "dumperpro";

export interface ExtractorEntry {
  name: string;
  value?: string; // RVA/VA/offset/deger (metin)
  note?: string;
}

export type ExtractorSectionKind =
  | "class" | "struct" | "enum" | "function" | "offset" | "module" | "region" | "map";

export interface ExtractorSection {
  key: string; // "classes" | "structs" | "enums" | "functions" | "offsets" | "modules" | "regions"
  title: string; // gorunen ad
  kind: ExtractorSectionKind;
  total: number; // gercek toplam
  entries: ExtractorEntry[]; // cap'li liste
  truncated?: boolean;
  note?: string;
}

export interface ExtractorOutput {
  id: ExtractorId;
  name: string; // "Dumper-7"
  version: string; // "v1.3.2 benzeri"
  generatorNote: string; // nasil uretildi
  available: boolean; // bu dosyada cikti uretebildi mi
  reason: string; // neden yok / nasil tespit edildi
  sections: ExtractorSection[];
  files: SdkFile[]; // uretilen cikti dosyalari (diskte storage/sdk/<id>)
}

export interface CommonEntry {
  name: string;
  kind: ExtractorSectionKind;
  foundIn: ExtractorId[]; // hangi cikaricilarda bulundu
  value?: string; // ilk bulunan deger
}

export interface ExtractorsInfo {
  extractors: ExtractorOutput[]; // en az 1 tanesi available
  common: {
    kind: ExtractorSectionKind;
    title: string;
    entries: CommonEntry[]; // sadece >=2 cikaricida bulunanlar
  }[];
  note?: string;
}

export interface AnalysisResult {
  kind: FileKind;
  file: {
    name: string;
    size: number;
    sha256: string;
  };
  overallEntropy: number;
  pe?: PeInfo;
  elf?: ElfInfo;
  dex?: DexInfo;
  apk?: ApkInfo;
  zip?: {
    entryCount: number;
    groups: ApkGroup[];
    notableFiles: string[];
    mainLibs: (ApkEntry & { engineHint?: string })[];
  };
  engine: EngineInfo;
  security: SecurityInfo;
  signatureCandidates: SigCandidate[];
  strings: InterestingString[]; // cap 250
  functions?: FunctionsInfo; // PE: .pdata/heuristic fonksiyon tablosu + decompile
  rtti?: RttiInfo; // PE: MSVC RTTI siniflari + vftable
  resources?: ResourcesInfo; // PE: kaynak agaci + gomulu payload sezgisi
  structs?: StructsInfo; // PE: kod/RTTI kurtarma ile structlar
  enums?: EnumsInfo; // PE: RTTI + switch tablosu enumlari
  il2cpp?: Il2CppInfo; // global-metadata.dat tam parse (Il2CppDumper benzeri)
  il2cppBin?: Il2CppBinaryInfo; // GameAssembly.dll / libil2cpp.so binary tarafi
  gameFiles?: GameFilesInfo; // pak / utoc / ucas / uasset / macho
  art?: ArtInfo; // ART VDEX/OAT gomulu DEX (vdexExtractor mantigi)
  pdb?: PdbResult; // eslesen .pdb sembolleri (MSF/DBI/S_PUB32/S_UDT)
  mem?: MemInfo; // minidump / raw+memmap bellegi (LeechCore benzeri)
  savegame?: SaveGameInfo; // UE GVAS .sav ozeti (Save Editor sekmesi)
  vdf?: VdfInfo; // Steam VDF ozeti (Save Editor sekmesi)
  sdk?: SdkInfo; // uretilen SDK ciktilari (diskte: storage/sdk/<uploadId>)
  extractors?: ExtractorsInfo; // coklu cikarici ciktilari (Dumper-7 / Il2CppDumper / UnrealCEDumper / MemProcFS / LeechCore)
  gamesIniSuggestion?: string;
  notes: string[];
  errors: string[]; // kismi parse uyarilari
}

// ----------------------------------------------------------------------------
// ART VDEX/OAT (gomulu DEX cikarma - vdexExtractor mantigi, Gorev 4)
// ----------------------------------------------------------------------------

export interface ArtDexEntry {
  index: number;
  offset: number;
  size: number;
  /** gomulu DEX'in kendi ozeti (parseDex ile; byte'lar DB'ye yazilmaz) */
  classes?: number;
  methods?: number;
  strings?: number;
}

export interface ArtInfo {
  kind: "vdex" | "oat";
  version: string;
  apiHint: string;
  dexSectionVersion?: string; // vdex icin "000"|"002"|""
  dexCount: number;
  dexes: ArtDexEntry[];
  notes: string[];
  error?: string;
}

// ----------------------------------------------------------------------------
// UE save game (GVAS) + Steam VDF - save editor ozetleri
// ----------------------------------------------------------------------------

export interface SaveGameInfo {
  magic: boolean; // GVAS imzasi dogrudan gorundu mu
  fileVersion: number;
  ue4Version: number;
  ue5Version?: number; // fileVersion >= 3 icin
  className: string;
  propCount: number; // toplam property dugumu (recursive)
  totalPropBytes: number; // ust seviye property'lerin kapladigi toplam bayt
  encrypted: boolean;
  compressed: boolean;
  engineVersion: string; // "5.3.2-0++UE5+Release-5.3" tarzi
}

export interface VdfInfo {
  kind: "text" | "binary";
  keyCount: number;
  maxDepth: number;
  sampleKeys: string[]; // ilk ~16 anahtar
}

// ----------------------------------------------------------------------------
// PDB sembolleri (MSF/DBI/S_PUB32/S_UDT okuma - Gorev 3)
// ----------------------------------------------------------------------------

export interface PdbSectionInfo {
  name: string;
  rva: number;
  vsize: number;
}

export interface PdbSymbolInfo {
  name: string;
  kind: "func" | "data";
  seg: number;
  off: number;
  rva?: number;
}

export interface PdbResult {
  valid: boolean;
  version: number;
  signature: number;
  age: number;
  guid: string;
  machine: string;
  streamCount: number;
  sectionCount: number;
  funcCount: number;
  dataCount: number;
  udtCount: number;
  symbols: PdbSymbolInfo[]; // cap 500 (DB satiri kontrolu)
  symbolsTotal: number;
  udtNames: string[]; // cap 300
  udtTotal: number;
  sections: PdbSectionInfo[];
  notes: string[];
  error?: string;
}
