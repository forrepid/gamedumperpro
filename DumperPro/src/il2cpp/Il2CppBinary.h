// ============================================================================
// DumperPro - Il2CppBinary.h
//
// IL2CPP BINARY ESLESTIRMESI (Il2CppDumper'in "ikinci yarisi").
//
// global-metadata.dat yalnizca METADATA tutar; Il2CppType tablosu ve metod
// native adresleri binarydedir (libil2cpp.so / GameAssembly.dll). Bu modul
// metadata parse sonucunu binary ile eslestirir:
//
//   1) Il2CppCodeGenModule taramasi (metadata v24.1+):
//      metadata image isimleri ("mscorlib.dll", ...) binary'de .rodata'da
//      aranir; bu stringlere isaret EDEN 8/4 baytlik slotlar Il2CppCodeGenModule
//      baslangicidir (layout, il2cpp runtime kaynagi ile ayni, tum v24.1+ surumlerde
//      ilk 3 alan sabit):
//          const char* moduleName;              // +0x00
//          uint32_t    methodPointerCount;      // +0x08 (x64: +4 pad)
//          const Il2CppMethodPointer* methodPointers; // +0x10
//      Metod adresi: token 0x06000000|RID -> methodPointers[RID-1].
//   2) Duz methodPointers taramasi (metadata v16-24.0):
//      Il2CppCodeRegistration.methodPointersCount == metadata metod sayisi
//      eslesen { u32 count; ptr array[] } kalibi taranir; array icindeki
//      gostericilerin exec bolumlerine isaret etme orani ile dogrulanir.
//   3) Il2CppMetadataRegistration taramasi (tum surumler, x64 offsetleri):
//          +0x30 typesCount   +0x38 types (Il2CppType**)
//          +0x50 fieldOffsetsCount == metadata tip sayisi  (GUCLU dogrulama)
//      Il2CppType tablosu cozuldugunde dump.cs ciktisinda GERCEK tip isimleri
//      ve alan ofsetleri (fieldOffsets) kullanilir.
//
// ELF (libil2cpp.so) icin PIE relocation destegi: R_X86_64_RELATIVE (8),
// R_AARCH64_RELATIVE (1027), R_RISCV_RELATIVE (3) RELA kayitlari okunur ve
// slot okumalarinda (relocation varsa) addend kullanilir. GameAssembly.dll
// (PE) icin ham gostericiler ImageBase ekle/çıkar ile normalize edilir.
//
// Il2CppClass layout'u (v16..31'de stabil): image(+0x00), gc_desc(+0x08),
// name(+0x10), namespaze(+0x18). v<23'te Il2CppType.data CLASS/VALUETYPE
// icin TypeDefinitionIndex'tir; v23+ Il2CppClass* gostericisidir.
//
// ONEMLI NOTLAR:
//   1) Tum okumalar sinir kontrolludur; bozuk/eksik binary'de kismi sonuc +
//      lastError doner, crash olmaz. Hicbir sonuc "sessiz tahmin" degildir:
//      count/eslesme dogrulamalari gecmeden adres URETILMEZ.
//   2) Bu modul CANLI BELLEK ERISIMI YAPMAZ - yalnizca diskteki dosya.
//   3) Kullanim siniri: yalnizca sahibi olunan/lisansli yazilimin analizi
//      (README DISCLAIMER). Cok oyunculu hile amacli kullanim kapsam disi.
// ============================================================================

#pragma once
#include "../framework.h"
#include "il2cpp/Il2Cpp.h"

namespace dumper {

struct Il2MethodAddress {
    u32 methodIndex = 0;      // metadata global metod indexi
    u32 rva = 0;              // image-goreli adres (PE: RVA; ELF PIE: VA)
    u64 va = 0;               // PE: ImageBase+RVA, ELF: VA (PIE base 0)
    u64 fileOffset = 0;       // cikti dosyasindaki raw ofset (0xFFFFFFFF = bilinmiyor)
    bool fromReloc = false;   // ELF RELATIVE relocation addend'i kullanildi
};

// bir metadata image icin bulunan Il2CppCodeGenModule
struct Il2ModuleMatch {
    u32 imageIndex = 0;
    std::string imageName;    // metadata'dan ("mscorlib.dll")
    u64 moduleVa = 0;         // Il2CppCodeGenModule VA
    u32 methodPointerCount = 0;
    u64 methodPointersVa = 0;
    u32 candidates = 0;       // bu image icin bulunan aday sayisi
    double execRatio = 0.0;   // methodPointers orneklemesinde exec isabet orani
};

// metadataUsage slotu: runtime'in kodgen global hucresi (g_MyClass_TypeInfo
// gibi) ile metadata kaydini baglayan eslesme. cellVa = metadataUsages[di]
// dizisinin tuttugu deger (hucrenin VA'si). Il2CppDumper StructGenerator.cs
// AddMetadataUsage* akisiyla ayni semantik.
struct Il2UsageSlot {
    u32 destinationIndex = 0;
    u32 usageType = 0;        // 1..6 (Il2CppMetadataUsage)
    u32 decodedIndex = 0;
    u64 cellVa = 0;           // kodgen global hucre VA
    bool resolved = false;    // hucre VA'si binary veri bolgesinde dogrulandi
    std::string name;         // cozulen referans (tip/metod/alan/literal)
};

struct Il2BinaryResult {
    bool valid = false;             // en az 1 metod adresi cozulduyse true
    std::string format;             // "pe" | "elf"
    int bits = 0;                   // 32 | 64
    std::string arch;               // "x86-64", "AArch64", ...
    u64 imageBase = 0;              // PE: ImageBase; ELF: 0 (PIE)
    std::string metadataVersion;    // eslesen metadata surumu ("27", "24.2", ...)
    std::string mode;               // "codegen-modules" | "flat"

    // registration / codegen modules
    std::vector<Il2ModuleMatch> modules;
    u64 codeGenModulesArrayVa = 0;  // bulunduysa: codeGenModules* dizisi
    u32 codeGenModulesCount = 0;

    // MetadataRegistration
    bool metadataRegistrationFound = false;
    u64 metadataRegistrationVa = 0;
    u64 typesVa = 0;
    u32 typesCount = 0;
    u64 fieldOffsetsVa = 0;
    u32 fieldOffsetsCount = 0;
    bool typesResolved = false;     // Il2CppType tablosu okunduysa tip isimleri cozulebilir
    u64 methodSpecsVa = 0;          // MethodRef usage'lar icin
    u32 methodSpecsCount = 0;

    // metadataUsages (yalnizca v19..24.5): kodgen global hucre eslestirmeleri
    bool usagesFound = false;
    u64 usagesVa = 0;               // MetadataRegistration.metadataUsages (slot dizisi)
    u32 usagesCountBinary = 0;      // binary struct'tan okunan slot sayisi
    std::vector<Il2UsageSlot> usageSlots;

    // metod adres haritasi (metadata global metod indexi -> adres)
    std::unordered_map<u32, Il2MethodAddress> methodAddresses;
    u32 resolvedCount = 0;          // adres bulundu
    u32 nullCount = 0;              // methodPointers[RID-1] == 0 (abstract/extern)
    u32 unresolvedCount = 0;        // token aralik disi / modul eslesmedi

    // alan ofsetleri (dump.cs yorumlari icin): tip indexi -> alan indexi -> ofset
    std::unordered_map<u32, std::vector<i32>> fieldOffsets;

    std::string lastError;
};

class Il2CppBinaryMatch {
public:
    // binary: PE (MZ) veya ELF; meta: Il2CppMetadataParser::Parse ile
    // doldurulmus (valid) metadata. Adres cozumu calisirsa out.valid=true.
    static bool Match(const u8* bin, size_t binSize, const Il2Metadata& meta,
                      Il2BinaryResult& out);

    // ---- ciktilar ----
    // Il2CppDumper bicimi dump.cs: gercek tipler + "// RVA: .. VA: .." yorumlari
    // + alan ofsetleri (fieldOffsets bulunduysa "// 0x..").
    // binData/binSize: tip cozumu icin ham binary (BinaryView yeniden kurulur);
    // null/0 verilirse tip isimleri T<idx> olarak yazilir.
    static std::string BuildDumpCsBinary(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                         const u8* binData, size_t binSize);
    // Il2CppDumper script.json uyumlu (IDA/Ghidra script girdileri);
    // usages bulunduysa ScriptMetadata/ScriptMetadataMethod/ScriptString doldurulur.
    // binData/binSize: Il2CppType isimleri icin (null -> T<idx> fallback)
    static std::string BuildScriptJson(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                       const u8* binData = nullptr, size_t binSize = 0);
    // usage slot tablosu: Slot | Tip | Index | HucreVA | Ad
    static std::string BuildUsagesTxt(const Il2Metadata& meta, const Il2BinaryResult& bin);
    // metod adres listesi: Image | Type | Method | RVA | VA | Offset | token
    static std::string BuildMethodAddressesTxt(const Il2Metadata& meta, const Il2BinaryResult& bin);
    // tarama raporu (Turkce): registration/module/eslesme ozeti
    static std::string BuildBinaryReport(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                         const std::string& binName, const std::string& metaName);

    // outDir altina yazar:
    //   il2cpp_dump.cs            (binary eslestirmeli, gercek tipler + adresler)
    //   il2cpp_methodaddresses.txt
    //   il2cpp_script.json        (usages varsa ScriptMetadata dolu)
    //   il2cpp_usages.txt         (v19-24.5 usage slot tablosu)
    //   il2cpp_binary_report.txt
    static void WriteOutputs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                             const fs::path& outDir,
                             const std::string& binName, const std::string& metaName,
                             const u8* binData = nullptr, size_t binSize = 0);

    // DummyDll/dump.cs ureticileri icin ortak yardimci: Il2CppType tablosu
    // indexini C# bicimi tip adina cozer. typesResolved + binData yoksa
    // "T<idx>" fallback doner (sessiz tahmin yok).
    static std::string ResolveTypeCSharpName(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                             const u8* binData, size_t binSize, i32 typeIndex);
};

} // namespace dumper
