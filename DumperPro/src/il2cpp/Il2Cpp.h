// ============================================================================
// DumperPro - Il2Cpp.h
//
// Unity IL2CPP global-metadata.dat parser (metadata surumleri 16..31).
//
// Layout kaynaklari (dogrulanmis - bu dosyadaki tum struct boyutlari buradan
// birebir alindi, "arastir-bul-incele-dogrula" akisi):
//   - Il2CppDumper (Perfare) Il2Cpp/Metadata.cs + Il2Cpp/MetadataClass.cs
//     https://github.com/Perfare/Il2CppDumper
//   - Unity libil2cpp GlobalMetadataHeader (ayni alan sirasi)
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) global-metadata.dat yalnizca METADATA tutar; Il2CppType tablosu,
//      metod gostericileri (native adresler) binary'dedir
//      (libil2cpp.so / GameAssembly.dll). Metadata-yalniz modda tip isimleri
//      yerine TypeIndex gosterilir; binary eslestirmesi Il2CppBinary.cpp
//      modulundedir (CodeRegistration/MetadataRegistration taramasi).
//   2) v24 alt surumleri (24 / 24.1 / 24.2 / 24.4 / 24.5) Il2CppDumper'in
//      ayni sezgisel kontroluyle ayristirilir (stringLiteralOffset==264,
//      image token != 1, assembliesSize/64 eslesmesi).
//   3) Tum okumalar sinir kontrolludur; bozuk/kesik dosyalarda kismi sonuc
//      + lastError doner, crash olmaz. Kati dogrulama: sanity 0xFAB11BAF.
//   4) Kullanim sinirlari: yalnizca sahibi olunan/lisansli yazilim analizi.
// ============================================================================

#pragma once
#include "../framework.h"

namespace dumper {

struct Il2ImageInfo {
    std::string name;        // image nameIndex -> string havuzu
    u32 typeStart = 0;
    u32 typeCount = 0;
    u32 token = 0;
};

struct Il2FieldInfo {
    std::string name;
    i32 typeIndex = -1;      // binary Il2CppType tablosuna referans (cozumesiz mod)
    u32 token = 0;
    u16 flags = 0;
};

struct Il2MethodInfo {
    std::string name;
    i32 returnTypeIndex = -1;
    i32 parameterStart = -1;
    u16 parameterCount = 0;
    u16 flags = 0;           // MethodAttributes
    u16 iflags = 0;
    u16 slot = 0;
    u32 token = 0;
};

struct Il2ParamInfo {
    std::string name;
    i32 typeIndex = -1;
};

// ---------------------------------------------------------------------------
// metadataUsages (metadata v19..24.5): runtime'in "bu kodgen global hucreye
// hangi metadata kaydini baglayacagi" eslestirmeleri. Layout Il2CppDumper
// Metadata.cs / MetadataClass.cs kaynaklarindan dogrulandi:
//   Il2CppMetadataUsageList { u32 start; u32 count; }   (8 bayt)
//   Il2CppMetadataUsagePair { u32 destinationIndex; u32 encodedSourceIndex; }
//   usageType    = (encodedSourceIndex & 0xE0000000) >> 29   (1..6)
//   decodedIndex =  encodedSourceIndex & 0x1FFFFFFF          (v<27)
// Tipler (Il2CppMetadataUsage enum):
//   1=TypeInfo, 2=Il2CppType, 3=MethodDef, 4=FieldInfo,
//   5=StringLiteral, 6=MethodRef
// ---------------------------------------------------------------------------
struct Il2UsagePair {
    u32 destinationIndex = 0;
    u32 usageType = 0;
    u32 decodedIndex = 0;
};

// metadata fieldRefs tablosu kaydi (yalnizca FieldInfo usage'larinda kullanilanlar)
struct Il2FieldRefInfo {
    i32 typeIndex = -1;      // binary Il2CppType tablosu indexi
    i32 fieldIndex = -1;     // tipin kendi fieldStart'ina gore lokal index
};

struct Il2TypeInfo {
    std::string name;
    std::string ns;
    i32 parentIndex = -1;    // binary TypeIndex (cozumesiz modda yalnizca index)
    u32 flags = 0;           // TypeAttributes
    u32 fieldStart = 0, methodStart = 0;
    u16 fieldCount = 0, methodCount = 0, propertyCount = 0, eventCount = 0;
    bool isValueType = false;
    bool isEnum = false;
    bool isInterface = false;
    u32 token = 0;
};

struct Il2Metadata {
    bool valid = false;
    int version = 0;         // tamsayi ana surum (16..31)
    std::string versionStr;  // "24.1", "27", "29", "31", ...
    std::string unityHint;   // yaklasik Unity surum araligi

    std::vector<Il2ImageInfo> images;
    std::vector<Il2TypeInfo> types;
    std::vector<Il2FieldInfo> fields;
    std::vector<Il2MethodInfo> methods;
    std::vector<Il2ParamInfo> params;

    u32 stringLiteralCount = 0;
    std::vector<std::string> stringLiterals; // cap'li ornek
    u64 stringLiteralDataSize = 0;
    u64 stringDataSize = 0;

    // ---- metadataUsages (yalnizca metadata v19..24.5'te tablo vardir) ------
    bool hasUsages = false;
    u32 usageSlotCount = 0;                       // max destinationIndex + 1
    std::vector<Il2UsagePair> usages;             // list->pair acilimi (cozulen)
    u32 fieldRefCount = 0;                        // fieldRefs tablosu kayit sayisi
    std::unordered_map<u32, Il2FieldRefInfo> usageFieldRefs;      // idx -> kayit (kullanilanlar)
    std::unordered_map<u32, std::string> usageStringLiterals;     // idx -> deger (kullanilanlar)

    u64 fileSize = 0;
    std::string lastError;
};

class Il2CppMetadataParser {
public:
    // sanity (0xFAB11BAF) + makul surum kontrolu; dosyanin IL2CPP metadata'si
    // olup olmadigini hizli soyler (ilk 8 bayt).
    static bool LooksLikeMetadata(const u8* data, size_t size);

    // tam parse; hata halinde false + out.lastError
    static bool Parse(const u8* data, size_t size, Il2Metadata& out);

    // cikti dosyalari (outDir altina):
    //   il2cpp_report.txt        Turkce ozet rapor
    //   il2cpp_dump.cs           dump.cs benzeri tip/metod iskeleti
    //   il2cpp_stringliterals.txt (cap'li)
    //   il2cpp_metadata.json     makine-okur sema
    static void WriteOutputs(const Il2Metadata& m, const fs::path& outDir,
                             const std::string& fileName, size_t maxStrings = 100000);

    static std::string BuildReport(const Il2Metadata& m, const std::string& fileName);
    static std::string BuildJson(const Il2Metadata& m, const std::string& fileName);
    static std::string BuildDumpCs(const Il2Metadata& m);
};

} // namespace dumper
