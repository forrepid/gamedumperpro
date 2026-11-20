// ============================================================================
// DumperPro - StaticAnalyzer.h
//
// Static file analysis orchestrator for non-PE (and quick PE summary) inputs:
//   PE   -> PEFile summary + UE strings (full deep pipeline lives in --file mode)
//   ELF  -> sections + UE strings (libUE4.so / libUE5.so / libil2cpp.so ...)
//   DEX  -> header counts + string pool engine hints
//   ZIP/APK -> central directory + manifest + lib/*.so extraction & scan
//
// Output: tek bir insan-okur TXT rapor + games.ini taslagi (PE icin).
//Used by:
//   DumperPro.exe --file game.apk        (non-PE file mode)
//   DumperPro.exe --serve                (HTTP upload mode)
// ============================================================================
#pragma once
#include "../framework.h"
#include "file/UniFormat.h"
#include "il2cpp/Il2Cpp.h"
#include "il2cpp/Il2CppBinary.h"

namespace dumper {

struct StaticReport {
    std::string kind;        // pe | elf | dex | apk | zip | oat | vdex | cdex | il2cpp | macho | macho-fat | unknown
    std::string engine;      // UE4 | UE5 | Unity (IL2CPP) | ...
    std::string engineVersion;
    std::string text;        // full report (Turkish)
    std::string gamesIni;    // only for PE
    // IL2CPP metadata'si bulundugunda dolu (APK icinden cikarilan veya
    // dogrudan yuklenen global-metadata.dat); arayan taraf tam ciktilari
    // Il2CppMetadataParser::WriteOutputs ile uretebilir.
    std::shared_ptr<Il2Metadata> il2cppMeta;
    // APK icinde metadata + libil2cpp.so BIRLIKTE bulundugunda otomatik
    // binary eslestirmesi sonucu ("es cifti"). Arayan taraf ciktilari
    // Il2CppBinaryMatch::WriteOutputs ile yazar (data vererek).
    std::shared_ptr<Il2BinaryResult> il2cppBinary;
    std::string il2cppSoName;    // eslestirilen .so adi (rapor/cikti icin)
    // dump.cs'te GERCEK tip isimleri uretmek icin cikarilan .so'nun baytlari
    // (cikti yazilana kadar raporla tasınır; <= 512 MiB)
    std::shared_ptr<std::vector<u8>> il2cppBinaryData;

    // --- yeni arama/cikarma veri tipleri (JSON + rapor) ---
    // PE: debug directory (PDB)
    bool hasPdb = false;
    std::string pdbPath, pdbGuid, pdbFormat;   // RSDS/NB10/NB11
    u32 pdbAge = 0;
    // PE: imports (dll + fonksiyon sayisi satirlari, cap 64)
    std::vector<std::string> imports;
    // PE: VS_VERSIONINFO kaynak degerleri (key=value satirlari, cap 12)
    std::vector<std::string> versionInfo;
    // PE: Rich Header toolchain ozeti
    std::string richSummary;                   // "VC++ Compiler 19.29 (build 33130), Linker ..."
    // PE: TLS callback sayisi + RVA listesi (cap 8 satir)
    u32 tlsCallbacks = 0;
    std::vector<std::string> tlsLines;
    // PE: bolum entropisi satirlari ("name 6.54 [W]")
    std::vector<std::string> entropyLines;
    bool highEntropy = false;                  // >= 7.2 bolum var
    // PE: MSVC RTTI sinif adlari (cap 64)
    std::vector<std::string> rttiClasses;
    u32 rttiCount = 0;
    // UTF-16LE genel string taramasi (cap 64)
    std::vector<std::string> wideStrings;
    // ELF: dynamic symbols (cap 64 satir "FUNC GLOBAL value name")
    u32 elfDynsymCount = 0;
    std::vector<std::string> elfDynsyms;
    // DEX: string havuzu ipuclari
    u32 dexStringCount = 0;
    std::vector<std::string> dexHints;
    // Mach-O
    std::string machoSummary;                  // cpu/filetype/platform/sdk/uuid
    std::vector<std::string> machoExports;     // export trie isimleri (cap 64)
    std::vector<std::string> machoLibs;        // LC_LOAD_DYLIB (cap 48)
    std::vector<std::string> machoFatArchs;    // "arm64 0x..+0x.."
    // guvenlik/koruma ipuclari (anti-cheat dll, packer bolumleri...)
    std::vector<std::string> securityHints;
};

class StaticAnalyzer {
public:
    // Analyze raw bytes. fileName is used only for display/ini suggestion.
    static StaticReport Analyze(const u8* data, size_t size, const std::string& fileName);

    // convenience: load a file and analyze
    static bool AnalyzeFile(const fs::path& path, StaticReport& out);

    // makine-okur JSON ozeti (analysis_report.json; IL2CPP detaylari
    // il2cpp_metadata.json'dadir - burada yalnizca kind/engine/ozet)
    static std::string BuildJsonReport(const StaticReport& rep, const std::string& fileName,
                                       size_t fileSize);
};

} // namespace dumper
