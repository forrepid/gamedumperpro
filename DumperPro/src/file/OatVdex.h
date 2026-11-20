// ============================================================================
// DumperPro - OatVdex.h
//
// ART (Android Runtime) derlenmis kod konteynerleri icin temel header parse:
//   OAT  (.oat / .odex) : magic "art\n" + "NNN\0" surum + checksum +
//                         dex_file_count + executable_offset (AOSP
//                         art/runtime/oat.h OatHeader duzeni)
//   VDEX (.vdex)        : magic "vdex" + surum; header layout'lari
//                         vdexExtractor kaynaklarindan birebir dogrulandi:
//                           006 (API 26): magic,ver,#dex,dexSize,verifDeps,quick  (24B)
//                           010 (API 27): ayni 24B duzen
//                           019 (API 28): magic,verifVer,dexSectVer,#dex,verifDeps (20B)
//                           021 (API 29): +bootCksums,classLoaderCtx               (28B)
//                         (anestisb/vdexExtractor src/vdex/vdex_006|010|019|021.h
//                          ve src/vdex_api.c API eslemesi - dogrulanmis)
//   CDEX (Compact DEX)  : magic "cdex" (VDEX icerisinde DEX varyanti)
//
// ONEMLI NOTLAR:
//   - "Temel header parse" kapsami: magic/surum/sayim dogrulamasi + ozet rapor.
//     OAT icerisindeki DEX cikarma (vdexExtractor'in yaptigi) kapsam disidir.
//   - Tum okumalar sinir kontrolludur; bozuk dosya kismi rapor + hata uretir.
// ============================================================================

#pragma once
#include "../framework.h"

namespace dumper {

struct OatVdexInfo {
    std::string kind;        // "oat" | "vdex" | "cdex"
    std::string magic;       // ham 4 bayt (gorsel)
    std::string version;     // "039", "021", ...
    std::string apiHint;     // "API 29 (Android 10)" vb (yakin, dogrulanmis tablo)
    bool valid = false;

    u32 dexFileCount = 0;
    u32 checksum = 0;
    u64 executableOffset = 0;    // oat
    u64 dexSize = 0;             // vdex 006/010
    u64 verifierDepsSize = 0;    // tum vdex'ler
    u64 quickeningInfoSize = 0;  // vdex 006/010
    u64 bootClasspathChecksumsSize = 0;  // vdex 021
    u64 classLoaderContextSize = 0;      // vdex 021
    std::vector<std::string> oatKeyValue; // oat key/value store ornekleri
    u64 fileSize = 0;
    std::string lastError;
};

class OatVdex {
public:
    static bool LooksLike(const u8* data, size_t size);   // art\n | vdex | cdex
    static bool Parse(const u8* data, size_t size, OatVdexInfo& out);
    static std::string BuildReport(const OatVdexInfo& m, const std::string& fileName);
};

} // namespace dumper
