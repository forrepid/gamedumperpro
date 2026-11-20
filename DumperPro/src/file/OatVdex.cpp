// ============================================================================
// DumperPro - OatVdex.cpp
//
// OAT / VDEX / CDEX temel header parser.
// VDEX header duzenleri ve API eslemeleri vdexExtractor kaynaklarindan
// birebir dogrulandi (src/vdex/vdex_006|010|019|021.h, src/vdex_api.c):
//   006 -> API 26 (Android 8.0) | 010 -> API 27 (8.1)
//   019 -> API 28 (Android 9)   | 021 -> API 29 (Android 10)
// OAT duzeni AOSP art/runtime/oat.h OatHeader'a uyar (magic "art\n",
// surum "NNN\0", checksum, dex_file_count, executable_offset).
//
// ONEMLI NOTLAR:
//   - OAT surumu -> Android eslemesi raporda YAPILMAZ (surum haritasi
//     surumden surume degisir); yalnizca ham surum string'i gosterilir.
//   - Icerik cikarma (DEX ayristma) kapsam disidir; temel dogrulama hedefi.
// ============================================================================

#include "file/OatVdex.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

u32 Rd32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

// ART surum alanlari "NNN\0" bicimindedir (3 hane + NUL); NUL'u kirp
std::string VerStr(const u8* p) {
    std::string s((const char*)p, 4);
    while (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::string MagicToStr(const u8* p) {
    std::string s;
    for (int i = 0; i < 4; i++) {
        const u8 c = p[i];
        s += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    return s;
}

// vdex surumu -> API eslemesi (vdexExtractor src/vdex_api.c dogrulanmis)
const char* VdexApiHint(const std::string& ver) {
    if (ver == "006") return "API 26 (Android 8.0)";
    if (ver == "010") return "API 27 (Android 8.1)";
    if (ver == "019") return "API 28 (Android 9)";
    if (ver == "021") return "API 29 (Android 10)";
    return nullptr; // yeni surumler: tahmin YAPMA
}

} // namespace

// ---------------------------------------------------------------------------
bool OatVdex::LooksLike(const u8* data, size_t size) {
    if (!data || size < 8) return false;
    if (memcmp(data, "art\n", 4) == 0) return true;
    if (memcmp(data, "vdex", 4) == 0) return true;
    if (memcmp(data, "cdex", 4) == 0) return true;
    return false;
}

// ---------------------------------------------------------------------------
bool OatVdex::Parse(const u8* data, size_t size, OatVdexInfo& out) {
    out = OatVdexInfo{};
    out.fileSize = size;
    if (!data || size < 8) {
        out.lastError = "dosya cok kucuk";
        return false;
    }

    // ---- CDEX (Compact DEX) -------------------------------------------------
    if (memcmp(data, "cdex", 4) == 0) {
        out.kind = "cdex";
        out.magic = MagicToStr(data);
        out.version = VerStr(data + 4);
        // cdex header: magic(4), version(4), checksum(4), file_size(4), ...
        if (size >= 16) {
            out.checksum = Rd32(data + 8);
            out.dexFileCount = 1;
        }
        out.apiHint = "ART compact DEX varyanti (vdex icerisinde)";
        out.valid = true;
        return true;
    }

    // ---- VDEX -----------------------------------------------------------------
    if (memcmp(data, "vdex", 4) == 0) {
        out.kind = "vdex";
        out.magic = MagicToStr(data);
        const std::string ver = VerStr(data + 4);
        out.version = ver;
        if (const char* hint = VdexApiHint(ver)) out.apiHint = hint;

        if (ver == "006" || ver == "010") {
            // vdexHeader_006/010 (24B): magic,ver,#dex,dexSize,verifDeps,quick
            if (size < 24) { out.lastError = "vdex header kesik"; return false; }
            out.dexFileCount = Rd32(data + 8);
            out.dexSize = Rd32(data + 12);
            out.verifierDepsSize = Rd32(data + 16);
            out.quickeningInfoSize = Rd32(data + 20);
        } else if (ver == "019") {
            // vdexHeader_019 (20B): magic,verifVer,dexSectVer,#dex,verifDeps
            if (size < 20) { out.lastError = "vdex header kesik"; return false; }
            out.dexFileCount = Rd32(data + 12);
            out.verifierDepsSize = Rd32(data + 16);
        } else if (ver == "021") {
            // vdexHeader_021 (28B): magic,verifVer,dexSectVer,#dex,verifDeps,
            //                       bootCksums,classLoaderCtx
            if (size < 28) { out.lastError = "vdex header kesik"; return false; }
            out.dexFileCount = Rd32(data + 12);
            out.verifierDepsSize = Rd32(data + 16);
            out.bootClasspathChecksumsSize = Rd32(data + 20);
            out.classLoaderContextSize = Rd32(data + 24);
        } else {
            // taninmayan surum: yalnizca #dex alanini dene (021 duzeni ile ayni
            // konum 019 ile ortak; garanti DEGIL, raporda isaretlenir)
            if (size >= 16) out.dexFileCount = Rd32(data + 12);
            out.lastError = "taninmayan vdex surumu: " + ver +
                            " (yalnizca temel alanlar okundu)";
        }
        if (out.dexFileCount > 65535) {
            out.lastError += (out.lastError.empty() ? "" : "; ") + std::string("dex sayisi sacma");
        }
        out.valid = true;
        return true;
    }

    // ---- OAT ---------------------------------------------------------------------
    if (memcmp(data, "art\n", 4) == 0) {
        out.kind = "oat";
        out.magic = MagicToStr(data);
        const std::string ver = VerStr(data + 4);
        out.version = ver;
        // OatHeader: magic(4) version(4) adler32_checksum_(8) dex_file_count_(12)
        //            executable_offset_(16)
        if (size < 20) { out.lastError = "oat header kesik"; return false; }
        out.checksum = Rd32(data + 8);
        out.dexFileCount = Rd32(data + 12);
        out.executableOffset = Rd32(data + 16);
        if (out.dexFileCount > 65535) {
            out.lastError = "dex_file_count sacma (bozuk header olabilir)";
        }

        // key/value store: header sonrasi NUL-sonlandirilmis "key=value" dizileri.
        // Baslangic ofseti surume gore degisir (20. baytdan itibaren tarama;
        // yazilabilir + '=' icerme sarti yanlis pozitifi engeller, cap 8).
        const u64 scanEnd = std::min<u64>(size, 20 + 2048);
        u64 p = 20;
        while (p < scanEnd && out.oatKeyValue.size() < 8) {
            u64 e = p;
            while (e < scanEnd && data[e] != 0) e++;
            if (e == p) { p++; continue; }
            if (e - p >= 8 && e - p <= 512 && e < size) {
                std::string s((const char*)data + p, e - p);
                bool printable = true;
                for (char c : s) {
                    const u8 u = (u8)c;
                    if (!(u >= 0x20 && u < 0x7f)) { printable = false; break; }
                }
                if (printable && s.find('=') != std::string::npos)
                    out.oatKeyValue.push_back(s);
            }
            p = e + 1;
        }
        out.valid = true;
        return true;
    }

    out.lastError = "magic eslesmedi (art/vdex/cdex bekleniyor)";
    return false;
}

// ---------------------------------------------------------------------------
std::string OatVdex::BuildReport(const OatVdexInfo& m, const std::string& fileName) {
    std::vector<std::string> L;
    auto H = [&](const std::string& t) {
        std::string line(64, '=');
        L.push_back(line); L.push_back(t); L.push_back(line);
    };
    auto Hz = [&](u64 b) {
        char buf[64];
        if (b < 1024) snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
        else if (b < 1024ull * 1024) snprintf(buf, sizeof(buf), "%.1f KB", (double)b / 1024);
        else snprintf(buf, sizeof(buf), "%.1f MB", (double)b / (1024 * 1024));
        return std::string(buf);
    };

    H("DumperPro - ART Konteyner Raporu (OAT/VDEX/CDEX)");
    L.push_back("Dosya            : " + fileName);
    L.push_back("Boyut            : " + Hz(m.fileSize));
    L.push_back("Tur              : " + m.kind);
    L.push_back("Magic            : " + m.magic);
    L.push_back("Surum            : " + m.version);
    if (!m.apiHint.empty())
        L.push_back("API eslemesi     : " + m.apiHint + "  (dogrulanmis tablo)");
    std::string durum;
    if (!m.valid) durum = "SORUN: " + m.lastError;
    else if (!m.lastError.empty()) durum = "header OK (uyari: " + m.lastError + ")";
    else durum = "header OK";
    L.push_back("Durum            : " + durum);
    L.push_back("");

    H("ALANLAR");
    L.push_back("DEX sayisi       : " + std::to_string(m.dexFileCount));
    char cb[32];
    snprintf(cb, sizeof(cb), "0x%08X", m.checksum);
    L.push_back("Checksum         : " + std::string(cb));
    if (m.kind == "oat") {
        char eb[32];
        snprintf(eb, sizeof(eb), "0x%X", (unsigned)m.executableOffset);
        L.push_back("Executable offset: " + std::string(eb));
        if (!m.oatKeyValue.empty()) {
            L.push_back("");
            L.push_back("-- Key/Value store ornekleri");
            for (const std::string& kv : m.oatKeyValue) {
                std::string one = kv;
                if (one.size() > 90) one = one.substr(0, 87) + "...";
                L.push_back("  " + one);
            }
        }
    }
    if (m.kind == "vdex") {
        if (m.dexSize) L.push_back("DEX boyutu       : " + Hz(m.dexSize));
        L.push_back("Verifier deps    : " + Hz(m.verifierDepsSize));
        if (m.quickeningInfoSize) L.push_back("Quickening info  : " + Hz(m.quickeningInfoSize));
        if (m.bootClasspathChecksumsSize)
            L.push_back("Boot cksums      : " + Hz(m.bootClasspathChecksumsSize));
        if (m.classLoaderContextSize)
            L.push_back("ClassLoader ctx  : " + Hz(m.classLoaderContextSize));
    }
    L.push_back("");

    H("NOTLAR");
    L.push_back("  - Temel header dogrulamasi; DEX cikarma kapsam disidir.");
    L.push_back("  - OAT surum string'i ART yapilandirma surumudur (Android eslemesi");
    L.push_back("    surumden surume degisir, tahmin edilmez).");
    L.push_back("  - CDEX: Compact DEX, VDEX icerisinde gorulen DEX varyantidir.");
    L.push_back("  - Yasal sinir: yalnizca sahibi olunan/lisansli yazilimin analizi.");
    return str::Join(L, "\n") + "\n";
}

} // namespace dumper
