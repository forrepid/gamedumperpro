// ============================================================================
// DumperPro - StaticAnalyzer.cpp
//
// Hat (pipeline):
//   1. magic tespiti (MZ / \x7fELF / dex\n / PK)
//   2. format parser -> PE (PEFile) / ELF (UniFormat) / DEX (UniFormat)
//   3. ZIP ise APK mi kontrolu (AndroidManifest.xml) -> evet: APK hatti
//      a) manifest + ABi'ler + dex/pak/notable listesi
//      b) en buyuk lib/<abi>/*.so dosyalarini cikar (ZipReader STORE+DEFLATE)
//      c) ELF parse + UE version string taramasi
//   4. motor tespiti + rapor uretimi (Turkce, ASCII)
//
// Bu mod CANLI BELLEK ERISIMI YAPMAZ - yalnizca diskteki dosyayi okur.
// Calistirilabilir PE'ler icin derin analiz (GObjects/GNames imzalari,
// SDK uretimi) --file modunun tam hattinda yine ayni sekilde calisir.
// ============================================================================

#include "file/StaticAnalyzer.h"
#include "file/ZipReader.h"
#include "file/OatVdex.h"
#include "file/MachO.h"
#include "core/PEFile.h"
#include "utils/StrUtil.h"

#include <ctime>
#include <cmath>

namespace dumper {

namespace {

std::string HumanSize(u64 b) {
    char buf[64];
    if (b < 1024) snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    else if (b < 1024ull * 1024) snprintf(buf, sizeof(buf), "%.1f KB", (double)b / 1024);
    else if (b < 1024ull * 1024 * 1024) snprintf(buf, sizeof(buf), "%.1f MB", (double)b / (1024 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f GB", (double)b / (1024 * 1024 * 1024));
    return buf;
}

void Header(std::vector<std::string>& L, const std::string& t) {
    std::string line(64, '=');
    L.push_back(line);
    L.push_back(t);
    L.push_back(line);
}

void Sub(std::vector<std::string>& L, const std::string& t) {
    L.push_back("-- " + t);
}

std::string NowStamp() {
    std::time_t t = std::time(nullptr);
    std::tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

std::string SanitizeIdent(std::string s) {
    std::string out;
    for (char c : s) out += (isalnum((u8)c) || c == '_' || c == '-') ? c : '_';
    return out;
}

// string havuzundan motor tahmini (ELF/DEX icerigi icin)
std::string GuessEngineFromStrings(const std::vector<std::string>& strs) {
    std::string joined;
    for (size_t i = 0; i < strs.size() && i < 400; i++) {
        for (char c : strs[i]) joined += (char)tolower((u8)c);
        joined += ' ';
    }
    if (joined.find("global-metadata") != std::string::npos ||
        joined.find("il2cpp") != std::string::npos) return "Unity";
    if (joined.find("unityplayer") != std::string::npos ||
        joined.find("com.unity3d") != std::string::npos) return "Unity";
    if (joined.find("unreal") != std::string::npos) return "Unreal Engine";
    if (joined.find("godot") != std::string::npos) return "Godot";
    if (joined.find("source engine") != std::string::npos) return "Source";
    return "";
}

std::vector<std::string> ExtractAsciiStrings(const u8* d, size_t sz, size_t minLen, size_t cap) {
    std::vector<std::string> out;
    std::string cur;
    for (size_t i = 0; i < sz; i++) {
        const u8 c = d[i];
        if (c >= 0x20 && c < 0x7f) {
            cur += (char)c;
        } else {
            if (cur.size() >= minLen && out.size() < cap) out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= minLen && out.size() < cap) out.push_back(cur);
    return out;
}

// --- YENI VERI TIPI: UTF-16LE genel string taramasi (motor-uzel degil) ---
// min uzunlukta UTF-16LE dizileri toplar (Windows PE genis stringleri,
// Unity prefs anahtarlari, UE config yollari vs. icin)
// kalite kontrolu: yalnizca asil-ASCII + en az %70 alfanumerik/yer tutucu
static bool WideLooksLikeText(const std::string& s) {
    if (s.size() < 4) return false;
    size_t good = 0;
    for (char c : s) {
        const u8 ch = (u8)c;
        if (ch == '?') return false;                    // ascii-disi BMP: reddet
        if (isalnum(ch) || ch == ' ' || ch == '.' || ch == '/' || ch == '\\' ||
            ch == '_' || ch == '-' || ch == ':' || ch == ',' || ch == '(' || ch == ')' ||
            ch == '%' || ch == '=' || ch == '<' || ch == '>' || ch == '@') good++;
    }
    return good * 10 >= s.size() * 7;
}
std::vector<std::string> ExtractWideStrings(const u8* d, size_t sz, size_t minChars, size_t cap) {
    std::vector<std::string> out;
    std::string cur;
    size_t i = 0;
    while (i + 2 <= sz) {
        const u16 c = (u16)(d[i] | ((u16)d[i + 1] << 8));
        if (c >= 0x20 && c < 0x7f) {
            cur += (char)c;
            i += 2;
        } else {
            if (c == 0) i += 2;
            else i += 1;                                // hizayi geri yakala
            if (cur.size() >= minChars && WideLooksLikeText(cur) && out.size() < cap)
                out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= minChars && WideLooksLikeText(cur) && out.size() < cap) out.push_back(cur);
    return out;
}

// --- YENI VERI TIPI: guvenlik/koruma ipuclari (import + bolum + string) ---
void SecurityHintsFromImports(const std::vector<PEImportDll>& imps, const std::vector<std::string>& strs,
                              std::vector<std::string>& out) {
    auto has = [&](const char* sub) {
        for (const PEImportDll& x : imps) {
            std::string low = str::Lower(x.dllName);
            if (low.find(sub) != std::string::npos) return true;
        }
        return false;
    };
    auto hasStr = [&](const char* sub) {
        for (const std::string& s : strs) {
            if (str::Lower(s).find(sub) != std::string::npos) return true;
        }
        return false;
    };
    if (has("easyanticheat")) out.push_back("EasyAntiCheat (anti-cheat)");
    if (has("battleye") || has("beservice")) out.push_back("BattlEye (anti-cheat)");
    if (has("vac")) out.push_back("VAC izarlari");
    if (has("ricochet")) out.push_back("Ricochet (anti-cheat)");
    if (has("vgk") || has("vanguard")) out.push_back("Vanguard (anti-cheat)");
    if (has("steam_api")) out.push_back("Steam API");
    if (has("eossdk") || has("epiconline")) out.push_back("Epic Online Services");
    if (has("denuvo") || hasStr("denuvo")) out.push_back("Denuvo (DRM)");
    if (has("xinput")) out.push_back("XInput (gamepad)");
    if (has("d3d11") || has("d3d12") || has("d3d9")) out.push_back("DirectX (d3d)");
    if (has("vulkan")) out.push_back("Vulkan");
    if (has("opengl32")) out.push_back("OpenGL");
    if (has("winhttp") || has("wininet")) out.push_back("HTTP istemci kutuphanesi");
    if (has("vcruntime") || has("msvcp")) out.push_back("MSVC runtime (VC++ derleyici)");
    if (has("libiomp") || has("tbb")) out.push_back("Intel/Threading runtime");
}

// --- APK ---------------------------------------------------------------
void AnalyzeApk(const u8* d, size_t sz, ZipReader& zip, StaticReport& rep,
                std::vector<std::string>& L, std::string& errors) {
    std::set<std::string> abis;
    std::vector<ZipEntry> libs;
    size_t dexCount = 0, pakCount = 0;
    std::vector<std::string> notable, pakFiles;
    const ZipEntry* metadataEntry = nullptr;   // global-metadata.dat (IL2CPP)
    std::string il2cppSoName;                  // libil2cpp.so (dogrulama)
    std::vector<ZipEntry> il2cppSos;           // tum libil2cpp.so kayitlari (ABI onceligi ile)

    for (const ZipEntry& e : zip.Entries()) {
        if (e.name.size() >= 4 && e.name.compare(e.name.size() - 4, 4, ".dex") == 0) dexCount++;
        if (e.name.rfind("lib/", 0) == 0 && e.name.size() >= 3 &&
            e.name.compare(e.name.size() - 3, 3, ".so") == 0) {
            libs.push_back(e);
            const size_t slash = e.name.find('/', 4);
            if (slash != std::string::npos) abis.insert(e.name.substr(4, slash - 4));
        }
        if (e.name.size() >= 4 && e.name.compare(e.name.size() - 4, 4, ".pak") == 0) {
            pakCount++;
            pakFiles.push_back(e.name + "  " + HumanSize(e.uncompressedSize));
        }
        std::string low = str::Lower(e.name);
        if (low.find("global-metadata.dat") != std::string::npos) {
            notable.push_back(e.name + "  (" + HumanSize(e.uncompressedSize) + ")");
            // Unity IL2CPP metadata klasik yolu: assets/bin/Data/Managed/Metadata/
            if (!metadataEntry && e.uncompressedSize <= 512ull * 1024 * 1024)
                metadataEntry = &e;
        }
        if (low.find("libil2cpp.so") != std::string::npos && il2cppSoName.empty())
            il2cppSoName = e.name;
        if (low.rfind("lib/", 0) == 0 && low.size() >= 3 &&
            low.compare(low.size() - 3, 3, ".so") == 0 &&
            low.find("il2cpp") != std::string::npos)
            il2cppSos.push_back(e);
        if (low.find("unityplayer") != std::string::npos ||
            low.find(".obb") != std::string::npos ||
            low.find("resources.assets") != std::string::npos) {
            notable.push_back(e.name + "  (" + HumanSize(e.uncompressedSize) + ")");
        }
    }

    L.push_back("Kayit sayisi    : " + std::to_string(zip.Entries().size()));
    L.push_back("DEX sayisi      : " + std::to_string(dexCount));
    std::string abiLine;
    for (const auto& a : abis) { if (!abiLine.empty()) abiLine += ", "; abiLine += a; }
    L.push_back("ABI'ler         : " + (abiLine.empty() ? "-" : abiLine));

    if (!pakFiles.empty()) {
        Sub(L, "UE .pak dosyalari (" + std::to_string(pakCount) + ")");
        for (size_t i = 0; i < pakFiles.size() && i < 12; i++) L.push_back("  " + pakFiles[i]);
    }
    if (!notable.empty()) {
        Sub(L, "Dikkat ceken dosyalar");
        for (size_t i = 0; i < notable.size() && i < 16; i++) L.push_back("  " + notable[i]);
    }

    std::sort(libs.begin(), libs.end(), [](const ZipEntry& a, const ZipEntry& b) {
        return a.uncompressedSize > b.uncompressedSize;
    });

    if (!libs.empty()) {
        Sub(L, "Ana kutuphaneler (lib/*/*.so)");
        for (size_t i = 0; i < libs.size() && i < 24; i++) L.push_back("  " + libs[i].name + "  " + HumanSize(libs[i].uncompressedSize));
    }

    // motor taramasi: en buyuk 2 .so'yu cikar, ELF parse + UE string taramasi
    std::string soEngine, soVersion;
    int scanned = 0;
    for (const ZipEntry& e : libs) {
        if (scanned >= 2) break;
        // tum .so'lar degil: buyuk olanlar + isim ipucu olanlar
        std::string low = str::Lower(e.name);
        const bool hint = low.find("ue4") != std::string::npos || low.find("ue5") != std::string::npos ||
                          low.find("unreal") != std::string::npos || low.find("unity") != std::string::npos ||
                          low.find("il2cpp") != std::string::npos || low.find("game") != std::string::npos;
        if (!hint && e.uncompressedSize < 8 * 1024 * 1024) continue;
        std::vector<u8> so;
        if (!zip.Extract(e, so)) {
            errors += "! " + e.name + " acilamadi: " + zip.LastError() + "\n";
            continue;
        }
        scanned++;
        ElfInfo elf;
        std::string tag = " (ELF ayrıstırılamadı)";
        if (UniFormat::ParseElf(so.data(), so.size(), elf) && elf.valid) {
            tag = " (" + std::to_string(elf.bits) + "-bit " + elf.machine + ")";
        }
        auto versions = UniFormat::UeVersionStrings(so.data(), so.size(), 8);
        L.push_back("");
        L.push_back("  " + e.name + "  " + HumanSize(so.size()) + tag);
        if (!versions.empty()) {
            for (const auto& v : versions)
                L.push_back("    UE string: " + v.raw);
            if (soEngine.empty()) {
                soEngine = versions[0].raw.rfind("++UE5", 0) == 0 ? "UE5" : "UE4";
                soVersion = versions[0].version;
            }
        } else {
            auto strs = ExtractAsciiStrings(so.data(), so.size(), 10, 600);
            std::string guess = GuessEngineFromStrings(strs);
            if (!guess.empty()) L.push_back("    Motor ipucu: " + guess);
            if (soEngine.empty() && !guess.empty()) {
                soEngine = guess;
                soVersion = "";
            }
        }
    }
    if (scanned == 0 && !libs.empty()) {
        errors += "! hicbir .so taranamadi (sikistirma/limit)\n";
    }

    // ---- IL2CPP metadata taramasi (Il2CppDumper hizasi - metadata yalniz) ----
    // ONEMLI NOT: metadata yalnizca tip/isim/mетод isimlerini tutar; native
    // adresler libil2cpp.so'dadir. Bu bolum metadata'yi DOGRULAR ve ozetler.
    if (metadataEntry) {
        Sub(L, "IL2CPP metadata (global-metadata.dat)");
        std::vector<u8> md;
        if (!zip.Extract(*metadataEntry, md)) {
            errors += "! global-metadata.dat acilamadi: " + zip.LastError() + "\n";
        } else if (!Il2CppMetadataParser::LooksLikeMetadata(md.data(), md.size())) {
            L.push_back("  il2cpp metadata degil (sanity eslesmedi)");
        } else {
            auto meta = std::make_shared<Il2Metadata>();
            if (Il2CppMetadataParser::Parse(md.data(), md.size(), *meta) && meta->valid) {
                L.push_back("  Metadata surumu : " + meta->versionStr +
                            (meta->unityHint.empty() ? "" : "  (" + meta->unityHint + ")"));
                L.push_back("  Images/Asm      : " + std::to_string(meta->images.size()));
                L.push_back("  Tipler          : " + std::to_string(meta->types.size()));
                L.push_back("  Alanlar/Metodlar: " + std::to_string(meta->fields.size()) + " / " +
                            std::to_string(meta->methods.size()));
                L.push_back("  String literal  : " + std::to_string(meta->stringLiteralCount));
                rep.il2cppMeta = meta;
                rep.engine = "Unity (IL2CPP)";
                if (rep.engineVersion.empty()) rep.engineVersion = meta->versionStr;

                // ---- BINARY ES CIFTI: metadata + libil2cpp.so birarada ise ----
                // "araştır-bul-incele-doğrula" akisi: ABI onceligi arm64-v8a >
                // x86_64 > armeabi-v7a > digerleri; ilk uyumlu .so cikarilir ve
                // Il2CppBinaryMatch ile CodeRegistration/MetadataRegistration
                // taramasi yapilir. Basarisizlik kismi kalir (raporlanir).
                if (!il2cppSos.empty()) {
                    auto AbiRank = [](const std::string& n) -> int {
                        const std::string low = str::Lower(n);
                        if (low.find("arm64-v8a") != std::string::npos) return 0;
                        if (low.find("x86_64") != std::string::npos)   return 1;
                        if (low.find("armeabi-v7a") != std::string::npos) return 2;
                        if (low.find("x86") != std::string::npos)      return 3;
                        return 4;
                    };
                    std::sort(il2cppSos.begin(), il2cppSos.end(),
                              [&](const ZipEntry& a, const ZipEntry& b) {
                                  const int ra = AbiRank(a.name), rb = AbiRank(b.name);
                                  if (ra != rb) return ra < rb;
                                  return a.uncompressedSize > b.uncompressedSize;
                              });
                    std::vector<u8> so;
                    bool matched = false;
                    for (const ZipEntry& soEntry : il2cppSos) {
                        if (soEntry.uncompressedSize > 512ull * 1024 * 1024) continue;
                        if (!zip.Extract(soEntry, so)) {
                            errors += "! " + soEntry.name + " acilamadi: " + zip.LastError() + "\n";
                            continue;
                        }
                        Il2BinaryResult binres;
                        if (Il2CppBinaryMatch::Match(so.data(), so.size(), *meta, binres)) {
                            rep.il2cppBinary = std::make_shared<Il2BinaryResult>(std::move(binres));
                            rep.il2cppBinaryData = std::make_shared<std::vector<u8>>(std::move(so));
                            rep.il2cppSoName = soEntry.name;
                            L.push_back("  Binary es cifti : " + soEntry.name + "  [ESLESTIRILDI]");
                            L.push_back("    cozulen metod : " +
                                        std::to_string(rep.il2cppBinary->resolvedCount) + " / " +
                                        std::to_string(meta->methods.size()) +
                                        "  (govdesiz: " + std::to_string(rep.il2cppBinary->nullCount) + ")");
                            if (rep.il2cppBinary->metadataRegistrationFound)
                                L.push_back("    Il2CppType tablosu: cozuldu (dump.cs'te gercek tipler var)");
                            matched = true;
                            break;
                        }
                        errors += "! binary eslestirme (" + soEntry.name + "): " +
                                  binres.lastError + "\n";
                    }
                    if (!matched && !il2cppSoName.empty())
                        L.push_back("  Binary es cifti : " + il2cppSoName + "  (eslestirilemedi)");
                } else if (!il2cppSoName.empty()) {
                    L.push_back("  Binary es cifti : " + il2cppSoName +
                                "  (cikarma/butunluk siniri nedeniyle eslestirilmedi)");
                }
                // ornek tipler
                const size_t tcap = std::min<size_t>(meta->types.size(), 8);
                for (size_t i = 0; i < tcap; i++) {
                    const Il2TypeInfo& t = meta->types[i];
                    std::string full = t.ns.empty() ? t.name : t.ns + "." + t.name;
                    L.push_back("    tip: " + full.substr(0, 56));
                }
            } else {
                errors += "! il2cpp metadata parse: " + meta->lastError + "\n";
            }
        }
        L.push_back("");
    }

    if (!soEngine.empty()) {
        if (rep.engine.empty()) rep.engine = soEngine;
        if (rep.engineVersion.empty()) rep.engineVersion = soVersion;
    }
}

// --- ZIP (APK degil) ----------------------------------------------------
void AnalyzePlainZip(ZipReader& zip, std::vector<std::string>& L) {
    L.push_back("Kayit sayisi    : " + std::to_string(zip.Entries().size()));
    std::map<std::string, std::pair<u32, u64>> groups; // dir -> (count, size)
    for (const ZipEntry& e : zip.Entries()) {
        std::string dir = "(kok)";
        const size_t slash = e.name.rfind('/');
        if (slash != std::string::npos) dir = e.name.substr(0, slash);
        auto& g = groups[dir];
        g.first++;
        g.second += e.uncompressedSize;
    }
    std::vector<std::pair<std::string, std::pair<u32, u64>>> sorted(groups.begin(), groups.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) { return a.second.second > b.second.second; });
    Sub(L, "Dizin gruplari (boyuta gore)");
    for (size_t i = 0; i < sorted.size() && i < 16; i++)
        L.push_back("  " + sorted[i].first + "  (" + std::to_string(sorted[i].second.first) + " dosya, " +
                    HumanSize(sorted[i].second.second) + ")");
}

} // namespace

// ---------------------------------------------------------------------------
StaticReport StaticAnalyzer::Analyze(const u8* data, size_t size, const std::string& fileName) {
    StaticReport rep;
    std::vector<std::string> L;
    std::string errors;

    Header(L, "DumperPro - Statik Dosya Analiz Raporu");
    L.push_back("Dosya           : " + fileName);
    L.push_back("Boyut           : " + HumanSize(size) + " (" + std::to_string(size) + " bayt)");
    L.push_back("Rapor zamani    : " + NowStamp());
    L.push_back("");

    const std::string magic = UniFormat::SniffMagic(data, size);
    rep.kind = magic;

    Header(L, "FORMAT & MOTOR");
    L.push_back("Format          : " + magic);

    // ---- PE ----
    if (magic == "pe") {
        rep.kind = "pe";
        PEFile pe;
        if (pe.Parse(data, size, false) && pe.Valid()) {
            auto versions = UniFormat::UeVersionStrings(data, size, 12);
            if (!versions.empty()) {
                rep.engine = versions[0].raw.rfind("++UE5", 0) == 0 ? "UE5" : "UE4";
                rep.engineVersion = versions[0].version;
                L.push_back("Motor           : " + rep.engine + " " + rep.engineVersion);
            } else {
                auto strs = ExtractAsciiStrings(data, size, 8, 3000);
                std::string g = GuessEngineFromStrings(strs);
                if (!g.empty()) rep.engine = g;
                L.push_back("Motor           : " + (rep.engine.empty() ? "tespit edilemedi" : rep.engine + " (dusuk guven)"));
            }
            L.push_back("ImageBase       : " + Hex(pe.ImageBase()));
            L.push_back("SizeOfImage     : " + Hex32(pe.SizeOfImage()));
            Sub(L, "Bolumler");
            for (const PESection& s : pe.Sections()) {
                std::string flags;
                if (s.exec) flags += "x";
                if (s.read) flags += "r";
                if (s.write) flags += "w";
                L.push_back("  " + s.name + "  VA=" + Hex32(s.va) + "  VSZ=" + Hex32(s.vs) +
                            "  RAW=" + Hex32(s.rawSize) + "  [" + flags + "]");
            }
            auto exps = pe.Exports();
            if (!exps.empty()) {
                Sub(L, "Disa aktarma (ilk 30 / " + std::to_string(exps.size()) + ")");
                for (size_t i = 0; i < exps.size() && i < 30; i++)
                    L.push_back("  " + exps[i].name);
            }

            // ---- YENI VERI TIPLERI ----
            // 1) bolum entropisi (packer tespiti)
            {
                auto ents = pe.SectionEntropy();
                if (!ents.empty()) {
                    Sub(L, "Bolum entropisi (Shannon, >=7.2 = paketlenmis suphe)");
                    for (const auto& e : ents) {
                        char b[64];
                        snprintf(b, sizeof(b), "%.2f", e.entropy);
                        std::string line = "  " + e.name + "  " + b;
                        if (e.high) line += "  [YUKSEK]";
                        if (!e.packerHint.empty()) line += "  -> " + e.packerHint;
                        L.push_back(line);
                        rep.entropyLines.push_back(e.name + " " + b + (e.high ? " [YUKSEK]" : "") +
                                                   (e.packerHint.empty() ? "" : " -> " + e.packerHint));
                        if (e.high) rep.highEntropy = true;
                    }
                }
            }
            // 2) debug directory (PDB yolu/GUID)
            {
                auto dbg = pe.DebugDirectory();
                if (!dbg.empty()) {
                    Sub(L, "Debug directory (ilk 8 / " + std::to_string(dbg.size()) + ")");
                    for (size_t i = 0; i < dbg.size() && i < 8; i++) {
                        const auto& de = dbg[i];
                        std::string line = "  [" + de.typeName + "]";
                        if (de.typeName == "?") { char tb[24]; snprintf(tb, sizeof(tb), "type=%u", de.type); line += tb; }
                        if (!de.cvFormat.empty()) line += " " + de.cvFormat;
                        if (!de.pdbPath.empty()) line += "  PDB: " + de.pdbPath;
                        if (!de.guid.empty()) line += "  GUID: " + de.guid;
                        if (de.age) line += "  age=" + std::to_string(de.age);
                        L.push_back(line);
                        if (de.type == 2 && !de.pdbPath.empty() && !rep.hasPdb) {
                            rep.hasPdb = true;
                            rep.pdbPath = de.pdbPath;
                            rep.pdbGuid = de.guid;
                            rep.pdbAge = de.age;
                            rep.pdbFormat = de.cvFormat;
                        }
                    }
                }
                // PDB yolundan guclu motor tespiti (dusuk-guven string tahminini EZER)
                if (rep.hasPdb) {
                    const std::string pl = str::Lower(rep.pdbPath);
                    if (pl.find("il2cpp") != std::string::npos ||
                        pl.find("windowsplayer") != std::string::npos ||
                        pl.find("unity") != std::string::npos)
                        rep.engine = "Unity (IL2CPP)";
                    // motor satirini da guncelle (raporda tutarli gorunsun)
                    for (std::string& ln : L) {
                        if (ln.rfind("Motor           : ", 0) == 0) {
                            ln = "Motor           : " + rep.engine +
                                 (rep.engineVersion.empty() ? "" : " " + rep.engineVersion) +
                                 "  [PDB yolu dogruladi]";
                            break;
                        }
                    }
                }
            }
            // 3) import tablosu (IAT)
            {
                auto imps = pe.Imports();
                if (!imps.empty()) {
                    size_t totalFuncs = 0;
                    for (const auto& d : imps) totalFuncs += d.funcCount;
                    Sub(L, "Import tablosu (" + std::to_string(imps.size()) + " DLL, " +
                        std::to_string(totalFuncs) + " fonksiyon)");
                    for (size_t i = 0; i < imps.size() && i < 32; i++) {
                        std::string line = "  " + imps[i].dllName + "  (" +
                            std::to_string(imps[i].funcCount) + " fn)";
                        L.push_back(line);
                        rep.imports.push_back(imps[i].dllName + " (" +
                                              std::to_string(imps[i].funcCount) + " fn)");
                    }
                    if (imps.size() > 32) L.push_back("  ... " + std::to_string(imps.size() - 32) + " DLL daha");
                }
            }
            // 4) VS_VERSIONINFO kaynagi
            {
                auto vi = pe.VersionResource();
                if (vi.present) {
                    Sub(L, "Kaynak: VS_VERSIONINFO");
                    char fvs[64];
                    snprintf(fvs, sizeof(fvs), "%u.%u.%u.%u", vi.fileMajor, vi.fileMinor, vi.fileBuild, vi.fileRev);
                    char pvs[64];
                    snprintf(pvs, sizeof(pvs), "%u.%u.%u.%u", vi.prodMajor, vi.prodMinor, vi.prodBuild, vi.prodRev);
                    L.push_back(std::string("  FileVersion    : ") + fvs);
                    L.push_back(std::string("  ProductVersion : ") + pvs);
                    if (!vi.companyName.empty()) L.push_back("  CompanyName    : " + vi.companyName);
                    if (!vi.productName.empty()) L.push_back("  ProductName    : " + vi.productName);
                    if (!vi.fileDescription.empty()) L.push_back("  FileDescription: " + vi.fileDescription);
                    if (!vi.internalName.empty()) L.push_back("  InternalName   : " + vi.internalName);
                    if (!vi.originalFilename.empty()) L.push_back("  OriginalFilename: " + vi.originalFilename);
                    if (!vi.legalCopyright.empty()) L.push_back("  Copyright      : " + vi.legalCopyright);
                    rep.versionInfo.push_back(std::string("FileVersion=") + fvs);
                    rep.versionInfo.push_back(std::string("ProductVersion=") + pvs);
                    if (!vi.companyName.empty()) rep.versionInfo.push_back("CompanyName=" + vi.companyName);
                    if (!vi.productName.empty()) rep.versionInfo.push_back("ProductName=" + vi.productName);
                    if (!vi.fileDescription.empty()) rep.versionInfo.push_back("FileDescription=" + vi.fileDescription);
                    if (!vi.internalName.empty()) rep.versionInfo.push_back("InternalName=" + vi.internalName);
                    if (!vi.originalFilename.empty()) rep.versionInfo.push_back("OriginalFilename=" + vi.originalFilename);
                    // FileDescription motor ipucusu olarak da kullan
                    if (rep.engine.empty() && !vi.fileDescription.empty()) {
                        auto strs = ExtractAsciiStrings((const u8*)vi.fileDescription.c_str(),
                                                        vi.fileDescription.size(), 4, 16);
                        std::string g = GuessEngineFromStrings(strs);
                        if (!g.empty()) rep.engine = g + " (resource)";
                    }
                }
            }
            // 5) Rich Header (toolchain)
            {
                auto rh = pe.RichHeader();
                if (rh.present) {
                    Sub(L, "Rich Header (MSVC toolchain)");
                    std::string line;
                    std::string comp, link;
                    for (const auto& t : rh.tools) {
                        if (!line.empty()) line += ", ";
                        line += t.toolName + " build " + std::to_string(t.build) +
                                " x" + std::to_string(t.count);
                        if (t.toolName.find("Compiler") != std::string::npos && comp.empty())
                            comp = t.toolName + " " + std::to_string(t.build);
                        if (t.toolName.find("Linker") != std::string::npos && link.empty())
                            link = t.toolName + " " + std::to_string(t.build);
                    }
                    L.push_back("  " + (line.empty() ? "(giris yok)" : line));
                    rep.richSummary = line.substr(0, 240);
                    if (!comp.empty() || !link.empty())
                        rep.securityHints.push_back("MSVC toolchain: " + comp + (link.empty() ? "" : " / " + link));
                }
            }
            // 6) TLS callbacks
            {
                auto tls = pe.TlsCallbacks();
                if (!tls.empty()) {
                    Sub(L, "TLS callback'leri (main once calisir; anti-tamper)" + std::string(""));
                    for (size_t i = 0; i < tls.size() && i < 8; i++) {
                        std::string line = "  RVA " + Hex32(tls[i].rva);
                        if (!tls[i].section.empty()) line += "  (" + tls[i].section + ")";
                        L.push_back(line);
                        rep.tlsLines.push_back("RVA " + Hex32(tls[i].rva) +
                                               (tls[i].section.empty() ? "" : " (" + tls[i].section + ")"));
                    }
                    rep.tlsCallbacks = (u32)tls.size();
                }
            }
            // 7) MSVC RTTI sinif isimleri
            {
                auto rtti = pe.RttiClasses();
                if (!rtti.empty()) {
                    rep.rttiCount = (u32)rtti.size();
                    Sub(L, "MSVC RTTI siniflari (ilk 48 / " + std::to_string(rtti.size()) + ")");
                    std::unordered_set<std::string> uniq;
                    for (const auto& rc : rtti) {
                        if (rep.rttiClasses.size() < 64 && uniq.insert(rc.name).second)
                            rep.rttiClasses.push_back(rc.name);
                    }
                    uniq.clear();
                    size_t shown = 0;
                    for (const auto& rc : rtti) {
                        if (shown >= 48) break;
                        if (uniq.insert(rc.name).second) {
                            std::string line = "  " + rc.name;
                            if (rc.numBases > 1) line += "  (baza: " + std::to_string(rc.numBases) + ")";
                            L.push_back(line);
                            shown++;
                        }
                    }
                    L.push_back("  -> vtable sınıf esleştirme (colRva): vtable_funcs.txt analizi icin kullanilabilir");
                }
            }
            // 8) UTF-16LE genel string taramasi
            {
                auto wide = ExtractWideStrings(data, size, 8, 64);
                if (!wide.empty()) {
                    Sub(L, "UTF-16LE stringler (ilk 24 / " + std::to_string(wide.size()) + ")");
                    for (size_t i = 0; i < wide.size() && i < 24; i++)
                        L.push_back("  " + wide[i].substr(0, 96));
                    for (const auto& w : wide) rep.wideStrings.push_back(w.substr(0, 128));
                }
            }
            // 9) guvenlik ipuclari (import tabanli)
            {
                auto imps = pe.Imports();
                auto strs = ExtractAsciiStrings(data, size, 6, 2000);
                std::vector<std::string> hints;
                SecurityHintsFromImports(imps, strs, hints);
                auto ents = pe.SectionEntropy();
                for (const auto& e : ents) if (!e.packerHint.empty()) hints.push_back(e.packerHint + " bolumu: " + e.name);
                if (!hints.empty()) {
                    Sub(L, "Guvenlik/koruma ipuclari");
                    for (const auto& h : hints) {
                        L.push_back("  - " + h);
                        rep.securityHints.push_back(h);
                    }
                }
            }

            // games.ini taslagi
            std::string base = SanitizeIdent(fileName);
            size_t dot = base.rfind('.');
            if (dot != std::string::npos) base = base.substr(0, dot);
            rep.gamesIni = "[" + base + "]\n";
            if (!rep.engineVersion.empty()) {
                const size_t dotv = rep.engineVersion.find('.');
                rep.gamesIni += "version = " + rep.engineVersion.substr(0, dotv) + "\n";
            }
            rep.gamesIni += "; adresler canli dump sonrasi <Oyun>_sigs.txt ciktisindan eklenir\n";
            rep.gamesIni += "; gobjects = 0x...  gnames = 0x...\n";
            // PDB bilgisi games.ini taslagina not olarak
            if (rep.hasPdb) {
                rep.gamesIni += "; PDB: " + rep.pdbPath + "\n";
            }
        } else {
            errors += "! PE parse edilemedi (x64 PE32+ gerekli)\n";
        }
        L.push_back("");
    }
    // ---- Mach-O / FAT universal ----
    else if (magic == "macho" || magic == "macho-fat") {
        rep.kind = magic;
        MachOInfo mo;
        if (magic == "macho" ? MachO::Parse(data, size, mo) : MachO::ParseFat(data, size, mo)) {
            L.push_back("Mimari          : " + std::to_string(mo.bits) + "-bit " + mo.cpu +
                        " (" + mo.endian + ")");
            L.push_back("Tur             : Mach-O " + mo.fileType + (mo.pie ? "  [PIE]" : ""));
            if (!mo.platform.empty()) L.push_back("Platform        : " + mo.platform);
            if (!mo.minos.empty()) L.push_back("Min OS / SDK    : " + mo.minos + " / " + mo.sdk);
            if (!mo.uuid.empty()) L.push_back("UUID            : " + mo.uuid);
            if (!mo.sourceVersion.empty()) L.push_back("SourceVersion   : " + mo.sourceVersion);
            L.push_back("Load commands   : " + std::to_string(mo.loadCmdCount) +
                        "  (segment: " + std::to_string(mo.segmentCount) +
                        ", sembol: " + std::to_string(mo.symtabCount) + ")");
            rep.machoSummary = std::to_string(mo.bits) + "-bit " + mo.cpu + " " + mo.fileType;
            if (!mo.platform.empty()) rep.machoSummary += " | " + mo.platform +
                                     (mo.minos.empty() ? "" : " min " + mo.minos + " sdk " + mo.sdk);
            if (!mo.uuid.empty()) rep.machoSummary += " | uuid " + mo.uuid;
            for (const auto& a : mo.fatArchs) {
                char b[96];
                snprintf(b, sizeof(b), "%s @0x%llX+0x%llX", a.cpuName.c_str(),
                         (unsigned long long)a.offset, (unsigned long long)a.size);
                rep.machoFatArchs.push_back(b);
            }
            Sub(L, "Bolumler (ilk 24)");
            for (size_t i = 0; i < mo.sections.size() && i < 24; i++) {
                std::string flags;
                if (mo.sections[i].exec) flags += "x";
                if (mo.sections[i].write) flags += "w";
                L.push_back("  " + mo.sections[i].segment + "/" + mo.sections[i].name +
                            "  addr=" + Hex(mo.sections[i].addr) + "  size=" + Hex(mo.sections[i].size) +
                            "  [" + flags + "]");
            }
            if (!mo.exports.empty()) {
                Sub(L, "Disa aktarma (export trie, ilk 32 / " + std::to_string(mo.exports.size()) + ")");
                for (size_t i = 0; i < mo.exports.size() && i < 32; i++) {
                    L.push_back("  " + mo.exports[i]);
                    if (rep.machoExports.size() < 64) rep.machoExports.push_back(mo.exports[i]);
                }
            }
            if (!mo.linkedLibs.empty()) {
                Sub(L, "Bagli kutuphaneler (ilk 24 / " + std::to_string(mo.linkedLibs.size()) + ")");
                for (size_t i = 0; i < mo.linkedLibs.size() && i < 24; i++) {
                    L.push_back("  " + mo.linkedLibs[i]);
                    if (rep.machoLibs.size() < 48) rep.machoLibs.push_back(mo.linkedLibs[i]);
                }
            }
            // motor taramasi
            auto versions = UniFormat::UeVersionStrings(data, size, 12);
            if (!versions.empty()) {
                rep.engine = versions[0].raw.rfind("++UE5", 0) == 0 ? "UE5" : "UE4";
                rep.engineVersion = versions[0].version;
                Sub(L, "UE surum stringleri");
                for (const auto& v : versions) L.push_back("  " + v.raw);
            } else {
                auto strs = ExtractAsciiStrings(data, size, 10, 800);
                std::string g = GuessEngineFromStrings(strs);
                if (!g.empty()) rep.engine = g;
            }
            auto wide = ExtractWideStrings(data, size, 6, 40);
            for (const auto& w : wide) rep.wideStrings.push_back(w.substr(0, 128));
        } else {
            errors += "! Mach-O parse edilemedi: " + mo.lastError + "\n";
        }
        L.push_back("");
    }
    // ---- ELF ----
    else if (magic == "elf") {
        rep.kind = "elf";
        ElfInfo elf;
        if (UniFormat::ParseElf(data, size, elf) && elf.valid) {
            L.push_back("Mimari          : " + std::to_string(elf.bits) + "-bit " + elf.machine + " (" + elf.endian + ")");
            L.push_back("Tip             : " + elf.type);
            L.push_back("Entry           : " + Hex(elf.entryPoint));
            L.push_back("Bolum sayisi    : " + std::to_string(elf.sectionCount));
            Sub(L, "Bolumler (ilk 40)");
            for (size_t i = 0; i < elf.sections.size() && i < 40; i++)
                L.push_back("  " + elf.sections[i].name + "  " + elf.sections[i].typeName +
                            "  size=" + Hex(elf.sections[i].size));
            // ---- YENI VERI TIPI: dynamic symbol tablosu (.dynsym) ----
            {
                std::vector<ElfDynSym> syms;
                const u32 total = UniFormat::ParseElfDynSym(data, size, elf, syms, 64);
                if (total > 0) {
                    rep.elfDynsymCount = total;
                    Sub(L, "Dynamic semboller (.dynsym, ilk 48 / " + std::to_string(total) + " girdi)");
                    for (const auto& s : syms) {
                        std::string line = "  " + s.type + " " + s.bind + "  " + Hex(s.value) + "  " + s.name;
                        L.push_back(line);
                        if (rep.elfDynsyms.size() < 64)
                            rep.elfDynsyms.push_back(s.type + " " + s.bind + " " + Hex(s.value) + " " + s.name);
                    }
                    // JNI/girdi noktalari ipucu
                    bool jni = false, il2 = false;
                    for (const auto& s : syms) {
                        if (s.name.rfind("JNI_OnLoad", 0) == 0) jni = true;
                        if (s.name.rfind("il2cpp_", 0) == 0) il2 = true;
                    }
                    if (jni) { L.push_back("  -> JNI_OnLoad var (Android native kutuphane)"); rep.elfDynsyms.push_back("JNI_OnLoad"); }
                    if (il2) { L.push_back("  -> il2cpp_* API sembolleri var (Unity IL2CPP)"); rep.elfDynsyms.push_back("il2cpp_* API"); }
                }
            }
        } else {
            errors += "! ELF parse edilemedi\n";
        }
        auto versions = UniFormat::UeVersionStrings(data, size, 12);
        if (!versions.empty()) {
            rep.engine = versions[0].raw.rfind("++UE5", 0) == 0 ? "UE5" : "UE4";
            rep.engineVersion = versions[0].version;
            Sub(L, "UE surum stringleri");
            for (const auto& v : versions) L.push_back("  " + v.raw);
        } else {
            auto strs = ExtractAsciiStrings(data, size, 10, 800);
            std::string g = GuessEngineFromStrings(strs);
            if (!g.empty()) rep.engine = g;
        }
        L.push_back("");
    }
    // ---- DEX ----
    else if (magic == "dex") {
        rep.kind = "dex";
        DexInfo dex;
        if (UniFormat::ParseDex(data, size, dex) && dex.valid) {
            L.push_back("DEX surumu      : " + dex.version);
            L.push_back("String havuzu   : " + std::to_string(dex.stringIdsSize));
            L.push_back("Tip/Proto       : " + std::to_string(dex.typeIdsSize) + " / " + std::to_string(dex.protoIdsSize));
            L.push_back("Alan/Metod      : " + std::to_string(dex.fieldIdsSize) + " / " + std::to_string(dex.methodIdsSize));
            L.push_back("Sinif tanimi    : " + std::to_string(dex.classDefsSize));
            // ---- YENI VERI TIPI: string havuzu (MUTF-8) ----
            {
                DexStrings ds;
                if (UniFormat::ParseDexStrings(data, size, ds)) {
                    rep.dexStringCount = ds.totalStrings;
                    L.push_back("Cozulen string  : " + std::to_string(ds.decoded) + " / " + std::to_string(ds.totalStrings));
                    Sub(L, "String havuzu ornekleri (ilk 24)");
                    for (size_t i = 0; i < ds.sample.size() && i < 24; i++)
                        L.push_back("  " + ds.sample[i].substr(0, 96));
                    if (!ds.hints.empty()) {
                        Sub(L, "Paket/motor ipuclari (string havuzundan)");
                        for (const auto& h : ds.hints) {
                            L.push_back("  - " + h.substr(0, 96));
                            if (rep.dexHints.size() < 32) rep.dexHints.push_back(h.substr(0, 128));
                        }
                    }
                    // ipuclarindan motor tahmini
                    if (rep.engine.empty()) {
                        std::string g = GuessEngineFromStrings(ds.hints);
                        if (!g.empty()) rep.engine = g + " (dex string)";
                    }
                }
            }
        } else {
            errors += "! DEX header okunamadi\n";
        }
        auto strs = ExtractAsciiStrings(data, size, 8, 3000);
        std::string g = GuessEngineFromStrings(strs);
        if (!g.empty()) rep.engine = g;
        L.push_back("");
    }
    // ---- ZIP / APK ----
    else if (magic == "zip") {
        ZipReader zip;
        if (!zip.Parse(data, size)) {
            errors += "! ZIP parse edilemedi: " + zip.LastError() + "\n";
        } else {
            const ZipEntry* manifest = zip.EntryByName("AndroidManifest.xml");
            if (manifest) {
                rep.kind = "apk";
                L.push_back("Tur             : APK (AndroidManifest.xml dogrulandi)");
                Header(L, "APK BILGILERI");
            } else {
                rep.kind = "zip";
                L.push_back("Tur             : ZIP konteyner (Android manifest yok)");
                Header(L, "ZIP BILGILERI");
            }
            if (rep.kind == "apk")
                AnalyzeApk(data, size, zip, rep, L, errors);
            else
                AnalyzePlainZip(zip, L);
        }
        L.push_back("");
    }
    // ---- IL2CPP metadata (dogrudan yukleme) ----
    else if (magic == "il2cpp") {
        rep.kind = "il2cpp";
        auto meta = std::make_shared<Il2Metadata>();
        if (Il2CppMetadataParser::Parse(data, size, *meta) && meta->valid) {
            rep.il2cppMeta = meta;
            rep.engine = "Unity (IL2CPP)";
            rep.engineVersion = meta->versionStr;
            L.push_back("Tur             : IL2CPP global-metadata.dat (sanity dogrulandi)");
            Header(L, "IL2CPP METADATA");
            // tam raporu gom (BuildReport kendi basliklarini yazar)
            L.push_back(Il2CppMetadataParser::BuildReport(*meta, fileName));
        } else {
            errors += "! il2cpp metadata parse: " + meta->lastError + "\n";
        }
        L.push_back("");
    }
    // ---- OAT / VDEX / CDEX ----
    else if (magic == "oat" || magic == "vdex" || magic == "cdex") {
        rep.kind = magic;
        OatVdexInfo info;
        if (OatVdex::Parse(data, size, info) && info.valid) {
            L.push_back("Tur             : ART " + info.kind + " konteyneri");
            Header(L, "ART KONTEYNERI");
            L.push_back(OatVdex::BuildReport(info, fileName));
        } else {
            errors += "! " + magic + " header parse: " + info.lastError + "\n";
        }
        L.push_back("");
    } else {
        L.push_back("Format          : bilinmeyen (magic eslesmedi)");
        L.push_back("");
        errors += "! format taninmadi; exe/dll (PE), so (ELF), dex, apk/zip bekleniyor\n";
    }

    // ---- sonuc + notlar ----
    if (rep.kind == "elf" && !rep.engine.empty()) {
        Header(L, "MOTOR TESPITI");
        L.push_back("Tespit          : " + rep.engine + (rep.engineVersion.empty() ? "" : " " + rep.engineVersion));
        L.push_back("");
    }

    Header(L, "NOTLAR");
    L.push_back("  - Bu rapor yalnizca statik dosya analizidir; canli bellek okumasi yapilmadi.");
    L.push_back("  - Canli dump (GObjects/GNames/SDK) Windows hedeflerinde: DumperPro.exe --process <Oyun>.exe");
    if (rep.kind == "apk" || rep.kind == "dex" || rep.kind == "elf")
        L.push_back("  - Android hedefleri: lib/*.so dosyasini cikarip --file ile statik tarama yapin.");
    if (rep.kind == "il2cpp" || rep.il2cppMeta)
        L.push_back("  - IL2CPP: tam ciktilar (dump.cs/json/stringliterals) ayrica yazildi.");
    if (rep.il2cppBinary)
        L.push_back("  - IL2CPP binary eslestirmesi: metod adresleri (il2cpp_methodaddresses.txt),");
    if (rep.il2cppBinary)
        L.push_back("    script.json (IDA/Ghidra) ve tip tablosu cozumlu dump.cs yazildi.");
    if (rep.kind == "oat" || rep.kind == "vdex" || rep.kind == "cdex")
        L.push_back("  - ART konteynerleri temel header dogrulamasi ile raporlandi.");
    L.push_back("  - Yasal sinirlar: yalnizca sahibi oldugunuz/analiz etmeye yetkili yazilimlar icin.");

    if (!errors.empty()) {
        Header(L, "UYARILAR");
        size_t s = 0;
        while (s < errors.size()) {
            size_t e = errors.find('\n', s);
            if (e == std::string::npos) e = errors.size();
            L.push_back("  " + errors.substr(s, e - s));
            s = e + 1;
        }
    }

    rep.text = str::Join(L, "\n") + "\n";
    return rep;
}

bool StaticAnalyzer::AnalyzeFile(const fs::path& path, StaticReport& out) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return false;
    const u64 sz = fs::file_size(path, ec);
    if (ec || sz == 0 || sz > 0x80000000ull) return false;

    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return false;
    std::vector<u8> data((size_t)sz);
    in.read(reinterpret_cast<char*>(data.data()), (std::streamsize)sz);
    if ((u64)in.gcount() != sz) return false;

    out = Analyze(data.data(), data.size(), path.filename().string());
    return true;
}

// ---------------------------------------------------------------------------
// makine-okur JSON ozeti (roadmap 2.1: JSON cikti secenekleri)
// ---------------------------------------------------------------------------
std::string StaticAnalyzer::BuildJsonReport(const StaticReport& rep, const std::string& fileName,
                                            size_t fileSize) {
    auto esc = [](const std::string& in) {
        std::string o;
        for (unsigned char ch : in) {
            switch (ch) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if (ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", ch); o += b; }
                    else o += (char)ch;
            }
        }
        return o;
    };

    std::string j;
    j += "{\n";
    j += "  \"tool\": \"DumperPro\",\n";
    j += "  \"file\": \"" + esc(fileName) + "\",\n";
    j += "  \"fileSize\": " + std::to_string(fileSize) + ",\n";
    j += "  \"kind\": \"" + esc(rep.kind) + "\",\n";
    j += "  \"engine\": \"" + esc(rep.engine) + "\",\n";
    j += "  \"engineVersion\": \"" + esc(rep.engineVersion) + "\",\n";
    // --- yeni veri tipleri ---
    if (rep.hasPdb) {
        j += "  \"pdb\": { \"format\": \"" + esc(rep.pdbFormat) + "\", \"path\": \"" + esc(rep.pdbPath) +
             "\", \"guid\": \"" + esc(rep.pdbGuid) + "\", \"age\": " + std::to_string(rep.pdbAge) + " },\n";
    }
    if (!rep.imports.empty()) {
        j += "  \"imports\": [";
        for (size_t i = 0; i < rep.imports.size() && i < 32; i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.imports[i]) + "\"";
        j += "],\n";
    }
    if (!rep.versionInfo.empty()) {
        j += "  \"versionResource\": { ";
        for (size_t i = 0; i < rep.versionInfo.size(); i++) {
            const size_t eq = rep.versionInfo[i].find('=');
            if (eq == std::string::npos) continue;
            j += (i ? ", " : "") + std::string("\"") + esc(rep.versionInfo[i].substr(0, eq)) + "\": \"" +
                 esc(rep.versionInfo[i].substr(eq + 1)) + "\"";
        }
        j += " },\n";
    }
    if (!rep.richSummary.empty()) j += "  \"richHeader\": \"" + esc(rep.richSummary) + "\",\n";
    if (rep.tlsCallbacks) j += "  \"tlsCallbacks\": " + std::to_string(rep.tlsCallbacks) + ",\n";
    if (rep.highEntropy) j += "  \"highEntropy\": true,\n";
    if (!rep.entropyLines.empty()) {
        j += "  \"sectionEntropy\": [";
        for (size_t i = 0; i < rep.entropyLines.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.entropyLines[i]) + "\"";
        j += "],\n";
    }
    if (!rep.rttiClasses.empty()) {
        j += "  \"rtti\": { \"count\": " + std::to_string(rep.rttiCount) + ", \"classes\": [";
        for (size_t i = 0; i < rep.rttiClasses.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.rttiClasses[i]) + "\"";
        j += "] },\n";
    }
    if (!rep.wideStrings.empty()) {
        j += "  \"wideStrings\": [";
        for (size_t i = 0; i < rep.wideStrings.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.wideStrings[i]) + "\"";
        j += "],\n";
    }
    if (rep.elfDynsymCount) {
        j += "  \"elfDynsym\": { \"total\": " + std::to_string(rep.elfDynsymCount) + ", \"exported\": [";
        for (size_t i = 0; i < rep.elfDynsyms.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.elfDynsyms[i]) + "\"";
        j += "] },\n";
    }
    if (rep.dexStringCount) {
        j += "  \"dexStrings\": { \"total\": " + std::to_string(rep.dexStringCount) + ", \"hints\": [";
        for (size_t i = 0; i < rep.dexHints.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.dexHints[i]) + "\"";
        j += "] },\n";
    }
    if (!rep.machoSummary.empty()) {
        j += "  \"macho\": { \"summary\": \"" + esc(rep.machoSummary) + "\"";
        if (!rep.machoFatArchs.empty()) {
            j += ", \"fatArchs\": [";
            for (size_t i = 0; i < rep.machoFatArchs.size(); i++)
                j += (i ? ", " : "") + std::string("\"") + esc(rep.machoFatArchs[i]) + "\"";
            j += "]";
        }
        if (!rep.machoExports.empty()) {
            j += ", \"exports\": [";
            for (size_t i = 0; i < rep.machoExports.size(); i++)
                j += (i ? ", " : "") + std::string("\"") + esc(rep.machoExports[i]) + "\"";
            j += "]";
        }
        if (!rep.machoLibs.empty()) {
            j += ", \"linkedLibs\": [";
            for (size_t i = 0; i < rep.machoLibs.size(); i++)
                j += (i ? ", " : "") + std::string("\"") + esc(rep.machoLibs[i]) + "\"";
            j += "]";
        }
        j += " },\n";
    }
    if (!rep.securityHints.empty()) {
        j += "  \"securityHints\": [";
        for (size_t i = 0; i < rep.securityHints.size(); i++)
            j += (i ? ", " : "") + std::string("\"") + esc(rep.securityHints[i]) + "\"";
        j += "],\n";
    }
    if (rep.il2cppMeta && rep.il2cppMeta->valid) {
        const Il2Metadata& m = *rep.il2cppMeta;
        j += "  \"il2cpp\": {\n";
        j += "    \"metadataVersion\": \"" + esc(m.versionStr) + "\",\n";
        j += "    \"unityHint\": \"" + esc(m.unityHint) + "\",\n";
        j += "    \"images\": " + std::to_string(m.images.size()) + ",\n";
        j += "    \"types\": " + std::to_string(m.types.size()) + ",\n";
        j += "    \"fields\": " + std::to_string(m.fields.size()) + ",\n";
        j += "    \"methods\": " + std::to_string(m.methods.size()) + ",\n";
        j += "    \"stringLiterals\": " + std::to_string(m.stringLiteralCount) + "\n";
        j += "  },\n";
    }
    j += "  \"hasGamesIniSuggestion\": " + std::string(rep.gamesIni.empty() ? "false" : "true") + ",\n";
    j += "  \"report\": \"" + esc(rep.text) + "\"\n";
    j += "}\n";
    return j;
}

} // namespace dumper
