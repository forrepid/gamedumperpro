// ============================================================================
// DumperPro - main orchestration
//
// Live mode  : DumperPro.exe --process Game.exe [--kernel]
// PID mode   : DumperPro.exe --pid 1234
// File mode  : DumperPro.exe --file Game-Win64-Shipping.exe | oyun.apk | libUE4.so | classes.dex
// Device mode: DumperPro.exe --device "fpga" | "file://dump.bin" | "dump://x.dmp"
// Linux: leechcore.so (ufrisk/LeechCore make build) ayni ABI ile dlopen edilir.
//              (LeechCore device-level physical memory, docs/LEECH.md)
// Serve mode : DumperPro.exe --serve [port]   (online dosya yukleme, tarayici)
// ============================================================================

#include "framework.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"
#include "utils/Progress.h"
#include "core/MemoryReader.h"
#include "core/LeechReader.h"
#include "core/Pattern.h"
#include "ue/UEVersion.h"
#include "ue/Offsets.h"
#include "ue/UEObject.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"
#include "ue/OffsetProbe.h"
#include "dump/Dumps.h"
#include "dump/SDKGenerator.h"
#include "dump/VTableResolver.h"
#include "sig/SigFinder.h"
#include "config/Config.h"
#include "file/StaticAnalyzer.h"
#include "net/HttpServer.h"
#include "hex/HexTool.h"
#include "il2cpp/Il2CppBinary.h"
#include "il2cpp/Il2CppDummyDll.h"
#include "core/ModuleRegistry.h"
#include "binfold/BinFold.h"

#include <iostream>
#include <ctime>

using namespace dumper;

struct Options {
    std::string process;     // process name (substring match, ci)
    u32 pid = 0;
    fs::path file;           // file mode
    std::string device;      // LeechCore device string (--device, docs/LEECH.md)
    fs::path metadata;       // IL2CPP global-metadata.dat (binary eslestirme cifti)
    std::string moduleName;  // optional non-main module
    fs::path outDir;         // output dir
    fs::path iniPath = "games.ini";
    bool kernel = false;
    bool verbose = false;
    bool noSdk = false;
    bool offlineSdkOnly = false;
    bool serve = false;      // HTTP upload server mode
    bool json = false;       // JSON outputs (names/objects/analysis report)
    u16 servePort = 8420;
    int probeCount = 400;

    // ---- hex/aob view-editor-save ----
    bool hex = false;
    std::vector<std::string> hexViews;      // "0x1000" veya "0x1000:8" (off:rows)
    std::vector<std::string> hexCodes;      // "0x140001000:24"
    std::vector<std::string> hexBinaries;   // "0x1000:16" (off:bytes)
    std::vector<std::string> hexSearches;   // AOB / text:... / text16:...
    std::vector<std::string> hexPatches;    // "0x1000=90 E9;0x2000=CC"
    fs::path hexSave;                       // yamali kopyayi dosyaya yaz
    bool hexLive = false;                   // yamalari canli prosese uygula
    int hexBits = 64;                       // kod gorunumu bit
    int hexRows = 16;                       // gorunum satir sayisi

    // ---- binfold diff mode (binfold module, docs/modules.md) ----
    fs::path bindiffA;                      // --bindiff <A> <B> (reference)
    fs::path bindiffB;                      //                (target)
    fs::path bindiffJson;                   // opsiyonel JSON ciktisi
};

static void PrintUsage() {
    fprintf(stdout,
        "DumperPro - Unreal Engine memory/SDK dumper (UE4 4.20-4.27, UE5 5.0-5.5)\n"
        "\n"
        "Usage:\n"
        "  DumperPro.exe --process Game.exe            attach to a running process\n"
        "  DumperPro.exe --pid 1234                    attach by pid\n"
        "  DumperPro.exe --file Game-Win64-Shipping.exe      offline analysis of a PE file\n"
        "  DumperPro.exe --file oyun.apk               static analysis: APK/ZIP/ELF/DEX\n"
        "  DumperPro.exe --file global-metadata.dat    Unity IL2CPP metadata dump\n"
        "  DumperPro.exe --file libUE4.so              static analysis: ELF + UE strings\n"
        "  DumperPro.exe --file base.vdex | base.odex  ART container (vdex/oat/cdex)\n"
        "  DumperPro.exe --device \"file://dump.bin\"    LeechCore device / dump file (docs/LEECH.md)\n"
        "  DumperPro.exe --serve                       local web upload mode (default port 8420)\n"
        "  DumperPro.exe --bindiff old.exe new.exe     binary diff: function GUIDs + similarity\n"
        "\n"
        "IL2CPP binary matching (Il2CppDumper second half):\n"
        "  DumperPro.exe --file GameAssembly.dll --metadata global-metadata.dat\n"
        "  DumperPro.exe --file libil2cpp.so  --metadata global-metadata.dat\n"
        "    (APK input auto-pairs metadata + libil2cpp.so when both are present)\n"
        "\n"
        "Live hex/byte/code/binary/AOB view-editor-save:\n"
        "  DumperPro.exe --hex --file oyun.exe --hex-view 0x1000 --hex-code 0x140001000:16\n"
        "  DumperPro.exe --hex --file oyun.exe --hex-search \"48 8B 05 ?? ?? ?? ?? 48 85 C0\"\n"
        "  DumperPro.exe --hex --file oyun.exe --hex-patch \"0x1000=90 E9\" --hex-save patched.exe\n"
        "  DumperPro.exe --hex --process Game.exe --module Game.exe --hex-view 0x140001000\n"
        "  DumperPro.exe --hex --process Game.exe --hex-patch \"0x140001000=90\" --hex-live\n"
        "\n"
        "Options:\n"
        "  --module <name>       scan a specific module instead of the main module\n"
        "  --metadata <file>     pair with --file: Unity IL2CPP global-metadata.dat\n"
        "  --hex                 hex/aob mode (see examples above)\n"
        "  --hex-view <off[:r]>  hex+ascii table (rows r, default 16)\n"
        "  --hex-code <off[:r]>  x86/x64 code view (rows r)\n"
        "  --hex-binary <o[:b]>  bit-level binary view (bytes b)\n"
        "  --hex-search <aob>    AOB search: \"48 8B 05 ?? ??\" / \"488B05????\" / text:str / text16:str\n"
        "  --hex-patch <spec>    patch buffer: \"0x1000=90 E9;0x2000=CC\"\n"
        "  --hex-save <file>     write patched copy to a NEW file\n"
        "  --hex-live            apply patches to the live process via Write\n"
        "  --hex-bits <32|64>    code view mode (default 64)\n"
        "  --hex-rows <n>        default row count (default 16)\n"
        "  --out <dir>           output directory (default ./DumperPro_Out/<game>_<timestamp>)\n"
        "  --ini <games.ini>     config file (default ./games.ini)\n"
        "  --device <lc>         LeechCore device (fpga / file://dump.bin / dump://x.dmp - see docs/LEECH.md)\n"
        "  --kernel              kernel-assisted memory access (see docs/KERNEL.md)\n"
        "  --serve [port]        online file upload: open http://127.0.0.1:<port> in a browser\n"
        "  --bindiff <A> <B>     binfold diff of two binaries (WARP function GUIDs,\n"
        "                        call-graph constraint matching, similarity score)\n"
        "  --bindiff-json <f>    with --bindiff: also write a machine-readable JSON report\n"
        "  --modules             list engine modules (registry) and exit\n"
        "  --json                machine-readable JSON outputs (names.json, objects.json,\n"
        "                        analysis_report.json) alongside the text dumps\n"
        "  --probe <n>           offset probe sample count (default 400)\n"
        "  --no-sdk              dump names/objects/offsets only, skip SDK generation\n"
        "  --verbose             detailed logging\n"
        "  --list-profiles       show built-in game profiles\n"
        "  --help\n"
        "\n"
        "Intended for offline analysis, single-player modding and engine research\n"
        "on software you own or are licensed to analyze.\n");
}

static void PrintProfiles() {
    fprintf(stdout, "Built-in profiles:\n");
    for (const GameProfile& p : Config::Builtins()) {
        fprintf(stdout, "  %-10s UE%d.%d\n", p.name.c_str(), p.version.major, p.version.minor);
    }
}

static void PrintModules() {
    fprintf(stdout, "DumperPro engine modules:\n\n");
    fprintf(stdout, "%s", ModuleRegistry::BuildTable().c_str());
}

static bool ParseArgs(int argc, char** argv, Options& o, std::string& err) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) { err = "missing value for " + a; return false; }
            dst = argv[++i];
            return true;
        };
        if (a == "--help" || a == "-h") { PrintUsage(); exit(0); }
        else if (a == "--list-profiles") { PrintProfiles(); exit(0); }
        else if (a == "--modules") { PrintModules(); exit(0); }
        else if (a == "--process") { if (!next(o.process)) return false; }
        else if (a == "--pid") {
            std::string v; if (!next(v)) return false;
            o.pid = (u32)std::atoi(v.c_str());
            if (!o.pid) { err = "invalid --pid"; return false; }
        }
        else if (a == "--file") { std::string v; if (!next(v)) return false; o.file = v; }
        else if (a == "--device") { if (!next(o.device)) return false; }
        else if (a == "--metadata") { std::string v; if (!next(v)) return false; o.metadata = v; }
        else if (a == "--bindiff") {
            std::string v1, v2;
            if (!next(v1)) return false;
            if (!next(v2)) return false;
            o.bindiffA = v1;
            o.bindiffB = v2;
        }
        else if (a == "--bindiff-json") { std::string v; if (!next(v)) return false; o.bindiffJson = v; }
        else if (a == "--hex") { o.hex = true; }
        else if (a == "--hex-view") { if (!next(o.hexViews.emplace_back())) return false; }
        else if (a == "--hex-code") { if (!next(o.hexCodes.emplace_back())) return false; }
        else if (a == "--hex-binary") { if (!next(o.hexBinaries.emplace_back())) return false; }
        else if (a == "--hex-search") { if (!next(o.hexSearches.emplace_back())) return false; }
        else if (a == "--hex-patch") { if (!next(o.hexPatches.emplace_back())) return false; }
        else if (a == "--hex-save") { std::string v; if (!next(v)) return false; o.hexSave = v; }
        else if (a == "--hex-live") { o.hexLive = true; }
        else if (a == "--hex-bits") {
            std::string v; if (!next(v)) return false;
            o.hexBits = std::atoi(v.c_str());
            if (o.hexBits != 32 && o.hexBits != 64) { err = "--hex-bits must be 32 or 64"; return false; }
        }
        else if (a == "--hex-rows") {
            std::string v; if (!next(v)) return false;
            o.hexRows = std::atoi(v.c_str());
            if (o.hexRows <= 0 || o.hexRows > 4096) { err = "--hex-rows must be 1..4096"; return false; }
        }
        else if (a == "--serve") {
            o.serve = true;
            // opsiyonel port: sonraki arguman sayi ise al, degilse default birak
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') {
                o.servePort = (u16)std::atoi(argv[++i]);
                if (!o.servePort) { err = "invalid --serve port"; return false; }
            }
        }
        else if (a == "--module") { if (!next(o.moduleName)) return false; }
        else if (a == "--out") { std::string v; if (!next(v)) return false; o.outDir = v; }
        else if (a == "--ini") { std::string v; if (!next(v)) return false; o.iniPath = v; }
        else if (a == "--kernel") { o.kernel = true; }
        else if (a == "--verbose") { o.verbose = true; }
        else if (a == "--no-sdk") { o.noSdk = true; }
        else if (a == "--json") { o.json = true; }
        else if (a == "--probe") {
            std::string v; if (!next(v)) return false;
            o.probeCount = std::atoi(v.c_str());
        } else {
            err = "unknown argument: " + a;
            return false;
        }
    }

    int modes = (o.process.empty() ? 0 : 1) + (o.pid ? 1 : 0) + (o.file.empty() ? 0 : 1) +
                (o.device.empty() ? 0 : 1) + (o.serve ? 1 : 0) + (o.bindiffA.empty() ? 0 : 1);
    if (modes == 0) { err = "no target: use --process, --pid, --file, --device, --serve or --bindiff"; return false; }
    if (modes > 1) { err = "only one of --process / --pid / --file / --device / --serve / --bindiff can be used"; return false; }
    if (!o.bindiffA.empty() && o.bindiffB.empty()) { err = "--bindiff needs two files: --bindiff <fileA> <fileB>"; return false; }
    if (!o.bindiffJson.empty() && o.bindiffA.empty()) { err = "--bindiff-json requires --bindiff"; return false; }
    // hex modu bir hedef gerektirir; serve ile kullanilamaz
    if (o.hex && !o.device.empty()) { err = "--hex cannot be combined with --device (no module model at device level)"; return false; }
    const bool anyHexAction = !o.hexViews.empty() || !o.hexCodes.empty() || !o.hexBinaries.empty() ||
                              !o.hexSearches.empty() || !o.hexPatches.empty() || o.hexLive || !o.hexSave.empty();
    if (o.hex && o.serve) { err = "--hex cannot be combined with --serve"; return false; }
    if (o.hex && !anyHexAction) { err = "--hex needs an action: --hex-view/--hex-code/--hex-binary/--hex-search/--hex-patch"; return false; }
    if (o.hexLive && modes != 1) { err = "--hex-live requires --process or --pid"; return false; }
    if (!o.hex && anyHexAction) { err = "hex actions require --hex"; return false; }
    return true;
}

static void FailWithHint(const std::string& msg, const std::string& hint) {
    Log::Err("%s", msg.c_str());
    if (!hint.empty()) {
        Log::Raw("  Hint: " + hint);
    }
}

// --device (LeechCore) best-effort scan window (docs/LEECH.md). LeechCore is a
// device-level API: no process/module model, so when Modules() is empty the UE
// pipeline runs over this raw physical-address window. The base starts at the
// reader's near-null guard (kMinValidVa = 0x10000), not at literal PA 0.
static constexpr u64 kDeviceScanBase = 0x10000;
// Window upper bound. When the device reports a max physical address (paMax,
// LC_OPT_CORE_ADDR_MAX) the window is clamped to that so file-backed dumps
// (raw module dumps easily exceed 64 MiB on UE5 shipping builds) are scanned
// in full; hardware devices are capped so a giant RAM dump cannot stall the
// CLI for minutes. Without a reported max the legacy 64 MiB window applies.
static constexpr u64 kDeviceScanFallback = 64ull * 1024 * 1024;  // legacy: 64 MiB
static constexpr u64 kDeviceScanCap      = 512ull * 1024 * 1024; // hard cap: 512 MiB

static std::string TimeStampDir() {
    std::time_t t = std::time(nullptr);
    std::tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

// dosyanin ilk 4 baytindan PE olup olmadigini anlamak icin hafif koklama
static bool SniffIsPe(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in.good()) return false;
    char b[4] = {};
    in.read(b, 4);
    return in.gcount() >= 2 && b[0] == 'M' && b[1] == 'Z';
}

// PE olmayan dosyalar icin statik analiz hatti (apk/zip/elf/dex/il2cpp/oat/vdex)
static int RunStaticFileMode(const Options& opt, const std::string& gameName) {
    StaticReport rep;
    if (!StaticAnalyzer::AnalyzeFile(opt.file, rep)) {
        FailWithHint("cannot read file: " + opt.file.string(),
                     "make sure the file exists and is under 2 GiB");
        return 2;
    }
    Log::Info("Static analysis kind: %s", rep.kind.c_str());

    fs::path outDir = opt.outDir.empty()
        ? fs::path("DumperPro_Out") / (str::SanitizeIdent(gameName) + "_" + TimeStampDir())
        : opt.outDir;
    std::error_code ec;
    fs::create_directories(outDir, ec);

    const fs::path reportFile = outDir / "analysis_report.txt";
    {
        std::ofstream out(reportFile, std::ios::binary | std::ios::trunc);
        out << rep.text;
    }
    if (!rep.gamesIni.empty()) {
        std::ofstream ini(outDir / "games.ini.oneri.txt", std::ios::binary | std::ios::trunc);
        ini << rep.gamesIni;
    }
    if (opt.json) {
        std::ofstream jr(outDir / "analysis_report.json", std::ios::binary | std::ios::trunc);
        jr << StaticAnalyzer::BuildJsonReport(rep, opt.file.filename().string(),
                                              (size_t)fs::file_size(opt.file, ec));
        Log::Ok("analysis_report.json written");
    }

    // IL2CPP metadata: tam ciktilar (dump.cs benzeri iskelet + JSON + literals)
    if (rep.il2cppMeta && rep.il2cppMeta->valid) {
        Il2CppMetadataParser::WriteOutputs(*rep.il2cppMeta, outDir,
                                           opt.file.filename().string());
    }

    // IL2CPP binary es cifti (APK icinden otomatik eslestirildi)
    if (rep.il2cppBinary && rep.il2cppMeta) {
        Il2CppBinaryMatch::WriteOutputs(*rep.il2cppMeta, *rep.il2cppBinary, outDir,
                                        rep.il2cppSoName.empty() ? "binary" : rep.il2cppSoName,
                                        "global-metadata.dat",
                                        rep.il2cppBinaryData ? rep.il2cppBinaryData->data() : nullptr,
                                        rep.il2cppBinaryData ? rep.il2cppBinaryData->size() : 0);
        // DummyDll: image basina derlenebilir C# kaynak stub'lar
        Il2CppDummyDll::WriteOutputs(*rep.il2cppMeta, *rep.il2cppBinary, outDir,
                                     rep.il2cppBinaryData ? rep.il2cppBinaryData->data() : nullptr,
                                     rep.il2cppBinaryData ? rep.il2cppBinaryData->size() : 0);
    }

    // raporu konsola da yansit
    Log::Raw("");
    Log::Raw(rep.text);
    Log::Ok("analysis_report.txt written -> %s", reportFile.string().c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// IL2CPP cift modu: --file <GameAssembly.dll | libil2cpp.so> --metadata <global-metadata.dat>
// Il2CppDumper'in tam hatti: metadata parse + binary eslestirme (CodeRegistration
// / MetadataRegistration taramasi) -> metod adresleri + gercek tip isimleri.
// ---------------------------------------------------------------------------
static int RunIl2CppPairMode(const Options& opt, const std::string& gameName) {
    // metadata yukle
    std::error_code ec;
    if (!fs::exists(opt.metadata, ec) || ec) {
        FailWithHint("metadata dosyasi bulunamadi: " + opt.metadata.string(),
                     "Unity IL2CPP projesinde assets/bin/Data/Managed/Metadata/ altindadir");
        return 2;
    }
    std::ifstream mf(opt.metadata, std::ios::binary);
    if (!mf.good()) { FailWithHint("metadata okunamadi", ""); return 2; }
    std::vector<u8> mdata((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());

    // binary yukle
    if (!fs::exists(opt.file, ec) || ec) {
        FailWithHint("binary dosyasi bulunamadi: " + opt.file.string(), "");
        return 2;
    }
    std::ifstream bf(opt.file, std::ios::binary);
    if (!bf.good()) { FailWithHint("binary okunamadi", ""); return 2; }
    std::vector<u8> bdata((std::istreambuf_iterator<char>(bf)), std::istreambuf_iterator<char>());

    Log::Info("IL2CPP pair mode: %s + %s", opt.file.string().c_str(), opt.metadata.string().c_str());

    Il2Metadata meta;
    if (!Il2CppMetadataParser::Parse(mdata.data(), mdata.size(), meta) || !meta.valid) {
        FailWithHint("metadata parse edilemedi: " + meta.lastError,
                     "desteklenen surumler: metadata v16..31");
        return 4;
    }
    Log::Ok("Metadata OK: surum %s (%s)", meta.versionStr.c_str(), meta.unityHint.c_str());
    Log::Info("Images=%llu Types=%llu Fields=%llu Methods=%llu",
              (unsigned long long)meta.images.size(), (unsigned long long)meta.types.size(),
              (unsigned long long)meta.fields.size(), (unsigned long long)meta.methods.size());

    Il2BinaryResult binres;
    const bool matched = Il2CppBinaryMatch::Match(bdata.data(), bdata.size(), meta, binres);
    if (!matched) {
        FailWithHint("binary eslestirme basarisiz: " + binres.lastError,
                     "metadata ile binary ayni build'den olmali (surumler birebir eslesmelidir)");
        // yine de metadata-yalniz ciktilari yaz
    } else {
        Log::Ok("Binary eslestirme BASARILI: %u / %llu metod adresi cozuldu (govdesiz %u)",
                binres.resolvedCount, (unsigned long long)meta.methods.size(), binres.nullCount);
        if (binres.metadataRegistrationFound)
            Log::Ok("Il2CppType tablosu cozuldu (types=%u) - dump.cs gercek tipler iceriyor",
                    binres.typesCount);
        for (const Il2ModuleMatch& m : binres.modules) {
            Log::Debug("  module: %-32s count=%u exec=%.0f%%", m.imageName.c_str(),
                       m.methodPointerCount, m.execRatio * 100.0);
        }
    }

    fs::path outDir = opt.outDir.empty()
        ? fs::path("DumperPro_Out") / (str::SanitizeIdent(gameName) + "_il2cpp_" + TimeStampDir())
        : opt.outDir;
    fs::create_directories(outDir, ec);

    // metadata-yalniz ciktilar (rapor/json/literals) + binary ciktilar + DummyDll
    Il2CppMetadataParser::WriteOutputs(meta, outDir, opt.metadata.filename().string());
    Il2CppBinaryMatch::WriteOutputs(meta, binres, outDir,
                                    opt.file.filename().string(),
                                    opt.metadata.filename().string(),
                                    bdata.data(), bdata.size());
    Il2CppDummyDll::WriteOutputs(meta, binres, outDir, bdata.data(), bdata.size());

    Log::Raw("");
    Log::Raw(Il2CppBinaryMatch::BuildBinaryReport(meta, binres,
             opt.file.filename().string(), opt.metadata.filename().string()));
    Log::Ok("Cikti klasoru: %s", outDir.string().c_str());
    return matched ? 0 : 3;
}

static void WriteSignatureFiles(const std::string& game, const SigFinder& sf, const UEVersion& ver, const fs::path& outDir) {
    auto primary = [&](const SigHit& h) -> std::string {
        if (!h.va) return "";
        if (!h.pattern.empty() && h.pattern.find("??") == std::string::npos) return h.pattern;
        return h.extended; // heuristic hits: extended bytes pattern is reusable
    };

    std::ofstream out(outDir / "signatures.txt", std::ios::binary | std::ios::trunc);
    if (out.good()) {
        out << "; DumperPro signatures for " << game << "\n";
        out << "; primary + extended (16-byte context) signatures, reusable in games.ini\n\n";
        if (sf.GNamesHit.va && !primary(sf.GNamesHit).empty()) {
            out << "; via: " << sf.GNamesHit.via << "  va: 0x" << std::hex << sf.GNamesHit.va << "\n" << std::dec;
            out << "GNames = " << primary(sf.GNamesHit) << "\n";
            out << "GNamesExtended = " << sf.GNamesHit.extended << "\n\n";
        }
        if (sf.GObjectsHit.va && !primary(sf.GObjectsHit).empty()) {
            out << "; via: " << sf.GObjectsHit.via << "  va: 0x" << std::hex << sf.GObjectsHit.va << "\n" << std::dec;
            out << "GObjects = " << primary(sf.GObjectsHit) << "\n";
            out << "GObjectsExtended = " << sf.GObjectsHit.extended << "\n\n";
        }
        if (sf.GWorldHit.va && !primary(sf.GWorldHit).empty()) {
            out << "GWorld = " << primary(sf.GWorldHit) << " ; va: 0x" << std::hex << sf.GWorldHit.va << "\n" << std::dec;
        }
    }

    std::ofstream out2(outDir / (game + "_sigs.txt"), std::ios::binary | std::ios::trunc);
    if (out2.good()) {
        out2 << "[" << game << "]\n";
        if (ver.IsValid()) out2 << "version = " << ver.major << "." << ver.minor << "\n";
        if (sf.GNamesHit.va) out2 << "gnames_pattern = " << primary(sf.GNamesHit) << "\n";
        if (sf.GObjectsHit.va) out2 << "gobjects_pattern = " << primary(sf.GObjectsHit) << "\n";
        out2 << "; drop these lines into games.ini to skip scanning next time\n";
    }

    Log::Ok("signatures.txt + %s_sigs.txt written", game.c_str());
}

static void WriteVTableFuncsTxt(const fs::path& outDir, const std::vector<VTResult>& results) {
    std::ofstream out(outDir / "vtable_funcs.txt", std::ios::binary | std::ios::trunc);
    if (!out.good()) return;
    out << "; DumperPro vtable-resolved functions\n";
    for (const VTResult& r : results) {
        out << r.note << ": ";
        if (!r.found) {
            out << "NOT_FOUND\n";
            continue;
        }
        out << "FOUND_IN_VTABLE [" << r.via << "]"
            << " slot=0x" << std::hex << r.slot
            << " RVA=0x" << r.rva
            << " VA=0x" << r.funcVA
            << " SlotRVA=0x" << r.slotRVA
            << std::dec
            << " thunkDepth=" << r.thunkDepth
            << " votes=" << r.votes << "\n";
    }
    Log::Ok("vtable_funcs.txt written");
}

// ---------------------------------------------------------------------------
// --bindiff modu: binfold modulu - iki binary arasinda fonksiyon seviyesinde
// diff + benzerlik (WARP GUID'leri + call-graph constraint eslestirme).
// Detay: docs/modules.md ve src/binfold/BinFold.h
// ---------------------------------------------------------------------------
static int RunBindiffMode(const Options& opt) {
    Log::Banner("DumperPro - BinFold Binary Diff");

    std::vector<u8> a, b;
    std::string err;
    if (!binfold::BinFold::LoadFile(opt.bindiffA, a, err)) {
        FailWithHint(err, "check the file path and size (cap 1 GiB)");
        return 2;
    }
    if (!binfold::BinFold::LoadFile(opt.bindiffB, b, err)) {
        FailWithHint(err, "check the file path and size (cap 1 GiB)");
        return 2;
    }
    Log::Info("File A (reference): %s (%s)", opt.bindiffA.string().c_str(), str::HumanSize(a.size()).c_str());
    Log::Info("File B (target)   : %s (%s)", opt.bindiffB.string().c_str(), str::HumanSize(b.size()).c_str());

    binfold::BfDiffResult res;
    if (!binfold::BinFold::Diff(a.data(), a.size(), b.data(), b.size(), res, err)) {
        FailWithHint("binfold diff failed: " + err, "");
        return 4;
    }

    Log::Raw(binfold::BinFold::BuildReport(res, opt.bindiffA.filename().string(),
                                           opt.bindiffB.filename().string()));

    if (!opt.bindiffJson.empty()) {
        std::ofstream out(opt.bindiffJson, std::ios::binary | std::ios::trunc);
        if (!out.good()) {
            FailWithHint("cannot write JSON: " + opt.bindiffJson.string(), "");
            return 2;
        }
        out << binfold::BinFold::BuildJson(res, opt.bindiffA.filename().string(),
                                           opt.bindiffB.filename().string());
        Log::Ok("JSON written: %s", opt.bindiffJson.string().c_str());
    }
    return 0;
}

// ---------------------------------------------------------------------------
// --hex modu: live code/hex/byte/binary/AOB view-editor-save
// ---------------------------------------------------------------------------
static bool ParseOffRows(const std::string& spec, u64& off, int& rows) {
    const size_t colon = spec.find(':');
    const std::string offPart = colon == std::string::npos ? spec : spec.substr(0, colon);
    if (!str::ParseU64(offPart, off)) return false;
    rows = 0;
    if (colon != std::string::npos) rows = std::atoi(spec.substr(colon + 1).c_str());
    return true;
}

static std::string HexOf(u64 v) {
    char b[32];
    snprintf(b, sizeof(b), "%llX", (unsigned long long)v);
    return b;
}

static int RunHexMode(const Options& opt) {
    Log::Banner("DumperPro - Hex/AOB View-Editor-Save");

    std::unique_ptr<IMemoryReader> reader;
    std::unique_ptr<HexTool> hx;

    if (!opt.file.empty()) {
        hx = HexTool::OpenFile(opt.file);
    } else {
        reader = CreateProcessReader(opt.process, opt.pid, opt.kernel);
        if (!reader || !reader->IsOK()) {
            FailWithHint("cannot open target: " + (reader ? reader->LastError() : "?"),
                         "run as Administrator or check the process name");
            return 2;
        }
        std::vector<ModuleInfo> mods = reader->Modules();
        if (mods.empty()) { FailWithHint("no modules in target", ""); return 3; }
        ModuleInfo m = mods.front();
        if (!opt.moduleName.empty()) {
            bool found = false;
            for (const ModuleInfo& x : mods) {
                if (str::Contains(str::Lower(x.name), str::Lower(opt.moduleName))) { m = x; found = true; break; }
            }
            if (!found) { FailWithHint("module not found: " + opt.moduleName, ""); return 3; }
        }
        hx = HexTool::OpenLive(*reader, m);
    }
    if (!hx || !hx->OK()) {
        FailWithHint("hex kaynagi acilamadi: " + (hx ? hx->LastError() : std::string("?")),
                     "--file <dosya> veya --process <proses> --module <modul> deneyin");
        return 2;
    }
    Log::Info("Kaynak : %s  base=0x%llX  boyut=%s%s", hx->Label().c_str(),
              (unsigned long long)hx->BaseAddr(), str::HumanSize(hx->Size()).c_str(),
              hx->IsLive() ? "  [CANLI]" : "");

    // ---- views ----
    auto ShowView = [&](const std::string& title, const std::string& body) {
        Log::Raw("");
        Log::Raw(title);
        Log::Raw(body);
    };
    for (const std::string& spec : opt.hexViews) {
        u64 off = 0; int rows = 0;
        if (!ParseOffRows(spec, off, rows)) {
            Log::Warn("gecersiz --hex-view: %s", spec.c_str());
            continue;
        }
        if (!rows) rows = opt.hexRows;
        ShowView("HEX VIEW (offset 0x" + HexOf(off) + ")",
                 hx->RenderHex(off, (size_t)rows));
    }
    for (const std::string& spec : opt.hexCodes) {
        u64 off = 0; int rows = 0;
        if (!ParseOffRows(spec, off, rows)) {
            Log::Warn("gecersiz --hex-code: %s", spec.c_str());
            continue;
        }
        if (!rows) rows = opt.hexRows;
        ShowView(std::string("CODE VIEW x") + std::to_string(opt.hexBits) +
                 " (offset 0x" + HexOf(off) + ")",
                 hx->RenderCode(off, (size_t)rows, opt.hexBits));
    }
    for (const std::string& spec : opt.hexBinaries) {
        u64 off = 0; int bytes = 0;
        if (!ParseOffRows(spec, off, bytes)) {
            Log::Warn("gecersiz --hex-binary: %s", spec.c_str());
            continue;
        }
        if (!bytes) bytes = 16;
        ShowView("BINARY VIEW (offset 0x" + HexOf(off) + ")",
                 hx->RenderBinary(off, (size_t)bytes));
    }

    // ---- searches ----
    for (const std::string& q : opt.hexSearches) {
        std::vector<u8> bytes;
        std::vector<bool> wild;
        std::string err;
        if (!HexTool::ParseQuery(q, bytes, wild, err)) {
            Log::Warn("AOB sorgu hatasi: %s (%s)", q.c_str(), err.c_str());
            continue;
        }
        auto hits = hx->Search(bytes, wild, 256);
        Log::Info("AOB: %s -> %zu eslesme", q.c_str(), hits.size());
        for (size_t k = 0; k < hits.size() && k < 64; k++) {
            Log::Raw("  [" + std::to_string(k + 1) + "] VA=0x" + HexOf(hits[k].addr) +
                     "  fileOff=0x" + HexOf(hits[k].offset));
        }
        if (hits.size() > 64)
            Log::Raw("  ... (" + std::to_string(hits.size() - 64) + " daha; cikti 64 ile sinirli)");
    }

    // ---- patches ----
    bool hadPatch = false;
    for (const std::string& spec : opt.hexPatches) {
        // bicim: "0x1000=90 E9;0x2000=CC"
        std::vector<std::string> parts = str::Split(spec, ';');
        for (const std::string& partRaw : parts) {
            const std::string part = str::Trim(partRaw);
            if (part.empty()) continue;
            const size_t eq = part.find('=');
            if (eq == std::string::npos) {
                Log::Warn("gecersiz --hex-patch parcalari (off=BYTES): %s", part.c_str());
                continue;
            }
            u64 off = 0;
            if (!str::ParseU64(part.substr(0, eq), off)) {
                Log::Warn("gecersiz offset: %s", part.c_str());
                continue;
            }
            // hex baytlarini jokerli/normal ayristir
            std::vector<u8> bytes;
            std::vector<bool> wild;
            std::string err;
            if (!HexTool::ParseQuery(part.substr(eq + 1), bytes, wild, err)) {
                Log::Warn("gecersiz yama baytlari: %s (%s)", part.c_str(), err.c_str());
                continue;
            }
            bool anyWild = false;
            for (bool w : wild) anyWild |= w;
            if (anyWild) { Log::Warn("yama baytlarinda joker olamaz: %s", part.c_str()); continue; }
            if (hx->Patch(off, bytes, err)) {
                hadPatch = true;
                Log::Ok("Yama @0x%llX (%zu bayt)", (unsigned long long)hx->BaseAddr() + off, bytes.size());
            } else {
                Log::Warn("Yama reddedildi: %s", err.c_str());
            }
        }
    }

    // ---- save / live apply ----
    if (!opt.hexSave.empty()) {
        std::string err;
        if (hx->SaveToFile(opt.hexSave, err))
            Log::Ok("Yamali kopya yazildi: %s", opt.hexSave.string().c_str());
        else
            Log::Warn("Kaydetme basarisiz: %s", err.c_str());
    }
    if (opt.hexLive) {
        if (!reader) { Log::Warn("--hex-live icin canli hedef gerekli (--process/--pid)"); }
        else {
            std::string err;
            if (hx->ApplyLive(*reader, err))
                Log::Ok("Canli yamalar uygulandi");
            else
                Log::Warn("Canli uygulama basarisiz: %s", err.c_str());
        }
    }
    if (hadPatch && opt.hexSave.empty() && !opt.hexLive) {
        Log::Warn("Yamalar yalnizca buffer'da kaldı: --hex-save <dosya> veya --hex-live ile kaydedin");
    }
    if (!hadPatch && !opt.hexSave.empty() && opt.hexPatches.empty() && !opt.hexLive) {
        Log::Warn("--hex-save verildi ama --hex-patch yok; yama yok, dosya yazilmadi");
    }
    return 0;
}

int main(int argc, char** argv) {
    Log::Banner("DumperPro - UE Memory & SDK Dumper");

    Options opt;
    std::string err;
    if (!ParseArgs(argc, argv, opt, err)) {
        FailWithHint(err, "run with --help to see usage");
        return 1;
    }
    Log::SetVerbose(opt.verbose);

    // ---- binfold diff modu: iki binary karsilastirma (binfold module) ----
    if (!opt.bindiffA.empty()) {
        return RunBindiffMode(opt);
    }

    // ---- hex modu: live code/hex/byte/binary/AOB view-editor-save ----
    if (opt.hex) {
        return RunHexMode(opt);
    }

    // ---- serve mode: online dosya yukleme (tarayici -> http://127.0.0.1:<port>) ----
    if (opt.serve) {
        Log::Banner("DumperPro - Online Dosya Analiz Sunucusu");
        Log::Info("Adres     : http://127.0.0.1:%u  (Ctrl+C ile kapatilir)", opt.servePort);
        Log::Info("Raporlar  : DumperPro_Out/serve/");
        Log::Info("Formatlar : exe / dll / sys / apk / so / dex / zip / metadata / vdex / oat");
        HttpServer srv(opt.servePort);
        srv.Run();
        FailWithHint("server stopped: " + srv.LastError(), "port kullanimda olabilir; --serve 8421 gibi baska bir port deneyin");
        return 0;
    }

    auto t0 = std::chrono::steady_clock::now();

    // ---- config ----
    Config cfg;
    cfg.LoadIni(opt.iniPath);

    // ---- IL2CPP cift modu: --file <so/dll> --metadata global-metadata.dat ----
    if (!opt.file.empty() && !opt.metadata.empty()) {
        const std::string gname = opt.file.stem().string();
        return RunIl2CppPairMode(opt, gname);
    }

    // ---- reader ----
    std::unique_ptr<IMemoryReader> reader;
    std::string gameName;

    if (!opt.file.empty()) {
        gameName = opt.file.stem().string();

        // PE olmayan dosyalar (apk/zip/so/dex) dogrudan statik analiz hattina girer
        if (!SniffIsPe(opt.file)) {
            Log::Info("Non-PE file: static analysis mode (apk/zip/elf/dex)");
            return RunStaticFileMode(opt, gameName);
        }

        reader = CreateFileReader(opt.file);
        if (reader && reader->IsOK()) {
            Log::Info("File mode: %s", opt.file.string().c_str());
        }
    } else if (!opt.device.empty()) {
        // LeechCore device mode: dynamic leechcore.dll binding (docs/LEECH.md).
        reader = TryCreateLeechReader(opt.device);
        gameName = reader ? reader->TargetName() : ("device_" + str::SanitizeIdent(opt.device));
        if (reader && reader->IsOK()) {
            Log::Info("Device mode: %s (LeechCore)", reader->TargetName().c_str());
        }
    } else {
        reader = CreateProcessReader(opt.process, opt.pid, opt.kernel);
        gameName = reader ? reader->TargetName() : opt.process;
        if (reader && reader->IsOK()) {
            Log::Info("Process mode: %s (pid %u)%s", reader->TargetName().c_str(), opt.pid, opt.kernel ? " [kernel-assisted]" : "");
        }
    }

    if (!reader || !reader->IsOK()) {
        if (!opt.device.empty() && !reader) {
            // factory returns nullptr gracefully (missing dll / failed LcCreate);
            // the concrete reason was already logged by TryCreateLeechReader()
            FailWithHint("cannot open LeechCore device: " + opt.device,
                         "leechcore.dll must sit next to DumperPro.exe or in PATH (the MemProcFS "
                         "release ships it); device strings: fpga / file://dump.bin (+,write=1) / dump://x.dmp - "
                         "see docs/LEECH.md");
            return 2;
        }
        std::string le = reader ? reader->LastError() : "unknown error";
        FailWithHint("cannot open target: " + le,
            opt.file.empty()
                ? "run as Administrator, check the process name (use the exact image name), or try --kernel"
                : "make sure the file exists and is a x64 PE image (.exe/.dll)");
        return 2;
    }

    // ---- module image ----
    ModuleInfo targetMod;
    bool leechRawScan = false; // --device without module model: best-effort raw window
    {
        std::vector<ModuleInfo> mods = reader->Modules();
        if (mods.empty()) {
            if (!opt.device.empty()) {
                // LeechCore is a device-level API (raw physical memory): there is
                // no process/module model here - that layer belongs to MemProcFS
                // (vmm.dll, VMMDLL_Map_GetModule / VMMDLL_Map_GetVad). Run the UE
                // pipeline best-effort over a raw window instead (docs/LEECH.md).
                if (!opt.moduleName.empty())
                    Log::Warn("--module is ignored in LeechCore device mode (no module model)");
                Log::Warn("LeechCore device '%s' reports no modules: the UE SDK needs "
                          "MemProcFS-level module info (vmm.dll VMMDLL_*) or a raw dump + "
                          "memmap (docs/LEECH.md).", reader->TargetName().c_str());
                const u64 devMax = reader->MaxAddress();
                u64 scanSize = kDeviceScanFallback;
                if (devMax > kDeviceScanBase)
                    scanSize = std::min<u64>(devMax - kDeviceScanBase, kDeviceScanCap);
                Log::Warn("Falling back to a best-effort %s signature scan from %s "
                          "(device max=%s; GObjects/GNames candidates only; heuristic "
                          "struct scans stay disabled without a PE module image).",
                          str::HumanSize(scanSize).c_str(), Hex(kDeviceScanBase).c_str(),
                          devMax ? Hex(devMax).c_str() : "unknown");
                targetMod.name = reader->TargetName();
                targetMod.base = kDeviceScanBase; // reader rejects near-null PAs
                // kDeviceScanCap (512 MiB) u32'ye sigar - MSVC C4244 icin acik cast
                targetMod.size = (u32)scanSize;
                leechRawScan = true;
            } else {
                FailWithHint("no modules found in target", "target may be protected; try --kernel or file mode");
                return 3;
            }
        } else if (opt.moduleName.empty()) {
            targetMod = mods.front();
        } else {
            for (const ModuleInfo& m : mods) {
                if (str::Contains(str::Lower(m.name), str::Lower(opt.moduleName))) { targetMod = m; break; }
            }
            if (!targetMod.base) {
                FailWithHint("module not found: " + opt.moduleName, "list modules with --verbose");
                return 3;
            }
        }
    }

    ModuleImage mod;
    {
        if (leechRawScan) {
            // raw device window: chunked read with zero-filled holes and NO PE
            // parse (physical memory at the window base is not a guaranteed PE)
            mod.Name = targetMod.name;
            mod.Base = targetMod.base;
            mod.Data.assign(targetMod.size, 0);
            constexpr u64 kChunk = 1ull << 20; // 1 MB, same as ModuleImage::LoadFromReader
            const u64 totalChunks = (targetMod.size + kChunk - 1) / kChunk;
            Progress p("Device", totalChunks);
            u64 holes = 0;
            for (u64 done = 0; done < targetMod.size; done += kChunk) {
                const u64 take = std::min<u64>(kChunk, targetMod.size - done);
                if (!reader->Read(targetMod.base + done, mod.Data.data() + done, (size_t)take)) {
                    holes++;
                    // keep the zero fill for the missing chunk, continue best-effort
                }
                p.Add();
                if (take < kChunk) break;
            }
            p.Done(str::HumanSize(mod.Data.size()));
            if (holes)
                Log::Warn("device scan: %llu/%llu chunks unreadable (left zero-filled)",
                          (unsigned long long)holes, (unsigned long long)totalChunks);
            mod.pe.reset(); // raw physical memory: no PE mapping guarantees
        } else {
            Progress p("Module", 1);
            if (!mod.LoadFromReader(*reader, targetMod)) {
                FailWithHint("cannot read module image: " + targetMod.name, "try --kernel or file mode with the on-disk binary");
                return 3;
            }
            p.Add();
            p.Done(str::HumanSize(mod.Data.size()));
        }
    }
    if (leechRawScan) {
        Log::Info("Device window: %s base=0x%llX size=%s", mod.Name.c_str(),
                  (unsigned long long)mod.Base, str::HumanSize(mod.Data.size()).c_str());
    } else {
        Log::Info("Module: %s base=0x%llX size=%s", mod.Name.c_str(),
                  (unsigned long long)mod.Base, str::HumanSize(mod.Data.size()).c_str());
    }

    // ---- version ----
    UEVersion ver;
    if (!VersionDetector::Detect(mod, ver)) {
        ver = UEVersion{0, 0};
        Log::Warn("UE version not detected from image strings");
    } else {
        Log::Ok("Detected UE version: %s (%s mode)", ver.Str().c_str(), ver.IsUE5() ? "UE5" : "UE4");
    }

    // ---- profile (ini -> builtin) ----
    UEOffsets off;
    GameProfile profile;
    std::string profileSrc = "defaults";
    off.SetDefaultsFor(ver);

    if (cfg.FindProfile(gameName, profile)) {
        off = profile.offsets;
        profileSrc = "games.ini [" + profile.name + "]";
    } else if (const GameProfile* bp = Config::BuiltinForVersion(ver)) {
        off = bp->offsets;
        profileSrc = "builtin [" + bp->name + "]";
    }
    cfg.ApplyIniToOffsets(gameName, off); // dotted keys directly on game section also apply
    Log::Info("Offsets profile: %s", profileSrc.c_str());

    UEContext ctx;
    ctx.reader = reader.get();
    ctx.mod = &mod;
    ctx.ver = ver;
    ctx.off = off;

    // ---- output dir ----
    fs::path outDir = opt.outDir.empty() ? fs::path("DumperPro_Out") / (str::SanitizeIdent(gameName) + "_" + TimeStampDir())
                                         : opt.outDir;
    std::error_code ec;
    fs::create_directories(outDir, ec);
    Log::Info("Output: %s", outDir.string().c_str());

    // ---- GNames ----
    NameArray names;
    ctx.names = &names;
    SigFinder sigFinder(*reader, mod, ctx.off, ver, nullptr, cfg);
    {
        Log::Info("Searching GNames...");
        std::string via;
        u64 va = sigFinder.FindGNames(&via);
        if (!va) {
            FailWithHint("GNames not found",
                "add to games.ini:  [" + gameName + "]\n  gnames = 0x<address>\nor a gnames_pattern = 48 8D 35 ... line");
            return 4;
        }
        Log::Ok("GNames @ 0x%llX (via %s)", (unsigned long long)va, via.c_str());
        std::string perr;
        if (!names.TryInit(*reader, ctx.off, ver, &perr)) {
            FailWithHint("GNames parse failed: " + perr,
                "if the game uses a custom name pool, add pool offsets to games.ini");
            return 4;
        }
        Log::Ok("Names parsed: %llu entries (%s)", (unsigned long long)names.Num(), names.ModeInfo().c_str());
    }

    // ---- GObjects ----
    // Partial-output path (1b lesson, real UE5.1 shipping binary): a COLD
    // module image (static file / module dump) cannot contain runtime GObjects
    // heap state - the array numbers are zero on disk. GNames, however, often
    // IS present (populated pool data). So when GObjects fails AFTER names
    // parsed, still write Names.txt + signature files instead of exiting with
    // nothing.
    auto writeNamesOnly = [&](const char* why) {
        Log::Warn("%s", why);
        DumpNames(ctx, outDir / "Names.txt");
        if (opt.json) DumpNamesJson(ctx, outDir / "names.json");
        WriteSignatureFiles(gameName, sigFinder, ver, outDir);
        Log::Ok("Partial output written: %s (Names.txt)", outDir.string().c_str());
        Log::Warn("Full SDK needs runtime GObjects: re-run against the live process "
                  "(--process/--pid) or a full memory dump (--device \"file://ram.bin\")");
    };
    ObjectArray objects;
    ctx.objects = &objects;
    SigFinder sigFinder2(*reader, mod, ctx.off, ver, &names, cfg);
    {
        Log::Info("Searching GObjects...");
        std::string via;
        u64 va = sigFinder2.FindGObjects(&via);
        if (!va) {
            writeNamesOnly("GObjects: no valid candidate (sigs + struct scan failed; "
                           "cold module image has no runtime array state)");
            FailWithHint("GObjects not found",
                "add to games.ini:  [" + gameName + "]\n  gobjects = 0x<address>\nor a gobjects_pattern = 48 8B 05 ... line");
            return 5;
        }
        Log::Ok("GObjects @ 0x%llX (via %s)", (unsigned long long)va, via.c_str());
        std::string perr;
        if (!objects.TryInit(*reader, ctx.off, ver, &names, &perr)) {
            writeNamesOnly("GObjects parse failed - writing partial GNames output");
            FailWithHint("GObjects parse failed: " + perr,
                "try adding array.item_stride=0x18 / array.chunk_size=0x10000 (UE4: 0x2800) to games.ini");
            return 5;
        }
        Log::Ok("Objects parsed: %llu entries (%s)", (unsigned long long)objects.Num(), objects.LayoutInfo().c_str());
    }

    // ---- GWorld (optional) ----
    {
        std::string via;
        u64 gw = sigFinder2.FindGWorld(&via);
        if (gw) Log::Ok("GWorld @ 0x%llX (via %s)", (unsigned long long)gw, via.c_str());
    }

    // ---- offset probing ----
    {
        Log::Info("Probing runtime offsets (max %d objects)...", opt.probeCount);
        OffsetProbe probe(ctx);
        ProbeResult pr = probe.Run(opt.probeCount);
        for (const std::string& w : pr.warnings) Log::Warn("%s", w.c_str());
        if (pr.applied || pr.confirmed) {
            Log::Ok("Offsets: %d auto-detected, %d confirmed by probe (%d sampled)",
                    pr.applied, pr.confirmed, pr.probed);
        }
        probe.WriteOffsetsTxt(outDir / "offsets.txt");
        Log::Ok("offsets.txt written");
    }

    // ---- names / objects dumps ----
    DumpNames(ctx, outDir / "Names.txt");
    DumpObjects(ctx, outDir / "Objects.txt");
    if (opt.json) {
        DumpNamesJson(ctx, outDir / "names.json");
        DumpObjectsJson(ctx, outDir / "objects.json");
    }

    // ---- vtable resolution ----
    std::map<std::string, VTResult> vtMap;
    std::vector<VTResult> vtList;
    if (!opt.noSdk || true) {
        Log::Info("Resolving tracked virtual functions...");
        VTableResolver vt(ctx);
        vt.minIndexSlot = cfg.KeyInt(gameName, "vtable.minindex", 8);

        VTResult pe = vt.ResolveProcessEvent();
        pe.note = "ProcessEvent (UObject)";
        vtList.push_back(pe);

        VTResult pr2 = vt.ResolvePostRender();
        pr2.note = "PostRender (UGameViewportClient)";
        vtList.push_back(pr2);

        VTResult prf = vt.ResolveProcessRemoteFunction();
        prf.note = "ProcessRemoteFunction (UNetDriver)";
        vtList.push_back(prf);

        for (const VTResult& r : vtList) vtMap[r.note.substr(0, r.note.find(' '))] = r;

        for (const VTResult& r : vtList) {
            if (r.found) {
                Log::Ok("%s: slot 0x%X [vtable>%s] RVA 0x%llX", r.note.c_str(), r.slot, r.via.c_str(),
                        (unsigned long long)r.rva);
            } else {
                Log::Warn("%s: not found in vtable (fingerprints may need tuning)", r.note.c_str());
            }
        }
        WriteVTableFuncsTxt(outDir, vtList);
    }

    // ---- SDK ----
    if (!opt.noSdk) {
        SDKOptions so;
        so.outDir = outDir / "SDK";
        so.vtResults = &vtMap;
        SDKGenerator gen(ctx, so);
        if (!gen.Generate()) {
            FailWithHint("SDK generation failed", "check --verbose output; dumps are still valid");
        }
    }

    // ---- signature files ----
    WriteSignatureFiles(gameName, sigFinder2, ver, outDir);

    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    char doneBuf[512];
    snprintf(doneBuf, sizeof(doneBuf), "Done in %.1fs -> %s", secs, outDir.string().c_str());
    Log::Banner(doneBuf);
    return 0;
}
