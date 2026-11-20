// ============================================================================
//  UnrealDumperX - main.cpp
//  Pipeline orchestration (7 stages, each with its own progress UX):
//
//    [1/7] GObjects / GNames resolution  (finder: ini -> patterns -> anchors)
//    [2/7] FName pool load               (UE5 FNamePool / UE4 arrays)
//    [3/7] Runtime offset discovery      (<=400 object vote, 65% threshold)
//    [4/7] GWorld resolution             (needs the name pool)
//    [5/7] Names.txt + Objects.txt
//    [6/7] SDK generation                (_classes.h / _struct.h per package)
//    [7/7] VTable resolver + signature archive + games.ini update
//
//  Usage:
//    UnrealDumperX.exe --list
//    UnrealDumperX.exe --process Game-Win64-Shipping.exe
//    UnrealDumperX.exe --pid 1234 --out dump --ini games.ini --verbose
//    UnrealDumperX.exe --process Game.exe --driver-load C:\udx\UnrealDumperX.sys
//    UnrealDumperX.exe --process Game.exe --no-sdk --names-only
// ============================================================================
#include "common.h"
#include "log.h"
#include "process.h"
#include "driver.h"
#include "pattern.h"
#include "version.h"
#include "ue_types.h"
#include "fname.h"
#include "finder.h"
#include "classparse.h"
#include "sdkgen.h"
#include "vtable.h"
#include "outputs.h"
#include "ini.h"

#include <chrono>

using namespace udx;

struct Args {
    bool list = false;
    bool verbose = false;
    bool noSdk = false;
    bool noVtable = false;
    bool namesOnly = false;
    bool driverConnect = false;
    std::wstring driverSys;             // --driver-load path
    std::string processName;            // --process
    DWORD pid = 0;                      // --pid
    std::string outDir = "dump_out";
    std::string iniPath = "games.ini";
};

static Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto next = [&]() -> std::string {
            return (i + 1 < argc) ? argv[++i] : "";
        };
        if (arg == "--list") a.list = true;
        else if (arg == "--verbose" || arg == "-v") a.verbose = true;
        else if (arg == "--no-sdk") a.noSdk = true;
        else if (arg == "--no-vtable") a.noVtable = true;
        else if (arg == "--names-only") a.namesOnly = true;
        else if (arg == "--driver") a.driverConnect = true;
        else if (arg == "--driver-load") {
            const std::string v = next();
            a.driverSys = std::wstring(v.begin(), v.end());
        }
        else if (arg == "--process") a.processName = next();
        else if (arg == "--pid") a.pid = (DWORD)atoi(next().c_str());
        else if (arg == "--out") a.outDir = next();
        else if (arg == "--ini") a.iniPath = next();
        else if (arg == "--help" || arg == "-h") {
            std::printf(
                "UnrealDumperX v%s\n"
                "  --process <exe>      attach by executable name\n"
                "  --pid <n>            attach by pid\n"
                "  --list               list running processes\n"
                "  --out <dir>          output directory (default dump_out)\n"
                "  --ini <path>         games.ini path (default games.ini)\n"
                "  --driver             connect to kernel driver bridge\n"
                "  --driver-load <sys>  load + connect (admin, testsigning)\n"
                "  --names-only         Names.txt/Objects.txt only\n"
                "  --no-sdk             skip SDK generation\n"
                "  --no-vtable          skip vtable/function tracking\n"
                "  --verbose            verbose logging\n",
                UDX_VERSION_STRING);
            exit(0);
        }
    }
    return a;
}

int main(int argc, char** argv) {
    const Args args = parseArgs(argc, argv);
    log::setVerbose(args.verbose);
    log::banner();

    // ---- --list --------------------------------------------------------------
    if (args.list) {
        for (const auto& p : listProcesses())
            std::printf("%8lu  %s\n", (unsigned long)p.pid, p.name.c_str());
        return 0;
    }

    const u64 started = GetTickCount64();

    // ---- attach --------------------------------------------------------------
    log::section("[0/7] Surec baglantisi");
    Process proc;
    if (args.pid)
        proc.attachById(args.pid);
    else if (!args.processName.empty())
        proc.attachByName(args.processName);
    else {
        log::error("Hedef belirtilmedi: --process <exe> veya --pid <n> kullanin");
        return 1;
    }
    if (!proc.valid()) {
        log::error("Surece baglanilamadi (yonsuz olarak yonetici mi calistiriyorsun?)");
        return 1;
    }
    log::ok(fmt("Baglanildi: %s (pid %lu)", proc.exeName().c_str(),
                (unsigned long)proc.pid()));

    // ---- optional kernel driver ----------------------------------------------
    Driver driver;
    if (args.driverConnect || !args.driverSys.empty()) {
        if (driver.connectOrLoad(args.driverSys)) {
            proc.setDriver(&driver);
            log::ok("Kernel driver koprusu aktif");
        } else {
            log::warn("Driver baglanamadi - ReadProcessMemory ile devam");
        }
    }

    // ---- configuration -------------------------------------------------------
    Ini ini;
    if (ini.load(args.iniPath))
        log::ok(fmt("games.ini yuklendi (%s) - yetkili degerler korunur",
                    args.iniPath.c_str()));
    else
        log::info("games.ini yok - ilk calistirma, tarama otomatik yapilacak");

    const std::string gameName =
        std::filesystem::path(proc.exeName()).stem().string();

    // ---- [1/7] core addresses -------------------------------------------------
    log::section("[1/7] Cekirdek adresleri (GObjects / GNames)");
    ue::Offsets off;
    off.applyIni(ini);

    std::string verMethod;
    UEVersion ver = ue::versionFromIniValue(
        ini.get("Engine", "Version", "Auto")).value_or(
        ue::detectVersion(proc, *proc.mainModule(), &verMethod));
    log::ok(fmt("S surumu: %s (%s)", ue::versionToString(ver),
                ver == ue::UEVersion::Unknown ? "otomatik kalibrasyon"
                                              : verMethod.c_str()));

    std::vector<ue::SigRecord> sigs;
    ue::FinderResult found = ue::findCoreAddresses(proc, off, ini, ver, sigs);
    if (!found.gObjects) {
        log::error("GObjects olmadan dump yapilamaz - games.ini'ye sig ekleyin");
        return 2;
    }

    // ---- [2/7] FName pool -------------------------------------------------------
    log::section("[2/7] FName havuzu");
    ue::NameDb names;
    if (!names.init(proc, off, ver, ini)) {
        log::error("FName havuzu okunamadi - NameStride/NameLenShift'i games.ini'ye sabitleyin");
        return 3;
    }

    // ---- [3/7] runtime offsets -------------------------------------------------
    log::section("[3/7] Calisma zaman offset kesifi");
    ue::discoverRuntimeOffsets(proc, off, ini, ver, names);
    log::info(off.describe());

    // ---- [4/7] GWorld ----------------------------------------------------------
    log::section("[4/7] GWorld");
    ue::findGWorld(proc, off, ver, names, sigs);

    // ---- [5/7] Names + Objects -------------------------------------------------
    log::section("[5/7] Names.txt / Objects.txt");
    ue::ObjectDb objects;
    if (!objects.init(proc, off)) {
        log::error("Nesne dizisi baslatilamadi");
        return 4;
    }
    ensureDir(args.outDir);
    out::writeNamesTxt(args.outDir + "/Names.txt", names);
    if (args.namesOnly) {
        out::writeObjectsTxt(args.outDir + "/Objects.txt", proc, off, objects, names);
        log::ok("names-only modu tamamlandi");
        return 0;
    }
    out::writeObjectsTxt(args.outDir + "/Objects.txt", proc, off, objects, names);

    // ---- [6/7] SDK ---------------------------------------------------------------
    log::section("[6/7] SDK uretimi");
    sdk::SdkOptions sdkOpts;
    sdkOpts.outDir = args.outDir;
    sdkOpts.gameName = gameName;
    sdkOpts.version = ue::versionToString(ver);
    sdkOpts.eventThunks = !args.noSdk;   // thunks follow the --no-sdk switch too
    if (!args.noSdk) {
        ue::ClassParser parser(proc, off, names, objects);
        // ProcessEvent slot lands in stage 7; re-running the tool once refreshes
        // Basic.h with the discovered vtable index.
        sdk::SdkGenerator gen(proc, off, names, objects, parser, sdkOpts);
        gen.generate();
    } else {
        log::info("--no-sdk: SDK uretimi atlandi");
    }

    // ---- [7/7] vtable + signatures + ini ----------------------------------------
    log::section("[7/7] VTable / imzalar / games.ini");
    Ini saveIni;
    saveIni.load(args.iniPath);
    std::vector<vt::ResolvedFunc> funcs;
    int peIndex = -1;
    if (!args.noVtable) {
        ue::ClassParser parser(proc, off, names, objects);
        vt::VTableResolver resolver(proc, off, names, objects, saveIni);
        funcs = resolver.resolveAll();
        peIndex = resolver.processEventIndex();
        resolver.dumpVtables(args.outDir + "/vtable_funcs.txt");
    }

    out::writeOffsetsTxt(args.outDir + "/offsets.txt", off, ver, gameName,
                         "auto");
    out::writeSignaturesTxt(args.outDir + "/signatures.txt", sigs,
                            "signatures.txt", &funcs);
    out::writeSignaturesTxt(args.outDir + "/" + gameName + "_sigs.txt", sigs,
                            gameName + "_sigs.txt", &funcs);

    // Persist signatures + resolved layout for the NEXT run. games.ini keeps
    // its authoritative lines; only missing keys get added (NOTE #6).
    for (const auto& s : sigs) {
        if (s.mainSig.empty()) continue;
        const std::string key = s.name;
        if (!saveIni.has("Signatures", key))
            saveIni.set("Signatures", key, s.mainSig + " | " + s.extSig);
    }
    off.saveMissingToIni(saveIni);
    if (!saveIni.has("Game", "Name")) saveIni.set("Game", "Name", gameName);
    if (!saveIni.has("Engine", "Version"))
        saveIni.set("Engine", "Version", ue::versionToString(ver));
    saveIni.setU64("Resolved", "GObjects", off.gObjects);
    saveIni.setU64("Resolved", "GNames", off.gNames);
    saveIni.setU64("Resolved", "GWorld", off.gWorld);
    saveIni.set("Resolved", "NumElements", std::to_string(objects.count()));
    saveIni.set("Resolved", "DumpedAt", timestamp());
    saveIni.save(args.iniPath);
    log::ok(fmt("games.ini guncellendi (yetkili satirlar korundu): %s",
                args.iniPath.c_str()));

    // ---- summary -----------------------------------------------------------------
    const u64 elapsed = GetTickCount64() - started;
    log::section("Ozet");
    std::printf("  Surec          : %s (pid %lu)\n", proc.exeName().c_str(),
                (unsigned long)proc.pid());
    std::printf("  Engine         : %s\n", ue::versionToString(ver));
    std::printf("  GObjects       : %s\n", toHex(off.gObjects).c_str());
    std::printf("  GNames         : %s\n", toHex(off.gNames).c_str());
    std::printf("  GWorld         : %s\n",
                off.gWorld ? toHex(off.gWorld).c_str() : "bulunamadi");
    std::printf("  Nesneler       : %d\n", objects.count());
    std::printf("  Isimler        : %zu\n", names.count());
    std::printf("  Takip edilen f : %zu / 3\n", funcs.size());
    std::printf("  Cikti klasoru  : %s\n", args.outDir.c_str());
    std::printf("  Sure           : %.1f sn\n", elapsed / 1000.0);
    log::ok("Dump tamamlandi");
    return 0;
}
