// ============================================================================
// DumperPro - ModuleRegistry.cpp
// Central module table; see ModuleRegistry.h for the design notes.
// ============================================================================
#include "core/ModuleRegistry.h"

namespace dumper {

bool ModuleRegistry::sBuiltinsDone = false;

std::vector<EngineModule>& ModuleRegistry::Vec() {
    static std::vector<EngineModule> v;
    return v;
}

void ModuleRegistry::Register(const EngineModule& m) {
    // idempotent per name: replace instead of duplicate
    for (EngineModule& x : Vec()) {
        if (m.name && x.name && strcmp(x.name, m.name) == 0) {
            x = m;
            return;
        }
    }
    Vec().push_back(m);
}

void ModuleRegistry::RegisterBuiltins() {
    if (sBuiltinsDone) return;
    sBuiltinsDone = true;

    // Additive list: every engine module shows up in `--modules`.
    // Existing modules are versioned together with the engine (0.3.0);
    // standalone additions carry their own version (e.g. binfold 0.1.0).
    Register({"core",    "0.3.0", "PE parsing, masked AOB patterns, file/process/kernel memory readers"});
    Register({"sig",     "0.3.0", "GNames/GObjects/GWorld signature scan with validation"});
    Register({"ue",      "0.3.0", "UE4 4.20-4.27 / UE5 5.0-5.5 version detection + offset profiles"});
    Register({"il2cpp",  "0.3.0", "Unity IL2CPP metadata v16-31 parser, binary match, DummyDll out"});
    Register({"file",    "0.3.0", "APK/ZIP/ELF/DEX/Mach-O/OAT-VDEX static analysis pipeline"});
    Register({"dump",    "0.3.0", "SDK header/struct generation (SDKGenerator + Dumps)"});
    Register({"hex",     "0.3.0", "hex/code/binary view, AOB search, patch/undo/save (--hex)"});
    Register({"net",     "0.3.0", "--serve HTTP upload + analysis server"});
    Register({"config",  "0.3.0", "games.ini profiles + built-in offset profiles"});
    Register({"binfold", "0.1.0", "binary diff/similarity: WARP function GUIDs + constraint matching"});
}

const std::vector<EngineModule>& ModuleRegistry::Modules() {
    RegisterBuiltins();
    return Vec();
}

std::string ModuleRegistry::BuildTable() {
    const std::vector<EngineModule>& mods = Modules();
    size_t wName = 4, wVer = 7; // header widths ("NAME", "VERSION")
    for (const EngineModule& m : mods) {
        wName = std::max(wName, strlen(m.name));
        wVer  = std::max(wVer, strlen(m.version));
    }

    std::string out;
    char buf[128];
    snprintf(buf, sizeof(buf), "%-*s  %-*s  DESCRIPTION\n", (int)wName, "NAME", (int)wVer, "VERSION");
    out += buf;
    snprintf(buf, sizeof(buf), "%-*s  %-*s  %s\n", (int)wName, std::string(wName, '-').c_str(),
             (int)wVer, std::string(wVer, '-').c_str(), std::string(11, '-').c_str());
    out += buf;
    for (const EngineModule& m : mods) {
        snprintf(buf, sizeof(buf), "%-*s  %-*s  %s\n", (int)wName, m.name, (int)wVer, m.version, m.description);
        out += buf;
    }
    return out;
}

} // namespace dumper
