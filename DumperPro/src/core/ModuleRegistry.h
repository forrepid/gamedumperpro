// ============================================================================
// DumperPro - ModuleRegistry.h
//
// Engine-wide module registry (2-B): a lightweight descriptor table for every
// pluggable capability the engine ships. Used by `--modules` to print an
// aligned NAME | VERSION | DESCRIPTION table; future tooling (serve pages,
// docs generators) can reuse the same accessor.
//
// Design: explicit registration list in one function (RegisterBuiltins) -
// minimal invasiveness, deterministic order, no macro/static-init magic.
// New modules add ONE entry there (see docs/modules.md "yeni modul ekleme").
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {

struct EngineModule {
    const char* name;          // short id ("core", "binfold", ...)
    const char* version;       // semver string
    const char* description;   // one-line summary (kept short for the table)
};

class ModuleRegistry {
public:
    // Append a module (idempotent per name: re-registering replaces the entry).
    static void Register(const EngineModule& m);

    // Register all engine-bundled modules exactly once (called lazily by
    // Modules(); safe to call again).
    static void RegisterBuiltins();

    // Registered modules in registration order (built-ins auto-registered).
    static const std::vector<EngineModule>& Modules();

    // Aligned table "NAME  VERSION  DESCRIPTION" (no ANSI colors, LF endings).
    static std::string BuildTable();

private:
    static std::vector<EngineModule>& Vec();
    static bool sBuiltinsDone;
};

} // namespace dumper
