// ============================================================================
//  UnrealDumperX - vtable.cpp
// ============================================================================
#include "vtable.h"
#include "log.h"

namespace udx::vt {

using namespace udx;

// ---------------------------------------------------------------------------
// Prologue fingerprint databases (NOTE #8: max 4 candidates per target)
// ---------------------------------------------------------------------------
static const char* kProcessEventFingerprints[kMaxFingerprints] = {
    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4",
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 81 EC ?? ?? ?? ?? 48 8B 01 48 8B D9",
    "4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 41 54 41 55 41 56 41 57 48 81 EC",
    "48 8B C4 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 ??",
};

static const char* kPostRenderFingerprints[kMaxFingerprints] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B 01",
    "40 53 48 83 EC ?? 48 8B D9 48 8B 49 ?? 48 85 C9",
    "48 83 EC ?? 48 8B 01 FF 50 ?? 48 85 C0",
    "40 55 53 56 57 48 8B EC 48 83 EC ?? 48 8B 41",
};

static const char* kProcessRemoteFunctionFingerprints[kMaxFingerprints] = {
    "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC",
    "40 53 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8B D9",
    "4C 8B DC 55 56 57 41 54 41 55 41 56 41 57 49 89 5B ?? 49 89 6B",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 41 56 48 81 EC",
};

// Pattern-seeded fallbacks (NOTE #9) - used when fingerprint scans fail.
static const char* kProcessEventPatternSeeds[kMaxFingerprints] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B 89 ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 50",
    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 41 10",
    "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 48 81 EC ?? ?? ?? ?? 48 8B 41 10 48 8B F9",
    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 4D 8B F1 4C 8B FA",
};

VTableResolver::VTableResolver(Process& proc, ue::Offsets& off,
                               ue::NameDb& names, ue::ObjectDb& objects,
                               const Ini& ini)
    : proc_(proc), off_(off), names_(names), objects_(objects), ini_(ini) {}

// ---------------------------------------------------------------------------
// IMPORTANT NOTE #10: thunk / adjustor unchaining
// ---------------------------------------------------------------------------
uintptr_t VTableResolver::unchain(uintptr_t a, int depth, std::string* note) {
    if (!a || depth >= kMaxThunkDepth) return a;

    u8 b[32] = {};
    if (!proc_.read(a, b, sizeof(b))) return a;

    // JMP rel8  : EB xx
    if (b[0] == 0xEB) {
        const i8 rel = (i8)b[1];
        return unchain(a + 2 + (i64)rel, depth + 1, note);
    }
    // JMP rel32 : E9 xx xx xx xx
    if (b[0] == 0xE9) {
        i32 rel = 0;
        std::memcpy(&rel, b + 1, 4);
        return unchain(a + 5 + (i64)rel, depth + 1, note);
    }
    // Adjustor thunks: SUB/ADD RCX, imm8/imm32
    //   48 83 E9 imm8 | 48 81 E9 imm32 | 48 83 C1 imm8 | 48 81 C1 imm32
    if (b[0] == 0x48 && (b[1] == 0x83 || b[1] == 0x81) &&
        (b[2] == 0xE9 || b[2] == 0xC1)) {
        const int len = (b[1] == 0x83) ? 4 : 7;
        if (note) *note = "adjustor thunk (SUB/ADD RCX)";
        return unchain(a + (usize)len, depth + 1, note);
    }
    // JMP [RIP+rel32] import stub : FF 25 disp32
    if (b[0] == 0xFF && b[1] == 0x25) {
        i32 rel = 0;
        std::memcpy(&rel, b + 2, 4);
        const u64 iat = a + 6 + (i64)rel;
        const u64 fn = proc_.read<u64>(iat);
        if (fn) {
            if (const auto m = proc_.moduleContaining(iat)) {
                const std::string imp = lookupImportName(proc_, *m, iat);
                if (note && !imp.empty()) *note = "import " + imp;
            }
            return fn;
        }
        return a;
    }
    // Common MSVC prologue thunk (saves registers, then JMP rel32 nearby).
    if (b[0] == 0x48 && (b[1] == 0x89 || b[1] == 0x8B)) {
        for (int i = 3; i + 5 <= (int)sizeof(b); ++i) {
            if (b[i] == 0xE9 && b[i - 1] != 0x0F) {
                i32 rel = 0;
                std::memcpy(&rel, b + i + 1, 4);
                return unchain(a + (usize)i + 5 + (i64)rel, depth + 1, note);
            }
        }
    }
    return a;
}

// ---------------------------------------------------------------------------
// Vtable collection: find live instances of a class by its FName
// ---------------------------------------------------------------------------
std::vector<u64> VTableResolver::collectVtables(const std::string& classFName,
                                                usize maxInstances) {
    std::vector<u64> out;
    if (classFName.empty()) return out;
    const i32 num = objects_.count();
    const std::string want = lower(classFName);
    for (i32 i = 0; i < num && out.size() < maxInstances; ++i) {
        const u64 obj = objects_.objectAt(i);
        if (!obj) continue;
        const u64 cls = proc_.read<u64>(obj + off_.uobjClass);
        if (!cls) continue;
        const std::string cn = names_.get(proc_.read<u32>(cls + off_.uobjName));
        if (lower(cn) != want) continue;
        const u64 vft = proc_.read<u64>(obj);
        if (vft && proc_.ptrReadable(vft)) out.push_back(vft);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Slot scan with fingerprints
// ---------------------------------------------------------------------------
int VTableResolver::scanSlots(u64 vtable, const std::vector<Pattern>& fps,
                              int maxSlot, usize* votesOut) {
    for (int slot = kMinVtableIndex; slot < maxSlot; ++slot) {   // NOTE #4
        const u64 fn = proc_.read<u64>(vtable + (u64)slot * 8);
        if (!fn || !proc_.ptrReadable(fn)) continue;
        u8 code[0x100] = {};
        if (!proc_.read(fn, code, sizeof(code))) continue;

        for (usize fi = 0; fi < fps.size() && fi < kMaxFingerprints; ++fi) {
            const Pattern& p = fps[fi];
            for (usize i = 0; i + p.length() <= sizeof(code); ++i) {
                bool ok = true;
                for (usize k = 0; k < p.length() && ok; ++k)
                    if (p.mask[k] && code[i + k] != p.bytes[k]) ok = false;
                if (ok) {
                    if (votesOut) *votesOut = fi;
                    return slot;
                }
            }
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Ini-backed resolution ([Signatures] / [VTable] sections)
// ---------------------------------------------------------------------------
std::optional<ResolvedFunc> VTableResolver::resolveByIni(
    const std::string& targetName) {
    if (!ini_.has("Signatures", targetName)) return std::nullopt;
    const std::string pair = ini_.get("Signatures", targetName);
    const usize bar = pair.find('|');
    const std::string main = bar == std::string::npos ? pair : pair.substr(0, bar);
    const std::string ext = bar == std::string::npos ? "" : pair.substr(bar + 1);

    const ModuleInfo* mainMod = proc_.mainModule();
    if (!mainMod) return std::nullopt;
    const u64 hit = resolveSignaturePair(proc_, *mainMod, trim(main), trim(ext));
    if (!hit) return std::nullopt;

    ResolvedFunc r;
    r.name = targetName;
    r.address = unchain(hit, 0, &r.note);
    r.source = "pattern";
    if (const auto m = proc_.moduleContaining(r.address)) r.module = m->name;
    return r;
}

// ---------------------------------------------------------------------------
// Fingerprint + voting resolution (NOTE #8 / #10 / #11)
// ---------------------------------------------------------------------------
std::optional<ResolvedFunc> VTableResolver::resolveByFingerprints(
    const std::string& targetName, const std::vector<std::string>& fingerprints,
    const std::vector<u64>& vtables, const std::string& iniSlotKey) {

    // games.ini pinned slot -> [vtable] tag.
    if (!iniSlotKey.empty() && ini_.has("VTable", iniSlotKey)) {
        const int slot = ini_.getI32("VTable", iniSlotKey, -1);
        if (slot >= kMinVtableIndex && !vtables.empty()) {
            const u64 fn = proc_.read<u64>(vtables[0] + (u64)slot * 8);
            if (fn) {
                ResolvedFunc r;
                r.name = targetName;
                r.address = unchain(fn, 0, &r.note);
                r.vtableIndex = slot;
                r.source = "vtable";
                if (const auto m = proc_.moduleContaining(r.address))
                    r.module = m->name;
                return r;
            }
        }
    }

    std::vector<Pattern> fps;
    for (usize i = 0; i < fingerprints.size() && i < kMaxFingerprints; ++i)
        fps.push_back(parseIda(fingerprints[i]));

    // IMPORTANT NOTE #11: post-thunk voting across independent vtables.
    std::map<int, std::map<u64, usize>> slotVotes;
    for (const u64 vft : vtables) {
        const int slot = scanSlots(vft, fps, 0x60);
        if (slot < 0) continue;
        const u64 fn = proc_.read<u64>(vft + (u64)slot * 8);
        const u64 finalAddr = unchain(fn);
        ++slotVotes[slot][finalAddr];
    }
    int bestSlot = -1;
    u64 bestAddr = 0;
    usize bestVotes = 0;
    for (const auto& [slot, addrVotes] : slotVotes) {
        for (const auto& [addr, votes] : addrVotes) {
            if (votes > bestVotes) {
                bestVotes = votes;
                bestAddr = addr;
                bestSlot = slot;
            }
        }
    }
    if (bestSlot < 0 || bestVotes == 0) return std::nullopt;

    ResolvedFunc r;
    r.name = targetName;
    r.address = bestAddr;
    r.vtableIndex = bestSlot;
    r.source = "vtable>pattern";
    if (const auto m = proc_.moduleContaining(bestAddr)) r.module = m->name;
    return r;
}

// ---------------------------------------------------------------------------
// Pattern-seeded fallback (NOTE #9)
// ---------------------------------------------------------------------------
std::optional<ResolvedFunc> VTableResolver::resolveByPatternSeed(
    const std::string& targetName, const std::vector<std::string>& patterns) {
    const ModuleInfo* main = proc_.mainModule();
    if (!main) return std::nullopt;
    for (usize i = 0; i < patterns.size() && i < kMaxFingerprints; ++i) {
        const Pattern p = parseIda(patterns[i]);
        if (p.empty()) continue;
        for (const u64 hit : scanModuleAll(proc_, *main, p, 16)) {
            ResolvedFunc r;
            r.name = targetName;
            r.address = unchain(hit, 0, &r.note);
            r.source = "pattern";
            if (const auto m = proc_.moduleContaining(r.address))
                r.module = m->name;
            return r;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// All targets
// ---------------------------------------------------------------------------
std::vector<ResolvedFunc> VTableResolver::resolveAll() {
    std::vector<ResolvedFunc> out;

    const auto emit = [&](ResolvedFunc r) {
        std::string line = fmt("[%s] %s @ 0x%llX", r.source.c_str(), r.name.c_str(),
                               (unsigned long long)r.address);
        if (r.vtableIndex >= 0) line += fmt(" (vtable slot %d)", r.vtableIndex);
        if (!r.module.empty()) line += fmt(" [%s]", r.module.c_str());
        if (!r.note.empty()) line += " {" + r.note + "}";
        log::ok(line);
        out.push_back(std::move(r));
    };
    const auto miss = [&](const char* n) {
        log::warn(fmt("%s cozumlenemedi", n));
        ResolvedFunc r;
        r.name = n;
        r.source = "unresolved";
        out.push_back(std::move(r));
    };

    // ---- UObject::ProcessEvent - present in every UObject vtable ------------
    {
        std::vector<u64> vtables;
        for (const u64 obj : objects_.sample(16)) {
            const u64 vft = proc_.read<u64>(obj);
            if (vft && proc_.ptrReadable(vft)) vtables.push_back(vft);
        }
        std::vector<std::string> fps(kProcessEventFingerprints,
                                     kProcessEventFingerprints + kMaxFingerprints);
        auto r = resolveByFingerprints("UObject::ProcessEvent", fps, vtables,
                                       "ProcessEventIndex");
        if (!r)
            r = resolveByPatternSeed("UObject::ProcessEvent",
                                     {kProcessEventPatternSeeds[0],
                                      kProcessEventPatternSeeds[1],
                                      kProcessEventPatternSeeds[2],
                                      kProcessEventPatternSeeds[3]});
        if (r) {
            peIndex_ = r->vtableIndex;
            emit(std::move(*r));
        } else
            miss("UObject::ProcessEvent");
    }

    // ---- UGameViewportClient::PostRender ------------------------------------
    {
        const std::vector<u64> vtables = collectVtables("GameViewportClient", 4);
        if (!vtables.empty()) {
            std::vector<std::string> fps(kPostRenderFingerprints,
                                         kPostRenderFingerprints + kMaxFingerprints);
            auto r = resolveByFingerprints("UGameViewportClient::PostRender", fps,
                                           vtables, "PostRenderIndex");
            if (r) emit(std::move(*r));
            else miss("UGameViewportClient::PostRender");
        } else {
            miss("UGameViewportClient::PostRender");
        }
    }

    // ---- UNetDriver::ProcessRemoteFunction ----------------------------------
    {
        std::vector<u64> vtables = collectVtables("NetDriver", 4);
        if (vtables.empty()) vtables = collectVtables("GameNetDriver", 4);
        if (!vtables.empty()) {
            std::vector<std::string> fps(
                kProcessRemoteFunctionFingerprints,
                kProcessRemoteFunctionFingerprints + kMaxFingerprints);
            auto r = resolveByFingerprints("UNetDriver::ProcessRemoteFunction",
                                           fps, vtables, "ProcessRemoteFunctionIndex");
            if (r) emit(std::move(*r));
            else miss("UNetDriver::ProcessRemoteFunction");
        } else {
            miss("UNetDriver::ProcessRemoteFunction");
        }
    }

    return out;
}

// ---------------------------------------------------------------------------
// vtable_funcs.txt dump
// ---------------------------------------------------------------------------
bool VTableResolver::dumpVtables(const std::string& path, usize maxSlots) {
    std::string o;
    o += fmt("; vtable_funcs.txt - generated by UnrealDumperX %s\n",
             UDX_VERSION_STRING);
    o += fmt("; slot | function | final(after thunk) | module!rva\n\n", nullptr);

    std::set<u64> seenVft;
    usize dumped = 0;
    const i32 num = objects_.count();
    for (i32 i = 0; i < num && dumped < 16; ++i) {
        const u64 obj = objects_.objectAt(i);
        if (!obj) continue;
        const u64 vft = proc_.read<u64>(obj);
        if (!vft || !proc_.ptrReadable(vft) || !seenVft.insert(vft).second) continue;

        // Class name for the header.
        std::string clsName;
        const u64 cls = proc_.read<u64>(obj + off_.uobjClass);
        if (cls) clsName = names_.get(proc_.read<u32>(cls + off_.uobjName));
        if (clsName.empty()) clsName = "?";

        o += fmt("== %s vtable @ 0x%llX ==\n", clsName.c_str(),
                 (unsigned long long)vft);
        for (usize slot = 0; slot < maxSlots; ++slot) {
            const u64 fn = proc_.read<u64>(vft + slot * 8);
            if (!fn || !proc_.ptrReadable(fn)) continue;
            std::string note;
            const u64 finalAddr = unchain(fn, 0, &note);
            std::string mod;
            if (const auto m = proc_.moduleContaining(finalAddr))
                mod = fmt("%s!0x%llX", m->name.c_str(),
                          (unsigned long long)(finalAddr - m->base));
            o += fmt("[%04zu] 0x%016llX -> 0x%016llX  %s%s\n", slot,
                     (unsigned long long)fn, (unsigned long long)finalAddr,
                     mod.c_str(), note.empty() ? "" : ("  {" + note + "}").c_str());
        }
        o += "\n";
        ++dumped;
    }
    return writeTextFile(path, o);
}

} // namespace udx::vt
