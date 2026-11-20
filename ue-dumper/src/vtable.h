// ============================================================================
//  UnrealDumperX - vtable.h
//  Module 6 - VTable Function Resolver.
//
//  Tracks the key runtime functions the whole ecosystem needs:
//      * UObject::ProcessEvent                  (SDK thunks + hooks)
//      * UGameViewportClient::PostRender        (render hooks)
//      * UNetDriver::ProcessRemoteFunction      (network RPC tracing)
//
//  Resolution strategy per target:
//    1. games.ini stored pattern          -> source tag [pattern]
//    2. games.ini known vtable slot       -> source tag [vtable]
//    3. prologue fingerprint scan across  -> source tag [vtable>pattern]
//       vtable slots (max 4 candidate
//       fingerprints) + thunk unchaining
//       + post-thunk voting
//    4. pattern-seeded fallback scan      -> source tag [pattern]
//
//  IMPORTANT NOTE #4 (minIndex guard): vtable slots 0 and 1 are the D0/D1
//  destructors and are ALWAYS rejected as candidates (kMinVtableIndex).
//  IMPORTANT NOTE #8: at most kMaxFingerprints (4) prologue fingerprints are
//  tried per target.
//  IMPORTANT NOTE #9: when the fingerprint scan fails, the resolver falls
//  back to scanning the module with the target's stored patterns.
//  IMPORTANT NOTE #10: thunk/adjustor chains are unlinked (JMP rel8/rel32,
//  SUB/ADD RCX imm8/imm32, JMP [RIP+rel32] import stubs) before voting.
//  IMPORTANT NOTE #11: the final address must win a majority vote across
//  several independent vtables before being accepted.
// ============================================================================
#pragma once
#include "classparse.h"
#include "ini.h"

namespace udx::vt {

constexpr int kMinVtableIndex = 2;   // NOTE #4: skip D0/D1 destructor slots
constexpr usize kMaxFingerprints = 4; // NOTE #8
constexpr int kMaxThunkDepth = 8;     // NOTE #10 safety cap

struct ResolvedFunc {
    std::string name;         // "UObject::ProcessEvent"
    uintptr_t   address = 0;  // final (post-thunk) address
    int         vtableIndex = -1;
    std::string source;       // "vtable" | "vtable>pattern" | "pattern"
    std::string module;       // module containing the final address
    std::string note;         // import resolution info etc.
};

class VTableResolver {
public:
    VTableResolver(Process& proc, ue::Offsets& off, ue::NameDb& names,
                   ue::ObjectDb& objects, const Ini& ini);

    std::vector<ResolvedFunc> resolveAll();

    int processEventIndex() const { return peIndex_; }

    // vtable_funcs.txt: slot-by-slot dump for sampled classes.
    bool dumpVtables(const std::string& path, usize maxSlots = 0x80);

private:
    uintptr_t unchain(uintptr_t funcAddr, int depth = 0, std::string* note = nullptr);

    // Scans vtable slots for any fingerprint; returns the slot or -1.
    int scanSlots(u64 vtable, const std::vector<Pattern>& fingerprints,
                  int maxSlot, usize* votesOut = nullptr);

    std::optional<ResolvedFunc> resolveByIni(const std::string& targetName);
    std::optional<ResolvedFunc> resolveByFingerprints(
        const std::string& targetName, const std::vector<std::string>& fingerprints,
        const std::vector<u64>& vtables, const std::string& iniSlotKey);
    std::optional<ResolvedFunc> resolveByPatternSeed(
        const std::string& targetName, const std::vector<std::string>& patterns);

    std::vector<u64> collectVtables(const std::string& classFName, usize maxInstances);

    Process& proc_;
    ue::Offsets& off_;
    ue::NameDb& names_;
    ue::ObjectDb& objects_;
    const Ini& ini_;
    int peIndex_ = -1;
};

} // namespace udx::vt
