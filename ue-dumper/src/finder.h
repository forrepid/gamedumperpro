// ============================================================================
//  UnrealDumperX - finder.h
//  GSpots-style automatic location of GObjects / GNames / GWorld (Module 1).
//
//  Resolution pipeline per address (each step feeds the next):
//    1. games.ini signature reuse      -> resolveSignaturePair(main|ext)
//    2. known candidate patterns       -> RIP-relative global decode
//    3. data-section anchor scan       -> structural shape matching
//  Every candidate is STRICTLY verified before acceptance (chunk sanity,
//  entry #0 == "None", first items reachable, vtables inside a module...).
//
//  IMPORTANT NOTE #14: verification is what makes automation safe - a wrong
//  candidate is always rejected, never trusted.
// ============================================================================
#pragma once
#include "ue_types.h"
#include "pattern.h"
#include "fname.h"

namespace udx {
class Ini;

namespace ue {

// A resolved signature pair (stored to signatures.txt / <Game>_sigs.txt).
struct SigRecord {
    std::string name;      // GObjects / GNames / GWorld / ProcessEvent ...
    std::string mainSig;   // IDA-style main signature
    std::string extSig;    // 16-byte extended signature (NOTE #12)
    uintptr_t   resolved = 0;
    std::string module;
    std::string source;    // ini | known | anchor
};

// Read-only view over the resolved FUObjectArray.
class ObjectDb {
public:
    bool init(Process& proc, Offsets& off);
    i32 count() const { return num_; }
    bool chunked() const { return chunked_; }
    u64 objectAt(i32 idx) const;
    // First `max` valid object pointers (used by discovery + SDK walk).
    std::vector<u64> sample(i32 max) const;

private:
    Process* proc_ = nullptr;
    const Offsets* off_ = nullptr;
    i32 num_ = 0;
    bool chunked_ = true;
};

struct FinderResult {
    bool gObjects = false;
    bool gNames = false;
    std::string methodObjects;
    std::string methodNames;
};

FinderResult findCoreAddresses(Process& proc, Offsets& off, const Ini& ini,
                               UEVersion ver, std::vector<SigRecord>& sigs);

// Needs the FName pool loaded (validates the UWorld object's class name).
bool findGWorld(Process& proc, Offsets& off, UEVersion ver, const NameDb& names,
                std::vector<SigRecord>& sigs);

} // namespace ue
} // namespace udx
