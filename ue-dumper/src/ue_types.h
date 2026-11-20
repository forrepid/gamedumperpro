// ============================================================================
//  UnrealDumperX - ue_types.h
//  Unreal Engine type definitions and the central Offsets structure.
//
//  IMPORTANT NOTE #1 (UE5 FNamePool): UE5 replaced TNameEntryArray with
//  FNamePool - 2-byte entry headers, variable-length names and 64KB (0x10000)
//  blocks. The reader lives in fname.cpp and auto-calibrates header layout.
//
//  IMPORTANT NOTE #2 (FName::Number placement):
//      UE5 : FName = { int32 ComparisonIndex @+0x00 ; int32 Number @+0x04 }
//      UE4 : several builds place Number BEFORE the index  -> delta = -0x04
//  The placement is probed at runtime (offsets.cpp) and can be pinned
//  through games.ini ([Offsets] FNameNumberDelta=...).
//
//  IMPORTANT NOTE #5/#7 (Runtime Offset Discovery): fields are voted with at
//  most kMaxProbeObjects live objects and accepted at >= kConfidenceThreshold.
//
//  IMPORTANT NOTE #6 (games.ini authority): values loaded from games.ini are
//  authoritative - runtime probing never overrides them, and saving never
//  rewrites user-pinned lines.
// ============================================================================
#pragma once
#include "common.h"

namespace udx {
class Ini;
class Process;

namespace ue {

enum class UEVersion {
    Unknown = 0,
    UE4_20, UE4_21, UE4_22, UE4_23, UE4_24, UE4_25, UE4_26, UE4_27,
    UE5_0, UE5_1, UE5_2, UE5_3, UE5_Unk,
};

bool isUE5(UEVersion v);
bool usesFNamePool(UEVersion v);   // >= 4.23  (FNamePool)
bool usesIndirectArray(UEVersion v); // <= 4.22 (TNameEntryArray)
bool usesFFields(UEVersion v);     // >= 4.25  (FField / FProperty)
const char* versionToString(UEVersion v);

// FUObjectItem - same shape for both generations (size auto-probed).
struct FUObjectItem {
    u64 object;
    i32 flags;
    i32 clusterRootIndex;
    i32 serialNumber;
};

// ---------------------------------------------------------------------------
//  Central layout store. Every field carries its provenance in `meta`
//  (source: ini | sig | anchor | vote | default) for offsets.txt reporting.
// ---------------------------------------------------------------------------
struct OffsetEntry {
    int offset = 0;
    float confidence = 0.0f;
    std::string source;
};

struct Offsets {
    // ---- resolved absolute addresses --------------------------------------
    uintptr_t gObjects = 0;
    uintptr_t gNames = 0;
    uintptr_t gWorld = 0;

    // ---- FUObjectArray / TUObjectArray ------------------------------------
    int  tuObjectArrayOffset = 0x00;   // sub-struct inside FUObjectArray (probed 0x00/0x10/0x20)
    int  objMaxElements = 0x04;
    int  objNumElements = 0x08;
    int  objMaxChunks   = 0x0C;
    int  objNumChunks   = 0x10;
    int  objectItemSize = 0x18;
    int  chunkCapacity  = 0x10000;
    bool chunkedArray   = true;

    // ---- UObject core ------------------------------------------------------
    int uobjFlags = 0x08;
    int uobjIndex = 0x0C;
    int uobjClass = 0x10;
    int uobjName  = 0x18;
    int uobjOuter = 0x20;

    // ---- FName::Number quirk (IMPORTANT NOTE #2) ---------------------------
    int fNameNumberDelta = 0x04;   // UE5: +4, UE4: -4 (probed, ini-pinnable)

    // ---- FName pool / TNameEntryArray (IMPORTANT NOTE #1) ------------------
    int nameBlocksOffset = 0x10;   // FNamePool::Blocks offset inside the pool
    int nameStride       = 2;      // UE5: 2, UE4.23+: 4 (auto-probed)
    int nameLenShift     = 6;      // UE5: >>6 (probe hash), UE4.23+: >>1
    int nameHeaderSize   = 2;      // 2-byte header (pool), 4 (old entry array)
    int nameChunkBits    = 16;     // entries per pool block (1<<16); 14 for old arrays
    int nameMaxBlocks    = 8192;

    // ---- provenance tracking ----------------------------------------------
    std::map<std::string, OffsetEntry> meta;
    void record(const std::string& key, int value, const std::string& source,
                float confidence);
    const OffsetEntry& metaFor(const std::string& key) const;

    // ---- config / defaults -------------------------------------------------
    void applyDefaultsFor(UEVersion v);
    void applyIni(const Ini& ini);              // authoritative (NOTE #6)
    void saveMissingToIni(Ini& ini) const;      // only fills keys the user has not pinned
    std::string describe() const;
};

// ---- discovery constants (IMPORTANT NOTE #5 / #7) --------------------------
constexpr int   kMaxProbeObjects     = 400;    // live objects used for voting
constexpr float kConfidenceThreshold = 0.65f;  // per-field acceptance threshold

class NameDb;
class ObjectDb;

// Runtime Offset Discovery (Module 7). Requires gObjects + NameDb ready.
bool discoverRuntimeOffsets(Process& proc, Offsets& off, const Ini& ini,
                            UEVersion ver, const NameDb& names);

// FName number delta probe used by discoverRuntimeOffsets (exposed for tests).
void probeFNameNumberDelta(Process& proc, Offsets& off, const NameDb& names,
                           const std::vector<u64>& objects);

} // namespace ue
} // namespace udx
