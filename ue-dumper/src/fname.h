// ============================================================================
//  UnrealDumperX - fname.h
//  FName pool readers (Module 1 core).
//
//  IMPORTANT NOTE #1 (UE5 FNamePool):
//      * entry header is 2 bytes: { bIsWide:1 | LowercaseProbeHash:5 | Len:10 }
//        -> len = header >> 6 (UE5) or >> 1 (UE4.23, no probe hash)
//      * names are variable length, entries packed with 2-byte (UE5) or
//        4-byte (UE4.23+) stride
//      * blocks are 64KB (0x10000); entry address =
//            Blocks[idx >> 16] + (idx & 0xFFFF) * stride
//      * Blocks[] (FNameEntry*[8192]) sits inside FNamePool at a small offset
//        that is auto-probed by validating entry #0 == "None"
//
//  IMPORTANT NOTE #3 (ANSICHAR/WIDECHAR): every entry carries a wide flag;
//  narrow entries are read as ANSI bytes, wide entries as UTF-16 and both are
//  normalised to UTF-8 for output.
//
//  UE4 <= 4.22 uses TNameEntryArray instead: FNameEntry* Chunks[128] with
//  16384 entries per chunk (indirect pointers, header 4 bytes).
// ============================================================================
#pragma once
#include "ue_types.h"

namespace udx {

class Ini;

namespace ue {

class NameDb {
public:
    // Loads every name from GNames. Auto-calibrates the pool layout unless
    // games.ini pins it (NameBlocksOffset / NameStride / NameLenShift ...).
    bool init(Process& proc, Offsets& off, UEVersion ver, const Ini& ini);

    usize count() const { return names_.size(); }
    std::string get(u32 index) const;                 // "" when invalid
    bool valid(u32 index) const { return index < names_.size(); }
    const std::vector<std::string>& all() const { return names_; }

    bool poolMode() const { return poolMode_; }
    const std::string& calibrationNote() const { return note_; }

private:
    bool initFNamePool(Process& proc, Offsets& off);
    bool initIndirectArray(Process& proc, Offsets& off);
    std::vector<std::string> names_;
    bool poolMode_ = false;
    std::string note_;
};

// One-off entry read used by address validation (finder / offsets probing).
bool readFNameEntry(Process& proc, const Offsets& off, u32 index,
                    std::string& out);

// Decodes a single FNameEntry at an absolute address. Shared with the finder
// for candidate validation. `headerSize` 2 = FNamePool (UE5/4.23+), 4 = old
// TNameEntryArray entries. `lenShift` 6 = UE5 (probe hash), 1 = UE4.23+.
bool decodeEntryAt(Process& proc, uintptr_t entryAddr, int headerSize,
                   int lenShift, std::string& out);

// Reads the raw FName stored inside a UObject (index + Number per NOTE #2).
struct FNameValue { u32 index = 0; i32 number = 0; };
FNameValue readFName(Process& proc, const Offsets& off, u64 nameAddr);

} // namespace ue
} // namespace udx
