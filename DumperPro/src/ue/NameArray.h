// DumperPro - GNames / FNamePool parsing (UE4.23+ pool + legacy TNameEntryArray)
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

class IMemoryReader;
struct UEVersion;

class NameArray {
public:
    bool TryInit(IMemoryReader& r, UEOffsets& off, const UEVersion& v, std::string* err = nullptr);
    bool IsReady() const { return ready_; }

    i32 Num() const { return (i32)names_.size(); }
    std::string Get(i32 idx) const;                       // "" when invalid
    u64 GNamesVA() const { return gNamesVA_; }
    const std::vector<std::string>& All() const { return names_; }

    std::string ModeInfo() const;                          // "FNamePool bs=0x20000 align=4" etc.

    // static validation used by SigFinder on candidate addresses
    static bool ValidateCandidate(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                                  u64 gNamesVA, std::string* why = nullptr);

private:
    IMemoryReader* r_ = nullptr;
    UEOffsets* off_ = nullptr;
    UEVersion ver_;

    u64 gNamesVA_ = 0;
    bool poolMode_ = true;
    u32 blockSize_ = 0x10000;
    u32 entryAlign_ = 2;
    bool ready_ = false;
    std::vector<std::string> names_;

    bool ReadAsPool(std::string* err);
    bool ReadAsLegacy(std::string* err);
    void ReadPoolBlock(u64 blockPtr, u32 usedSize, u32 entryAlign, u32& outEntries, u32& outBad);
};

} // namespace dumper
