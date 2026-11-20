// DumperPro - byte pattern utilities (IDA-style "48 8B 05 ?? ?? ?? ??")
#pragma once
#include "../framework.h"

namespace dumper {

struct PatByte {
    u8 value = 0;
    u8 mask  = 0xFF; // 0xFF exact, 0xF0 hi-nibble, 0x0F lo-nibble, 0x00 wildcard
};

class Pattern {
public:
    // parse IDA-style pattern; returns empty vector on parse error
    static std::vector<PatByte> Parse(const std::string& idaStyle);
    static std::string ToString(const std::vector<PatByte>& pat);
    static bool Valid(const std::vector<PatByte>& pat) { return !pat.empty(); }
};

class PatternScanner {
public:
    // find up to maxHits match offsets relative to data
    static std::vector<size_t> FindAll(const u8* data, size_t size, const std::vector<PatByte>& pat, size_t maxHits = 64);
    static i64 FindFirst(const u8* data, size_t size, const std::vector<PatByte>& pat); // -1 if none

    // Resolve RIP-relative displacement of an instruction that matched at hitOffset:
    //   target VA = imageBase + hitOffset + instLen + disp32@(hitOffset + dispPos)
    static u64 RipTargetVA(u64 imageBase, size_t hitOffset, const u8* data, size_t dataSize, int dispPos, int instLen);

    // Build an IDA-style pattern string from the actual bytes around a hit.
    // The disp32 region is masked as ?? so the sig survives code relocation.
    static std::string BuildExtendedSig(const u8* data, size_t dataSize, size_t hitOffset,
                                        size_t patLen, int dispPos, int instLen,
                                        size_t before = 8, size_t after = 8);
};

} // namespace dumper
