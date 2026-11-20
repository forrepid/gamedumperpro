// DumperPro - auto sig-finder with hit validation + heuristic struct scan fallback
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

class IMemoryReader;
class ModuleImage;
class NameArray;
class Config;

struct SigHit {
    u64 va = 0;
    size_t hitOffset = 0;    // RVA of pattern hit inside module image
    std::string pattern;     // primary sig used
    std::string extended;    // 16-byte context version for robustness
    std::string via;         // "config" | "sig" | "heuristic"
};

class SigFinder {
public:
    SigFinder(IMemoryReader& r, ModuleImage& img, UEOffsets& off, const UEVersion& v,
              const NameArray* names, Config& cfg);

    u64 FindGNames(std::string* via = nullptr);   // names first: object validation needs name count
    u64 FindGObjects(std::string* via = nullptr);
    u64 FindGWorld(std::string* via = nullptr);   // heuristic; requires names+objects ready

    SigHit GObjectsHit;
    SigHit GNamesHit;
    SigHit GWorldHit;

private:
    IMemoryReader& r_;
    ModuleImage& img_;
    UEOffsets& off_;
    const UEVersion& ver_;
    const NameArray* names_;
    Config& cfg_;

    struct SigCand {
        const char* pat;
        int dispPos;    // byte offset of disp32 inside the pattern
        int instLen;    // total instruction length (bytes from pattern start)
        const char* note;
    };
    static const std::vector<SigCand>& GObjectsSigs();
    static const std::vector<SigCand>& GNamesSigs();

    u64 TryPatternList(const std::vector<SigCand>& list,
                       bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                       bool usesNames, const char* what, SigHit& hit, std::string* via);
    u64 TryConfigPattern(const std::string& key, bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                         bool usesNames, const char* what, SigHit& hit, std::string* via);
    u64 FromConfigAddress(const std::string& key,
                          bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                          const char* what, SigHit& hit, std::string* via);

    u64 HeuristicScan_GObjects(SigHit& hit, std::string* via);
    u64 HeuristicScan_GNames(SigHit& hit, std::string* via);
    u64 HeuristicScan_GWorld(SigHit& hit, std::string* via);

    SigHit MakeHit(size_t hitOffset, int dispPos, int instLen, const std::string& pat, const char* via);
};

} // namespace dumper
