// DumperPro - Unreal Engine version detection
#pragma once
#include "../framework.h"
#include "core/MemoryReader.h"

namespace dumper {

struct UEVersion {
    int major = 0;
    int minor = 0;

    bool IsValid() const { return major > 0; }
    bool IsUE5() const { return major >= 5; }
    bool AtLeast(int mj, int mn) const { return major > mj || (major == mj && minor >= mn); }
    std::string Str() const {
        if (!IsValid()) return "unknown";
        return "UE" + std::to_string(major) + "." + std::to_string(minor);
    }
};

class VersionDetector {
public:
    // scans the module image for embedded version strings ("++UE4+Release-4.27", ...)
    static bool Detect(const ModuleImage& img, UEVersion& out);
};

} // namespace dumper
