// ============================================================================
//  UnrealDumperX - version.cpp
// ============================================================================
#include "version.h"
#include "pattern.h"

namespace udx::ue {

bool isUE5(UEVersion v) {
    return v >= UEVersion::UE5_0 && v <= UEVersion::UE5_Unk;
}

bool usesFNamePool(UEVersion v) {
    return v >= UEVersion::UE4_23 || isUE5(v);
}

bool usesIndirectArray(UEVersion v) {
    return v >= UEVersion::UE4_20 && v <= UEVersion::UE4_22;
}

bool usesFFields(UEVersion v) {
    return v >= UEVersion::UE4_25 || isUE5(v);
}

const char* versionToString(UEVersion v) {
    switch (v) {
        case UEVersion::UE4_20: return "UE4.20";
        case UEVersion::UE4_21: return "UE4.21";
        case UEVersion::UE4_22: return "UE4.22";
        case UEVersion::UE4_23: return "UE4.23";
        case UEVersion::UE4_24: return "UE4.24";
        case UEVersion::UE4_25: return "UE4.25";
        case UEVersion::UE4_26: return "UE4.26";
        case UEVersion::UE4_27: return "UE4.27";
        case UEVersion::UE5_0:  return "UE5.0";
        case UEVersion::UE5_1:  return "UE5.1";
        case UEVersion::UE5_2:  return "UE5.2";
        case UEVersion::UE5_3:  return "UE5.3";
        case UEVersion::UE5_Unk: return "UE5.x";
        default: return "Unknown";
    }
}

std::optional<UEVersion> versionFromReleaseString(const std::string& s) {
    // Match "Release-4.27.2" / "Release-5.2.1" inside build strings like
    // "++UE5+Release-5.2.1-0+++UE5+Release-5.2".
    const usize pos = s.find("Release-");
    std::string rest = pos == std::string::npos ? s : s.substr(pos + 8);
    int major = 0, minor = 0;
    if (sscanf_s(rest.c_str(), "%d.%d", &major, &minor) != 2) return std::nullopt;
    if (major == 4 && minor >= 20 && minor <= 27)
        return (UEVersion)((int)UEVersion::UE4_20 + (minor - 20));
    if (major == 5) {
        if (minor >= 0 && minor <= 3)
            return (UEVersion)((int)UEVersion::UE5_0 + minor);
        return UEVersion::UE5_Unk;
    }
    return std::nullopt;
}

std::optional<UEVersion> versionFromIniValue(const std::string& s) {
    std::string v = lower(trim(s));
    if (v.empty() || v == "auto") return std::nullopt;
    if (v == "ue5" || v == "5.x") return UEVersion::UE5_Unk;
    if (v == "ue4" || v == "4.x") return UEVersion::UE4_27;
    return versionFromReleaseString(replaceAll(v, "ue", ""));
}

UEVersion detectVersion(Process& proc, const ModuleInfo& mainModule,
                        std::string* methodOut) {
    if (methodOut) methodOut->clear();

    // 1) Embedded release string scan across initialized data sections.
    for (const auto& sec : peSectionsOf(proc, mainModule)) {
        if (sec.size == 0 || sec.size > 256ull * 1024 * 1024) continue;
        // Only .rdata/.data-like sections carry the build string.
        if (lower(sec.name).find(".rdata") == std::string::npos &&
            lower(sec.name).find(".data") == std::string::npos)
            continue;
        std::vector<u8> buf(std::min<usize>(sec.size, 64ull * 1024 * 1024), 0);
        if (!proc.read(sec.start, buf.data(), buf.size())) continue;

        static const char* tags[] = {
            "++UE4+Release-", "++UE5+Release-", "Release-4.", "Release-5.",
        };
        for (const char* tag : tags) {
            const usize tlen = std::strlen(tag);
            for (usize i = 0; i + tlen < buf.size(); ++i) {
                if (std::memcmp(buf.data() + i, tag, tlen) != 0) continue;
                std::string s((const char*)buf.data() + i,
                              std::min<usize>(buf.size() - i, 64));
                if (auto v = versionFromReleaseString(s)) {
                    if (methodOut) *methodOut = std::string("embedded string \"") + tag + "\"";
                    return *v;
                }
            }
        }
    }

    // 2) Exe product metadata on disk (best-effort).
    if (!mainModule.path.empty()) {
        // PE version resource parsing is intentionally light: shipping builds
        // rarely keep the resource, so this is only a fallback hint.
        if (methodOut && methodOut->empty()) *methodOut = "not detected";
    }
    if (methodOut && methodOut->empty()) *methodOut = "not detected";
    return UEVersion::Unknown;
}

} // namespace udx::ue
