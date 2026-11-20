#include "ue/UEVersion.h"
#include "core/PEFile.h"
#include "utils/StrUtil.h"

namespace dumper {

// ---------------------------------------------------------------------------
// raw-memory fallback for device-mode images (LeechCore --device): the scan
// window is raw physical memory with no guaranteed PE header, so version
// markers are scanned as plain ASCII instead of via PEFile::VersionStrings().
// Looks for embedded build markers like "++UE5+Release-5.3.2-0+..." and votes.
// ---------------------------------------------------------------------------
static bool DetectFromRawStrings(const u8* data, size_t size, UEVersion& out) {
    std::map<std::pair<int, int>, int> votes;
    if (data && size >= 24) {
        const size_t lim = size - 23;
        for (size_t i = 0; i < lim; i++) {
            if (data[i] != '+' || data[i + 1] != '+' || data[i + 2] != 'U' || data[i + 3] != 'E')
                continue;
            size_t p = i + 4;
            while (p < size && data[p] >= '0' && data[p] <= '9') p++; // branch digits ("UE4"/"UE5")
            if (p >= size || data[p] != '+') continue;
            if (p + 9 >= size || memcmp(data + p, "+Release-", 9) != 0) continue;
            p += 9;
            int maj = 0, mino = 0;
            bool any = false;
            while (p < size && data[p] >= '0' && data[p] <= '9') { maj = maj * 10 + (data[p] - '0'); any = true; p++; }
            if (!any || p >= size || data[p] != '.') continue;
            p++;
            any = false;
            while (p < size && data[p] >= '0' && data[p] <= '9') { mino = mino * 10 + (data[p] - '0'); any = true; p++; }
            if (!any) continue;
            votes[{maj, mino}]++;
            i = p; // skip past this marker
        }
    }
    if (votes.empty()) return false;

    // most votes wins, tie -> higher version (same rule as the PE path below)
    std::pair<int, int> best = votes.begin()->first;
    int bestCount = 0;
    for (const auto& kv : votes) {
        if (kv.second > bestCount || (kv.second == bestCount && kv.first > best)) {
            best = kv.first;
            bestCount = kv.second;
        }
    }
    out.major = best.first;
    out.minor = best.second;
    return out.IsValid();
}

bool VersionDetector::Detect(const ModuleImage& img, UEVersion& out) {
    // device-mode images (LeechCore --device) carry no parsed PE header:
    // fall back to a plain ASCII marker scan over the raw window
    if (!img.pe || !img.pe->Valid())
        return DetectFromRawStrings(img.Data.data(), img.Data.size(), out);

    std::vector<std::string> markers = img.pe->VersionStrings();
    if (markers.empty()) return false;

    // parse "Release-M.m" tokens and vote
    std::map<std::pair<int, int>, int> votes;
    for (const std::string& s : markers) {
        size_t p = s.find("Release-");
        if (p == std::string::npos) continue;
        std::string v = s.substr(p + 8);

        size_t dot = v.find('.');
        if (dot == std::string::npos) continue;
        std::string maj = v.substr(0, dot);
        std::string rest = v.substr(dot + 1);
        size_t end = 0;
        while (end < rest.size() && rest[end] >= '0' && rest[end] <= '9') end++;
        std::string mino = rest.substr(0, end);

        if (maj.empty() || mino.empty()) continue;
        bool okMaj = true, okMin = true;
        for (char c : maj) if (c < '0' || c > '9') okMaj = false;
        for (char c : mino) if (c < '0' || c > '9') okMin = false;
        if (!okMaj || !okMin) continue;

        votes[{std::atoi(maj.c_str()), std::atoi(mino.c_str())}]++;
    }

    if (votes.empty()) return false;

    // most votes wins, tie -> higher version
    std::pair<int, int> best = votes.begin()->first;
    int bestCount = 0;
    for (const auto& kv : votes) {
        if (kv.second > bestCount || (kv.second == bestCount && kv.first > best)) {
            best = kv.first;
            bestCount = kv.second;
        }
    }
    out.major = best.first;
    out.minor = best.second;
    return out.IsValid();
}

} // namespace dumper
