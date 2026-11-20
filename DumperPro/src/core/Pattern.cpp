#include "core/Pattern.h"
#include "utils/StrUtil.h"

namespace dumper {

std::vector<PatByte> Pattern::Parse(const std::string& idaStyle) {
    std::vector<PatByte> out;
    for (const std::string& tokRaw : str::Split(idaStyle, ' ')) {
        std::string tok = str::Trim(tokRaw);
        if (tok.empty()) continue;
        tok = str::Lower(tok);

        if (tok == "?" || tok == "??") { out.push_back({0, 0x00}); continue; }
        if (tok.size() != 2) return {};

        auto hexv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };

        if (tok[0] == '?' && tok[1] == '?') { out.push_back({0, 0x00}); continue; }
        if (tok[0] == '?') {
            int lo = hexv(tok[1]);
            if (lo < 0) return {};
            out.push_back({(u8)lo, 0x0F});
            continue;
        }
        if (tok[1] == '?') {
            int hi = hexv(tok[0]);
            if (hi < 0) return {};
            out.push_back({(u8)(hi << 4), 0xF0});
            continue;
        }
        int hi = hexv(tok[0]), lo = hexv(tok[1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back({(u8)((hi << 4) | lo), 0xFF});
    }
    return out;
}

std::string Pattern::ToString(const std::vector<PatByte>& pat) {
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < pat.size(); i++) {
        if (i) out.push_back(' ');
        if (pat[i].mask == 0x00) { out += "??"; continue; }
        char hi = (pat[i].mask & 0xF0) ? digits[(pat[i].value >> 4) & 0xF] : '?';
        char lo = (pat[i].mask & 0x0F) ? digits[pat[i].value & 0xF] : '?';
        out.push_back(hi);
        out.push_back(lo);
    }
    return out;
}

namespace {

inline bool MatchAt(const u8* data, size_t size, size_t pos, const std::vector<PatByte>& pat) {
    if (pos + pat.size() > size) return false;
    const u8* p = data + pos;
    for (size_t i = 0; i < pat.size(); i++) {
        if ((p[i] & pat[i].mask) != (pat[i].value & pat[i].mask)) return false;
    }
    return true;
}

} // namespace

std::vector<size_t> PatternScanner::FindAll(const u8* data, size_t size, const std::vector<PatByte>& pat, size_t maxHits) {
    std::vector<size_t> hits;
    if (pat.empty() || pat.size() > size) return hits;

    // anchor = first fully specified byte -> memchr fast path
    i64 anchor = -1;
    u8 anchorVal = 0;
    for (size_t i = 0; i < pat.size(); i++) {
        if (pat[i].mask == 0xFF) { anchor = (i64)i; anchorVal = pat[i].value; break; }
    }

    size_t last = size - pat.size();
    for (size_t pos = 0; pos <= last; pos++) {
        if (anchor >= 0) {
            const u8* found = (const u8*)memchr(data + pos + anchor, anchorVal, size - pos - anchor);
            if (!found) break;
            size_t newPos = (size_t)(found - data) - (size_t)anchor;
            pos = newPos;
            if (pos > last) break;
        }
        if (MatchAt(data, size, pos, pat)) {
            hits.push_back(pos);
            if (hits.size() >= maxHits) break;
        }
    }
    return hits;
}

i64 PatternScanner::FindFirst(const u8* data, size_t size, const std::vector<PatByte>& pat) {
    auto all = FindAll(data, size, pat, 1);
    return all.empty() ? -1 : (i64)all[0];
}

u64 PatternScanner::RipTargetVA(u64 imageBase, size_t hitOffset, const u8* data, size_t dataSize, int dispPos, int instLen) {
    if (!data) return 0;
    size_t dispOff = hitOffset + (size_t)dispPos;
    if (dispOff + 4 > dataSize) return 0;
    i32 disp = 0;
    memcpy(&disp, data + dispOff, 4);
    return imageBase + (u64)hitOffset + (u64)instLen + (u64)(i64)disp;
}

std::string PatternScanner::BuildExtendedSig(const u8* data, size_t dataSize, size_t hitOffset,
                                             size_t patLen, int dispPos, int instLen,
                                             size_t before, size_t after) {
    if (!data || hitOffset >= dataSize) return "";

    size_t start = (hitOffset > before) ? hitOffset - before : 0;
    size_t end   = std::min(dataSize, hitOffset + patLen + after);

    // wildcard region = the disp32 of the resolved instruction (if within range)
    size_t wStart = (size_t)-1, wEnd = 0;
    if (dispPos >= 0) {
        size_t d = hitOffset + (size_t)dispPos;
        if (d + 4 <= hitOffset + patLen) { // classic: disp inside the pattern
            wStart = d; wEnd = d + 4;
        } else if (d + 4 <= dataSize) {    // disp right after pattern (lea r??,[rip+disp])
            wStart = d; wEnd = d + 4;
        }
    }
    // also mask the remainder of the resolved instruction (bytes between patLen and instLen)
    size_t tailStart = (size_t)-1, tailEnd = 0;
    if (instLen > (int)patLen) {
        tailStart = hitOffset + patLen;
        tailEnd   = hitOffset + (size_t)instLen;
    }

    static const char* digits = "0123456789ABCDEF";
    std::string out;
    for (size_t i = start; i < end; i++) {
        bool wild = (i >= wStart && i < wEnd) || (i >= tailStart && i < tailEnd);
        if (out.size()) out.push_back(' ');
        if (wild) out += "??";
        else {
            u8 b = data[i];
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0xF]);
        }
    }
    return out;
}

} // namespace dumper
