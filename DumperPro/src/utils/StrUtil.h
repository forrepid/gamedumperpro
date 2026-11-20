// DumperPro - string / conversion helpers (header-only)
#pragma once
#include "../framework.h"

namespace dumper {
namespace str {

inline std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

inline std::string Upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::toupper(c); });
    return s;
}

inline std::vector<std::string> Split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

inline bool StartsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && 0 == s.compare(0, p.size(), p);
}
inline bool EndsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && 0 == s.compare(s.size() - p.size(), p.size(), p);
}
inline bool Contains(const std::string& s, const std::string& p) {
    return s.find(p) != std::string::npos;
}

inline std::string Join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

inline std::string Replace(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

inline bool IsHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// accepts "0x1234", "1234h", plain hex and decimal
inline bool ParseU64(const std::string& inRaw, u64& out) {
    std::string in = Trim(inRaw);
    if (in.empty()) return false;
    std::string s = Lower(in);
    u64 base = 10;
    if (StartsWith(s, "0x")) { base = 16; s = s.substr(2); }
    else if (EndsWith(s, "h")) { base = 16; s = s.substr(0, s.size() - 1); }
    if (s.empty()) return false;
    for (char c : s) {
        if (base == 16 && !IsHexDigit(c)) return false;
        if (base == 10 && (c < '0' || c > '9')) return false;
    }
    out = std::stoull(s, nullptr, (int)base);
    return true;
}

inline bool ParseU32(const std::string& in, u32& out) {
    u64 v = 0;
    if (!ParseU64(in, v) || v > 0xFFFFFFFFull) return false;
    out = (u32)v;
    return true;
}

inline u64 AlignUp(u64 v, u64 a) { return a ? ((v + a - 1) / a) * a : v; }

inline bool IsPrintableAscii(const char* s, size_t n) {
    size_t good = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0) break;
        if ((c >= 0x20 && c < 0x7F) || c == '\t') good++;
    }
    if (n == 0) return true;
    return good * 20 >= n * 18; // >= 90%
}

inline std::string HumanSize(u64 bytes) {
    char buf[64];
    if (bytes >= 1024ull * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ull * 1024)
        snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return buf;
}

// UTF-16LE -> UTF-8 (BMP only, invalid chars replaced with '?')
inline std::string WideToUtf8(const u16* data, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; i++) {
        u32 c = data[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < len) { // surrogate pair
            u32 lo = data[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i++;
            } else { c = '?'; }
        }
        if (c < 0x80) out.push_back((char)c);
        else if (c < 0x800) {
            out.push_back((char)(0xC0 | (c >> 6)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back((char)(0xE0 | (c >> 12)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else {
            out.push_back((char)(0xF0 | (c >> 18)));
            out.push_back((char)(0x80 | ((c >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

// sanitize identifier for generated C++ code
inline std::string SanitizeIdent(const std::string& in) {
    std::string out;
    for (char c : in) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
            out.push_back(c);
        else
            out.push_back('_');
    }
    if (out.empty() || (out[0] >= '0' && out[0] <= '9')) out = "_" + out;
    return out;
}

} // namespace str
} // namespace dumper
