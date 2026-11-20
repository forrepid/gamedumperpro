// ============================================================================
//  UnrealDumperX - common.cpp
// ============================================================================
#include "common.h"

namespace udx {

std::string fmt(const char* pattern, ...) {
    char stackBuf[512];
    va_list args;
    va_start(args, pattern);
    int n = vsnprintf(stackBuf, sizeof(stackBuf), pattern, args);
    va_end(args);
    if (n >= 0 && n < (int)sizeof(stackBuf))
        return std::string(stackBuf, (usize)n);

    // Grew beyond the stack buffer - retry with a heap buffer.
    std::vector<char> heapBuf((usize)(n > 0 ? n + 1 : 4096));
    va_start(args, pattern);
    n = vsnprintf(heapBuf.data(), heapBuf.size(), pattern, args);
    va_end(args);
    if (n < 0) return {};
    return std::string(heapBuf.data(), (usize)n);
}

std::string trim(const std::string& s) {
    usize b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    usize e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::toupper(c); });
    return s;
}

bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && 0 == s.compare(0, prefix.size(), prefix);
}

bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           0 == s.compare(s.size() - suffix.size(), suffix.size(), suffix);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (usize i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string replaceAll(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    usize pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string toHex(u64 value) { return fmt("0x%llX", (unsigned long long)value); }
std::string toHexPadded(u64 value) { return fmt("0x%016llX", (unsigned long long)value); }

std::string sanitizeIdent(std::string name) {
    for (char& c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_';
        if (!ok) c = '_';
    }
    if (!name.empty() && name[0] >= '0' && name[0] <= '9') name = "_" + name;
    return name;
}

bool ensureDir(const std::string& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return !ec;
}

bool writeTextFile(const std::string& path, const std::string& content) {
    std::error_code ec;
    std::filesystem::path p(path);
    if (p.has_parent_path())
        std::filesystem::create_directories(p.parent_path(), ec);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(content.data(), (std::streamsize)content.size());
    return f.good();
}

std::string timestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return fmt("%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out((usize)need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                        out.data(), need, nullptr, nullptr);
    return out;
}

} // namespace udx
