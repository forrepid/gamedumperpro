// ============================================================================
//  UnrealDumperX - ini.cpp
// ============================================================================
#include "ini.h"

namespace udx {

bool Ini::load(const std::string& path) {
    path_ = path;
    loaded_ = false;
    lines_.clear();
    index_.clear();

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;   // first run - file may not exist yet

    std::string currentSection;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines_.push_back(line);

        std::string t = trim(line);
        if (t.empty() || t[0] == ';' || t[0] == '#') continue;

        if (t.front() == '[' && t.back() == ']') {
            currentSection = normSec(t.substr(1, t.size() - 2));
            continue;
        }
        usize eq = t.find('=');
        if (eq == std::string::npos) eq = t.find(':');
        if (eq == std::string::npos) continue;
        const std::string key = normKey(t.substr(0, eq));
        if (key.empty()) continue;
        index_[{currentSection, key}] = lines_.size() - 1;
    }
    loaded_ = true;
    return true;
}

bool Ini::save(const std::string& path) const {
    std::ofstream f(path.empty() ? path_ : path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    for (const auto& l : lines_) f << l << "\r\n";
    return f.good();
}

bool Ini::has(const std::string& sec, const std::string& key) const {
    return index_.count({normSec(sec), normKey(key)}) != 0;
}

std::string Ini::get(const std::string& sec, const std::string& key,
                     const std::string& def) const {
    auto it = index_.find({normSec(sec), normKey(key)});
    if (it == index_.end()) return def;
    const std::string raw = lines_[it->second];
    usize eq = raw.find('=');
    if (eq == std::string::npos) eq = raw.find(':');
    if (eq == std::string::npos) return def;
    // Strip trailing comments ("; ..." / "# ...").
    std::string val = trim(raw.substr(eq + 1));
    usize c1 = val.find(';'), c2 = val.find('#');
    usize cut = std::min(c1 == std::string::npos ? val.size() : c1,
                         c2 == std::string::npos ? val.size() : c2);
    return trim(val.substr(0, cut));
}

u64 Ini::getU64(const std::string& sec, const std::string& key, u64 def) const {
    std::string v = lower(get(sec, key));
    if (v.empty()) return def;
    if (startsWith(v, "0x")) {
        unsigned long long r = 0;
        if (sscanf_s(v.c_str(), "0x%llx", &r) == 1) return (u64)r;
        return def;
    }
    unsigned long long r = 0;
    if (sscanf_s(v.c_str(), "%llu", &r) == 1) return (u64)r;
    return def;
}

i32 Ini::getI32(const std::string& sec, const std::string& key, i32 def) const {
    return (i32)getU64(sec, key, (u64)(i64)def);
}

bool Ini::getBool(const std::string& sec, const std::string& key, bool def) const {
    std::string v = lower(get(sec, key));
    if (v.empty()) return def;
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

void Ini::ensureSection(const std::string& sec) {
    const std::string want = "[" + sec + "]";
    for (const auto& l : lines_) {
        std::string t = trim(l);
        if (lower(t) == lower(want)) return;
    }
    if (!lines_.empty()) lines_.push_back("");
    lines_.push_back(want);
}

void Ini::set(const std::string& sec, const std::string& key, const std::string& value) {
    const std::string s = normSec(sec), k = normKey(key);
    auto it = index_.find({s, k});
    if (it != index_.end()) {
        // Replace exactly this key's line; keep the rest of the file as-is.
        lines_[it->second] = key + " = " + value;
        return;
    }
    ensureSection(sec);
    // Append under the most recent occurrence of the section header.
    const std::string want = "[" + sec + "]";
    usize insertAt = lines_.size();
    for (usize i = lines_.size(); i-- > 0;) {
        std::string t = trim(lines_[i]);
        if (lower(t) == lower(want)) { insertAt = i + 1; break; }
    }
    // Skip past consecutive key lines belonging to the same section.
    while (insertAt < lines_.size()) {
        std::string t = trim(lines_[insertAt]);
        if (t.empty() || t[0] == ';' || t[0] == '#') break;
        if (t.front() == '[') break;
        ++insertAt;
    }
    const std::string newLine = key + " = " + value;
    lines_.insert(lines_.begin() + (std::ptrdiff_t)insertAt, newLine);
    index_[{s, k}] = insertAt;
    // Re-index: line numbers after the insertion point shifted by one.
    for (auto& kv : index_) {
        if (kv.second >= insertAt && kv.second != insertAt) ++kv.second;
        if (kv.second == insertAt && kv.first != std::pair{s, k}) ++kv.second;
    }
}

void Ini::setU64(const std::string& sec, const std::string& key, u64 value) {
    set(sec, key, toHex(value));
}

void Ini::setI32(const std::string& sec, const std::string& key, i32 value) {
    set(sec, key, fmt("0x%X", (unsigned)value));
}

} // namespace udx
