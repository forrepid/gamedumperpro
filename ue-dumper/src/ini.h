// ============================================================================
//  UnrealDumperX - ini.h
//  games.ini configuration system (Module 3 - Configuration).
//
//  Key property: SAVING PRESERVES EVERYTHING THE USER WROTE. Existing lines,
//  comments and authoritative values are never rewritten; the dumper only
//  replaces the exact key it changed or appends new keys. This is what makes
//  games.ini "authoritative": values the user pinned are used verbatim and
//  survive every dump run (IMPORTANT NOTE #6).
// ============================================================================
#pragma once
#include "common.h"

namespace udx {

class Ini {
public:
    bool load(const std::string& path);
    bool save(const std::string& path) const;

    bool has(const std::string& sec, const std::string& key) const;
    std::string get(const std::string& sec, const std::string& key,
                    const std::string& def = {}) const;
    u64 getU64(const std::string& sec, const std::string& key, u64 def) const;
    i32 getI32(const std::string& sec, const std::string& key, i32 def) const;
    bool getBool(const std::string& sec, const std::string& key, bool def) const;

    void set(const std::string& sec, const std::string& key, const std::string& value);
    void setU64(const std::string& sec, const std::string& key, u64 value);
    void setI32(const std::string& sec, const std::string& key, i32 value);

    bool loaded() const { return loaded_; }
    const std::string& path() const { return path_; }

private:
    void ensureSection(const std::string& sec);
    static std::string normKey(const std::string& k) { return lower(trim(k)); }
    static std::string normSec(const std::string& s) { return lower(trim(s)); }

    std::string path_;
    bool loaded_ = false;
    std::vector<std::string> lines_;   // raw file lines (comments preserved)
    std::map<std::pair<std::string, std::string>, usize> index_; // (sec, key) -> line
};

} // namespace udx
