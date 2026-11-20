// DumperPro - games.ini configuration + built-in fallback profiles
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

struct GameProfile {
    std::string name;
    UEVersion version;
    UEOffsets offsets;
    bool fromIni = false;
};

class Config {
public:
    // ini is optional; missing file just leaves built-in defaults
    bool LoadIni(const fs::path& path);
    bool Loaded() const { return loaded_; }
    const fs::path& IniPath() const { return iniPath_; }

    bool HasSection(const std::string& s) const;
    std::string Get(const std::string& section, const std::string& key, const std::string& def = "") const;

    // find ini profile for a game: exact section match (ci), then "section is prefix of game"
    bool FindProfile(const std::string& gameName, GameProfile& out) const;

    // apply dotted offset keys of a game section onto an offsets struct (marks Prov::Profile)
    void ApplyIniToOffsets(const std::string& section, UEOffsets& off) const;

    // global helper keys (looked up in [Global], [Sig], [Patterns] then the game section)
    u64 KeyU64(const std::string& gameSection, const std::string& key, u64 def = 0) const;
    std::vector<std::string> KeyPatterns(const std::string& gameSection, const std::string& key) const;
    std::vector<std::string> Fingerprints(const std::string& gameSection, const std::string& funcName) const;
    int KeyInt(const std::string& gameSection, const std::string& key, int def = 0) const;

    // 10 profiles pre-loaded in code as fallback when games.ini has no entry
    static std::vector<GameProfile> Builtins();
    // pick builtin matching a detected version (exact, else nearest lower minor of same major)
    static const GameProfile* BuiltinForVersion(const UEVersion& v);

private:
    std::map<std::string, std::map<std::string, std::string>> secs_; // keys lowercased
    fs::path iniPath_;
    bool loaded_ = false;
};

} // namespace dumper
