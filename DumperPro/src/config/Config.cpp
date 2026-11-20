#include "config/Config.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

namespace dumper {

bool Config::LoadIni(const fs::path& path) {
    iniPath_ = path;
    std::ifstream f(path);
    if (!f.good()) {
        Log::Warn("games.ini not found at %s - using built-in profiles only",
                  path.string().c_str());
        return false;
    }
    std::string line;
    std::string cur;
    while (std::getline(f, line)) {
        // strip comments
        size_t c = line.find_first_of(";#");
        if (c != std::string::npos) line = line.substr(0, c);
        line = str::Trim(line);
        if (line.empty()) continue;

        if (line.front() == '[' && line.back() == ']') {
            cur = str::Lower(line.substr(1, line.size() - 2));
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = str::Lower(str::Trim(line.substr(0, eq)));
        std::string val = str::Trim(line.substr(eq + 1));
        if (key.empty()) continue;
        secs_[cur][key] = val;
    }
    loaded_ = true;
    Log::Info("games.ini loaded: %llu sections",
              (unsigned long long)secs_.size());
    return true;
}

bool Config::HasSection(const std::string& s) const {
    return secs_.count(str::Lower(s)) > 0;
}

std::string Config::Get(const std::string& section, const std::string& key, const std::string& def) const {
    auto it = secs_.find(str::Lower(section));
    if (it == secs_.end()) return def;
    auto kt = it->second.find(str::Lower(key));
    if (kt == it->second.end()) return def;
    return kt->second;
}

static std::vector<std::string> SplitPatterns(const std::string& v) {
    std::vector<std::string> out;
    for (const std::string& part : str::Split(v, '|')) {
        std::string t = str::Trim(part);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

std::vector<std::string> Config::KeyPatterns(const std::string& gameSection, const std::string& key) const {
    std::vector<std::string> out;
    std::string v = Get(gameSection, key);
    if (!v.empty()) { out = SplitPatterns(v); return out; }
    for (const char* fb : {"global", "sig", "patterns"}) {
        v = Get(fb, key);
        if (!v.empty()) { out = SplitPatterns(v); return out; }
    }
    return out;
}

std::vector<std::string> Config::Fingerprints(const std::string& gameSection, const std::string& funcName) const {
    std::vector<std::string> out;
    std::string v = Get(gameSection, "fingerprint." + str::Lower(funcName));
    if (v.empty()) v = Get("fingerprints", str::Lower(funcName));
    if (v.empty()) v = Get("fingerprints", "fingerprint." + str::Lower(funcName));
    if (!v.empty()) out = SplitPatterns(v);
    return out;
}

int Config::KeyInt(const std::string& gameSection, const std::string& key, int def) const {
    std::string v = Get(gameSection, key);
    if (v.empty()) v = Get("global", key);
    if (v.empty()) return def;
    return std::atoi(v.c_str());
}

u64 Config::KeyU64(const std::string& gameSection, const std::string& key, u64 def) const {
    std::string v = Get(gameSection, key);
    if (v.empty()) {
        for (const char* fb : {"global", "sig", "patterns"}) {
            v = Get(fb, key);
            if (!v.empty()) break;
        }
    }
    if (v.empty()) return def;
    u64 out = 0;
    if (str::ParseU64(v, out)) return out;
    return def;
}

void Config::ApplyIniToOffsets(const std::string& section, UEOffsets& off) const {
    auto it = secs_.find(str::Lower(section));
    if (it == secs_.end()) return;

    UEVersion ver;
    std::string vstr = it->second.count("version") ? it->second.at("version") : "";
    if (!vstr.empty()) {
        size_t dot = vstr.find('.');
        if (dot != std::string::npos) {
            ver.major = std::atoi(vstr.substr(0, dot).c_str());
            ver.minor = std::atoi(vstr.substr(dot + 1).c_str());
        }
    }

    for (const auto& kv : it->second) {
        if (kv.first == "version") continue;
        if (bool* b = off.BindBool(kv.first)) {
            *b = (kv.second == "1" || kv.second == "true" || kv.second == "yes");
            off.prov[kv.first] = {UEOffsets::Src::Profile, 100};
            continue;
        }
        u32* p = off.Bind(kv.first);
        if (!p) continue;
        u32 val = 0;
        if (!str::ParseU32(kv.second, val)) continue;
        *p = val;
        off.prov[kv.first] = {UEOffsets::Src::Profile, 100};
    }
}

bool Config::FindProfile(const std::string& gameName, GameProfile& out) const {
    std::string game = str::Lower(gameName);
    for (const auto& skv : secs_) {
        const std::string& sec = skv.first;
        if (sec == "global" || sec == "sig" || sec == "patterns" || sec == "fingerprints" || sec == "general")
            continue;
        if (game == sec || (game.size() > sec.size() && 0 == game.compare(0, sec.size(), sec))) {
            out.name = skv.first;
            out.fromIni = true;
            out.offsets.SetDefaultsFor(UEVersion{0, 0});
            ApplyIniToOffsets(skv.first, out.offsets);
            std::string v = skv.second.count("version") ? skv.second.at("version") : "";
            if (!v.empty()) {
                size_t dot = v.find('.');
                if (dot != std::string::npos) {
                    out.version.major = std::atoi(v.substr(0, dot).c_str());
                    out.version.minor = std::atoi(v.substr(dot + 1).c_str());
                }
            }
            return true;
        }
    }
    return false;
}

std::vector<GameProfile> Config::Builtins() {
    std::vector<GameProfile> out;
    const char* names[] = {"UE4.20", "UE4.24", "UE4.25", "UE4.27", "UE5.0", "UE5.1", "UE5.2",
                           "UE5.3", "UE5.4", "UE5.5"};
    const UEVersion vers[] = {{4, 20}, {4, 24}, {4, 25}, {4, 27}, {5, 0}, {5, 1}, {5, 2},
                              {5, 3}, {5, 4}, {5, 5}};
    // UE5.4/UE5.5 reuse the UE5.3 FUObjectArray/FNamePool layout in our model;
    // engine changes in those releases may shift individual struct offsets, so
    // a profile may need OffsetProbe confirmation or games.ini overrides.
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        GameProfile p;
        p.name = names[i];
        p.version = vers[i];
        p.offsets.SetDefaultsFor(vers[i]);
        out.push_back(std::move(p));
    }
    return out;
}

const GameProfile* Config::BuiltinForVersion(const UEVersion& v) {
    static std::vector<GameProfile> builtins = Builtins();
    if (!v.IsValid()) return nullptr;

    const GameProfile* best = nullptr;
    for (const GameProfile& p : builtins) {
        if (p.version.major == v.major && p.version.minor == v.minor) return &p;
        if (p.version.major == v.major && p.version.minor <= v.minor) {
            if (!best || p.version.minor > best->version.minor) best = &p;
        }
    }
    return best;
}

} // namespace dumper
