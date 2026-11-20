// ============================================================================
//  UnrealDumperX - log.h
//  Console UX: colored logging, section headers, animated progress bars.
//  Header-only; no external dependencies.
// ============================================================================
#pragma once
#include "common.h"

namespace udx::log {

enum class Color : u16 {
    Reset   = 7,   // default grey/white
    Grey    = 8,
    Green   = 10,
    Cyan    = 11,
    Red     = 12,
    Magenta = 13,
    Yellow  = 14,
    White   = 15,
};

inline void setColor(Color c) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(h, (WORD)c);
}

inline void writeColored(const char* prefix, Color c, const std::string& msg) {
    setColor(c);
    std::printf("%s%s\n", prefix, msg.c_str());
    setColor(Color::Reset);
}

inline void info  (const std::string& msg) { writeColored("[*] ", Color::Cyan,    msg); }
inline void ok    (const std::string& msg) { writeColored("[+] ", Color::Green,   msg); }
inline void warn  (const std::string& msg) { writeColored("[!] ", Color::Yellow,  msg); }
inline void error (const std::string& msg) { writeColored("[-] ", Color::Red,     msg); }

// Verbose-only logging (enabled with --verbose).
inline bool& verboseFlag() { static bool v = false; return v; }
inline void  setVerbose(bool on) { verboseFlag() = on; }
inline void  debug(const std::string& msg) {
    if (verboseFlag()) writeColored("[v] ", Color::Grey, msg);
}

inline void section(const std::string& title) {
    std::printf("\n");
    setColor(Color::Magenta);
    std::printf("======== %s ========\n", title.c_str());
    setColor(Color::Reset);
}

inline void banner() {
    setColor(Color::Green);
    std::printf(
        "=============================================================\n"
        "   UnrealDumperX v%s   UE4 4.20-4.27 / UE5 5.0-5.3 dumper\n"
        "   ill2cpp2dumper | Dumper-7 | UE5CEDumper | UEDumper | GSpots\n"
        "=============================================================\n",
        UDX_VERSION_STRING);
    setColor(Color::Reset);
}

// ---------------------------------------------------------------------------
//  Progress: single-line animated bar, safe for long-running memory walks.
//    [FName pool      ] [########------------]  40.0% (12345/30867)
// ---------------------------------------------------------------------------
class Progress {
public:
    explicit Progress(std::string label, u64 total)
        : label_(std::move(label)), total_(total ? total : 1), start_(GetTickCount64()) {}

    ~Progress() { finishLine(); }

    void tick(u64 delta = 1) { update(value_ + delta); }

    void update(u64 value) {
        value_ = value;
        const u64 now = GetTickCount64();
        if (!done_ && now - lastRender_ < 60 && value_ < total_) return;
        lastRender_ = now;
        render();
    }

    void done(const std::string& suffix = {}) {
        render();
        finishLine();
        if (!suffix.empty()) ok(suffix);
    }

    u64 elapsedMs() const { return GetTickCount64() - start_; }

private:
    void render() {
        const double pct = 100.0 * (double)std::min<u64>(value_, total_) / (double)total_;
        const int filled = (int)(pct / 5.0 + 0.5);
        char bar[21];
        for (int i = 0; i < 20; ++i) bar[i] = i < filled ? '#' : '-';
        bar[20] = '\0';
        setColor(Color::Yellow);
        std::printf("\r[%s] [%s] %5.1f%% (%llu/%llu)",
                    label_.c_str(), bar, pct,
                    (unsigned long long)value_, (unsigned long long)total_);
        std::fflush(stdout);
        setColor(Color::Reset);
    }

    void finishLine() {
        if (lineClosed_) return;
        lineClosed_ = true;
        std::printf("\n");
        std::fflush(stdout);
    }

    std::string label_;
    u64 total_ = 1;
    u64 value_ = 0;
    u64 lastRender_ = 0;
    u64 start_ = 0;
    bool done_ = false;
    bool lineClosed_ = false;
};

} // namespace udx::log
