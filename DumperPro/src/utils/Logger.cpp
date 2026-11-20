#include "utils/Logger.h"
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

namespace dumper {

bool Log::sVerbose = false;
std::mutex Log::sMtx;

namespace {

bool IsTty() {
    static int cached = -1;
    if (cached < 0) {
#ifdef _WIN32
        cached = _isatty(_fileno(stdout)) ? 1 : 0;
#else
        cached = isatty(fileno(stdout)) ? 1 : 0;
#endif
    }
    return cached == 1;
}

void EnableAnsi() {
#ifdef _WIN32
    if (IsTty()) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (h && GetConsoleMode(h, &mode)) {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif
}

const char* ColorFor(LL lvl) {
    if (!IsTty()) return "";
    switch (lvl) {
        case LL::Debug: return "\x1b[90m";
        case LL::Info:  return "\x1b[96m";
        case LL::Ok:    return "\x1b[92m";
        case LL::Warn:  return "\x1b[93m";
        case LL::Err:   return "\x1b[91m";
    }
    return "";
}
const char* Reset() { return IsTty() ? "\x1b[0m" : ""; }

const char* TagFor(LL lvl) {
    switch (lvl) {
        case LL::Debug: return "[D]";
        case LL::Info:  return "[*]";
        case LL::Ok:    return "[+]";
        case LL::Warn:  return "[!]";
        case LL::Err:   return "[X]";
    }
    return "[?]";
}

struct AnsiInit {
    AnsiInit() { EnableAnsi(); }
};
AnsiInit g_ansiInit;

} // namespace

void Log::Emit(LL lvl, const char* fmt, va_list args) {
    if (lvl == LL::Debug && !sVerbose) return;

    char buf[4096];
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    if (n < 0) return;
    buf[n < 4095 ? n : 4095] = 0;

    std::lock_guard<std::mutex> lock(sMtx);

    char ts[16];
    {
        std::time_t t = std::time(nullptr);
        std::tm tmv;
#ifdef _WIN32
        localtime_s(&tmv, &t);
#else
        localtime_r(&t, &tmv);
#endif
        snprintf(ts, sizeof(ts), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    }

    fprintf(stdout, "%s %s %s%s%s\n", ts, TagFor(lvl), ColorFor(lvl), buf, Reset());
    fflush(stdout);
}

void Log::Debug(const char* fmt, ...) { va_list a; va_start(a, fmt); Emit(LL::Debug, fmt, a); va_end(a); }
void Log::Info(const char* fmt, ...)  { va_list a; va_start(a, fmt); Emit(LL::Info,  fmt, a); va_end(a); }
void Log::Ok(const char* fmt, ...)    { va_list a; va_start(a, fmt); Emit(LL::Ok,    fmt, a); va_end(a); }
void Log::Warn(const char* fmt, ...)  { va_list a; va_start(a, fmt); Emit(LL::Warn,  fmt, a); va_end(a); }
void Log::Err(const char* fmt, ...)   { va_list a; va_start(a, fmt); Emit(LL::Err,   fmt, a); va_end(a); }

void Log::Raw(const std::string& s) {
    std::lock_guard<std::mutex> lock(sMtx);
    fprintf(stdout, "%s\n", s.c_str());
    fflush(stdout);
}

void Log::Banner(const std::string& title) {
    std::lock_guard<std::mutex> lock(sMtx);
    const char* c = ColorFor(LL::Info);
    const char* r = Reset();
    fprintf(stdout, "\n%s=============================================%s\n", c, r);
    fprintf(stdout, "%s  %s%s\n", c, title.c_str(), r);
    fprintf(stdout, "%s=============================================%s\n", c, r);
    fflush(stdout);
}

} // namespace dumper
