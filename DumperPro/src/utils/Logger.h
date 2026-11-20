// DumperPro - logger (console, colored when available)
#pragma once
#include "../framework.h"

namespace dumper {

enum class LL : int { Debug = 0, Info = 1, Ok = 2, Warn = 3, Err = 4 };

class Log {
public:
    static void SetVerbose(bool v) { sVerbose = v; }
    static bool Verbose() { return sVerbose; }

    static void Debug(const char* fmt, ...);   // only shown when --verbose
    static void Info(const char* fmt, ...);
    static void Ok(const char* fmt, ...);
    static void Warn(const char* fmt, ...);
    static void Err(const char* fmt, ...);

    static void Raw(const std::string& s);     // no prefix
    static void Banner(const std::string& title);

private:
    static void Emit(LL lvl, const char* fmt, va_list args);
    static bool sVerbose;
    static std::mutex sMtx;
};

} // namespace dumper
