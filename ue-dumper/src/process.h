// ============================================================================
//  UnrealDumperX - process.h
//  Target process abstraction: attach, memory access (RPM + kernel-driver
//  fallback), module enumeration, committed-range walking (Module 1 / 8).
// ============================================================================
#pragma once
#include "common.h"

namespace udx {

class Driver;   // kernel-driver bridge (driver.h)

struct ModuleInfo {
    std::string name;      // "Game-Win64-Shipping.exe"
    std::string path;      // full path on disk
    uintptr_t   base = 0;
    size_t      size = 0;
    bool        contains(uintptr_t a) const { return a >= base && a < base + size; }
};

struct MemRange {
    uintptr_t start = 0;
    uintptr_t end   = 0;   // exclusive
    uint32_t  protect = 0;
    bool executable() const {
        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                           PAGE_EXECUTE_WRITECOPY)) != 0;
    }
};

class Process {
public:
    Process() = default;
    ~Process() { detach(); }

    bool attachByName(const std::string& exeName);
    bool attachById(DWORD pid);
    void detach();

    bool valid() const { return handle_ != nullptr; }
    HANDLE handle() const { return handle_; }
    DWORD pid() const { return pid_; }
    const std::string& exeName() const { return exeName_; }

    // Kernel driver hook (optional; used automatically when RPM fails).
    void setDriver(Driver* driver) { driver_ = driver; }

    // ---- memory access -----------------------------------------------------
    bool read(uintptr_t addr, void* dst, size_t size) const;
    template <typename T>
    T read(uintptr_t addr, T def = T{}) const {
        T v{};
        if (!read(addr, &v, sizeof(T))) return def;
        return v;
    }
    template <typename T>
    T readOr(uintptr_t addr, T def) const { return read<T>(addr, def); }
    bool write(uintptr_t addr, const void* src, size_t size) const;
    bool ptrReadable(uintptr_t addr) const;

    std::string readCString(uintptr_t addr, size_t maxLen = 512) const;      // ANSI/UTF-8
    std::string readWideString(uintptr_t addr, size_t maxChars = 512) const; // UTF-16 -> UTF-8

    // ---- modules -----------------------------------------------------------
    void refreshModules();
    const std::vector<ModuleInfo>& modules();
    const ModuleInfo* mainModule();
    const ModuleInfo* findModule(const std::string& nameLower);   // case-insensitive
    std::optional<ModuleInfo> moduleContaining(uintptr_t addr);

    // ---- committed memory ranges (VirtualQueryEx walk) ----------------------
    std::vector<MemRange> committedRanges(bool executableOnly = false);

private:
    HANDLE handle_ = nullptr;
    DWORD  pid_ = 0;
    std::string exeName_;
    Driver* driver_ = nullptr;
    std::vector<ModuleInfo> modules_;
    bool modulesValid_ = false;
};

// Process listing for `--list` (empty exeName = all processes).
struct ProcEntry { DWORD pid; std::string name; };
std::vector<ProcEntry> listProcesses(const std::string& exeNameFilter = {});

} // namespace udx
