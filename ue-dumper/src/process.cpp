// ============================================================================
//  UnrealDumperX - process.cpp
// ============================================================================
#include "process.h"
#include "driver.h"

namespace udx {

// ---------------------------------------------------------------------------
// Attach / detach
// ---------------------------------------------------------------------------
bool Process::attachById(DWORD pid) {
    detach();
    pid_ = pid;
    handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION,
                          FALSE, pid);
    if (!handle_) {
        // Fall back to wider rights (helps for protected processes when
        // running elevated with a kernel driver attached later on).
        handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    if (!handle_) return false;

    char path[MAX_PATH] = {};
    DWORD size = sizeof(path);
    if (QueryFullProcessImageNameA(handle_, 0, path, &size))
        exeName_ = std::filesystem::path(path).filename().string();
    refreshModules();
    return valid();
}

bool Process::attachByName(const std::string& exeName) {
    const std::string want = lower(exeName);
    for (const auto& p : listProcesses()) {
        if (!want.empty() && lower(p.name) != want) continue;
        if (attachById(p.pid)) return true;
    }
    return false;
}

void Process::detach() {
    if (handle_) { CloseHandle(handle_); handle_ = nullptr; }
    pid_ = 0;
    exeName_.clear();
    modules_.clear();
    modulesValid_ = false;
}

std::vector<ProcEntry> listProcesses(const std::string& exeNameFilter) {
    std::vector<ProcEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (!exeNameFilter.empty() && lower(name) != lower(exeNameFilter)) continue;
            out.push_back({pe.th32ProcessID, name});
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------------
// Memory access - IMPORTANT: every read goes through this single choke point
// so the kernel driver (Module 8) automatically backs up failed RPM calls.
// ---------------------------------------------------------------------------
bool Process::read(uintptr_t addr, void* dst, size_t size) const {
    if (!dst || size == 0) return false;
    if (addr + size < addr) return false;   // overflow guard

    // Page-granular loop: RPM fails whole-call when ANY page is uncommitted,
    // so we read page by page and try the kernel driver for the bad pages.
    usize done = 0;
    while (done < size) {
        const uintptr_t cur = addr + done;
        const usize pageLeft = 0x1000 - (cur & 0xFFF);
        const usize chunk = std::min(pageLeft, size - done);

        BOOL okPage = FALSE;
        if (handle_)
            okPage = ReadProcessMemory(handle_, (LPCVOID)cur,
                                       (void*)((u8*)dst + done), chunk, nullptr);
        if (!okPage && driver_ && driver_->connected())
            okPage = driver_->readMem(pid_, cur, (u8*)dst + done, (u32)chunk)
                         ? TRUE : FALSE;
        if (!okPage) return false;
        done += chunk;
    }
    return true;
}

bool Process::write(uintptr_t addr, const void* src, size_t size) const {
    if (!handle_ || !src || size == 0) return false;
    SIZE_T written = 0;
    return WriteProcessMemory(handle_, (LPVOID)addr, src, size, &written) &&
           written == size;
}

bool Process::ptrReadable(uintptr_t addr) const {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(handle_, (LPCVOID)addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    if (mbi.Protect == PAGE_NOACCESS) return false;
    return true;
}

std::string Process::readCString(uintptr_t addr, size_t maxLen) const {
    if (!addr) return {};
    char buf[1024];
    const size_t n = std::min(maxLen, sizeof(buf));
    if (!read(addr, buf, n)) return {};
    buf[n - 1] = '\0';
    const size_t len = strnlen(buf, n);
    return std::string(buf, len);
}

std::string Process::readWideString(uintptr_t addr, size_t maxChars) const {
    if (!addr) return {};
    std::wstring wide;
    wchar_t buf[256];
    const size_t chunk = std::min(maxChars, sizeof(buf) / sizeof(wchar_t));
    while (wide.size() < maxChars) {
        const size_t want = std::min(chunk, maxChars - wide.size());
        if (!read(addr + wide.size() * sizeof(wchar_t), buf,
                  want * sizeof(wchar_t)))
            break;
        for (size_t i = 0; i < want; ++i) {
            if (buf[i] == L'\0') return wideToUtf8(wide);
            wide.push_back(buf[i]);
        }
        if (wide.size() > maxChars) break;
    }
    return wideToUtf8(wide);
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------
void Process::refreshModules() {
    modules_.clear();
    modulesValid_ = false;
    if (!handle_) return;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo m;
            m.name = me.szModule;
            m.path = me.szExePath;
            m.base = (uintptr_t)me.modBaseAddr;
            m.size = me.modBaseSize;
            modules_.push_back(std::move(m));
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    modulesValid_ = true;
}

const std::vector<ModuleInfo>& Process::modules() {
    if (!modulesValid_) refreshModules();
    return modules_;
}

const ModuleInfo* Process::mainModule() {
    auto& mods = modules();
    for (const auto& m : mods)
        if (lower(m.name) == lower(exeName_)) return &m;
    return mods.empty() ? nullptr : &mods[0];
}

const ModuleInfo* Process::findModule(const std::string& nameLower) {
    auto& mods = modules();
    const std::string want = lower(nameLower);
    for (const auto& m : mods)
        if (lower(m.name) == want) return &m;
    return nullptr;
}

std::optional<ModuleInfo> Process::moduleContaining(uintptr_t addr) {
    for (const auto& m : modules())
        if (m.contains(addr)) return m;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Committed ranges
// ---------------------------------------------------------------------------
std::vector<MemRange> Process::committedRanges(bool executableOnly) {
    std::vector<MemRange> out;
    if (!handle_) return out;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    while (addr < 0x7FFFFFFEFFFFULL) {
        if (!VirtualQueryEx(handle_, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
            mbi.Protect != PAGE_NOACCESS) {
            const bool exec = (mbi.Protect & 0xF0) != 0 &&
                              (mbi.Protect & PAGE_GUARD) == 0;
            if (!executableOnly || exec) {
                MemRange r;
                r.start = (uintptr_t)mbi.BaseAddress;
                r.end = r.start + mbi.RegionSize;
                r.protect = mbi.Protect;
                if (r.end > r.start) out.push_back(r);
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return out;
}

} // namespace udx
