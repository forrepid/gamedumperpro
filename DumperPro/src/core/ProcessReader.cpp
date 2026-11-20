// DumperPro - ProcessReader.cpp
//
// Live-process memory reader built on the Win32 API:
//   - attach via OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | ...)
//   - Read()  = ReadProcessMemory loop with partial-copy handling
//   - Write() = WriteProcessMemory loop with VirtualProtectEx repair for
//               read-only/guarded pages (live hex patch support)
//   - process finding + module enumeration via Toolhelp snapshots
//
// If kernel-assisted mode was requested, CreateProcessReader first tries the
// kernel driver client (KernelReader.cpp, device contract in docs/KERNEL.md)
// and falls back to user-mode reads with a single warning when the driver is
// not available.
//
// This is one of only two translation units allowed to include Win32 headers
// (the other is KernelReader.cpp); FileReader.cpp stays fully portable.
// ============================================================================

#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0601 // QueryFullProcessImageNameW requires Vista+
#endif
#if !defined(WINVER)
#define WINVER 0x0601
#endif

#include <windows.h>
#include <tlhelp32.h>

namespace dumper {

// Implemented in KernelReader.cpp. The optional pid binds the kernel client to
// the already-resolved target process (0 = unspecified). Declared here under
// an extern declaration as agreed between the two reader backends.
extern std::unique_ptr<IMemoryReader> TryCreateKernelReader(u32 pid = 0);

namespace {

constexpr u64 kMinValidVa    = 0x10000;      // below this is never mapped user space
constexpr size_t kMaxRpmChunk = 0x40000000;  // clamp a single Read/WriteProcessMemory call

// wchar -> UTF-8 via WideCharToMultiByte (surrogates handled by the OS)
std::string WideToUtf8Win(const wchar_t* ws, int len = -1) {
    if (!ws || !len) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, ws, len, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out((size_t)need, '\0');
    const int got = WideCharToMultiByte(CP_UTF8, 0, ws, len, out.data(), need, nullptr, nullptr);
    if (got <= 0) return {};
    if (len < 0 && !out.empty() && out.back() == '\0') out.pop_back(); // len==-1 appends terminator
    return out;
}

// readable text for a Win32 error code (used in LastError messages)
std::string WinErrText(DWORD e) {
    std::string out;
    LPSTR buf = nullptr;
    const DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   (LPSTR)&buf, 0, nullptr);
    if (buf) {
        if (n) out.assign(buf, n);
        LocalFree((HLOCAL)buf);
    }
    while (!out.empty() &&
           (out.back() == '\r' || out.back() == '\n' || out.back() == ' ' || out.back() == '.'))
        out.pop_back();
    if (out.empty()) {
        char b[40];
        snprintf(b, sizeof(b), "win32 error %lu", (unsigned long)e);
        out = b;
    } else {
        out += " [err " + std::to_string((unsigned long)e) + "]";
    }
    return out;
}

struct ProcEntry {
    u32 pid = 0;
    std::string name;
};

// one snapshot of all running processes (pid + image name)
bool SnapshotProcesses(std::vector<ProcEntry>& out) {
    out.clear();
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }
    do {
        if (!pe.th32ProcessID) continue; // "System Idle Process"
        ProcEntry e;
        e.pid  = (u32)pe.th32ProcessID;
        e.name = WideToUtf8Win(pe.szExeFile);
        out.push_back(std::move(e));
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return true;
}

std::string SnapshotProcessName(u32 pid) {
    std::vector<ProcEntry> procs;
    if (!SnapshotProcesses(procs)) return {};
    for (const ProcEntry& p : procs)
        if (p.pid == pid) return p.name;
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// ProcessReader
// ---------------------------------------------------------------------------
class ProcessReader final : public IMemoryReader {
public:
    // inert instance; used by the factory to carry an error message to the caller
    ProcessReader() = default;

    explicit ProcessReader(u32 pid, const std::string& nameHint = {}) {
        pid_ = pid;
        if (!pid_) {
            lastErr_ = "invalid pid 0";
            return;
        }
        // Prefer a handle that allows writes (live hex patching). Some targets
        // (protected processes / restricted tokens) reject write access while
        // still allowing read access, so fall back to a read-only handle.
        hProc_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                             PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid_);
        if (!hProc_) {
            hProc_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid_);
            if (hProc_)
                Log::Warn("opened %s without VM write access - live hex patch (--hex-live) unavailable",
                          nameHint.empty() ? "target" : nameHint.c_str());
        }
        if (!hProc_) {
            lastErr_ = "OpenProcess(pid " + std::to_string(pid_) + ") failed: " +
                       WinErrText(GetLastError()) +
                       "; the process may have exited, or access is denied "
                       "(run as Administrator, or use --kernel / --file)";
            return;
        }
        ok_ = true;
        EnumModules(); // best effort; Modules() retries once later if needed

        if (imageName_.empty())
            imageName_ = !nameHint.empty() ? nameHint : SnapshotProcessName(pid_);
        if (imageName_.empty()) imageName_ = "pid " + std::to_string(pid_);

        if (!mods_.empty()) {
            Log::Ok("attached to %s (pid %u, %zu modules, main base %s)",
                    imageName_.c_str(), pid_, mods_.size(), Hex(mainBase_).c_str());
        } else {
            Log::Warn("attached to %s (pid %u) but no modules are visible (protected target? try --kernel)",
                      imageName_.c_str(), pid_);
        }
    }

    ~ProcessReader() override {
        if (hProc_) CloseHandle(hProc_);
    }

    bool Read(u64 va, void* out, size_t size) override {
        if (!ok_ || !hProc_) {
            if (lastErr_.empty()) lastErr_ = "process not attached";
            return false;
        }
        if (size == 0) return true;
        if (!out) {
            lastErr_ = "null output buffer";
            return false;
        }
        if (va < kMinValidVa) {
            lastErr_ = "read at " + Hex(va) + " rejected (near-null address)";
            return false;
        }
        if (va > UINT64_MAX - (u64)size) {
            lastErr_ = "read at " + Hex(va) + " overflows the address range";
            return false;
        }

        u8* dst = (u8*)out;
        size_t done = 0;
        while (done < size) {
            const size_t chunk = std::min<size_t>(size - done, kMaxRpmChunk);
            SIZE_T got = 0;
            const BOOL okRpm = ReadProcessMemory(hProc_, (LPCVOID)(uintptr_t)(va + (u64)done),
                                                 dst + done, (SIZE_T)chunk, &got);
            if (got > (SIZE_T)chunk) got = (SIZE_T)chunk; // defensive clamp

            if (got == 0) {
                // hard failure (unmapped/protected page, dead process, ...)
                memset(dst + done, 0, size - done);
                lastErr_ = "ReadProcessMemory failed at " + Hex(va + (u64)done) + ": " +
                           WinErrText(okRpm ? 0 : GetLastError());
                return false;
            }
            // partial copies (ERROR_PARTIAL_COPY) keep what arrived and retry
            // at the new position; the next unmapped page then fails precisely
            done += (size_t)got;
        }
        return true;
    }

    std::vector<ModuleInfo> Modules() override {
        if (mods_.empty() && ok_ && enumAttempts_ < 2) EnumModules();
        return mods_;
    }

    bool Write(u64 va, const void* data, size_t size) override {
        if (!ok_ || !hProc_) {
            if (lastErr_.empty()) lastErr_ = "process not attached";
            return false;
        }
        if (size == 0) return true;
        if (!data) {
            lastErr_ = "null input buffer";
            return false;
        }
        if (va < kMinValidVa) {
            lastErr_ = "write at " + Hex(va) + " rejected (near-null address)";
            return false;
        }
        if (va > UINT64_MAX - (u64)size) {
            lastErr_ = "write at " + Hex(va) + " overflows the address range";
            return false;
        }

        const u8* src = (const u8*)data;
        size_t done = 0;
        while (done < size) {
            const size_t chunk = std::min<size_t>(size - done, kMaxRpmChunk);
            SIZE_T wrote = 0;
            const BOOL okWpm = WriteProcessMemory(hProc_, (LPVOID)(uintptr_t)(va + (u64)done),
                                                  src + done, (SIZE_T)chunk, &wrote);
            if (wrote > (SIZE_T)chunk) wrote = (SIZE_T)chunk; // defensive clamp

            if (wrote == 0) {
                // read-only / guarded page: repair protection once, then retry
                MEMORY_BASIC_INFORMATION mbi{};
                const LPVOID page = (LPVOID)(uintptr_t)(va + (u64)done);
                if (VirtualQueryEx(hProc_, page, &mbi, sizeof(mbi)) && (mbi.State & MEM_COMMIT)) {
                    DWORD want = PAGE_READWRITE;
                    switch (mbi.Protect) {
                        case PAGE_EXECUTE:         want = PAGE_EXECUTE_READWRITE; break;
                        case PAGE_EXECUTE_READ:    want = PAGE_EXECUTE_READWRITE; break;
                        case PAGE_EXECUTE_WRITECOPY: want = PAGE_EXECUTE_WRITECOPY; break;
                        case PAGE_WRITECOPY:       want = PAGE_WRITECOPY; break;
                        default:                   want = PAGE_READWRITE; break;
                    }
                    DWORD oldp = 0;
                    if (VirtualProtectEx(hProc_, page, chunk, want, &oldp)) {
                        const BOOL okRetry = WriteProcessMemory(hProc_, page, src + done,
                                                                (SIZE_T)chunk, &wrote);
                        DWORD restore = 0;
                        VirtualProtectEx(hProc_, page, chunk, oldp, &restore);
                        if (okRetry && wrote > 0) { done += (size_t)wrote; continue; }
                    }
                }
                lastErr_ = "WriteProcessMemory failed at " + Hex(va + (u64)done) + ": " +
                           WinErrText(okWpm ? 0 : GetLastError());
                return false;
            }
            // partial writes keep what arrived and retry at the new position
            done += (size_t)wrote;
        }
        return true;
    }

    u64 MainModuleBase() override {
        if (mods_.empty() && ok_ && enumAttempts_ < 2) EnumModules();
        return mainBase_;
    }

    std::string TargetName() override {
        if (imageName_.empty() && ok_ && enumAttempts_ < 2) EnumModules();
        if (!imageName_.empty()) return imageName_;
        return "pid " + std::to_string(pid_);
    }

    bool IsLiveProcess() const override { return true; }
    bool IsOK() const override { return ok_; }
    std::string LastError() const override { return lastErr_; }

    // factory helper for the inert instance (not part of IMemoryReader)
    void SetError(const std::string& m) { lastErr_ = m; }

private:
    struct ModEntry {
        ModuleInfo  info;
        std::string nameLower;
        std::string pathLower;
    };

    void EnumModules() {
        mods_.clear();
        mainBase_ = 0;
        enumAttempts_++;

        // process image path -> identifies the main module precisely
        wchar_t imgPath[1024] = {};
        DWORD pathLen = (DWORD)(sizeof(imgPath) / sizeof(imgPath[0]));
        bool havePath = false;
        if (QueryFullProcessImageNameW(hProc_, 0, imgPath, &pathLen) && pathLen) havePath = true;
        const std::string imgPathLower = havePath ? str::Lower(WideToUtf8Win(imgPath, (int)pathLen)) : "";

        const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pid_);
        if (snap == INVALID_HANDLE_VALUE) {
            Log::Warn("cannot enumerate modules of pid %u (%s)", pid_, WinErrText(GetLastError()).c_str());
            return;
        }

        std::vector<ModEntry> list;
        std::set<u64> seenBases;
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                const u64 base = (u64)(uintptr_t)me.modBaseAddr;
                const u32 msize = me.modBaseSize;
                if (!base || !msize) continue;
                if (!seenBases.insert(base).second) continue; // dedupe
                ModEntry e;
                e.info.name = WideToUtf8Win(me.szModule);
                e.info.base = base;
                e.info.size = msize;
                e.nameLower = str::Lower(e.info.name);
                e.pathLower = str::Lower(WideToUtf8Win(me.szExePath));
                list.push_back(std::move(e));
            } while (Module32NextW(snap, &me));
        } else {
            Log::Warn("Module32FirstW failed for pid %u (%s)", pid_, WinErrText(GetLastError()).c_str());
        }
        CloseHandle(snap);

        // main module: process-image-path match (== image base), else first *.exe, else first module
        size_t mainIdx = (size_t)-1;
        if (!imgPathLower.empty()) {
            for (size_t i = 0; i < list.size(); i++)
                if (list[i].pathLower == imgPathLower) { mainIdx = i; break; }
        }
        if (mainIdx == (size_t)-1) {
            for (size_t i = 0; i < list.size(); i++)
                if (str::EndsWith(list[i].nameLower, ".exe")) { mainIdx = i; break; }
        }
        if (mainIdx == (size_t)-1 && !list.empty()) mainIdx = 0;

        // Mods.front() must be the main module (main.cpp picks it), the rest by base desc
        if (mainIdx != (size_t)-1) {
            ModuleInfo main = list[mainIdx].info;
            list.erase(list.begin() + (std::ptrdiff_t)mainIdx);
            std::sort(list.begin(), list.end(),
                      [](const ModEntry& a, const ModEntry& b) { return a.info.base > b.info.base; });
            mods_.push_back(std::move(main));
            for (ModEntry& e : list) mods_.push_back(std::move(e.info));
        } else {
            std::sort(list.begin(), list.end(),
                      [](const ModEntry& a, const ModEntry& b) { return a.info.base > b.info.base; });
            for (ModEntry& e : list) mods_.push_back(std::move(e.info));
        }

        if (!mods_.empty()) {
            mainBase_ = mods_.front().base;
            if (imageName_.empty()) imageName_ = mods_.front().name;
        }

        if (Log::Verbose() && !mods_.empty()) {
            Log::Debug("%zu modules in %s:", mods_.size(), imageName_.c_str());
            const size_t cap = std::min<size_t>(mods_.size(), 64);
            for (size_t i = 0; i < cap; i++) {
                Log::Debug("  %-40s base=%s size=%s", mods_[i].name.c_str(), Hex(mods_[i].base).c_str(),
                           str::HumanSize(mods_[i].size).c_str());
            }
            if (mods_.size() > cap) Log::Debug("  ... (%zu more)", mods_.size() - cap);
        }
    }

    HANDLE hProc_ = nullptr;
    u32    pid_   = 0;
    bool   ok_    = false;
    int    enumAttempts_ = 0;
    u64    mainBase_     = 0;
    std::string imageName_;
    std::string lastErr_;
    std::vector<ModuleInfo> mods_;
};

// ---------------------------------------------------------------------------
// CreateProcessReader - factory declared in MemoryReader.h
// ---------------------------------------------------------------------------
std::unique_ptr<IMemoryReader> CreateProcessReader(const std::string& procName, u32 pid, bool kernelAssisted) {
    std::vector<ProcEntry> procs;
    const bool haveProcs = SnapshotProcesses(procs);

    // factories return a live (IsOK()==false) reader so LastError() stays reportable
    auto carryError = [](const std::string& msg) -> std::unique_ptr<IMemoryReader> {
        auto r = std::make_unique<ProcessReader>();
        r->SetError(msg);
        return r;
    };

    auto buildNotFound = [&](const std::string& what) -> std::string {
        if (!haveProcs) return "cannot enumerate running processes (toolhelp snapshot failed)";
        std::string msg = "no process matching '" + what + "' found; running processes (first 15):";
        const u32 self = (u32)GetCurrentProcessId();
        size_t shown = 0;
        for (const ProcEntry& p : procs) {
            if (p.pid == 0 || p.pid == self) continue;
            if (shown == 15) {
                msg += "\n  ... (use --pid <n> to attach to a specific process)";
                break;
            }
            msg += "\n  pid " + std::to_string(p.pid) + "  " + p.name;
            shown++;
        }
        if (!shown) msg += "\n  (no visible processes; run as Administrator)";
        return msg;
    };

    u32 targetPid = 0;
    std::string targetName;

    if (pid > 0) {
        // explicit pid wins; resolve its image name from the process snapshot
        targetPid = pid;
        if (haveProcs) {
            for (const ProcEntry& p : procs)
                if (p.pid == pid) { targetName = p.name; break; }
            if (targetName.empty())
                Log::Debug("pid %u not present in the process snapshot (may have just exited)", pid);
        }
    } else if (!procName.empty()) {
        if (!haveProcs) return carryError(buildNotFound(procName));

        // case-insensitive match: image name equals the argument OR ends with it
        const std::string want = str::Lower(procName);
        std::vector<const ProcEntry*> matches;
        for (const ProcEntry& p : procs) {
            const std::string n = str::Lower(p.name);
            if (n == want || str::EndsWith(n, want)) matches.push_back(&p);
        }
        if (matches.empty()) return carryError(buildNotFound(procName));

        targetPid  = matches.front()->pid;
        targetName = matches.front()->name;
        if (matches.size() > 1) {
            std::string others;
            for (size_t i = 1; i < matches.size(); i++) {
                others += (i > 1 ? ", " : "");
                others += matches[i]->name + " (pid " + std::to_string(matches[i]->pid) + ")";
            }
            Log::Info("multiple processes match '%s', using %s (pid %u); also: %s",
                      procName.c_str(), targetName.c_str(), targetPid, others.c_str());
        }
    } else {
        return carryError("no target specified: use --process <name> or --pid <n>");
    }

    // kernel-assisted reads take priority; the kernel client binds to the
    // resolved pid, so the target must be known before trying the driver
    if (kernelAssisted) {
        if (std::unique_ptr<IMemoryReader> k = TryCreateKernelReader(targetPid)) return k;
        Log::Warn("kernel driver not available, falling back to user-mode reads");
    }

    return std::make_unique<ProcessReader>(targetPid, targetName);
}

} // namespace dumper

#else // !defined(_WIN32)

// Win32 reader backends are excluded on non-Windows hosts (see CMakeLists.txt).
namespace dumper {

std::unique_ptr<IMemoryReader> CreateProcessReader(const std::string& procName, u32 pid, bool kernelAssisted) {
    (void)procName;
    (void)pid;
    (void)kernelAssisted;
    Log::Err("process mode requires a Windows build (Win32 API unavailable on this host)");
    return nullptr;
}

} // namespace dumper

#endif // _WIN32
