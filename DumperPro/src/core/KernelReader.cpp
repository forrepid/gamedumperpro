// ============================================================================
// DumperPro - KernelReader.cpp
//
// Optional kernel-assisted memory reader (client side).
//
// Talks to an external kernel driver through \\.\DumperPro using a single
// buffered IOCTL. No driver is shipped with DumperPro; the device contract is
// documented in docs/KERNEL.md. If the device cannot be opened the factory
// returns nullptr and ProcessReader falls back to user-mode reads.
//
// Minimal and safe by design: read-only (Write() always fails).
//
// NOTE: tlhelp32.h is included here as well because module enumeration reuses
// the same Toolhelp snapshot mechanism as ProcessReader (duplicated small
// helper, per design notes).
// ============================================================================

#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0601
#endif
#if !defined(WINVER)
#define WINVER 0x0601
#endif

#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>

namespace dumper {

// custom IOCTL served by the driver (see docs/KERNEL.md)
#define IOCTL_DUMPERPRO_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// wire format of the read request (see docs/KERNEL.md)
struct KReadReq {
    u64 address;
    u32 size;
    u32 pad;
};

namespace {

constexpr u64 kMinValidVa = 0x10000;      // below this is never mapped user space
constexpr u32 kMaxIoChunk = 0x100000;     // 1 MiB per METHOD_BUFFERED call (kernel pool friendly)

const wchar_t* kDevicePath = L"\\\\.\\DumperPro";

// "static-ish" last error reported by TryCreateKernelReader() on failure
std::string g_kernelLastError;

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

} // namespace

// ---------------------------------------------------------------------------
// KernelReader
// ---------------------------------------------------------------------------
class KernelReader final : public IMemoryReader {
public:
    KernelReader(HANDLE hDev, u32 pid) : hDev_(hDev), pid_(pid) {
        ok_ = (hDev_ != nullptr && hDev_ != INVALID_HANDLE_VALUE);
        if (!ok_) {
            lastErr_ = "invalid device handle";
            return;
        }
        if (!pid_)
            Log::Warn("kernel reader bound without a target pid; module enumeration disabled");
        Log::Debug("kernel reader ready (pid %u)", pid_);
    }

    ~KernelReader() override {
        if (hDev_ && hDev_ != INVALID_HANDLE_VALUE) CloseHandle(hDev_);
    }

    bool Read(u64 va, void* out, size_t size) override {
        if (!ok_) {
            if (lastErr_.empty()) lastErr_ = "kernel reader not connected";
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
            const u32 chunk = (u32)std::min<size_t>(size - done, kMaxIoChunk);

            KReadReq req;
            req.address = va + (u64)done;
            req.size    = chunk;
            req.pad     = 0;

            DWORD bytes = 0;
            if (!DeviceIoControl(hDev_, IOCTL_DUMPERPRO_READ, &req, (DWORD)sizeof(req),
                                 dst + done, (DWORD)chunk, &bytes, nullptr)) {
                memset(dst + done, 0, size - done); // never leave stale bytes behind
                lastErr_ = "kernel read failed at " + Hex(va + (u64)done) + ": " +
                           WinErrText(GetLastError());
                return false;
            }

            // validate output length: never trust more than requested,
            // refuse silently-empty transfers
            if (bytes > (DWORD)chunk) bytes = (DWORD)chunk;
            if (bytes == 0) {
                memset(dst + done, 0, size - done);
                lastErr_ = "kernel driver returned no data for " + Hex(va + (u64)done);
                return false;
            }

            done += (size_t)bytes; // partial transfers are retried at the new position
        }
        return true;
    }

    // intentionally unsupported: the driver interface is read-only
    bool Write(u64 va, const void* data, size_t size) override {
        (void)va;
        (void)data;
        (void)size;
        lastErr_ = "kernel reader is read-only (Write is not supported by the driver interface)";
        return false;
    }

    std::vector<ModuleInfo> Modules() override {
        if (mods_.empty() && ok_ && enumAttempts_ < 2) EnumModules();
        return mods_;
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

private:
    // Toolhelp snapshot enumeration, same mechanism as ProcessReader
    void EnumModules() {
        mods_.clear();
        mainBase_ = 0;
        enumAttempts_++;

        if (!pid_) {
            Log::Warn("kernel module enumeration needs a target pid");
            return;
        }

        const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pid_);
        if (snap == INVALID_HANDLE_VALUE) {
            Log::Warn("kernel mode: cannot enumerate modules of pid %u (%s)",
                      pid_, WinErrText(GetLastError()).c_str());
            return;
        }

        struct ModEntry {
            ModuleInfo  info;
            std::string nameLower;
        };
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
                list.push_back(std::move(e));
            } while (Module32NextW(snap, &me));
        } else {
            Log::Warn("kernel mode: Module32FirstW failed (%s)", WinErrText(GetLastError()).c_str());
        }
        CloseHandle(snap);

        // main module: first *.exe, else first module; Mods.front() must be it
        size_t mainIdx = (size_t)-1;
        for (size_t i = 0; i < list.size(); i++)
            if (str::EndsWith(list[i].nameLower, ".exe")) { mainIdx = i; break; }
        if (mainIdx == (size_t)-1 && !list.empty()) mainIdx = 0;

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
            imageName_ = mods_.front().name;
        }

        if (Log::Verbose() && !mods_.empty()) {
            Log::Debug("%zu modules in %s (kernel mode):", mods_.size(), imageName_.c_str());
            const size_t cap = std::min<size_t>(mods_.size(), 64);
            for (size_t i = 0; i < cap; i++) {
                Log::Debug("  %-40s base=%s size=%s", mods_[i].name.c_str(), Hex(mods_[i].base).c_str(),
                           str::HumanSize(mods_[i].size).c_str());
            }
            if (mods_.size() > cap) Log::Debug("  ... (%zu more)", mods_.size() - cap);
        }
    }

    HANDLE hDev_  = nullptr;
    u32    pid_   = 0;
    bool   ok_    = false;
    int    enumAttempts_ = 0;
    u64    mainBase_     = 0;
    std::string imageName_;
    std::string lastErr_;
    std::vector<ModuleInfo> mods_;
};

// ---------------------------------------------------------------------------
// TryCreateKernelReader - opens the driver device; nullptr if unavailable.
// The optional pid binds the client to the resolved target process.
// ---------------------------------------------------------------------------
std::unique_ptr<IMemoryReader> TryCreateKernelReader(u32 pid) {
    g_kernelLastError.clear();

    const HANDLE h = CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        g_kernelLastError = "kernel driver '\\\\.\\DumperPro' not available (see docs/KERNEL.md)";
        Log::Debug("%s (CreateFileW: %s)", g_kernelLastError.c_str(), WinErrText(e).c_str());
        return nullptr;
    }

    auto r = std::make_unique<KernelReader>(h, pid);
    if (!r->IsOK()) {
        g_kernelLastError = r->LastError();
        return nullptr;
    }
    Log::Ok("kernel driver connected: \\\\.\\DumperPro (target pid %u)", pid);
    return r;
}

} // namespace dumper

#else // !defined(_WIN32)

// Symbol kept available on non-Windows hosts; callers never get kernel reads there.
namespace dumper {

std::unique_ptr<IMemoryReader> TryCreateKernelReader(u32 /*pid*/) { return nullptr; }

} // namespace dumper

#endif // _WIN32
