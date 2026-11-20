// ============================================================================
// DumperPro - LeechReader.cpp
//
// Optional LeechCore-backed memory reader (device level, physical addresses).
//
// Binds leechcore.dll dynamically (LoadLibraryA + GetProcAddress) so the
// DumperPro binary starts fine even when LeechCore is not installed - the
// factory returns nullptr gracefully with an install hint in that case.
// ABI constants/structs mirrored from leechcore.h header version 2.23
// (ufrisk/LeechCore master; see LeechReader.h for the exact verified shapes).
//
// LeechCore exposes raw PHYSICAL memory only. Process/module enumeration is
// not part of this API - that belongs to MemProcFS (vmm.dll, VMMDLL_*).
// Therefore Modules() returns {} and MainModuleBase() returns 0 here.
//
// This is one of only three translation units allowed to include Win32
// headers (ProcessReader.cpp, KernelReader.cpp, LeechReader.cpp).
// ============================================================================

#include "core/MemoryReader.h"
#include "core/LeechReader.h"
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

namespace dumper {

// ---------------------------------------------------------------------------
// Minimal LeechCore ABI (verified against leechcore.h v2.23, ufrisk master).
// Deliberately LeechCore-prefixed typedef names to avoid clashing with any
// QWORD/PVOID definitions from other Win32 SDK/MinGW headers.
// ---------------------------------------------------------------------------

// The header comment says "must equal LC_CREATE_VERSION" but no such macro
// exists; the real constant in leechcore.h v2.23 is LC_CONFIG_VERSION.
#define LEECH_LC_CONFIG_VERSION 0xc0fd0002

// LC_OPT_CORE_ADDR_MAX (R): maximum physical address of the device.
#define LEECH_LC_OPT_CORE_ADDR_MAX 0x1000000800000000ull

typedef unsigned __int64 LcQword, *PLcQword;

typedef struct LcConfig {
    // set by caller
    DWORD dwVersion;                        // LEECH_LC_CONFIG_VERSION
    DWORD dwPrintfVerbosity;                // 0 = keep leechcore quiet
    CHAR  szDevice[MAX_PATH];               // device string, e.g. "fpga"
    CHAR  szRemote[MAX_PATH];               // remote config (unused here)
    int (*pfn_printf_opt)(char const*, ...);// optional printf hook (unused)
    // set by caller, updated by LeechCore
    LcQword paMax;                          // 0 = auto-detect
    // set by LeechCore
    BOOL fVolatile;
    BOOL fWritable;
    BOOL fRemote;
    BOOL fRemoteDisableCompress;
    CHAR szDeviceName[MAX_PATH];            // resolved name, e.g. "fpga"/"file"
} LcConfig, *PLcConfig;

// function pointer types for the dynamically bound exports
typedef HANDLE (*fnLcCreate)(PLcConfig);
typedef BOOL   (*fnLcRead)(HANDLE, LcQword, DWORD, PBYTE);
typedef BOOL   (*fnLcWrite)(HANDLE, LcQword, DWORD, PBYTE);
typedef VOID   (*fnLcClose)(HANDLE);
typedef VOID   (*fnLcMemFree)(PVOID);
typedef BOOL   (*fnLcGetOption)(HANDLE, LcQword, PLcQword);
typedef BOOL   (*fnLcSetOption)(HANDLE, LcQword, LcQword);

namespace {

constexpr u64  kMinValidVa  = 0x10000;   // near-null guard, same as ProcessReader
constexpr u32  kMaxIoChunk  = 0x100000;  // 1 MiB per LcRead/LcWrite call

// "static-ish" last error reported by TryCreateLeechReader() on failure
std::string g_leechLastError;

} // namespace

// ---------------------------------------------------------------------------
// LeechReader
// ---------------------------------------------------------------------------
class LeechReader final : public IMemoryReader {
public:
    LeechReader(HMODULE hMod, HANDLE hLC, fnLcRead fnRead, fnLcWrite fnWrite,
                fnLcClose fnClose, fnLcGetOption fnGetOption,
                const LcConfig& cfg, const std::string& deviceString)
        : hMod_(hMod), hLC_(hLC), fnRead_(fnRead), fnWrite_(fnWrite),
          fnClose_(fnClose), fnGetOption_(fnGetOption), device_(deviceString) {
        ok_ = (hMod_ && hLC_ && fnRead_ && fnClose_);
        if (!ok_) {
            lastErr_ = "invalid LeechCore handle";
            return;
        }
        // LcCreate updated cfg: reflect the device's own capabilities
        writable_  = cfg.fWritable != FALSE;
        volatile_  = cfg.fVolatile != FALSE;
        deviceName_ = cfg.szDeviceName;

        // best-effort max physical address report (never fails the reader)
        LcQword paMax = 0;
        if (fnGetOption_ && fnGetOption_(hLC_, LEECH_LC_OPT_CORE_ADDR_MAX, &paMax) && paMax)
            paMax_ = (u64)paMax;

        Log::Ok("LeechCore device ready: '%s'%s (writable=%s%s, maxPA=%s)",
                device_.c_str(),
                deviceName_.empty() ? "" : (" -> " + deviceName_).c_str(),
                writable_ ? "yes" : "no",
                volatile_ ? ", volatile" : "",
                paMax_ ? Hex(paMax_).c_str() : "auto");
        Log::Debug("leechcore.dll bound dynamically; LcRead/LcWrite/LcClose/LcGetOption active");
    }

    ~LeechReader() override {
        if (hLC_ && fnClose_) fnClose_(hLC_);
        if (hMod_) FreeLibrary(hMod_);
    }

    bool Read(u64 pa, void* out, size_t size) override {
        if (!ok_ || !hLC_) {
            if (lastErr_.empty()) lastErr_ = "leechcore cihazi bagli degil";
            return false;
        }
        if (size == 0) return true;
        if (!out) {
            lastErr_ = "cikis tamponu null";
            return false;
        }
        if (pa < kMinValidVa) {
            lastErr_ = "read at " + Hex(pa) + " rejected (near-null physical address)";
            return false;
        }
        if (pa > UINT64_MAX - (u64)size) {
            lastErr_ = "read at " + Hex(pa) + " overflows the address range";
            return false;
        }

        // LeechCore dosya cihazi (ve bazi kaynaklar) 4096 bayt sayfa
        // granularitesinde okur: adres ve boyut 4K hizali degilse sayfa
        // sayfa okuyup icerden keseriz (leechcore birebir test edildi).
        constexpr u64 kPage = 4096;
        if ((pa % kPage) == 0 && (size % kPage) == 0) {
            // hizali hizli yol: mevcut parcali okuma
            return readChunked(pa, (u8*)out, size);
        }
        return readPageShim(pa, (u8*)out, size);
    }

private:
    bool readChunked(u64 pa, u8* dst, size_t size) {
        size_t done = 0;
        while (done < size) {
            const u32 chunk = (u32)std::min<size_t>(size - done, kMaxIoChunk);
            if (!fnRead_(hLC_, (LcQword)(pa + (u64)done), chunk, dst + done)) {
                memset(dst + done, 0, size - done); // never leave stale bytes behind
                lastErr_ = "LcRead failed at " + Hex(pa + (u64)done) + " (" +
                           std::to_string(chunk) + " bytes; unmapped physical page?)";
                return false;
            }
            done += (size_t)chunk;
        }
        return true;
    }

    bool readPageShim(u64 pa, u8* dst, size_t size) {
        std::vector<u8> page(kPage); // cagri basina yerel - is parcasi guvenligi
        size_t done = 0;
        while (done < size) {
            const u64 paLo = (pa + done) & ~(kPage - 1);
            const u32 off = (u32)((pa + done) - paLo);
            const u32 take = (u32)std::min<size_t>(size - done, kPage - off);
            if (!fnRead_(hLC_, (LcQword)paLo, (u32)kPage, page.data())) {
                memset(dst + done, 0, size - done);
                lastErr_ = "LcRead failed at " + Hex(paLo) + " (page 4096; unmapped physical page?)";
                return false;
            }
            memcpy(dst + done, page.data() + off, take);
            done += take;
        }
        return true;
    }

public:
    // LcWrite exists in leechcore.h v2.23 (BOOL LcWrite(HANDLE, QWORD, DWORD, PBYTE)).
    // Many devices are read-only (fWritable reported by LeechCore at create time).
    bool Write(u64 pa, const void* data, size_t size) override {
        if (!ok_ || !hLC_) {
            if (lastErr_.empty()) lastErr_ = "leechcore device not connected";
            return false;
        }
        if (!fnWrite_) { // never expected: bound in the factory
            lastErr_ = "LcWrite not bound";
            return false;
        }
        if (size == 0) return true;
        if (!data) {
            lastErr_ = "null input buffer";
            return false;
        }
        if (!writable_) {
            lastErr_ = "device '" + device_ + "' reports fWritable=0 (read-only source)";
            return false;
        }
        if (pa < kMinValidVa) {
            lastErr_ = "write at " + Hex(pa) + " rejected (near-null physical address)";
            return false;
        }
        if (pa > UINT64_MAX - (u64)size) {
            lastErr_ = "write at " + Hex(pa) + " overflows the address range";
            return false;
        }

        const u8* src = (const u8*)data;
        // 4K hizali coklu sayfa yazimlari dogrudan; digerleri oku-degistir-yaz
        constexpr u64 kPage = 4096;
        if ((pa % kPage) == 0 && (size % kPage) == 0) {
            size_t done = 0;
            while (done < size) {
                const u32 chunk = (u32)std::min<size_t>(size - done, kMaxIoChunk);
                // leechcore.h declares PBYTE (no const) - casting constness away is
                // safe: LcWrite does not modify the buffer it is given.
                if (!fnWrite_(hLC_, (LcQword)(pa + (u64)done), chunk,
                              (PBYTE)(const_cast<u8*>(src + done)))) {
                    lastErr_ = "LcWrite failed at " + Hex(pa + (u64)done) + " (" +
                               std::to_string(chunk) + " bytes)";
                    return false;
                }
                done += (size_t)chunk;
            }
            return true;
        }

        // oku-degistir-yaz (sayfa granularitesi)
        std::vector<u8> page(kPage);
        size_t done = 0;
        while (done < size) {
            const u64 paLo = (pa + done) & ~(kPage - 1);
            const u32 off = (u32)((pa + done) - paLo);
            const u32 take = (u32)std::min<size_t>(size - done, kPage - off);
            if (!fnRead_(hLC_, (LcQword)paLo, (u32)kPage, page.data())) {
                memset(page.data(), 0, kPage); // okunamayan sayfa: sifir tabani ile devam
            }
            memcpy(page.data() + off, src + done, take);
            if (!fnWrite_(hLC_, (LcQword)paLo, (u32)kPage, page.data())) {
                lastErr_ = "LcWrite failed at " + Hex(paLo) + " (RMW page)";
                return false;
            }
            done += take;
        }
        return true;
    }

    // LeechCore is a device-level API (physical memory in/out). There is no
    // process/module model here - that layer belongs to MemProcFS vmm.dll
    // (VMMDLL_Map_GetModule / VMMDLL_Map_GetVad). main.cpp handles the empty
    // module list with a documented best-effort raw scan (docs/LEECH.md).
    std::vector<ModuleInfo> Modules() override {
        static bool warned = false;
        if (!warned) {
            warned = true;
            Log::Debug("LeechCore: no module model at device level (use MemProcFS vmm.dll "
                       "or --file with a raw dump for module-aware analysis)");
        }
        return {};
    }

    u64 MainModuleBase() override { return 0; }

    std::string TargetName() override { return device_; }

    // device-backed live memory (FPGA/PMEM/driver-backed devices are live;
    // file-backed devices behave as offline but the handle contract is the same)
    bool IsLiveProcess() const override { return true; }
    bool IsOK() const override { return ok_; }
    std::string LastError() const override { return lastErr_; }
    u64 MaxAddress() const override { return paMax_; } // LC_OPT_CORE_ADDR_MAX

private:
    HMODULE hMod_     = nullptr;
    HANDLE  hLC_      = nullptr;
    fnLcRead      fnRead_      = nullptr;
    fnLcWrite     fnWrite_     = nullptr;
    fnLcClose     fnClose_     = nullptr;
    fnLcGetOption fnGetOption_ = nullptr;
    bool    ok_       = false;
    bool    writable_ = false;
    bool    volatile_ = false;
    u64     paMax_    = 0;
    std::string device_;
    std::string deviceName_;
    std::string lastErr_;
};

// ---------------------------------------------------------------------------
// TryCreateLeechReader - loads leechcore.dll, binds exports, creates the device.
// Returns nullptr gracefully when anything is missing (never throws).
// ---------------------------------------------------------------------------
std::unique_ptr<IMemoryReader> TryCreateLeechReader(const std::string& deviceString) {
    g_leechLastError.clear();

    if (deviceString.empty()) {
        g_leechLastError = "empty LeechCore device string (--device)";
        Log::Warn("%s", g_leechLastError.c_str());
        return nullptr;
    }

    const HMODULE hMod = LoadLibraryA("leechcore.dll");
    if (!hMod) {
        g_leechLastError = "leechcore.dll not found (err " +
                           std::to_string((unsigned long)GetLastError()) + ")";
        Log::Warn("LeechCore: %s", g_leechLastError.c_str());
        Log::Warn("install hint: the MemProcFS release includes leechcore.dll - "
                  "copy it next to DumperPro.exe or into PATH (see docs/LEECH.md)");
        return nullptr;
    }

    const auto bind = [&](const char* name) -> FARPROC {
        FARPROC p = GetProcAddress(hMod, name);
        if (!p)
            Log::Warn("LeechCore: export '%s' missing in this leechcore.dll build", name);
        return p;
    };

    const fnLcCreate    fnCreate    = (fnLcCreate)bind("LcCreate");
    const fnLcRead      fnRead      = (fnLcRead)bind("LcRead");
    const fnLcWrite     fnWrite     = (fnLcWrite)bind("LcWrite");
    const fnLcClose     fnClose     = (fnLcClose)bind("LcClose");
    const fnLcMemFree   fnMemFree   = (fnLcMemFree)bind("LcMemFree"); // bound for completeness
    const fnLcGetOption fnGetOption = (fnLcGetOption)bind("LcGetOption");
    const fnLcSetOption fnSetOption = (fnLcSetOption)bind("LcSetOption"); // bound for completeness

    if (!fnCreate || !fnRead || !fnWrite || !fnClose) {
        g_leechLastError = "leechcore.dll is missing required exports (LcCreate/LcRead/LcWrite/LcClose)";
        Log::Err("%s - update to a current MemProcFS release", g_leechLastError.c_str());
        FreeLibrary(hMod);
        return nullptr;
    }

    // LC_CONFIG is _Inout_: caller fills the top half, LeechCore updates the rest
    LcConfig cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.dwVersion         = LEECH_LC_CONFIG_VERSION; // LC_CONFIG_VERSION (0xc0fd0002)
    cfg.dwPrintfVerbosity = 0;                       // keep leechcore's own printf quiet
    strncpy(cfg.szDevice, deviceString.c_str(), MAX_PATH - 1);
    cfg.szDevice[MAX_PATH - 1] = '\0';
    cfg.szRemote[0]  = '\0';
    cfg.pfn_printf_opt = nullptr;
    cfg.paMax = 0;                                   // 0 = let LeechCore auto-detect

    const HANDLE hLC = fnCreate(&cfg);
    if (!hLC) {
        g_leechLastError = "LcCreate failed for device '" + deviceString + "'";
        Log::Err("%s - check the device string (fpga / raw://dump.bin / dump://x.dmp, "
                 "docs/LEECH.md) and driver availability", g_leechLastError.c_str());
        FreeLibrary(hMod);
        return nullptr;
    }

    auto r = std::make_unique<LeechReader>(hMod, hLC, fnRead, fnWrite, fnClose,
                                           fnGetOption, cfg, deviceString);
    if (!r->IsOK()) {
        g_leechLastError = r->LastError();
        return nullptr;
    }
    return r;
}

} // namespace dumper

#elif defined(__linux__) // !defined(_WIN32) - gercek LeechCore (libleechcore.so)

// LeechCore resmi olarak Linux derlemesini de destekler (ufrisk/LeechCore
// deposu: make -> leechcore.so). Bu dal leechcore.dll ile AYNI ABI'yi
// dlopen + dlsym ile baglar; LC_CONFIG duzeni her iki platformda aynidir
// (leechcore.h Linux'ta MAX_PATH=260 tanimlar). Dogrulama: leechcore.h
// v2.23 - LC_CONFIG_VERSION 0xc0fd0002, LcCreate/LcRead/LcWrite/LcClose/
// LcGetOption/LcSetOption/LcMemFree exportlari (nm -D ile teyit edildi).

#if !defined(NOMINMAX)
#define NOMINMAX
#endif

#include <dlfcn.h>

namespace dumper {

// Windows tiplerinin Linux karsiliklari (leechcore.h Linux dalindaki tanimlar)
typedef uint32_t LcDword;
typedef int32_t  LcBool;
typedef uint64_t LcQword;
constexpr int LC_MAX_PATH_LNX = 260; // leechcore.h: #define MAX_PATH 260 (Linux dahil)

typedef struct LcConfigLnx {
    LcDword   dwVersion;
    LcDword   dwPrintfVerbosity;
    char      szDevice[LC_MAX_PATH_LNX];
    char      szRemote[LC_MAX_PATH_LNX];
    int (*pfn_printf_opt)(char const*, ...);
    LcQword   paMax;
    LcBool    fVolatile;
    LcBool    fWritable;
    LcBool    fRemote;
    LcBool    fRemoteDisableCompress;
    char      szDeviceName[LC_MAX_PATH_LNX];
} LcConfigLnx;

typedef void*        (*fnLcCreateLnx)(LcConfigLnx*);
typedef LcBool       (*fnLcReadLnx)(void*, LcQword, LcDword, unsigned char*);
typedef LcBool       (*fnLcWriteLnx)(void*, LcQword, LcDword, unsigned char*);
typedef void         (*fnLcCloseLnx)(void*);
typedef void         (*fnLcMemFreeLnx)(void*);
typedef LcBool       (*fnLcGetOptionLnx)(void*, LcQword, LcQword*);
typedef LcBool       (*fnLcSetOptionLnx)(void*, LcQword, LcQword);

// LC_OPT_CORE_ADDR_MAX (R): cihazin maksimum fiziksel adresi
#define LNX_LC_OPT_CORE_ADDR_MAX 0x1000000800000000ull
// leechcore.h LC_CONFIG_VERSION (0xc0fd0002) - Windows dali ile ayni deger
#ifndef LEECH_LC_CONFIG_VERSION
#define LEECH_LC_CONFIG_VERSION 0xc0fd0002
#endif

namespace {

constexpr u64  kMinValidVa  = 0x10000;   // ProcessReader ile ayni yakin-sifir korumasi
constexpr u32  kMaxIoChunk  = 0x100000;  // LcRead/LcWrite basina 1 MiB
// LeechCore dosya cihazi 4096 bayt sayfa granularitesi ister (birebir test)
constexpr u64  kLcPage      = 4096;

// TryCreateLeechReader() basarisizliginda bildirilen son hata
std::string g_leechLastError;

} // namespace

class LeechReaderLnx final : public IMemoryReader {
public:
    LeechReaderLnx(void* hLib, void* hLC, fnLcReadLnx fnRead, fnLcWriteLnx fnWrite,
                   fnLcCloseLnx fnClose, fnLcGetOptionLnx fnGetOption,
                   const LcConfigLnx& cfg, const std::string& deviceString)
        : hLib_(hLib), hLC_(hLC), fnRead_(fnRead), fnWrite_(fnWrite),
          fnClose_(fnClose), fnGetOption_(fnGetOption), device_(deviceString) {
        ok_ = (hLib_ && hLC_ && fnRead_ && fnClose_);
        if (!ok_) {
            lastErr_ = "gecersiz LeechCore handle";
            return;
        }
        // LcCreate cfg'yi guncelledi: cihazin kendi yetenekleri
        writable_   = cfg.fWritable != 0;
        volatile_   = cfg.fVolatile != 0;
        deviceName_ = cfg.szDeviceName;

        // en iyi caba ile maksimum fiziksel adres raporu (asla hata uretmez)
        LcQword paMax = 0;
        if (fnGetOption_ && fnGetOption_(hLC_, LNX_LC_OPT_CORE_ADDR_MAX, &paMax) && paMax)
            paMax_ = (u64)paMax;

        Log::Ok("LeechCore device ready: '%s'%s (writable=%s%s, maxPA=%s)",
                device_.c_str(),
                deviceName_.empty() ? "" : (" -> " + deviceName_).c_str(),
                writable_ ? "yes" : "no",
                volatile_ ? ", volatile" : "",
                paMax_ ? Hex(paMax_).c_str() : "auto");
        Log::Debug("libleechcore.so dlopen ile baglandi; LcRead/LcWrite/LcClose/LcGetOption aktif");
    }

    ~LeechReaderLnx() override {
        if (hLC_ && fnClose_) fnClose_(hLC_);
        if (hLib_) dlclose(hLib_);
    }

    bool Read(u64 pa, void* out, size_t size) override {
        if (!ok_ || !hLC_) {
            if (lastErr_.empty()) lastErr_ = "leechcore cihazi bagli degil";
            return false;
        }
        if (size == 0) return true;
        if (!out) {
            lastErr_ = "cikis tamponu null";
            return false;
        }
        if (pa < kMinValidVa) {
            lastErr_ = Hex(pa) + " adresinde okuma reddedildi (yakin-sifir fiziksel adres)";
            return false;
        }
        if (pa > UINT64_MAX - (u64)size) {
            lastErr_ = Hex(pa) + " adres araligini tasiriyor";
            return false;
        }

        // LeechCore dosya cihazi 4096 bayt sayfa granularitesinde okur (birebir
        // test edildi): 4K hizali degilse sayfa sayfa okuyup icerden kesiyoruz.
        if ((pa % kLcPage) == 0 && (size % kLcPage) == 0) {
            return readChunked(pa, (u8*)out, size);
        }
        return readPageShim(pa, (u8*)out, size);
    }

private:
    bool readChunked(u64 pa, u8* dst, size_t size) {
        size_t done = 0;
        while (done < size) {
            const u32 chunk = (u32)std::min<size_t>(size - done, kMaxIoChunk);
            if (!fnRead_(hLC_, (LcQword)(pa + (u64)done), chunk, dst + done)) {
                memset(dst + done, 0, size - done); // eski bayt birakma
                lastErr_ = "LcRead basarisiz @" + Hex(pa + (u64)done) + " (" +
                           std::to_string(chunk) + " bayt; eslenmemis fiziksel sayfa?)";
                return false;
            }
            done += (size_t)chunk;
        }
        return true;
    }

    bool readPageShim(u64 pa, u8* dst, size_t size) {
        std::vector<u8> page(kLcPage);
        size_t done = 0;
        while (done < size) {
            const u64 paLo = (pa + done) & ~(kLcPage - 1);
            const u32 off = (u32)((pa + done) - paLo);
            const u32 take = (u32)std::min<size_t>(size - done, kLcPage - off);
            if (!fnRead_(hLC_, (LcQword)paLo, (u32)kLcPage, page.data())) {
                memset(dst + done, 0, size - done);
                lastErr_ = "LcRead basarisiz @" + Hex(paLo) + " (4096 sayfa; eslenmemis fiziksel sayfa?)";
                return false;
            }
            memcpy(dst + done, page.data() + off, take);
            done += take;
        }
        return true;
    }

public:

    // LcWrite v2.23'te mevcut; bircok cihaz salt-okunur (fWritable create'de raporlanir)
    bool Write(u64 pa, const void* data, size_t size) override {
        if (!ok_ || !hLC_) {
            if (lastErr_.empty()) lastErr_ = "leechcore cihazi bagli degil";
            return false;
        }
        if (!fnWrite_) {
            lastErr_ = "LcWrite baglanmadi";
            return false;
        }
        if (size == 0) return true;
        if (!data) {
            lastErr_ = "giris tamponu null";
            return false;
        }
        if (!writable_) {
            lastErr_ = "cihaz '" + device_ + "' fWritable=0 raporladi (salt-okunur kaynak)";
            return false;
        }
        if (pa < kMinValidVa) {
            lastErr_ = Hex(pa) + " adresine yazma reddedildi (yakin-sifir fiziksel adres)";
            return false;
        }
        if (pa > UINT64_MAX - (u64)size) {
            lastErr_ = Hex(pa) + " adres araligini tasiriyor";
            return false;
        }

        const u8* src = (const u8*)data;
        // 4K hizali coklu sayfa yazimlari dogrudan; digerleri oku-degistir-yaz
        if ((pa % kLcPage) == 0 && (size % kLcPage) == 0) {
            size_t done = 0;
            while (done < size) {
                const u32 chunk = (u32)std::min<size_t>(size - done, kMaxIoChunk);
                if (!fnWrite_(hLC_, (LcQword)(pa + (u64)done), chunk,
                              (unsigned char*)(const_cast<u8*>(src + done)))) {
                    lastErr_ = "LcWrite basarisiz @" + Hex(pa + (u64)done) + " (" +
                               std::to_string(chunk) + " bayt)";
                    return false;
                }
                done += (size_t)chunk;
            }
            return true;
        }

        // oku-degistir-yaz (sayfa granularitesi)
        std::vector<u8> page(kLcPage);
        size_t done = 0;
        while (done < size) {
            const u64 paLo = (pa + done) & ~(kLcPage - 1);
            const u32 off = (u32)((pa + done) - paLo);
            const u32 take = (u32)std::min<size_t>(size - done, kLcPage - off);
            if (!fnRead_(hLC_, (LcQword)paLo, (u32)kLcPage, page.data())) {
                memset(page.data(), 0, kLcPage); // okunamayan sayfa: sifir tabani ile devam
            }
            memcpy(page.data() + off, src + done, take);
            if (!fnWrite_(hLC_, (LcQword)paLo, (u32)kLcPage, page.data())) {
                lastErr_ = "LcWrite basarisiz @" + Hex(paLo) + " (RMW sayfa)";
                return false;
            }
            done += take;
        }
        return true;
    }

    // LeechCore cihaz seviyesinde fiziksel bellek API'sidir - proses/modul
    // modeli yoktur (o katman MemProcFS vmm.dll'dir). main.cpp bos modul
    // listesini belgelenmis en-iyi-caba ham tarama ile yonetir.
    std::vector<ModuleInfo> Modules() override {
        static bool warned = false;
        if (!warned) {
            warned = true;
            Log::Debug("LeechCore: cihaz seviyesinde modul modeli yok (modul-farkindalikli "
                       "analiz icin --file ile ham dump kullanin)");
        }
        return {};
    }

    u64 MainModuleBase() override { return 0; }

    std::string TargetName() override { return device_; }

    bool IsLiveProcess() const override { return true; }
    bool IsOK() const override { return ok_; }
    std::string LastError() const override { return lastErr_; }
    u64 MaxAddress() const override { return paMax_; } // LC_OPT_CORE_ADDR_MAX

private:
    void*   hLib_        = nullptr;
    void*   hLC_         = nullptr;
    fnLcReadLnx      fnRead_      = nullptr;
    fnLcWriteLnx     fnWrite_     = nullptr;
    fnLcCloseLnx     fnClose_     = nullptr;
    fnLcGetOptionLnx fnGetOption_ = nullptr;
    bool    ok_       = false;
    bool    writable_ = false;
    bool    volatile_ = false;
    u64     paMax_    = 0;
    std::string device_;
    std::string deviceName_;
    std::string lastErr_;
};

// ---------------------------------------------------------------------------
// TryCreateLeechReader (Linux) - libleechcore.so yukle, exportlari bagla,
// cihazi olustur. Eksik her sey icin nullptr + kurulum ipucu (asla firlatmaz).
// ---------------------------------------------------------------------------
std::unique_ptr<IMemoryReader> TryCreateLeechReader(const std::string& deviceString) {
    g_leechLastError.clear();

    if (deviceString.empty()) {
        g_leechLastError = "bos LeechCore cihaz metni (--device)";
        Log::Warn("%s", g_leechLastError.c_str());
        return nullptr;
    }

    // Resmi Linux derlemesi "leechcore.so" uretir; dagitimlarda "lib" onekli de olabilir
    void* hLib = dlopen("leechcore.so", RTLD_NOW | RTLD_LOCAL);
    if (!hLib) {
        const std::string firstErr = dlerror() ? dlerror() : "bilinmeyen";
        hLib = dlopen("libleechcore.so", RTLD_NOW | RTLD_LOCAL);
        if (!hLib) {
            g_leechLastError = "leechcore kutuphanesi yuklenemedi (" + firstErr + ")";
            Log::Warn("LeechCore: %s", g_leechLastError.c_str());
            Log::Warn("kurulum ipucu: LeechCore deposunda: cd leechcore && make - "
                      "uretilen leechcore.so'yu DumperPro yanina ya da LD_LIBRARY_PATH'e koyun "
                      "(docs/LEECH.md)");
            return nullptr;
        }
    }

    const auto bind = [&](const char* name) -> void* {
        void* p = dlsym(hLib, name);
        if (!p)
            Log::Warn("LeechCore: '%s' exportu bu libleechcore.so derlemesinde yok", name);
        return p;
    };

    const fnLcCreateLnx    fnCreate    = (fnLcCreateLnx)bind("LcCreate");
    const fnLcReadLnx      fnRead      = (fnLcReadLnx)bind("LcRead");
    const fnLcWriteLnx     fnWrite     = (fnLcWriteLnx)bind("LcWrite");
    const fnLcCloseLnx     fnClose     = (fnLcCloseLnx)bind("LcClose");
    const fnLcMemFreeLnx   fnMemFree   = (fnLcMemFreeLnx)bind("LcMemFree");   // tamamlama icin baglanir
    const fnLcGetOptionLnx fnGetOption = (fnLcGetOptionLnx)bind("LcGetOption");
    const fnLcSetOptionLnx fnSetOption = (fnLcSetOptionLnx)bind("LcSetOption"); // tamamlama icin baglanir

    if (!fnCreate || !fnRead || !fnWrite || !fnClose) {
        g_leechLastError = "libleechcore.so zorunlu exportlar eksik (LcCreate/LcRead/LcWrite/LcClose)";
        Log::Err("%s - guncel bir LeechCore derlemesine guncelleyin", g_leechLastError.c_str());
        dlclose(hLib);
        return nullptr;
    }
    (void)fnMemFree;
    (void)fnSetOption;

    // LC_CONFIG _Inout_: ust yarisini cagiran doldurur, LeechCore kalanini gunceller
    LcConfigLnx cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dwVersion         = LEECH_LC_CONFIG_VERSION; // 0xc0fd0002 (leechcore.h ile birebir)
    cfg.dwPrintfVerbosity = 0;                       // leechcore'un kendi printf'ini sustur
    strncpy(cfg.szDevice, deviceString.c_str(), LC_MAX_PATH_LNX - 1);
    cfg.szDevice[LC_MAX_PATH_LNX - 1] = '\0';
    cfg.szRemote[0]     = '\0';
    cfg.pfn_printf_opt  = nullptr;
    cfg.paMax           = 0;                         // 0 = otomatik tespit

    void* hLC = fnCreate(&cfg);
    if (!hLC) {
        g_leechLastError = "LcCreate basarisiz: '" + deviceString + "'";
        Log::Err("%s - cihaz metnini (fpga / raw://dump.bin / dump://x.dmp, "
                 "docs/LEECH.md) ve surucu erisilebilirlik kontrol edin", g_leechLastError.c_str());
        dlclose(hLib);
        return nullptr;
    }

    auto r = std::make_unique<LeechReaderLnx>(hLib, hLC, fnRead, fnWrite, fnClose,
                                              fnGetOption, cfg, deviceString);
    if (!r->IsOK()) {
        g_leechLastError = r->LastError();
        return nullptr;
    }
    return r;
}

} // namespace dumper

#else // !defined(_WIN32) && !defined(__linux__)

// Diger platformlar (macOS vb.): LeechCore resmi Linux/Windows derlemeleri
// disinda dagitilmaz; sembol korunur, fabrika her zaman basarisiz raporlar.
namespace dumper {

std::unique_ptr<IMemoryReader> TryCreateLeechReader(const std::string& deviceString) {
    Log::Warn("LeechCore device mode (--device '%s') requires Windows (leechcore.dll) or "
              "Linux (leechcore.so, ufrisk/LeechCore make build); this host cannot load it - "
              "use --file <dump> for offline analysis (docs/LEECH.md)",
              deviceString.c_str());
    return nullptr;
}

} // namespace dumper

#endif // _WIN32
