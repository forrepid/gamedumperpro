// ============================================================================
// DumperPro - LeechCore reader backend (device-level physical memory access)
//
// Optional backend of IMemoryReader that talks to ufrisk's LeechCore library
// (https://github.com/ufrisk/LeechCore). LeechCore abstracts reading/writing
// physical memory from software and hardware acquisition sources: dump files,
// PMEM driver, USB3380 / FPGA DMA cards, VM backends and remote instances.
//
// The DLL is bound dynamically (LoadLibraryA + GetProcAddress) so the binary
// runs fine without leechcore.dll present - the factory then returns nullptr
// with an install hint. No leechcore.h is shipped; the minimal ABI mirrored
// below was verified against leechcore.h header version 2.23 (ufrisk master):
//
//   #define LC_CONFIG_VERSION 0xc0fd0002      // NOTE: header comment says
//                                             // "must equal LC_CREATE_VERSION"
//                                             // but that macro does NOT exist;
//                                             // the real constant is
//                                             // LC_CONFIG_VERSION (0xc0fd0002).
//   typedef struct LC_CONFIG {                 // exact layout, Win32 types
//       DWORD dwVersion;                       // must equal LC_CONFIG_VERSION
//       DWORD dwPrintfVerbosity;               // LC_CONFIG_PRINTF_*
//       CHAR  szDevice[MAX_PATH];              // device string ("fpga", ...)
//       CHAR  szRemote[MAX_PATH];              // remote config (unused here)
//       int (*pfn_printf_opt)(char const*, ...);
//       QWORD paMax;                           // 0 = auto-detect; updated by LC
//       BOOL  fVolatile;                       // set by LeechCore on return
//       BOOL  fWritable;                       // set by LeechCore on return
//       BOOL  fRemote;
//       BOOL  fRemoteDisableCompress;
//       CHAR  szDeviceName[MAX_PATH];          // e.g. "fpga" / "file"
//   } LC_CONFIG;
//
//   HANDLE LcCreate(_Inout_ PLC_CONFIG);       // _Inout_: LC updates fields
//   BOOL   LcRead (HANDLE hLC, QWORD pa, DWORD cb, PBYTE pb);
//   BOOL   LcWrite(HANDLE hLC, QWORD pa, DWORD cb, PBYTE pb);  // exists in 2.23
//   VOID   LcClose(HANDLE hLC);
//   VOID   LcMemFree(PVOID pv);
//   BOOL   LcGetOption(HANDLE hLC, QWORD fOption, PQWORD pqwValue);
//   BOOL   LcSetOption(HANDLE hLC, QWORD fOption, QWORD qwValue);
//
// This is a DEVICE-level API: LeechCore exposes raw physical memory only.
// There is no process/module/VAD model here - that layer belongs to MemProcFS
// (vmm.dll, VMMDLL_* API). Consequently Modules() always returns {} and
// MainModuleBase() returns 0; main.cpp runs a best-effort raw signature scan
// for the UE pipeline (see docs/LEECH.md).
//
// Include hygiene: like KernelReader.cpp this is one of the few translation
// units allowed to include Win32 headers (guarded by _WIN32). On non-Windows
// hosts the factory returns nullptr with a warning; the TU still compiles.
//
// Licensing note: LeechCore is GPL-3.0 and MemProcFS is AGPL-3.0. DumperPro
// links at runtime through LoadLibraryA and does not distribute or
// statically link LeechCore sources; users fetch leechcore.dll from the
// official MemProcFS release themselves (see docs/LEECH.md).
// ============================================================================

#pragma once
#include "../framework.h"
#include "core/MemoryReader.h"

namespace dumper {

// Create a LeechCore-backed reader for a device string.
//
//   deviceString examples (LC_CONFIG.szDevice, see docs/LEECH.md):
//     "fpga"                FPGA DMA card (Squirrel/AC701/... + FTDI driver)
//     "raw://C:\\dump.bin"  raw physical-memory dump file
//     "dump://x.dmp"        Windows crash/minidump style dump file
//     "pmem://..."          PMEM (WinPMEM) physical memory device
//     "usb3380:"            USB3380-based DMA card
//
// Returns nullptr (never throws) when:
//   - not on Windows, or leechcore.dll cannot be loaded (install hint logged),
//   - a required LeechCore export is missing, or
//   - LcCreate fails for the given device string.
// Errors are reported through Log::Warn/Log::Err before returning.
std::unique_ptr<IMemoryReader> TryCreateLeechReader(const std::string& deviceString);

} // namespace dumper
