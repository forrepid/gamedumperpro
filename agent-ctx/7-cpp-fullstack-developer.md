# Task 7-cpp - Full-stack developer agent (DumperPro LeechCore reader backend)

## Scope
C++ only + docs. ZERO TS files touched (no `bun run lint` needed), ZERO HTTP calls to
localhost:3000, ZERO reads/writes to storage/ or db/custom.db, ZERO modifications under
DumperPro/.test/ (only read fixtures for smoke tests). Deleted 2 stale compiler artifacts
(`src/utils/Logger.h.gch`, `src/utils/StrUtil.h.gch`) so g++ doesn't pick up stale PCHs.

## Files created
- `DumperPro/src/core/LeechReader.h` - factory decl + full ABI documentation comment
- `DumperPro/src/core/LeechReader.cpp` - LeechCore backend of IMemoryReader
- `DumperPro/docs/LEECH.md` - Turkish doc, KERNEL.md-style numbered sections/tables/diagram

## Files modified
- `DumperPro/src/main.cpp` - `--device <lc>` flag end-to-end (surgical):
  - header comment Device mode line; `#include "core/LeechReader.h"`
  - `Options::device`; usage example line; options line
    `--device <lc>         LeechCore device (fpga / raw://dump.bin / dump://x.dmp - see docs/LEECH.md)`
  - ParseArgs: `--device` value parse; modes counting includes device (exclusive with
    process/pid/file/serve); `--hex` + `--device` rejected with clear error
  - main(): device reader branch (`TryCreateLeechReader`), dedicated nullptr hint
    (leechcore.dll install hint), empty-Modules() handling: warn that UE SDK needs
    MemProcFS-level module info (vmm.dll) or raw dump + memmap, then best-effort 64 MiB
    signature scan window base=0x10000 (reader's kMinValidVa guard) size=64 MiB,
    chunked 1 MiB zero-fill-on-hole read, `mod.pe.reset()` (no PE parse), pattern sigs
    run, heuristic struct scans stay disabled (no PE sections) - continues or exits cleanly
- `DumperPro/src/ue/UEVersion.cpp` - `DetectFromRawStrings()` fallback: when ModuleImage
  has no parsed PE (only possible in device mode), votes on ASCII `++UE5+Release-X.Y`
  markers (same tie-break rule as PE path). PE path byte-for-byte unchanged.
- `DumperPro/src/config/Config.cpp` - Builtins(): +UE5.4/+UE5.5 (same 5.3 layout; comment
  says probe/games.ini overrides may be needed); loop bound now sizeof-based
- `DumperPro/src/config/Config.h` - comment "8 profiles" -> "10 profiles"
- `DumperPro/games.ini` - commented UE5.4/UE5.5 sample sections + `[Fingerprints]`
  fingerprint.* example block (real patterns copied from VTableResolver built-ins)

## Verified API constants from /tmp/research/leechcore.h (header v2.23, ufrisk master)
- `LC_CONFIG_VERSION = 0xc0fd0002`. The struct comment says "must equal LC_CREATE_VERSION"
  but that macro does NOT exist in the header - the real constant is LC_CONFIG_VERSION.
  Implemented as LEECH_LC_CONFIG_VERSION, documented in LeechReader.h/.cpp and LEECH.md.
- `LcWrite` EXISTS: `BOOL LcWrite(HANDLE, QWORD pa, DWORD cb, PBYTE pb)` -> implemented
  (chunked, near-null/overflow guards, refuses when device reports fWritable=0 from the
  _Inout_ LC_CONFIG after LcCreate).
- `LcRead(HANDLE, QWORD, DWORD, PBYTE)`, `LcClose(HANDLE)`, `LcMemFree(PVOID)`,
  `LcGetOption(HANDLE,QWORD,PQWORD)`, `LcSetOption(HANDLE,QWORD,QWORD)` - all bound.
- `LC_CONFIG` layout mirrored exactly (DWORD,DWORD,szDevice[260],szRemote[260],pfn,paMax,
  4xBOOL,szDeviceName[260]); LeechCore-prefixed typedefs (LcQword) avoid MinGW QWORD clash.
- `LC_OPT_CORE_ADDR_MAX = 0x1000000800000000` used for best-effort maxPA log.
- Licenses verified via curl (task-authorized): LeechCore LICENSE = GPL-3.0,
  MemProcFS LICENSE = AGPL-3.0. Doc notes dynamic LoadLibrary linking stance.

## CMakeLists
`file(GLOB_RECURSE ... src/*.cpp)` - LeechReader.cpp picked up automatically; no change.

## Compile + verification results
- `g++ -std=c++20 -O1 -I src -o build_test/DumperPro src/*.cpp src/*/*.cpp -lpthread`
  -> 0 errors. Strict `-Wall -Wextra` build -> only pre-existing warning
  (Il2CppDummyDll.cpp CsStringLit, untouched file).
- `--help`: shows the exact `--device <lc>` option line + usage example (UE5 range now
  "5.0-5.5").
- `--device "fpga"` on Linux: graceful Warn "requires Windows + leechcore.dll
  (MemProcFS release)" + Hint + exit 2, no crash. Also verified for raw:// string.
- `--hex --device` -> clean reject (exit 1). `--device --process` -> clean reject (exit 1).
- `--list-profiles` -> UE4.20..UE5.5 (10 profiles).
- Smoke regression `--file .test/testlib.so --out /tmp/leech_smoke` -> exit 0,
  analysis_report.txt written. Second regression `--file .test/test_rtti.exe --no-sdk`
  -> identical pre-existing behavior (PE path intact).
- _WIN32 code hand-reviewed: types (HANDLE/HMODULE/DWORD/BOOL/PBYTE/MAX_PATH all from
  windows.h), x64 single calling convention, export names LcCreate/LcRead/LcWrite/
  LcClose/LcMemFree/LcGetOption/LcSetOption exact, strncpy NUL-termination,
  LcClose+FreeLibrary RAII pairing, LcRead all-or-nothing semantics handled (zero-fill
  remainder + fail), const-cast for PBYTE param documented.

## Windows behavior summary
- Factory binds leechcore.dll dynamically; missing dll -> nullptr + Warn "install hint:
  the MemProcFS release includes leechcore.dll". Required-export missing -> Err + nullptr.
- `LcCreate` failure (bad device string / driver) -> Err + nullptr; never throws.
- Modules() returns {} (device-level API; process/module model is MemProcFS vmm.dll
  VMMDLL_*); documented in code + LEECH.md section 4.
- LEECH.md documents device strings (fpga, usb3380:, raw://, dump://, pmem://, qemu://,
  vmx://, vmm://), MemProcFS relationship, GPL/AGPL dynamic-link note, setup
  (MemProcFS zip, MSVC runtime, FTDI driver for FPGA), `--device "raw://dump.bin"`
  usage, and the web-side note: `src/lib/analysis/mem.ts` ports LeechCore file-device
  semantics (dump://, raw://, memmap pa/cb/paRemap) in TS; live DMA requires Windows
  `--device`.

## Status
- DONE. All task verifications green. Nothing else touched.
