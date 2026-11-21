# DumperPro - Unreal Engine Memory & SDK Dumper

> **Important:** DumperPro is intended for offline analysis, single-player game modding,
> interoperability and engine research on software you own or are licensed to analyze.
> Do not use it in multiplayer/competitive contexts or to bypass anti-cheat systems.
> See the full [DISCLAIMER](#disclaimer) at the end of this file.

## Türkçe Özet

DumperPro, çalışan bir Unreal Engine sürecinden (UE4 4.20-4.27, UE5 5.0-5.3) veya diskteki bir PE
dosyasından motor verilerini çıkarır: GNames ve GObjects'i otomatik bulur; isim ve nesne listeleri,
offset raporları, imzalar (signature) ve tam bir C++ SDK üretir (sınıf hiyerarşileri, struct ve
enum'lar, fonksiyon imzaları, üye offset'leri; padding ve bitfield desteğiyle). İmza taraması,
oylama tabanlı runtime offset keşfi, vtable fonksiyon çözümleme ve isteğe bağlı kernel destekli
bellek okuma içerir. Tüm oyun ayarları `games.ini` üzerinden yapılır; yeni bir oyun eklemek için
araç yeniden derlenmez. Unity IL2CPP oyunlarında global-metadata.dat + binary
eşleştirmesiyle metod native adresleri, gerçek tip isimleri ve alan ofsetleri
çıkarılır (Il2CppDumper uyumlu dump.cs/script.json). Canlı/tekil dosyada
hex/byte/kod/binary/AOB görüntüleyici-düzenleyici-kaydetme sistemi vardır.
Örnek kullanım: `DumperPro.exe --process Game.exe` (yönetici olarak
çalıştırın). Ayrıntılar için: `docs/ALGORITHM.md`, `docs/KERNEL.md`,
`docs/IL2CPP.md`, `docs/REFERENCES.md`.
Bu araç yalnızca offline analiz, tek oyunculu modding ve lisanslı yazılım üzerindeki motor
araştırmaları için tasarlanmıştır; çok oyunculu oyunlarda veya hile amaçlı kullanım kapsam dışıdır.

---

## What is DumperPro?

DumperPro is a Windows tool that extracts Unreal Engine data from a **live process** (UE4
4.20-4.27, UE5 5.0-5.3) or from a **PE file** on disk and generates a full C++ SDK:

- class hierarchies (inheritance chains preserved per package)
- structs and enums
- function signatures (parameters rendered as `Params_` structs)
- member offsets with padding and bitfield support

In addition to the SDK it produces raw dumps (names, objects, engine offsets), reusable
signatures, and resolved virtual-function addresses.

Typical use: you want to build tooling (trainers for single-player, asset editors, interoperability
bridges, research) against a UE4/UE5 title and need the engine's runtime object model without a
matching editor build.

## Feature overview

### Core dumping
- `Names.txt` - the full FName table, one entry per line (`0x000001: Name`).
- `Objects.txt` - every GUObjectArray entry with index, class, name, full path and address.
- Full SDK: per-package `SDK/<Pkg>_classes.h`, `SDK/<Pkg>_structs.h`, `SDK/<Pkg>_enums.h`,
  plus `SDK/_basics.hpp` (shared core types) and `SDK/SDK.hpp` (master include).
- Function parameter dumping: each UFunction is emitted with a `Params_<Function>` struct
  holding its parameters, sorted and offset-annotated.
- Bitfield + padding support: `FBoolProperty` members become `bool bName : 1;` bitfields
  (`ByteMask`/`FieldMask` honoured), and alignment gaps are filled with
  `uint8 UnknownData_XX[0xN];` so generated headers are layout-correct.

### Signature system
- Auto sig-finder with **hit validation**: every pattern hit is resolved via RIP-relative
  addressing and the candidate address is validated before use.
- `signatures.txt` contains a **primary** signature plus a **16-byte extended** context
  signature for each global (the disp32 is wildcarded, so the pattern is reusable across builds).
- `<Game>_sigs.txt` is written in `games.ini` format - drop the lines into your config and the
  next run skips scanning entirely.

### Configuration
- Everything lives in `games.ini` (offsets, addresses, patterns, fingerprints, probe/tuning keys).
- 8 built-in profiles: UE4.20, UE4.24, UE4.25, UE4.27, UE5.0, UE5.1, UE5.2, UE5.3.
- Auto UE version detection from embedded engine strings (`++UE4+Release-4.27` style).
- Game sections are matched by name prefix against the target image
  (`Game-Win64-Shipping.exe` -> `[Game]`), so one config file serves many builds.

### UE5 support
- FNamePool walking with 2-byte entry header blocks, wide (UTF-16) strings and FName
  number handling (`Name_3` suffixes).
- Object array chunk size 65536 (UE5) vs 10240 (UE4), item stride auto-detection
  (0x10 / 0x18 / 0x20).

### Usability
- Progress bars (`[########......] 45.2% | 12345/27300 | ETA 12s`) for long scans.
- Detailed console output and error messages that end in an actionable `Hint:` line
  (e.g. which `games.ini` key to add).

### VTable function resolver
- Dynamically discovers vtable slots for tracked functions
  (`ProcessEvent`, `PostRender`, `ProcessRemoteFunction`) - no hardcoded slot indices.
- Hint-based fingerprint scan per slot (built-in fingerprints or `fingerprint.*` in
  `games.ini`, alternatives separated by `|`).
- MSVC thunk/adjustor unwinding: `JMP rel8/rel32`, `SUB/ADD RCX, imm8/imm32` adjustors,
  stops at `FF 25` import stubs.
- Post-thunk voting across multiple vtables (up to 6) for stable results.
- `minIndex` guard rejects suspiciously low slots (slot 0/1 are MSVC destructors).
- Results: `vtable_funcs.txt`; `funcs.txt` lines are tagged with the vtable source when
  a tracked function was resolved.

### Runtime offset discovery
- Probes up to `--probe N` live objects (default 400) and **votes** on engine field
  offsets (Index, Class, Name, Outer, CDO, property model, function fields, ...).
- Per-field confidence; fields below 65% are skipped, not guessed.
- The `games.ini` profile stays authoritative: probe results never overwrite explicit
  profile values, disagreements produce warnings, agreements are counted as confirmed.
- `offsets.txt` records every field offset with its source and confidence (debug file).

### Optional kernel-assisted reader
- Client-side support for a read-only kernel driver backend (`--kernel`), useful for
  protected processes and for stability during large scans.
- Client interface only; the driver-side contract is documented separately in
  [docs/KERNEL.md](docs/KERNEL.md).

### Unity IL2CPP metadata mode (new)
- `--file global-metadata.dat` (or auto-detected inside an APK): parses IL2CPP
  metadata versions 16..31 with struct layouts verified against Il2CppDumper's
  own sources (Metadata.cs / MetadataClass.cs).
- Outputs: Turkish report, `dump.cs`-style skeleton (namespaces, class/struct/
  enum/interface kinds, fields, methods with tokens/slots/params),
  machine-readable `il2cpp_metadata.json`, and the string literal table.
- **Binary matching (Il2CppDumper's "second half" - done)**: pair the metadata
  with the game binary (`--file GameAssembly.dll --metadata global-metadata.dat`
  or `--file libil2cpp.so --metadata ...`; APKs auto-pair when both files are
  inside). DumperPro scans the binary for the IL2CPP CodeGenModules (v24.1+) or
  the flat method-pointer table (v16-24.0), validates candidates against the
  metadata counts, and resolves every method's native address (RVA/VA/file
  offset). A MetadataRegistration scan (validated by
  `fieldOffsetsCount == typeCount`) unlocks the Il2CppType table, so `dump.cs`
  is emitted with REAL type names, field offsets (`// 0x10`) and
  `// RVA: .. Offset: .. VA: ..` comments. ELF PIE relocations (RELA RELATIVE)
  are applied so stripped Android builds work. Also writes
  `il2cpp_script.json` (Il2CppDumper-compatible IDA/Ghidra input) and
  `il2cpp_methodaddresses.txt`.
- **metadataUsages (v19-24.5, done)**: resolves the codegen global cells
  (`g_MyClass_TypeInfo` style) that the runtime binds at startup - same
  list/pair decode as Il2CppDumper (`ProcessingMetadataUsage`). Output:
  `il2cpp_usages.txt` plus the `ScriptString` / `ScriptMetadata` /
  `ScriptMetadataMethod` sections inside `il2cpp_script.json`.
- **DummyDll (done, source-level)**: emits per-image COMPILABLE C# stubs
  (`DummyDll/<Image>.cs` + `_attributes.cs` + `build.bat`) with the
  Il2CppDumper attribute schema (`[Address]`, `[Token]`, `[FieldOffset]`);
  compile with `csc` to get dummy assemblies for dnSpy/ILSpy.

### Live hex / byte / code / binary / AOB view-editor-save (new)
- `--hex` mode works on a file (`--file oyun.exe`) or a live process module
  (`--process Game.exe [--module ...]`).
- Views: classic hex+ASCII table (`--hex-view 0x1000:16`), x86/x64 code view
  with correct instruction lengths and rip-relative/call/jmp target resolution
  (`--hex-code 0x140001000:24`), bit-level binary view (`--hex-binary 0x1000:16`).
  The disassembler is a deliberately scoped helper for signature work and
  patch previewing (unknown opcodes fall back to `db 0x..`); it is not a
  replacement for IDA/Capstone.
- Search: wildcard AOB (`--hex-search "48 8B 05 ?? ?? ?? ?? 48 85 C0"`),
  space-less hex (`488B05????????`), `text:...` ASCII search and **typed value
  search** (little-endian, DataType module): `f32:3.14`, `i32:1337`, `u64:0x7FF6...`,
  `bool:1`, `str:Hello`, `str16:Selam`, `vec3:1 2 3`.
- Typed value view: `--hex-type 0x1000:16:float` interprets 16 float values from
  an offset (types: `i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 bool bit str str16
  ptr vec2 vec3 vec4`; central DataType registry, same set on the web platform).
- Edit/save: `--hex-patch "0x1000=90 E9;0x2000=CC"` patches the buffer with an
  undo stack; `--hex-save out.exe` writes a patched COPY (the original file is
  never modified), and `--hex-live` applies the patches to the live process via
  memory write. Live patching is intended for analysis of software you own;
  the kernel reader stays read-only.

### ART containers: OAT / VDEX / CDEX (new)
- Basic header validation for `.vdex` / `.odex` / `.oat`: version string,
  DEX file count, verifier-deps/quickening sizes, OAT key/value store samples.
- VDEX layouts (006/010/019/021) and the version->API mapping are verified
  against the vdexExtractor sources.

### JSON outputs (new)
- `--json` emits machine-readable schemas next to the text dumps:
  `names.json`, `objects.json` (live mode), `analysis_report.json`
  (static mode). Every `--serve` upload also writes a `_report.json`.

### Concurrent uploads in serve mode (new)
- `--serve` handles each connection on its own thread; up to 4 analyses run
  concurrently (bounded pool), uploads beyond that briefly queue.

## Supported engines

| Engine | Versions | Property model | Names model | Object array |
|---|---|---|---|---|
| UE4 | 4.20 - 4.22 | UProperty (legacy chain) | legacy TNameEntryArray | chunked / flat, chunk 10240 |
| UE4 | 4.23 - 4.24 | UProperty (legacy chain) | FNamePool | chunked / flat, chunk 10240 |
| UE4 | 4.25 - 4.27 | FField / FProperty | FNamePool | chunked / flat, chunk 10240 |
| UE5 | 5.0 - 5.3 | FField / FProperty | FNamePool | chunked, chunk 65536 |

## Building (Windows)

DumperPro is a native C++20 Windows tool. No third-party dependencies (ZIP,
ELF, DEX, IL2CPP metadata, OAT/VDEX parsers are written in-tree and verified
against public specifications and reference implementations).

**MSVC (Visual Studio 2019/2022, "Desktop development with C++"):**

```bat
cmake -B build -A x64
cmake --build build --config Release
```

The executable is emitted at `build\Release\DumperPro.exe` and links the static CRT, so it runs
without redistributables.

**MinGW-w64 (GCC):**

```bat
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

The MinGW build is statically linked (`-static -static-libgcc -static-libstdc++`).

Notes:
- The tool targets Windows; the process reader backends use the WinAPI. Building on a
  non-Windows host emits a CMake warning and excludes the Win32 reader backends.
- CMake 3.16 or newer.

## Usage

```
DumperPro.exe --process Game.exe            attach to a running process (name substring match)
DumperPro.exe --pid 1234                    attach by pid
DumperPro.exe --file Game-Shipping.exe      offline analysis of a PE file (.exe/.dll, x64)
DumperPro.exe --file global-metadata.dat    Unity IL2CPP metadata dump (v16..31)
DumperPro.exe --file oyun.apk               static analysis: APK/ZIP/ELF/DEX/IL2CPP
DumperPro.exe --file base.vdex              ART container report (vdex/oat/cdex)
DumperPro.exe --serve                       local web upload mode (http://127.0.0.1:8420)
```

Exactly one target mode may be used at a time. Common examples:

```bat
:: basic live dump (run as Administrator), default output dir
DumperPro.exe --process Game.exe

:: dump a specific module, explicit output dir and config
DumperPro.exe --process Game.exe --module Game-Win64-Shipping.exe --out C:\dumps\game --ini mygames.ini

:: pid mode with kernel-assisted reads and a larger probe sample
DumperPro.exe --pid 1234 --kernel --probe 800

:: names/objects/offsets only (skip SDK generation)
DumperPro.exe --file Game-Win64-Shipping.exe --no-sdk

:: verbose diagnostics
DumperPro.exe --process Game.exe --verbose

:: show the built-in profiles and exit
DumperPro.exe --list-profiles

:: IL2CPP: full metadata + binary matching (method addresses, real types)
DumperPro.exe --file GameAssembly.dll --metadata global-metadata.dat
DumperPro.exe --file libil2cpp.so  --metadata global-metadata.dat

:: hex/aob: view, search, patch + save a patched copy
DumperPro.exe --hex --file Game.exe --hex-view 0x1000 --hex-code 0x140001000:24
DumperPro.exe --hex --file Game.exe --hex-search "48 8B 05 ?? ?? ?? ?? 48 85 C0"
DumperPro.exe --hex --file Game.exe --hex-patch "0x1000=90 E9" --hex-save patched.exe

:: typed values (DataType module, little-endian)
DumperPro.exe --hex --file Game.exe --hex-type 0x1000:16:float --hex-type 0x2000:8:ptr
DumperPro.exe --hex --file Game.exe --hex-search "f32:3.14"
DumperPro.exe --hex --file Game.exe --hex-search "vec3:1 2 3"

:: hex/aob: live process module viewing (no patches applied)
DumperPro.exe --hex --process Game.exe --module Game.exe --hex-view 0x140001000
:: live patching (only on software you own; writes to the target's memory)
DumperPro.exe --hex --process Game.exe --hex-patch "0x140001000=90" --hex-live
```

### Command-line reference

| Flag | Meaning | Default |
|---|---|---|
| `--process <name>` | attach to a process (case-insensitive substring of the image name) | - |
| `--pid <n>` | attach by process id | - |
| `--file <path>` | analyze an on-disk x64 PE image instead of a live process; non-PE inputs (apk/zip/so/dex/metadata/vdex/oat) go to the static analysis pipeline | - |
| `--module <name>` | scan this module instead of the main module | main module |
| `--out <dir>` | output directory | `./DumperPro_Out/<game>_<timestamp>` |
| `--ini <games.ini>` | config file | `./games.ini` |
| `--kernel` | kernel-assisted memory access (see `docs/KERNEL.md`) | off |
| `--serve [port]` | local HTTP upload mode (drag & drop analysis) | port 8420 |
| `--metadata <file>` | pair with `--file`: Unity IL2CPP `global-metadata.dat` for binary matching | - |
| `--json` | machine-readable JSON outputs (`names.json`, `objects.json`, `analysis_report.json`) | off |
| `--hex` | hex/AOB view-editor-save mode (requires one of the `--hex-*` actions) | off |
| `--hex-view <off[:rows]>` | hex+ASCII table | - |
| `--hex-code <off[:rows]>` | x86/x64 code view (`--hex-bits 32/64`) | - |
| `--hex-binary <off[:bytes]>` | bit-level binary view | - |
| `--hex-type <off[:n:t]>` | typed value view (`0x1000:16:float`) | type `u32` |
| `--hex-search <aob>` | AOB/hex/`text:`/`text16:` + typed value (`f32:3.14`, `i32:1337`, `vec3:1 2 3`) search | - |
| `--hex-patch <spec>` | patch buffer: `"0x1000=90 E9;0x2000=CC"` | - |
| `--hex-save <file>` | write the patched copy to a NEW file | - |
| `--hex-live` | apply patches to the live process via memory write | off |
| `--hex-bits <32\|64>` | code view mode | 64 |
| `--hex-rows <n>` | default row count for views | 16 |
| `--probe <n>` | offset probe sample count | 400 |
| `--no-sdk` | dump names/objects/offsets only, skip SDK generation | off |
| `--verbose` | detailed logging | off |
| `--list-profiles` | print built-in game profiles and exit | - |
| `--help` | usage | - |

## Configuration (games.ini)

`games.ini` drives everything. Sections named after the target image (prefix match) are picked
automatically. Values accept hex (`0x10`) or decimal; a value of `0` means "auto-detect / probe".

```ini
[MyGame]
version = 5.3
gobjects = 0x7FF6A1234568
gnames   = 0x7FF6A1234ABC

; or, instead of addresses, explicit patterns (validated before built-in sigs):
; gobjects_pattern = 48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8
; gnames_pattern   = 48 8D 35 ?? ?? ?? ?? EB 16

; structural overrides (dotted keys - the full key list is in the shipped games.ini):
; array.item_stride = 0x18
; array.chunk_size  = 0x2800
; class.cdo         = 0
; function.func     = 0
```

Global keys: `verbose`, `probe`, `vtable.minindex`, `gobjects`, `gnames`, `gobjects_pattern`,
`gnames_pattern`, `fingerprint.<Function>` (alternatives separated by `|`).

The shipped `games.ini` documents every recognized dotted key
(`uobject.*`, `ufield.next`, `ffield.*`, `property.*`, `struct.*`, `class.cdo`, `enum.names`,
`function.*`, `array.*`).

## Output files

| File | Contents |
|---|---|
| `Names.txt` | FName table: `0x000001: Name` per line, followed by the names-mode note (pool block size / alignment) |
| `Objects.txt` | `[000001] <class> <name> <outer path> 0x<address>` per entry, `<invalid>` for empty slots |
| `offsets.txt` | Runtime probe report: every field offset, its value, source (`profile` / `probe` / `confirmed`) and confidence |
| `signatures.txt` | Primary + 16-byte extended signatures for GNames/GObjects (and GWorld when found), reusable patterns |
| `<Game>_sigs.txt` | `games.ini`-ready section (`version`, `gnames_pattern`, `gobjects_pattern`) to skip scanning next run |
| `vtable_funcs.txt` | VTable resolver results: slot, RVA/VA, slot RVA, thunk depth, votes (or `NOT_FOUND`) |
| `funcs.txt` | Dumped UFunctions with native addresses; tagged with the vtable result when resolved |
| `il2cpp_report.txt` | IL2CPP metadata Turkish summary (versions 16..31) |
| `il2cpp_dump.cs` | dump.cs-style type/field/method skeleton with tokens and slots |
| `il2cpp_metadata.json` | Machine-readable IL2CPP schema (counts, images, types) |
| `il2cpp_stringliterals.txt` | IL2CPP string literal table (first 100k) |
| `il2cpp_methodaddresses.txt` | Binary matching: Image/Type/Method + RVA/VA/file-offset per method |
| `il2cpp_script.json` | Il2CppDumper-compatible ScriptMethod list (+ ScriptMetadata for v19-24.5 usages) |
| `il2cpp_usages.txt` | Binary matching: metadata usage slots (v19-24.5) - cell VA + resolved reference name |
| `il2cpp_binary_report.txt` | Binary matching scan report (modules, registration, usages, stats) |
| `DummyDll/` | Per-image compilable C# stubs (Il2CppDumper DummyDll parity) + build.bat |
| `analysis_report.txt` / `analysis_report.json` | Static file analysis report (apk/zip/so/dex/il2cpp/vdex/oat) |
| `names.json` / `objects.json` | JSON schemas of the live dumps (`--json`) |
| `SDK/_basics.hpp` | Shared core types and defines used by the generated SDK |
| `SDK/SDK.hpp` | Master include that pulls in every package |
| `SDK/<Pkg>_classes.h` | UClass-derived classes for one package (members + functions) |
| `SDK/<Pkg>_structs.h` | UStruct-derived structs for one package |
| `SDK/<Pkg>_enums.h` | UEnums for one package |

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `GObjects not found` / `GNames not found` | non-stock engine build, obfuscation, or protected process | Add explicit addresses (`gobjects = 0x...`, `gnames = 0x...`) or patterns (`gobjects_pattern = ...`) to the game's `games.ini` section; try `--kernel`; run as Administrator; for protected targets try file mode on the on-disk binary |
| `Objects parse failed: invalid stride` / implausible object counts | custom `FUObjectItem` stride or chunk size | Set `array.item_stride` (try `0x10`, `0x18`, `0x20`) and `array.chunk_size` (`0x2800` for UE4, `0x10000` for UE5) in the game section |
| `UE version not detected from image strings` | stripped or custom build info strings | Set `version = 4.27` (or `5.3`, ...) in the game section; the matching built-in profile is then used |
| `GNames parse failed` | custom name pool layout | Add pool offsets / patterns to `games.ini`; check `--verbose` output for the block size the pool validator chose |
| SDK members look shifted | tweaked struct layout | Override the dotted keys (`uobject.*`, `struct.*`, `property.*`, `function.*`, `class.cdo`, ...) per game; compare against `offsets.txt` |
| SDK generation failed | missing engine data for a package | Re-run with `--verbose`; dumps (`Names.txt`, `Objects.txt`, `offsets.txt`) are still valid |
| Cannot open target | missing privileges or handle stripped | Run as Administrator; try `--kernel` (see `docs/KERNEL.md`); or use `--file` mode |

## Project layout

```
src/main.cpp            orchestration: CLI, pipeline stages, output files
src/core/               MemoryReader (process/file/kernel abstraction), PEFile, Pattern scanning
src/ue/                 UEVersion, Offsets (profiles), ObjectArray, NameArray, OffsetProbe, UEObject
src/sig/                SigFinder: patterns + validation + heuristic struct scan
src/dump/               Dumps (Names/Objects + JSON), SDKGenerator, VTableResolver
src/config/             games.ini parsing, built-in profiles
src/file/               StaticAnalyzer, ZipReader (APK), UniFormat (ELF/DEX), OatVdex (ART)
src/il2cpp/             Il2Cpp metadata parser + binary matching + usages + DummyDll (Il2CppDumper-verified)
src/hex/                HexTool: hex/byte/code/binary/AOB view-editor-save (+ live patch)
src/net/                HttpServer: --serve upload mode (threaded, bounded)
docs/ALGORITHM.md       deep technical reference (byte layouts, pseudocode)
docs/REFERENCES.md      comparative research on similar tools
docs/KERNEL.md          optional kernel-assisted reader: contract and safety
docs/ONLINE.md          online upload / static analysis system
docs/IL2CPP.md          IL2CPP + OAT/VDEX modules (verified sources)
games.ini               config template + documented keys
CMakeLists.txt          build definition (C++20, MSVC/MinGW)
```

## DISCLAIMER

**DumperPro is provided for legitimate purposes only:**

- offline analysis of software you own or are licensed to analyze;
- single-player game modding;
- interoperability and engine research;
- security research on systems you own or are authorized to test.

**Do not use DumperPro to cheat in multiplayer games, to bypass anti-cheat or DRM systems, or to
attack, disrupt, or gain unauthorized access to any system or service.** Multiplayer/competitive
use is explicitly out of scope and unsupported.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. USE AT
YOUR OWN RISK AND IN COMPLIANCE WITH ALL APPLICABLE LAWS AND LICENSES.
