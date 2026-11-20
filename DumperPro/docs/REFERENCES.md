# DumperPro - Related Tools and Research References

Comparative research on the tools DumperPro draws from. The goal is a finetuning-corpus style
survey: what each project is, which techniques it uses, what it outputs, and which of those
ideas DumperPro adopted. All projects are referenced **by name only** - consult each project's
repository or distribution channel for the authoritative license text; the license notes below
summarize public knowledge at the time of writing and are informational only.

---

## 1. Il2CppDumper

**What it is.** The de-facto standard dumper for Unity games built with the IL2CPP backend. It
combines a metadata file with the game binary to reconstruct C# type information.

**Target engine / format.** Unity + IL2CPP: `global-metadata.dat` plus the game binary
(`GameAssembly.dll` on Windows, `libil2cpp.so` on Android/iOS).

**Core techniques.**
- Full parse of the IL2CPP metadata format (string literals, type/method/field definition
  tables, attribute data), versioned across dozens of metadata revisions.
- Locates `Il2CppCodeRegistration` / `Il2CppMetadataRegistration` in the binary to map
  method pointers to metadata indices.
- Binary analysis to find these registration structures when symbols are stripped
  (targeted signature/pointer-shape scanning).
- Produces "dummy DLLs": compilable assemblies with correct names, fields, and method
  addresses attached as metadata, loadable into decompilers/debuggers.

**Outputs.** `dump.cs`, dummy DLLs, `script.json`, IDA/Ghidra/Binary Ninja loader scripts,
string literal dumps, address resolution files.

**License.** Open source (permissive; see repository).

**What DumperPro adopted.**
- The "two-source" philosophy: pair a metadata/reflection source with the binary and
  cross-validate instead of trusting either alone (DumperPro: names + objects vs. code/image).
- Reusable artifacts: exactly like Il2CppDumper's scripts, DumperPro writes
  `<Game>_sigs.txt` so a one-time analysis accelerates every later run.
- Address annotation style in textual dumps (every item carries its address/index).

---

## 2. Dumper-7

**What it is.** The most influential Unreal Engine SDK generator of its generation; runs
injected into the target process and walks the live reflection data.

**Target engine / format.** UE4/UE5 live processes (engine 4.25+ and UE5 era emphasized).

**Core techniques.**
- In-process access: GObjects/GNames are read directly as engine globals; no external
  memory translation layer needed.
- Full `FField`/`FProperty` model traversal, including typed property extras and the
  `FFieldClass` dispatch.
- SDK emission with per-package file split, inheritance chains, and the now-standard
  `Params_` structs for UFunctions.
- Predefined-struct awareness (common engine structs like `FVector` get real definitions
  instead of raw bytes) and member sorting by `Offset_Internal`.

**Outputs.** A complete C++ SDK: `SDK.hpp` master include, per-package `_classes.h`,
`_structs.h`, `_enums.h`, basic header with common types, plus function-name to address maps.

**License.** Open source (public repository; see repository for the current license).

**What DumperPro adopted.**
- The per-package SDK layout verbatim: `_classes.h` / `_structs.h` / `_enums.h` per package,
  `_basics.hpp` + `SDK.hpp` master includes.
- `Params_<Function>` parameter structs with engine-accurate layouts.
- Member comments encoding offset and size (`// 0xOFF(0xSIZE)`).
- Inheritance-chain emission and prefix heuristics (`A/U/F/E`) for readable types.
- Bitfield-aware `FBoolProperty` rendering.

---

## 3. UEDumper

**What it is.** A GUI-oriented Unreal Engine SDK dumper, known for an interactive object-tree
inspector in addition to headless dumping.

**Target engine / format.** UE4/UE5 Windows targets (live process, with external and
in-process read paths).

**Core techniques.**
- External memory access through a reader abstraction, decoupled from the UI.
- Object-array layout auto-detection (strides, chunking) similar in spirit to DumperPro's
  `DetectLayout`.
- Interactive exploration of the GUObjectArray hierarchy before committing to a dump.
- C++ and JSON output generation with offset annotation.

**Outputs.** Generated C++ SDK headers, JSON dumps of the object model, name dumps.

**License.** Open source (public repository; see repository for the current license).

**What DumperPro adopted.**
- The reader-abstraction idea: all engine code consumes one `IMemoryReader` interface, so
  process/file/kernel backends are interchangeable.
- Layout auto-detection with sampled validity voting rather than fixed per-version offsets.
- The value of giving the operator visibility mid-run (DumperPro expresses this as
  progress bars and verbose logging rather than a GUI).

---

## 4. RE-UE4SS

**What it is.** A full framework for live Unreal Engine modding: Lua scripting over the engine
object model, live object inspection, GUI overlays, and hooking.

**Target engine / format.** UE4/UE5 live processes, broad version coverage.

**Core techniques.**
- Pattern-based bootstrap for GObjects/GNames/GWorld across many engine versions, including
  the FNamePool changes in 4.23+ and the legacy TNameEntryArray before it.
- Version-adaptive reflection traversal (both UProperty and FField chains).
- Live instrumentation: property injection, function hooks, and a Lua API bound to UObject
  instances - dumping is a byproduct of its introspection layer.
- Careful FName handling (pool walking, wide strings, FName numbers).

**Outputs.** Live object/model data, Lua-accessible type information, generated SDKs for
modders, extensive logs.

**License.** Open source (public repository; see repository for the current license).

**What DumperPro adopted.**
- The FNamePool walking strategy (block cursor layout, 2-byte entry headers, wide strings,
  printable-ratio validation) and the legacy name-array fallback for 4.20-4.22.
- The idea of shipping broad version defaults as data rather than code paths per game
  (DumperPro: built-in profiles + `games.ini` overrides).
- Operator-facing diagnostics: version detection and layout decisions are logged, not silent.

---

## 5. GSpots

**What it is.** A community toolchain in the UE memory-dumping space, cited alongside
Dumper-7-class SDK generators; public documentation is sparse compared with the other tools in
this list, so this summary is deliberately conservative.

**Target engine / format.** UE4/UE5 live processes (Windows), historically also mobile
targets in the surrounding community tooling.

**Core techniques.**
- Offset-first workflow: per-game offset tables gathered quickly (often semi-manually) and
  reused as configuration instead of re-scanning.
- Straight-forward GObjects/GNames enumeration with hardcoded-shape signature fallbacks.
- Emphasis on fast turnaround for package dumps over exhaustive SDK emission.

**Outputs.** Names/object listings, package dumps, offset tables for downstream tooling.

**License.** Open source lineage in the community tooling space; exact current license and
availability vary - verify before reuse.

**What DumperPro adopted.**
- The offset-first, config-as-data workflow: `games.ini` explicitly supports pinned
  addresses and per-game layout overrides so a known game never needs scanning again.
- The `via` reporting concept ("config" / "sig" / "heuristic") that makes provenance visible.

---

## 6. patternsleuth

**What it is.** A Rust library for binary analysis that specializes in *finding and
validating* engine symbols (GObjects, GNames, and friends) across many engine versions and
executables, used by several modern UE tooling projects.

**Target engine / format.** PE and ELF binaries from UE4/UE5 titles (both live and static
analysis contexts).

**Core techniques.**
- Candidate generation: many cheap patterns/heuristics per symbol instead of one brittle
  signature.
- Candidate validation: each candidate is checked against structural invariants (member
  relationships, pointer plausibility, cross-references) before acceptance.
- Multi-binary robustness: designed so that the same resolver works across a corpus of game
  builds, not just one.
- Explicit separation of "sleuthing" (discovery) from "reading" (layout interpretation).

**Outputs.** Library results (symbol addresses + confidence), consumed by higher-level
dumpers.

**License.** Open source (public repository; see repository for the current license).

**What DumperPro adopted.**
- The candidate-then-validate architecture: `SigFinder` produces candidates, dedicated
  validators (`ObjectArray::ValidateCandidate`, `NameArray::ValidateCandidate`) accept or
  reject them, and only validated candidates mutate state.
- The heuristic struct scan with count relationships (`NumChunks == ceil(NumElems/ChunkSize)`,
  chunk pointer sanity, sampled item validity) mirrors patternsleuth's invariant-driven
  discovery.
- Confidence reporting instead of silent best-guess acceptance.

---

## 7. UE5CEDumper

**What it is.** A community dumper oriented around UE5 titles and Cheat Engine workflows;
public documentation is sparse, so specifics below are kept general.

**Target engine / format.** UE5 Windows targets.

**Core techniques.**
- FNamePool walking tuned for UE5-era pools (larger blocks, wide entries).
- Pointer-scan-friendly output: object addresses and structures are arranged so downstream
  Cheat Engine tables can reference them directly.
- Chunked object array traversal with the UE5 chunk size (65536) as the common case.

**Outputs.** Object/name listings and table data suitable for manual inspection tools.

**License.** Open source lineage; exact current license and availability vary - verify before
reuse.

**What DumperPro adopted.**
- Treating UE5 chunk size 65536 as a first-class auto-detection candidate rather than an
  afterthought to the UE4 value.
- The recognition that downstream consumers want *addresses* (VA/RVA) alongside names;
  DumperPro's `Objects.txt` and `vtable_funcs.txt` carry both.

---

## 8. GPUDumpViewerTool

**What it is.** A vendor tool for inspecting "GPU dumps" - captures of the rendered frame's
GPU-side state (resources, passes, textures) produced by engine debug capture paths such as
UE's `r.DumpGPU` console command.

**Target engine / format.** UE renderer debug dumps (capture directories with metadata and
texture assets), not engine memory.

**Core techniques.**
- Parsing of the structured capture format (JSON metadata plus resource payloads).
- Interactive browsing of passes/resources with image previews.
- Rendering the dependency flow of a frame's GPU work.

**Outputs.** A browsable view over GPU state; no SDK, no memory dumps.

**License.** Freely available vendor tool (closed source; distributed as a free download).

**What DumperPro adopted.**
- Not a technique - a *design cue*: first-party debug dumps are structured, address-annotated,
  and human-browsable. DumperPro's textual dumps (`Names.txt`, `Objects.txt`, `offsets.txt`,
  `vtable_funcs.txt`) follow the same "the file is the UI" principle.
- Reminder of scope: a dumper's value is mostly its *format stability*; formats are documented
  and kept stable between versions.

---

## 9. ExecFunctionsImporter

**What it is.** A small community utility focused on enriching dumped SDKs with engine *exec*
functions - the console-callable UFunctions (`FUNC_Exec = 0x00000200` in `EFunctionFlags`) -
which stock SDK generators often render as plain functions without marking their exec nature.

**Target engine / format.** UE4/UE5 SDK dumps / live reflection data.

**Core techniques.**
- Scanning UFunction flags for the exec bit and correlating with console command name
  tables from the target.
- Importing/merging external function lists into existing SDK output rather than re-dumping.
- Post-processing existing dumps instead of owning the dump pipeline.

**Outputs.** Updated SDK headers or sidecar lists marking exec functions with their console
entry points.

**License.** Open source lineage (public repository; see repository for the current license).

**What DumperPro adopted.**
- Function flags are treated as first-class data: DumperPro reads `EFunctionFlags` per function
  (`function.flags`), and `funcs.txt` annotates native targets, so consumers can filter by
  flag semantics (`FUNC_Native = 0x400`, exec, net flags) without re-parsing the SDK.
- The merge-not-re-dump principle: `<Game>_sigs.txt` and `offsets.txt` are designed as
  drop-in inputs for subsequent runs.

---

## 10. FModel

**What it is.** The standard open-source Unreal Engine archives explorer: browses `.pak`
packages, extracts game assets, and renders many of them (textures, meshes, audio) with a map
and model viewer.

**Target engine / format.** UE `.pak`/`.utoc`/`.ucas` container formats and asset serialization
on disk; engine-agnostic across UE4/UE5 titles.

**Core techniques.** (brief)
- Container format parsing (pak versions, encryption, index handling) and UE asset
  serialization parsing (property system on disk, which mirrors the runtime property model).
- Mapping-based community data (aes keys, mapping files) shared as plain data files.
- On-disk FName/FProperty handling that largely parallels the runtime reflection model.

**Outputs.** Extracted assets, texture previews, model exports, directory listings.

**License.** Open source (public repository; see repository for the current license).

**What DumperPro adopted.**
- The confirmation that the UE property model is the same shape on disk and in memory, which
  is why DumperPro's property handling (typed extras, flags, enum/struct references) is
  version-table-driven rather than hardcoded.
- The idea that a dumper is most useful when its outputs are stable, widely understood file
  formats.

---

## 11. Technique matrix

Legend: yes = core part of the tool; partial = supported but not central; - = absent/not
documented. Judgements reflect public documentation and DumperPro's reading of the tools'
outputs; they are qualitative.

| Technique | Il2CppDumper | Dumper-7 | UEDumper | RE-UE4SS | GSpots | patternsleuth | UE5CEDumper | GPUDumpViewer | ExecFuncsImport | FModel | DumperPro |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Metadata/reflection source pairing | yes (metadata file) | yes (live reflection) | yes | yes | partial | partial | partial | - | partial | yes (disk assets) | yes |
| IL2CPP metadata + binary matching | yes | - | - | - | - | - | - | - | - | - | yes (v16-31) |
| Signature scanning | yes | partial | partial | yes | yes | yes | partial | - | - | - | yes |
| Heuristic + invariant validation | yes | - | partial | partial | - | yes | - | - | - | - | yes |
| Chunked object array walk (10240/65536) | - | yes | yes | yes | yes | - | yes | - | - | - | yes |
| FNamePool walk (2-byte header, wide) | - | yes | yes | yes | partial | - | yes | - | - | - | yes |
| Legacy name array (4.20-4.22) | - | - | partial | yes | partial | - | - | - | - | - | yes |
| Version auto-detection (strings) | yes | partial | partial | yes | - | yes | - | - | - | yes (mappings) | yes |
| Runtime offset probing (voting) | - | - | partial | partial | partial | partial | - | - | - | - | yes |
| Config-driven offsets (per game) | partial | partial | partial | partial | yes | - | partial | - | - | partial | yes |
| Full C++ SDK generation | - (dummy DLLs) | yes | yes | yes | partial | - | - | - | partial | - | yes |
| Params_ function structs | - | yes | yes | yes | partial | - | - | - | - | - | yes |
| Bitfield + padding correctness | - | yes | yes | yes | - | - | - | - | - | - | yes |
| VTable slot resolution (dynamic) | - | - | - | partial | - | partial | - | - | - | - | yes |
| Kernel-assisted reads | - | - | - | - | - | - | partial | - | - | - | yes (client) |
| Static file (PE) mode | yes (static binary) | - | - | - | - | yes | - | - | - | yes (containers) | yes |
| Non-PE binaries (ELF/APK) | yes | - | - | - | - | yes | - | - | - | yes (Android) | yes |
| Interactive GUI | - | - | yes | yes | - | - | - | yes | - | yes | - (console) |

Reading the matrix:

- DumperPro's distinctive column combination is **external/live + signature + heuristic
  validation + probing + static PE mode + config-as-data**, while Dumper-7/UE4SS dominate the
  in-process modding niche and Il2CppDumper/patternsleuth dominate static multi-binary analysis.
- Several techniques (FNamePool walking, SDK emission) are "solved problems" in the community;
  DumperPro's contribution is combining them behind one reader abstraction with confidence
  reporting at every stage.

---

## 12. Further research directions

Directions DumperPro (or a successor) could take, ordered roughly by expected value.

### 12.1 IL2CPP metadata parsing
The Il2CppDumper lineage shows the payoff of treating *metadata* as a first-class input.
For DumperPro the analogue is richer use of UE's own metadata that the dumper currently
ignores: class/function metadata strings, blueprint-generated names, and (for Unity-adjacent
tooling) an optional IL2CPP mode that reuses the same signature/validation plumbing. A
metadata-version table plus attribute parsing would also let generated SDKs carry
`UFUNCTION`/`UPROPERTY` specifiers verbatim.

### 12.2 ELF / APK static mode
Windows-only today. Most UE titles ship Android/Linux builds using the same engine layouts on
ELF binaries inside APK containers. Adding an ELF reader backend to the existing
`IMemoryReader`/`ModuleImage` unification is mostly mechanical (program headers replace
sections; the uniform "offset == RVA" model needs a PT_LOAD-based equivalent). Static APK mode
would additionally need container extraction; the community mapping files FModel consumes show
that once static mode works, version detection and profile tables port unchanged.

### 12.3 GWorld / GInstance heuristics
DumperPro finds GWorld only opportunistically today. The patternsleuth-style approach
generalizes: scan for data-section pointers whose target passes a `UWorld`-shaped validator
(class chain contains `World`, `OuterChain` plausible, `PersistentLevel` member resolves), then
vote across frames. `GEngine` / `GInstance` follow the same recipe with their own invariants.
This would make live tooling (not just dumping) possible from the same discovery layer.

### 12.4 CDO scraping
`ClassDefaultObject` is already probed (`class.cdo`, `RF_ClassDefaultObject = 0x01000000`), but
its *contents* are unused. Emitting default values (aligned to the generated member offsets)
into the SDK headers or a sidecar defaults file would give instant, engine-accurate
initializers for tooling, and doubles as a powerful validation signal (a wrong member offset
produces implausible CDO values - usable as probe evidence).

### 12.5 Blueprints
Blueprint data is the largest remaining blind spot: `UBlueprint`/`UBlueprintGeneratedClass`
objects carry node graphs and compiled bytecode that the current SDK ignores beyond the
generated class shell. Research directions: emitting BP-generated function flags distinctly,
parsing `FKismetBytecode` enough to recover call targets, and linking BP graphs to the dumped
SDK. Even a shallow pass (flag + name level) would materially help modding tooling.

### 12.6 Strings and serialization
FName pools are sometimes encrypted or re-hashed by custom builds; a "string pipeline" research
thread would cover: detection of encrypted pools (printable-ratio failure is already the
signal), derivation of deobfuscation parameters, string-table assets, and alternative output
serializations (JSON/SQLite alongside the current text dumps) so downstream tooling can query
the dump instead of grepping it. The same thread should cover stable machine-readable schemas
for all outputs - the lesson from both GPUDumpViewerTool and FModel is that format stability is
a feature.

---

## 13. Uc-arac ozellik paritesi (guncel durum)

Kullanici istegi: Dumper-7, Il2CppDumper ve UnrealCEDumper'daki TUM ozellikler
DumperPro'ya "calisir halde" tasinacak. Asagidaki tablo bu hizalamanin
guncel durumudur (her satir gercek bir modul/komut ile desteklenir).

### 13.1 Il2CppDumper paritesi

| Il2CppDumper ozelligi | DumperPro karsiligi | Durum |
|---|---|---|
| global-metadata.dat parse (v16-31) | `src/il2cpp/Il2Cpp.cpp` | TAM - ayni surum araligi, ayni v24 alt-surum sezgileri |
| CodeRegistration/MetadataRegistration taramasi | `src/il2cpp/Il2CppBinary.cpp` | TAM - codegen-modules (v24.1+) + flat (v16-24.0); fieldOffsetsCount==tip sayisi dogrulamasi |
| Metod native adresleri (token RID -> methodPointers) | `il2cpp_methodaddresses.txt` | TAM - RVA/VA/Offset + reloc etiketi |
| `dump.cs` (adres yorumlari) | `il2cpp_dump.cs` | TAM - "// RVA: .. Offset: .. VA: .." bicimi |
| Gercek tip isimleri (Il2CppType tablosu) | MetadataRegistration taramasi + `TypeResolver` | TAM - CLASS/VALUETYPE/GENERICINST/SZARRAY/PTR/ARRAY/VAR/MVAR rekursif cozum; Il2CppClass name(+0x10)/namespaze(+0x18) |
| Alan ofsetleri (fieldOffsets) | `// 0x..` yorumlari | TAM - dump.cs'te her alanda |
| `script.json` (IDA/Ghidra) | `il2cpp_script.json` | TAM - ScriptMethod + ScriptString/ScriptMetadata/ScriptMetadataMethod (v19-24.5 usages) |
| String literal dump | `il2cpp_stringliterals.txt` | TAM |
| metadataUsages isimlendirme (v19-24.5) | `Il2CppBinary.cpp` usage slot cozumleme + `il2cpp_usages.txt` | TAM - list/pair decode (Il2CppDumper Metadata.cs ile ayni formuller), kodgen hucre VA dogrulama (map'li VEYA bss), script.json ScriptMetadata doldurma |
| Dummy DLL | `src/il2cpp/Il2CppDummyDll.cpp` -> `DummyDll/` | TAM (kaynak duzeyi) - image basina derlenebilir C# stub + [Address]/[Token]/[FieldOffset] attribute'lari + build.bat; Il2CppDumper dnlib ile binary assembly yazar, DumperPro ayni icerigi csc ile derlenebilir kaynak olarak verir |
| PIE relocation destegi (ELF) | `BuildElfView` RELA RELATIVE | TAM - x86-64(8)/AArch64(1027)/RISC-V(3) |

### 13.2 Dumper-7 paritesi

| Dumper-7 ozelligi | DumperPro karsiligi | Durum |
|---|---|---|
| GObjects/GNames canli okuma | `ObjectArray`/`NameArray` | TAM - chunked + duz layout, FNamePool/TNameEntryArray |
| Paket-bazli SDK (`_classes/_structs/_enums`) | `SDKGenerator` | TAM - ayni dosya adlari + `SDK.hpp` |
| `Params_<Fonksiyon>` struct'lari | `SDKGenerator` | TAM |
| Uye ofset yorumlari | `// 0xOFF(0xSIZE)` | TAM |
| Bitfield/padding dogrulugu | `FBoolProperty` bitfield | TAM |
| Miras zinciri cikti | `SDKGenerator` | TAM |
| On-tanimli struct'lar (FVector/FTransform) | `_basics.hpp` | TAM |
| Fonksiyon-adres haritasi | `funcs.txt` + vtable fonksiyonlari | TAM |

### 13.3 UnrealCEDumper / UEDumper paritesi

| Araç ozelligi | DumperPro karsiligi | Durum |
|---|---|---|
| Okuyucu soyutlamasi (process/file/kernel) | `IMemoryReader` | TAM |
| Layout oto-tespiti (stride/chunk oy verme) | `DetectLayout`/`OffsetProbe` | TAM |
| Cikti icinde adres tasima (VA/RVA) | `Objects.txt`/`vtable_funcs.txt` | TAM |
| Canli bellek GORUNTULEME | `--hex --process --hex-view/--hex-code/--hex-binary` | TAM - klasik hex, x86/x64 kod, bit duzeyi |
| Canli ARAMA (AOB/metin) | `--hex-search` | TAM - jokerli AOB, bosluksuz hex, text: |
| Canli DÜZENLEME | `--hex-patch` + `--hex-live` | TAM - undo yigini, IMemoryReader::Write ile uygulama |
| Kaydetme | `--hex-save` | TAM - yamali kopya YENI dosya (orijinal korunur) |
| GUI nesne agaci | konsol ciktilari + --serve HTML rapor | KISMİ - ayni veri, farkli arayuz |

### 13.4 Kalan farklar (durusucusuz liste)

1. Dummy DLL binary formu (Il2CppDumper dnlib ile .NET PE yazar): DumperPro
   ayni icerigi DERLENEBILIR C# kaynak olarak uretir (DummyDll/ + build.bat);
   binary assembly yazici yerine kaynak duzeyi paritesi secildi. Istenirse
   iccil .NET metadata PE yazicisi sonraki adim olabilir.
2. metadataUsages MethodRef'in generic metod adresi (methodSpec -> generic
   methodPointers eslemesi): Il2CppDumper generic pointer tablosunu da cozer;
   DumperPro su an spec.methodDefinitionIndex ile isim verir, adres 0 kalir.
3. GUI: DumperPro bilincli olarak konsol + --serve (tarayici) kullanir.
