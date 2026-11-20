# DumperPro - Algorithm Reference

Deep technical reference for DumperPro, a C++20 Windows tool that dumps Unreal Engine game data
from a live process or a PE file and generates a full C++ SDK. This document doubles as
training/research material: every section gives concrete byte layouts and pseudocode-level detail.

Companion documents: `README.md` (usage), `docs/KERNEL.md` (kernel-assisted reader),
`docs/REFERENCES.md` (related tools and research directions).

---

## 0. Conventions

| Term | Meaning |
|---|---|
| `u8/u16/u32/u64`, `i8/i16/i32/i64` | fixed-width unsigned/signed integers |
| RVA | offset from the module image base |
| VA | absolute virtual address (`imageBase + RVA`) at runtime |
| image base | runtime module base (process mode) or preferred ImageBase (file mode) |
| offsets | hexadecimal byte offsets *inside* engine structures, as used by the engine |

All engine numbers in this document match the code defaults in `src/ue/Offsets.h` and the
profile table in `src/config/Config.cpp`. Where a build deviates, the corresponding
`games.ini` key overrides the default without recompiling.

---

## 1. Pipeline overview

```
target (--process / --pid / --file / --kernel)
  -> [1] reader            IMemoryReader      process | file | kernel client
  -> [2] module image      ModuleImage        uniform addressing: Data offset == RVA
  -> [3] version detect    VersionDetector    "Release-M.m" strings, voting
  -> [4] profile           UEOffsets          games.ini > builtin (8 profiles) > defaults
  -> [5] GNames            SigFinder+NameArray    config addr > config pattern > sigs > heuristic
  -> [6] GObjects          SigFinder+ObjectArray  same precedence, name-count-aware validation
  -> [7] GWorld (optional) SigFinder
  -> [8] offset probe      OffsetProbe        votes over live objects -> offsets.txt
  -> [9] dumps             DumpNames/DumpObjects  Names.txt, Objects.txt
  -> [10] vtable resolver  VTableResolver     ProcessEvent / PostRender / ProcessRemoteFunction
  -> [11] SDK generator    SDKGenerator       packages -> _classes.h/_structs.h/_enums.h
  -> [12] signature files  WriteSignature     signatures.txt + <Game>_sigs.txt
```

Stage order is deliberate:

- **GNames before GObjects.** Object validation is stronger when the name count is known
  (a candidate `FUObjectItem` whose FName index exceeds the name count is rejected).
- **Profile before probing.** The probe fills only what the profile left at `0` ("auto").
- **Probe before SDK.** The generator consumes the reconciled offset table, so generated
  headers already reflect any auto-detected layout.
- **VTable resolver before SDK.** Resolved slots are passed into the generator and used to
  tag `funcs.txt` entries.

---

## 2. Readers and module image unification

### 2.1 Reader abstraction

`IMemoryReader` (`src/core/MemoryReader.h`) is the single memory interface used by every later
stage. Implementations:

| Backend | Created by | Notes |
|---|---|---|
| process reader | `CreateProcessReader(proc, pid, kernel=false)` | user-mode `OpenProcess`/`ReadProcessMemory`-style access |
| kernel client | `CreateProcessReader(proc, pid, kernel=true)`  | speaks the IOCTL contract of `docs/KERNEL.md`; interface only |
| file reader | `CreateFileReader(path)` | memory-maps the on-disk PE; `IsLiveProcess() == false` |

The interface offers typed helpers (`ReadU32`, `ReadPtr`, `ReadCString`, `ReadWideString`,
`ReadVal<T>`) plus `Modules()`, `MainModuleBase()`, `TargetName()`, `IsOK()`, `LastError()`.
Writes exist on the interface but are unused; the tool is read-only by design (see
`docs/KERNEL.md` for the no-write policy of the kernel path as well).

### 2.2 Module image

`ModuleImage` solves the classic mapped-vs-file addressing problem by giving **one uniform
addressing model** to everything downstream:

```
Data offset == RVA   (always)
```

- **Process mode:** the module's mapped image is snapshotted as-is; the buffer offset of any
  byte equals its RVA already.
- **File mode:** the raw PE file is *expanded to memory layout* at load time (sections moved
  from `rawOff` to `va`), so after loading, buffer offset again equals RVA.

Consequences:

1. Pattern scans operate on RVAs directly; converting a hit RVA to a VA is `Base + rva`.
2. `PEFile::RvaToOffset` is identity (`mapped_ == true`) once the image is unified.
3. `Base` is the runtime base for live targets, or the preferred `ImageBase` from the optional
   header for file targets - both make `VA == Base + RVA` meaningful inside the snapshot.

### 2.3 PE parsing

`PEFile` (`src/core/PEFile.{h,cpp}`) is a portable parser (no `windows.h` in the parsing path):

- magic: `MZ` at 0x00, `e_lfanew` at 0x3C, `PE\0\0` at `e_lfanew`;
- PE32+ only (`OptionalHeader.Magic == 0x20B`); 32-bit images are rejected;
- fields read: `ImageBase` (opt+24), `SizeOfImage` (opt+56), `SizeOfHeaders` (opt+60),
  export directory RVA/size (opt+112/+116);
- section table entries (40 bytes each, capped at 96 sections): `name`, `VirtualSize` (+8),
  `VirtualAddress` (+12), `SizeOfRawData` (+16), `PointerToRawData` (+20), `Characteristics` (+36)
  with `IMAGE_SCN_MEM_EXECUTE` 0x20000000, `IMAGE_SCN_MEM_READ` 0x40000000,
  `IMAGE_SCN_MEM_WRITE` 0x80000000;
- `RvaToOffset` (file mode): headers range maps 1:1; otherwise the RVA is translated against
  sections using `max(VirtualSize, SizeOfRawData)`; an RVA inside the virtual zone
  (BSS / zero-fill) returns `0xFFFFFFFF` and callers treat it as "not present";
- `Exports()`: walks the export directory (names table, ordinal table, functions table);
- `VersionStrings()`: raw substring scan used by version detection (section 3).

`ModuleImage` additionally classifies a VA by section (`InExecSection`, `InDataSection`), which
the vtable resolver and signature validators use to reject nonsense pointers quickly.

---

## 3. UE version detection

`VersionDetector::Detect(img, ver)` (`src/ue/UEVersion.cpp`):

1. `PEFile::VersionStrings()` scans the whole image bytes for the needles
   `"++UE4+Release-"`, `"++UE5+Release-"`, `"Release-4."`, `"Release-5."`
   (UE embeds build info strings such as `++UE4+Release-4.27+...` in `.rdata`).
2. After each needle the parser accepts up to 16 characters of `[0-9.]` and requires the
   shape `M.m` (major/minor digits, patch digits are ignored).
3. Duplicates are dropped; every remaining string casts one vote for its `(major, minor)` pair.
4. **Voting:** the pair with the most votes wins; ties are broken by taking the **higher**
   version (later builds are the more likely origin of a stale duplicated string).
5. `UEVersion::IsValid()` is `major > 0`; detection failure leaves `{0, 0}` and a warning.

Example strings and votes:

```
++UE4+Release-4.27+CL-0  ->  (4,27)
++UE4+Release-4.27+CL-1  ->  (4,27)
++UE4+Release-4.26+CL-0  ->  (4,26)   -> winner: (4,27), 2 votes vs 1
```

If detection fails, `games.ini` can pin the version: `version = 5.2` in the game section.

---

## 4. Signature scanning

Everything global (GNames, GObjects, GWorld) is located with one shared mechanism in
`src/sig/SigFinder.*` on top of `src/core/Pattern.*`.

### 4.1 Resolution precedence

For each global, the first success wins:

1. `games.ini` explicit address (`gnames = 0x...`) - `via = "config"`;
2. `games.ini` explicit pattern (`gnames_pattern = ...`, alternatives split on `|`) - `via = "config"`;
3. built-in candidate signature list (`via = "sig"`);
4. heuristic struct scan (`via = "heuristic"`), only for GObjects/GNames/GWorld (section 5/6).

Config patterns are validated with the same validator as built-in sigs, so a stale
hand-written pattern fails safely instead of producing garbage.

### 4.2 IDA-style pattern parsing

Tokens are whitespace-separated hex bytes; `?`/`??` are full wildcards. A single `?` may also
be combined with a nibble (`4?` = high nibble fixed, low nibble wildcard). Internally a token
becomes `{value, mask}` with mask bits `0xFF` (fixed), `0xF0`/`0x0F` (half-wildcard), `0x00`
(wildcard):

| Token | value | mask |
|---|---|---|
| `48` | 0x48 | 0xFF |
| `4?` | 0x40 | 0xF0 |
| `?E` | 0x0E | 0x0F |
| `??` | 0x00 | 0x00 |

Matching is mask-based:

```text
MatchAt(data, pos, pat):
    for i in 0..pat.len:
        if (data[pos+i] & pat[i].mask) != (pat[i].value & pat[i].mask): return false
    return true
```

### 4.3 memchr-anchored scan

Full-image byte-by-byte matching is slow, so the scanner picks an **anchor**: the first token
whose mask is `0xFF`, then jumps with `memchr`:

```text
FindAll(data, size, pat, maxHits):
    anchor     = index of first fully-specified byte (-1 if none)
    pos        = 0
    while pos <= size - pat.len:
        if anchor >= 0:
            p = memchr(data + pos + anchor, pat[anchor].value, size - pos - anchor)
            if p == null: break
            pos = (p - data) - anchor          # candidate position of pattern start
            if pos > size - pat.len: break
        if MatchAt(data, pos, pat): hits.append(pos)
        pos += 1                                # continue scan after this position
    return hits
```

For the dense x64 prologues DumperPro scans, this collapses the scan to roughly one `memchr`
pass per pattern.

### 4.4 RIP-relative resolution

Each candidate (`SigCand`) declares:

| field | meaning |
|---|---|
| `pat` | IDA pattern bytes |
| `dispPos` | byte offset of the `disp32` inside the pattern |
| `instLen` | total instruction length in bytes (from pattern start) |
| `note` | description for logs |

A hit is resolved to a VA with:

```text
target = imageBase + hitOffset + instLen + disp32
```

where `disp32` is the little-endian i32 at `data[hitOffset + dispPos]`. This is the standard
x86-64 RIP-relative computation: the *next* instruction's address (`imageBase + hitOffset +
instLen`) plus the displacement. Example:

```
48 8B 05 43 7A 09 00        mov rax, [rip+0x9A743]
^  hit    ^dispPos=3   instLen=7
target = base + hitRVA + 7 + 0x0009A743
```

### 4.5 Extended (16-byte context) signature

For every accepted hit, `BuildExtendedSig` re-emits a **16-byte context** pattern: 16 bytes
spanning the original pattern, with the disp32 (and any bytes belonging to the resolved
instruction outside the pattern) wildcarded as `??`. The extended sig is stable across
rebuilds (addresses change, surrounding code rarely does) and is what gets written to
`signatures.txt` as `GNamesExtended` / `GObjectsExtended`.

### 4.6 Hit validation

A resolved VA is never trusted blindly. Validation is delegated to the consumers:

- `NameArray::ValidateCandidate` (section 6.4) for GNames;
- `ObjectArray::ValidateCandidate` (section 5.4) for GObjects, name-count-aware.

A pattern with multiple hits is tried hit-by-hit; the first hit whose validation succeeds is
kept, and its `{pattern, extended, via, va}` is stored in `SigHit` for the signature files.

---

## 5. GObjects discovery

### 5.1 Engine structures

Stock engine layouts (x64, stock alignment):

**`FUObjectArray`** - the GObjects global. The chunked array member `ObjObjects` starts at
`0x10` (the first four `int32`s at 0x00..0x0C are GC bookkeeping), which is why every array
offset below is shifted by `0x10`:

| Offset (in FUObjectArray) | Field (FChunkedFixedUObjectArray) | Type |
|---|---|---|
| 0x00 - 0x0F | GC bookkeeping (`ObjFirstGCIndex`, `ObjLastGCIndex`, `ObjOpenForDisregardForGC`, `AutoDisregardForGC`) | int32 x4 |
| 0x10 | `Objects` - chunk pointer table | `FUObjectItem**` |
| 0x18 | `MaxElements` | int32 |
| 0x1C | `NumElements` | int32 |
| 0x20 | `MaxChunks` | int32 |
| 0x24 | `NumChunks` | int32 |

These five offsets are exactly the profile defaults
(`array.chunks_ptr=0x10`, `array.max_elements=0x18`, `array.num_elements=0x1C`,
`array.max_chunks=0x20`, `array.num_chunks=0x24`).

**`FFixedUObjectArray`** (flat variant, `array.flat = 1`): no chunk table; the item array
pointer, `MaxElements`, `NumElements` live directly in the struct. The same `array.*` config
keys apply; `array.chunks_ptr` then points at the flat item array.

**`FUObjectItem`** - one slot per object. Three strides exist in the wild; DumperPro
auto-detects (`array.item_stride = 0` means auto):

| Stride | Layout |
|---|---|
| 0x10 | `UObject* Object` (8), `int32 Flags` (4), `int32 SerialNumber` (4) - builds without cluster tracking |
| 0x18 | `Object` (8), `Flags` (4), `ClusterRootIndex` (4), `SerialNumber` (4), pad (4) - classic UE4 |
| 0x20 | UE5-style: one additional int of GC bookkeeping after `SerialNumber` (+pad) |

**Chunk sizes:** UE4 default is 10240 (`0x2800`) objects per chunk; UE5 default is 65536
(`0x10000`). `array.chunk_size = 0` means auto-detect among these.

### 5.2 Signature candidates

Classic referencing code shapes (the shipped games.ini shows two of them):

```
GObjects:  48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8
           mov rax, [rip+disp32]         ; load GObjects (FUObjectArray*)
           lea rdx, [rsp+...]            ; nearby scratch setup
           call ...
           dispPos = 3, instLen = 7

GNames:    48 8D 35 ?? ?? ?? ?? EB 16
           lea rsi, [rip+disp32]         ; load GNames (FNamePool*)
           jmp short ...
           dispPos = 3, instLen = 7
```

A candidate hit resolves to the **address of the global variable** (the struct itself, not a
pointer to it). For the flat variant the resolved address is the same struct in both cases.

### 5.3 Validation of a candidate GObjects

`ObjectArray::ValidateCandidate(reader, off, ver, gObjectsVA, nameCount)` checks, in order:

1. **Count sanity:** read `MaxElements` (0x18) and `NumElements` (0x1C). Require
   `0 < NumElements <= MaxElements` and `MaxElements` below a sanity cap (tens of millions).
2. **Chunk table:** read `MaxChunks` (0x20) and `NumChunks` (0x24). Require
   `0 < NumChunks <= MaxChunks`, and the count relationship
   `NumChunks == ceil(NumElements / ChunkSize)` for the auto-detected chunk size
   (10240 UE4 / 65536 UE5), with `MaxChunks >= ceil(MaxElements / ChunkSize)`.
   The chunk pointer table at `0x10` must consist of `NumChunks` 8-aligned, non-null,
   heap-plausible pointers.
3. **Sampled item validity (`SampleValid`):** sample indices spread across
   `[0, NumElements)`; for each, read the item at `chunkPtrs[i / chunkSize] +
   (i % chunkSize) * stride` and validate the object pointer
   (`IsValidHeapPtr`: non-zero, 8-aligned, plausible user-space range). When the name array is
   available, additionally resolve the object's FName index and require it to be inside
   `[0, nameCount)`. The validator returns the fraction of valid samples; candidates below the
   acceptance threshold are rejected.
4. **Layout auto-detection (`DetectLayout`):** try strides `{0x10, 0x18, 0x20}` x chunk sizes
   `{10240, 65536}` and keep the combination with the best valid-sample fraction. The chosen
   layout is reported as `LayoutInfo()` (e.g. `chunked stride=0x18 chunk=10240`) and shown in
   the console log.

`TryInit` runs the same validation and then caches `num_`, `stride_`, `chunkSize_`,
`numChunks_` and the chunk pointer table for O(1) indexed access (`At`, `ObjectAt`,
`ValidateIndex`).

### 5.4 Heuristic struct scan (no signature needed)

When config and signatures both fail, `HeuristicScan_GObjects` scans the module image for
*struct instances that look like a `FUObjectArray`*:

```text
for rva in data sections, step 4, 8-aligned values preferred:
    numElems   = i32 @ rva + 0x1C
    maxElems   = i32 @ rva + 0x18
    numChunks  = i32 @ rva + 0x24
    maxChunks  = i32 @ rva + 0x20
    if not (0 < numElems <= maxElems < CAP):            continue
    if not (0 < numChunks <= maxChunks):                continue
    chunkSize = pick from {10240, 65536} where
                numChunks == ceil(numElems / chunkSize)
                and maxChunks >= ceil(maxElems / chunkSize)
    if no chunkSize fits:                               continue
    tablePtr = u64 @ rva + 0x10
    if not plausible(tablePtr):                         continue
    if SampleValid(rva, stride candidates) < threshold: continue
    return candidate VA = imageBase + rva
```

Additional filters that keep false positives near zero:

- the struct must live in a writable data section (GObjects is a mutable global);
- the chunk table's first pointers must be distinct and 8-aligned;
- sampled objects must resolve to distinct addresses (an all-zeros or repeated-value region
  fails the diversity check);
- when the name array is already initialized, sampled FName indices must be in range.

The same idea powers `HeuristicScan_GNames` (FNamePool-shaped memory, section 6) and
`HeuristicScan_GWorld` (a `UWorld` pointer in a data section whose object validates through
names + objects).

---

## 6. FNamePool walking

### 6.1 FNamePool layout (UE 4.23+ / UE5)

GNames points at the engine-global `FNameEntryAllocator` (inside `FNamePool`):

| Offset | Field | Type |
|---|---|---|
| 0x00 | lock (ignored by the dumper) | 8 bytes |
| 0x08 | `CurrentBlock` | pointer to the *next slot* in the `Blocks` array |
| 0x0C | `CurrentByteCursor` | u32, byte cursor inside the current block |
| 0x10 | `Blocks[]` | block pointer array (8 bytes per entry) |

Two details matter for walking:

- `+0x10` is where the block pointer array starts (`FNamePool +0x10 blocks`).
- The number of live blocks is `blockCount = (CurrentBlock - &Blocks[0]) / 8`, because
  `CurrentBlock` points one slot past the last allocated block.

Block sizes: `0x10000` (64 KiB) on most UE4.23-4.2x builds, `0x20000` (128 KiB) on many UE5
builds. DumperPro tries both and keeps the layout with the best validation score
(`NameArray::blockSize_`, reported by `ModeInfo()` as e.g. `FNamePool bs=0x20000 align=4`).

### 6.2 Entry format

Every entry begins with a 2-byte header:

```
u16 header
  bit 0      : wide flag (1 = UTF-16LE, 2 bytes per char)
  bits 6-15  : length = header >> 6   (characters)
  bits 1-5   : probe hash (ignored)
```

The entry data follows the header; entries are aligned to `2` or `4` bytes
(`NameArray::entryAlign_`, auto-detected between the two).

Decode rule per entry:

```text
wide     = header & 1
len      = header >> 6
charSize = wide ? 2 : 1
dataEnd  = entryOff + 2 + len * charSize
```

### 6.3 Walk algorithm

```text
ReadPoolBlock(blockPtr, usedSize, align):
    off = 0
    while off + 2 <= usedSize:
        header = u16 @ blockPtr + off
        wide   = header & 1
        len    = header >> 6
        if len == 0 or len > NAME_MAX_LEN:      # 1024
            mark bad entry; break
        end = off + 2 + len * (wide ? 2 : 1)
        if end > usedSize:                       # torn entry at block end
            break
        name = wide ? utf16le(blockPtr+off+2, len)
                    : ascii(blockPtr+off+2, len)
        names.append(name)
        off = alignUp(end, align)
```

For all blocks except the last, `usedSize` is the full block size; for the last block it is
clamped to `CurrentByteCursor`, so trailing garbage in the active block is never parsed.
Per-block counters (`outEntries`, `outBad`) drive the printable-ratio validation below.

### 6.4 Validation

`NameArray::ValidateCandidate` accepts a candidate GNames VA when:

- the header region decodes to a plausible `CurrentBlock`/`CurrentByteCursor`/`Blocks` triple
  (`CurrentBlock` points into or just past the `Blocks` array, cursor is small);
- each block pointer is non-null, 8-aligned and heap-plausible;
- walking the blocks yields a nonzero count with a high **printable ratio**: most decoded
  characters must be printable ASCII (or valid UTF-16 letters/digits/punctuation). Encrypted
  or mis-parsed pools fail this ratio and the next candidate/layout is tried;
- dedup ratio is sane (some duplicates are normal - FName numbers exist because names repeat -
  but an all-identical region indicates a wrong offset).

`NameArray::TryInit` then materializes the full table (index -> string) and reports
`ModeInfo()`. FName composition happens later at object level: `FName {i32 index; i32 number}`
(see `UEContext::ReadFName`), rendered as `Name_N` when `number > 0` - FName *number handling*
so that `Sprite_3`-style uniqueness survives dumping.

### 6.5 Legacy TNameEntryArray (UE 4.20 - 4.22)

For pre-4.23 builds, `ReadAsLegacy` parses the older chunked pointer table:

| Offset | Field |
|---|---|
| 0x00 | chunk pointer table (chunk 0 first) |
| 0x10000 | `NumElements` (int32) |
| 0x10004 | `NumChunks` (int32) |

- one chunk holds 16384 entry pointers (8 bytes each);
- entry index `i` lives in chunk `i / 16384`, slot `i % 16384`;
- a null chunk pointer terminates the table (chunks are allocated on demand);
- entry format is the same 2-byte header (`bit0` wide, `len >> 6`), 2-byte alignment, in-place
  strings.

Legacy mode is selected automatically for detected versions 4.20-4.22, or forced by a
`games.ini` profile that sets the corresponding offsets; `ModeInfo()` reports
`TNameEntryArray` for this path.

---

## 7. Runtime offset probing

`src/ue/OffsetProbe.*` reconciles the static profile with the *actual* binary, using live
objects as evidence.

### 7.1 What is probed

| Group | Fields |
|---|---|
| UObject | `uobject.flags/index/class/name/outer` |
| UStruct | `struct.super/children/childproperties/propertiessize` |
| UClass | `class.cdo` |
| Property model | `ffield.enabled`, FField member offsets |
| Typed property extras | `property.objectclass/struct/array_inner/set_inner/map_key/map_value/enum/bool_bytemask/bool_fieldmask` |
| UFunction | `function.paramssize/flags/func` |
| UEnum | `enum.names` |

### 7.2 Voting math

For each field, the probe samples up to `--probe N` objects (default 400), spread evenly over
the object array (`step = max(1, Num/N)`) so that both young and old objects are represented.
For every candidate offset the probe builds evidence, then votes:

```text
votes[candidateOffset] += weight(object satisfied the semantic test at this offset)
```

A semantic test is cross-referential, never self-referential. Examples:

- `uobject.class`: the value read at offset X must be a valid heap pointer whose target
  object's class is named `Class` (verified through the already-initialized class/name data);
- `uobject.index`: the value at offset X must equal the object's known GObjects index
  (for the sampled objects) for a large fraction of samples;
- `uobject.name`: the FName at offset X must resolve to a string, and the object's identity
  (class pointer + index) must be stable across repeated reads;
- `class.cdo`: the value at offset X must point to an object whose flags contain
  `RF_ClassDefaultObject = 0x01000000` and whose class equals the enclosing class;
- `function.func`: the pointer at offset X must land in an executable section of the main
  module (native exec target), cross-checked with `FUNC_Native = 0x400` in the function flags;
- typed property extras (`property.struct`, `property.map_key`, ...): the pointer at offset X
  must resolve to an object of the expected kind *only for properties whose type matches*
  (e.g. `Struct` candidates are voted only on `StructProperty` objects).

### 7.3 Confidence and the profile-authority rule

```text
confidence(field, candidate) = votes(field, candidate) / samples * 100
```

Application rules, enforced in `OffsetProbe::ApplyField` / `::Confirmed`:

1. `confidence < 65%` -> field is **skipped** (left missing; never guessed).
2. Profile value missing (`Src::Missing`) and confidence >= 65% -> probe value is **applied**,
   provenance becomes `{AutoDetect, confidence}`.
3. Profile value present and equal to the probe candidate -> counted as **confirmed**;
   provenance stays `Profile` (the profile is authoritative).
4. Profile value present and different -> **warning** (surfaced on the console via
   `ProbeResult::warnings`); the profile value stays in force. The probe never overwrites an
   explicit `games.ini` value.

The result counts are what the pipeline logs: `N auto-detected, M confirmed by probe (K sampled)`.

### 7.4 offsets.txt format

`WriteOffsetsTxt` writes one binding per line:

```
; DumperPro offsets - <game>
; src: profile   = value came from games.ini / built-in profile (authoritative)
;      probe     = auto-detected at runtime
;      confirmed = probe agreed with the profile
uobject.class        = 0x10   ; src=confirmed (100%)
uobject.name         = 0x18   ; src=confirmed (100%)
class.cdo            = 0x50   ; src=probe (97%)
property.map_value   = 0x58   ; src=probe (91%)
function.func        = 0x40   ; src=probe (88%)
```

Lines without a trailing confidence comment were never probed (profile-only). The file is a
debug/round-trip artifact: copy a `probe` line into `games.ini` to pin it for future runs.

---

## 8. Property model duality

UE changed its reflection storage in 4.25. DumperPro supports both models and switches on
version (`UEOffsets::useFFields`, set by `SetDefaultsFor`) plus runtime probing.

### 8.1 The two chains

```
<= 4.24 (UProperty chain):                 >= 4.25 / UE5 (FField chain):
UClass                                     UClass
  - Children (UField* chain)                 - Children (UField* chain: methods only)
  |                                            - ChildProperties (FField* chain)
  v
UProperty -> UProperty::Next               FProperty -> FField::Next
  (each property is a UObject)               (plain FField objects, NOT UObjects)
```

- `UProperty` objects are full `UObject`s: they appear in GObjects and are chained by
  `UField::Next` (offset `0x28`).
- `FField` objects are engine-internal (no `UObject` header), chained separately and reachable
  from `UStruct::ChildProperties`.

`UStruct` offsets (both models, stock builds):

| Offset | Field (UE5 / 4.25+) | Pre-4.25 |
|---|---|---|
| 0x30 | `SuperStruct` | `SuperStruct` |
| 0x38 | `Children` | `Children` |
| 0x40 | `ChildProperties` | not present (`struct.childproperties = 0`) |
| 0x48 | `PropertiesSize` | `PropertiesSize` at 0x40 |

The pre-4.25 defaults are applied by `UEOffsets::SetDefaultsFor`: `useFFields = false`,
`struct.childproperties = 0`, `struct.propertiessize = 0x40` (and `uobject.index = 0` for
4.21 and older, where `InternalIndex` is not guaranteed - the probe fills it).

### 8.2 FField / FProperty offsets (DumperPro table, 4.25+ / UE5)

| Offset | Field |
|---|---|
| 0x00 | 8-byte prologue (vtable / shared-this bookkeeping - never read) |
| 0x08 | `ClassPrivate` (`FFieldClass*`) - `ffield.class` |
| 0x10 | `Owner` - `ffield.owner` |
| 0x18 | `Next` - `ffield.next` |
| 0x20 | `NamePrivate` (FName: i32 index, i32 number) - `ffield.name` |
| 0x28 | `FlagsPrivate` (EObjectFlags) - `ffield.flags` |
| 0x30 | `ArrayDim` (i32) - `property.arraydim` |
| 0x34 | `ElementSize` (i32) - `property.elementsize` |
| 0x38 | `PropertyFlags` (u64) - `property.flags` |
| 0x40-0x4B | engine-internal replication bookkeeping (never read) |
| 0x4C | `Offset_Internal` (u32) - `property.offset` |
| 0x50+ | typed extras, per property class (table below) |

`FFieldClass` (the runtime type object) exposes its `FName Name` at offset `0x08`
(`ffield.class_name`); DumperPro dispatches on that name
(`"ObjectProperty"`, `"StructProperty"`, `"BoolProperty"`, ...). The same dispatch works for
the legacy model by comparing the property object's own class name.

### 8.3 Typed property extras

The extras follow `Offset_Internal`, typically at `0x50` (and `0x58` for the second half of
maps) in stock builds. DumperPro leaves them at `0` ("probe") by default; the probe fills them,
or a profile can pin them:

| Key | Property class | Meaning | Typical stock offset |
|---|---|---|---|
| `property.objectclass` | `ObjectProperty` | `PropertyClass` (`UClass*` target) | 0x50 |
| `property.struct` | `StructProperty` | `Struct` (`UScriptStruct*` target) | 0x50 |
| `property.array_inner` | `ArrayProperty` | `Inner` (element property) | 0x50 |
| `property.set_inner` | `SetProperty` | `Inner` (element property) | 0x50 |
| `property.map_key` | `MapProperty` | `KeyProperty` | 0x50 |
| `property.map_value` | `MapProperty` | `ValueProperty` | 0x58 |
| `property.enum` | `EnumProperty` / `ByteProperty` | `Enum` (`UEnum*` target) | 0x50 |
| `property.bool_bytemask` | `BoolProperty` | `ByteMask` (field bit within the byte) | 0x50 |
| `property.bool_fieldmask` | `BoolProperty` | `FieldMask` (actual stored bit) | 0x51 |

`BoolProperty` masks are what make bitfields correct in the SDK (section 9.4).

### 8.4 Property flags

`EPropertyFlags` is a u64. DumperPro validates flag reads against the known-bit mask
`kPropertyFlagMask = 0x003FFFFF` and actively uses these bits:

| Bit | Name | Meaning | Use in DumperPro |
|---|---|---|---|
| 0x0000000000000002 | `CPF_ConstParm` | const parameter | comment/input classification |
| 0x0000000000000080 | `CPF_Parm` | is a function parameter | separates members from parameters |
| 0x0000000000000100 | `CPF_OutParm` | output parameter | pointer-typed in `Params_` structs |
| 0x0000000000000200 | `CPF_ReturnParm` | return value | becomes the function return type |

Any flag value outside `0x003FFFFF` is treated as a mis-read (layout mismatch) and feeds the
probe warnings.

---

## 9. SDK generation rules

`src/dump/SDKGenerator.*` turns the reconciled object model into compilable headers.

### 9.1 Package grouping

Objects are grouped by their **top-most outer**: walking `OuterPrivate` (`uobject.outer`,
0x20) until it is null yields the owning `UPackage`; the package's name is the group key.

```text
BuildPackages():
    for each class/struct/enum/function object index i:
        root = object[i]
        while outer(root) != 0: root = outer(root)
        packages[NameString(name(root))].objIndices.append(i)
```

One package becomes one file triple: `<Pkg>_classes.h`, `<Pkg>_structs.h`, `<Pkg>_enums.h`.
`_basics.hpp` holds the shared core types; `SDK.hpp` is the master include over all packages.

### 9.2 Type naming heuristics

| Engine name | C++ name | Rule |
|---|---|---|
| `Actor` | `AActor` | class whose ancestry contains an actor base -> `A` prefix (`CppClassName`) |
| `Object` | `UObject` | all other classes -> `U` prefix |
| `Vector` | `FVector` | structs -> `F` prefix (`CppStructName`) |
| `ENetMode` | `ENetMode` | enums -> `E` prefix (`CppEnumName`) |

An engine name that already carries the right prefix is kept as-is; prefixes are only added,
never replaced. Inheritance chains are emitted by walking `SuperStruct` and collecting
ancestor names (`CollectAncestorNames`) so each generated class derives from its resolved
parent.

### 9.3 Member layout and padding

Members of a class/struct are sorted by `Offset_Internal` ascending. Gaps between consecutive
members (or between the parent's `PropertiesSize` and the first new member) are filled with
pad arrays so offsets stay truthful:

```text
EmitMembers(cls, inheritedSize):
    cursor = inheritedSize            # parent's PropertiesSize
    for member in sorted(members, by offset):
        if member.offset > cursor:
            emit uint8 UnknownData_XX[member.offset - cursor];   XX = 2-digit running counter
        emit member (typed, with // 0xOFF(0xSIZE) (flags) comment)
        cursor = member.offset + member.elementSize * arrayDim
```

- `UnknownData_XX` numbering restarts per class, increments per padding block.
- `ArrayDim > 1` renders as a fixed array `[ArrayDim]`.
- The `// 0xOFF(0xSIZE)` comment encodes the engine offset and element size, plus the
  property flag bits when present - keeping generated headers directly comparable with a
  disassembler.

### 9.4 BoolProperty bitfields

`FBoolProperty` occupies one byte but may represent a single bit:

- `ByteMask` = the bit within the native byte that the property claims (`1 << bitIndex`);
- `FieldMask` = the bit actually stored (may be narrower).

Generated code renders each bool as a C++ bitfield member (`bool bName : 1;`). Multiple bools
sharing one byte therefore emit successive `: 1` members at the same offset rather than
overlapping `bool` fields - which would break the layout.

### 9.5 Functions and Params_ structs

For each `UFunction` (chained via `Children`, class name `Function`):

- `ParamsSize` (`function.paramssize`) and `Flags` (`function.flags`) are read;
- parameters are the properties carrying `CPF_Parm (0x80)`, sorted by offset;
- `CPF_OutParm (0x100)` params render as pointers (out); `CPF_ReturnParm (0x200)` becomes the
  return type; `CPF_ConstParm (0x2)` is annotated;
- parameters are emitted into a `struct Params_<Function>` laid out exactly like the engine's
  parameter frame (padding rules from 9.3 apply), and the member function delegates to it:

```cpp
struct Params_GetHealth { float ReturnValue; };                     // 0x00(0x04)
class AMyActor : public AActor {
public:
    float GetHealth();                                              // uses Params_GetHealth
};
```

- native functions (`FUNC_Native = 0x400` in `EFunctionFlags`) additionally record the exec
  pointer (`function.func`, probed or pinned) for `funcs.txt`.

### 9.6 funcs.txt

`WriteFuncsTxt` emits one line per dumped function:

```
AMyActor::GetHealth  RVA=0x1A2B3C4  VA=0x7FF6ABCD1234  native=0x7FF6ABCD1100
AMyActor::ProcessEventThunk  RVA=0x9C10  vtable slot=0x2A  via=vtable>pattern  votes=6
```

When the vtable resolver resolved a tracked function (section 10), the corresponding line is
tagged with the vtable source (`slot`, `via`, `votes`) instead of - or in addition to - the
native pointer, driven by `SDKOptions::vtResults`.

---

## 10. VTable resolver

`src/dump/VTableResolver.*` finds *dynamic* functions (whose slot index varies per build)
without hardcoding slot numbers. Tracked targets:

| Function | Owning class vtable |
|---|---|
| `ProcessEvent` | `UObject` |
| `PostRender` | `UGameViewportClient` |
| `ProcessRemoteFunction` | `UNetDriver` |

### 10.1 Finding a vtable

- `FindVTableOfObjectClass`: take any plain `UObject` instance from GObjects, read its
  vftable pointer at offset 0 - this is the `UObject` vtable.
- `FindVTableOfClass(name)`: walk GObjects for a class object matching the name, then take
  the vftable from its CDO (`class.cdo`) or from any live instance of it.
- `CollectVTables(max = 6)`: gather several *distinct* vftables (different instances/build
  points) - used for voting.

### 10.2 Fingerprint scan per slot

For each vtable, slots are visited from `minIndex` upward. The default `minIndex` is 8
(`vtable.minindex` in `games.ini`): slots 0 and 1 are the MSVC scalar/vector deleting
destructors and several low slots are compiler/build artifacts, so results below the guard
are rejected as suspicious.

For a slot's function VA, a bounded code window is scanned with the fingerprint set for that
function - built-ins (`BuiltinFingerprints`) plus `games.ini` `fingerprint.<Name>` lines
(`|` separates alternatives). Matching is the same mask-based pattern engine as section 4.
Two `via` categories are reported:

- `vtable>pattern` - an explicit fingerprint matched;
- `vtable>heuristic` - a structural heuristic matched (e.g. `ProcessEvent`'s characteristic
  prologue shape: full register spills followed by a large `sub rsp`).

First fingerprint to match a slot wins that slot; among candidate slots, the match quality and
voting (10.4) decide.

### 10.3 Thunk / adjustor unwinding

A vtable slot often points to a small stub, not the real function. `UnwindThunks` follows the
standard MSVC stubs:

| Bytes | Instruction | Action |
|---|---|---|
| `E9 rel32` | `JMP rel32` | follow to `target = funcVA + 5 + rel32` |
| `EB rel8` | `JMP rel8` | follow to `target = funcVA + 2 + rel8` |
| `48 83 E9 imm8` | `SUB RCX, imm8` | adjustor: follow the trailing jump |
| `48 83 C1 imm8` | `ADD RCX, imm8` | adjustor: follow the trailing jump |
| `48 81 E9 imm32` | `SUB RCX, imm32` | adjustor: follow the trailing jump |
| `48 81 C1 imm32` | `ADD RCX, imm32` | adjustor: follow the trailing jump |
| `FF 25 ...` | `JMP [rip+disp32]` | import stub: **stop** (`hitImport = true`) |

```text
UnwindThunks(funcVA):
    depth = 0
    loop:
        code = read(funcVA, up to 16 bytes)
        if code starts with E9 rel32:      funcVA += 5 + rel32; depth++
        elif EB rel8:                      funcVA += 2 + rel8;  depth++
        elif 48 83 E9/C1 imm8:             skip SUB/ADD; then follow its trailing JMP; depth++
        elif 48 81 E9/C1 imm32:            same with imm32; depth++
        elif FF 25:                        return (funcVA, depth, hitImport=true)
        else:                              return (funcVA, depth, hitImport=false)
    (bounded by a maximum depth; targets outside the main module stop the walk)
```

Adjustors only exist to modify `RCX` (the `this` pointer for multiple-inheritance offsets);
after the `SUB/ADD`, control always transfers via one of the jump forms above, so the walk is
a straight-line computation with no ambiguity. `thunkDepth` is recorded in the result.

### 10.4 Post-thunk voting

Slot order can differ between vftables of the same class (compiler/layout variance), but the
*final function* is stable. `ResolveByFingerprints` resolves the target against up to 6
distinct vtables and votes on the post-thunk target VA:

```text
for vft in CollectVTables(6):
    r = ScanVTable(vft, fingerprints, minIndex)
    if r.found: votes[UnwindThunks(r.funcVA).target] += 1
final = argmax(votes)
```

The majority target becomes `funcVA`; `votes` and `slot` (best-scoring slot) are recorded.
A result needs a clear winner; ties or empty votes produce `found = false` rather than a
guess.

### 10.5 Output

`vtable_funcs.txt` lines mirror `VTResult`:

```
; DumperPro vtable-resolved functions
ProcessEvent (UObject): FOUND_IN_VTABLE [vtable>pattern] slot=0x2A RVA=0x1A2B3C VA=0x7FF6ABCD1234 SlotRVA=0x9C210 thunkDepth=1 votes=6
PostRender (UGameViewportClient): FOUND_IN_VTABLE [vtable>heuristic] slot=0x37 RVA=0x1C3D4E VA=0x7FF6ABCDE560 SlotRVA=0x9C298 thunkDepth=0 votes=5
ProcessRemoteFunction (UNetDriver): NOT_FOUND
```

The same results are handed to `SDKGenerator` (so `funcs.txt` can tag vtable-resolved
functions) and to the console log.

---

## 11. Kernel-assisted reading

When `--kernel` is set, the reader backend is replaced by a thin client that forwards read
requests to an externally provided kernel driver over a fixed IOCTL contract:

```
device : \\.\DumperPro
IOCTL  : IOCTL_DUMPERPRO_READ
         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
input  : KReadReq { u64 address; u32 size; u32 pad; }   (16 bytes)
output : the requested `size` bytes (METHOD_BUFFERED SystemBuffer)
```

What it buys:

- reads keep working when the target's user-mode handles are restricted or `ReadProcessMemory`
  is intercepted;
- one stable read path for very large scans (module snapshot, name pool walks), which
  reduces mixed-handle flakiness on some protected builds.

The driver itself is deliberately **not** part of this repository: `docs/KERNEL.md` specifies
the client-visible contract, the validation duties a driver implementation must fulfill
(buffer-size checks, `ProbeForRead`/`ProbeForWrite`-equivalent safety, process attachment via
`PsLookupProcessByProcessId` on the user-selected target), and the legal/safety constraints
(read-only v1, no anti-cheat evasion). Read it before enabling `--kernel`.

---

## 12. Number sheet (quick reference)

| Quantity | Value |
|---|---|
| `FUObjectArray.ObjObjects` base | 0x10 |
| `MaxElements / NumElements / MaxChunks / NumChunks` | 0x18 / 0x1C / 0x20 / 0x24 |
| `FUObjectItem` strides | 0x10 / 0x18 / 0x20 |
| Chunk sizes | 10240 (UE4) / 65536 (UE5) |
| `UObject` flags/index/class/name/outer | 0x08 / 0x0C / 0x10 / 0x18 / 0x20 |
| `UField::Next` | 0x28 |
| FField class/owner/next/name/flags | 0x08 / 0x10 / 0x18 / 0x20 / 0x28 |
| `FFieldClass::Name` | 0x08 |
| Property arraydim/elementsize/flags/offset | 0x30 / 0x34 / 0x38 / 0x4C |
| Typed property extras (typical) | 0x50 (0x58 for map value) |
| `UStruct` super/children/childproperties/propertiessize | 0x30 / 0x38 / 0x40 / 0x48 |
| `UEnum::Names` | 0x30 |
| `UFunction` paramssize/flags | 0x30 / 0x3C (func probed, typically 0x40) |
| FNamePool | cursor +0x0C, blocks +0x10, block 0x10000/0x20000 |
| Entry header | u16, bit0 wide, len = header >> 6, align 2/4 |
| Legacy name table | NumElements +0x10000, NumChunks +0x10004 |
| `CPF_ConstParm / Parm / OutParm / ReturnParm` | 0x2 / 0x80 / 0x100 / 0x200 |
| `kPropertyFlagMask` | 0x003FFFFF |
| `RF_ClassDefaultObject` | 0x01000000 |
| `FUNC_Native` | 0x400 |
| Probe default / confidence floor | 400 objects / 65% |
| VTable minIndex / voting vtables | 8 / up to 6 |
