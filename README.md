# DumperPro

Binary / memory / game-file analysis platform: a **C++17 engine** (CLI + HTTP serve mode) paired with a **Next.js 16 web UI** for uploading, analyzing and inspecting binaries — inspired by Dumper-7, Il2CppDumper, UnrealCEDumper and MemProcFS.

---

## What it does

### C++ engine (`DumperPro/`, ~16k LOC, 10 modules)

| Module | Responsibility |
|---|---|
| `core` | PEFile parser, masked AOB pattern engine, MemoryReader / FileReader / ProcessReader / KernelReader backends |
| `sig` | GNames / GObjects / GWorld signature scanning |
| `ue` | Unreal Engine 4.20–4.27 & 5.0–5.3 ObjectArray/NameArray auto-detection + offset probing |
| `il2cpp` | metadata v16–31, ELF RELA relocation, DummyDll generation |
| `file` | Static analysis of APK / ZIP / ELF / DEX / Mach-O / OAT-VDEX |
| `dump` | SDKGenerator → `<Pkg>_classes.h` / `_structs.h` / `_enums.h`, vtable resolver |
| `hex` | Interactive hex tool: hex/code/byte views, AOB search, patch, undo, save |
| `net` | Embedded HTTP server (`--serve`, port 8420) |
| `config` | `games.ini` profiles + 8 embedded game profiles |

```bash
# build
g++ -std=c++20 -O1 -I DumperPro/src -o DumperPro/DumperPro DumperPro/src/*.cpp DumperPro/src/*/*.cpp -lpthread

# analyze a file
./DumperPro --file target.exe

# dump UE SDK, serve REST API, hex tooling
./DumperPro --file target.exe --dump-sdk --serve 8420 --hex
```

### Web platform (`src/`)

- **Upload & analyze**: single files or folders; async worker queue with live progress
- **15 inspector tabs**: Genel / Bölümler / Hex / Import-Export / Motor & Güvenlik / İmza Adayları / Debug / Fonksiyonlar / Structlar / Enumlar / IL2CPP / SDK / Dizeler / Çıkarıcılar / Rapor
- **6-extractor matrix**: Dumper-7, DumperPro, Il2CppDumper, UnrealCEDumper, MemProcFS, LeechCore — availability badges + cross-extractor common-data intersection
- **Hex workspace**: AOB search (with RVA/VA resolution), patch + undo + save
- **Raw dump + `*.memmap` pairing**: upload a raw memory dump, follow up with a `.memmap` definition file within 24 h → memory device, region mapping, in-memory AOB search
- **SDK viewer**: browse generated C++ SDK files live in the browser
- **Savegame lab**: GVAS (`.sav`) parsing/editing for Unreal save files
- **REST API** under `/api/*`: upload, extract, hex, mem, sdk, report, codegen, explain, savegame, dumperpro bridge

## Tech stack

- **Engine**: C++17/20, pthreads, no external deps
- **Web**: Next.js 16 (App Router), TypeScript 5, Tailwind CSS 4, shadcn/ui (New York), Lucide icons
- **Data**: Prisma ORM + SQLite, local-memory caching
- **Runtime**: Bun

## Getting started (web)

```bash
bun install
bun run db:push      # create SQLite schema
bun run dev          # http://localhost:3000
```

Environment goes in `.env` (never committed):

```
DATABASE_URL="file:./db/custom.db"
```

## Repo layout

```
DumperPro/     C++ engine (src/, games.ini)
ue-dumper/     Secondary UE dumper component (src/, driver/)
src/           Next.js app + 20+ analysis modules (src/lib/analysis/)
prisma/        DB schema
docs/          Research notes: MemProcFS/LeechCore, IL2CPP, UE, savegame format, codegen
scripts/       Inspection / verification utilities
```

## Research notes (`docs/`)

- `MEMPROCFS_LEECHCORE.md` — device/live-memory integration research
- `IL2CPP_BINARY.md` — metadata versions, relocation handling
- `SAVEGAME.md` — GVAS format, encrypted save handling
- `GAMEFILES.md`, `CODEGEN.md`, `WEB_PLATFORM.md`

## Security

`.env`, databases, uploaded binaries (`storage/`), and vendored third-party research trees are intentionally **not** committed. The git history was squashed before the first public push so no secrets ever existed in the remote history.
