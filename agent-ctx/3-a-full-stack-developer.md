# Task 3-a - Full-stack developer agent (PDB module + fixture)

## Scope (strict: only 2 new files created, zero existing files modified)
- NEW `src/lib/analysis/pdb.ts` - MSVC PDB 7.0 (MSF container) symbol reader,
  pure TypeScript, no external deps. Follows LLVM DebugInfo/MSF +
  DebugInfo/PDB/Native + microsoft-pdb semantics.
- NEW `DumperPro/.test/make_pdb_fixture.ts` - dev fixture generator (bun).
  Builds synthetic minimal PDB7 files on disk and verifies parsePdb against
  them. Run: `bun DumperPro/.test/make_pdb_fixture.ts` (exit 0 = all green).
- Generated artifacts (from the fixture, untracked):
  `DumperPro/.test/test_symbols.pdb` (10240 B, BlockSize 0x400),
  `DumperPro/.test/test_symbols_bigblock.pdb` (36864 B, BlockSize 0x1000).

## Exported API (src/lib/analysis/pdb.ts)
- `interface PdbSection { name; rva; vsize }`
- `interface PdbSymbol { name; kind: "func"|"data"; seg; off; rva? }`
- `interface PdbInfo { valid; version; signature; age; guid; machine;
  streamCount; sectionCount; funcCount; dataCount; udtCount; symbols;
  udtNames; sections; notes; error? }`
- `parsePdb(buf: Buffer): PdbInfo | null` - null ONLY if MSF magic missing;
  otherwise never throws, corruption -> valid:false + error, benign gaps
  -> notes[]. Caps: symbols 20000, udtNames 2000, 500k CodeView records.

## Implementation semantics (verified vs. spec, all PASS in fixture)
- MSF: SuperBlock 56 B (magic prefix "Microsoft C/C++ MSF 7.00", BlockSize
  512..32768, FreeBlockMapBlock 1|2, NumBlocks, NumDirectoryBytes, BlockMapAddr);
  dir block list at BlockMapAddr, ceil(NumDirectoryBytes/BlockSize) entries;
  directory = u32 numStreams + sizes + per-stream block lists; size 0 /
  0xFFFFFFFF = empty stream (no block entries).
- Stream 1 = info (version/signature/age/GUID/namesIdx, read defensively);
  stream 3 = DBI 64-byte header; debug header at 64+Modi+SecContr+SecMap+
  FileInfo+TypeServer+EC, 11 u16 slots, slot 5 = SectionHdr stream (0xFFFF
  absent); SectionHdr = 40-byte COFF headers (name/rva/vsize).
- CodeView walk: { u16 len (excl. len field, incl. kind), u16 kind, payload };
  next = pos+2+len; stop on truncation/implausible record (trailing hash
  table) / 500k records. S_PUB32 0x110E, S_PUB32_ST 0x1109, S_UDT 0x1108,
  S_UDT_ST 0x1003, S_GDATA32 0x110D, S_LDATA32 0x110C; unknown kinds skipped.
- RVA = sections[seg-1].rva + off when 1 <= seg <= sectionCount, else undefined.
- Symbols dedup by name+seg+off; funcCount/dataCount counted from final list.

## Fixture results (bun, both runs exit 0): 39/39 PASS
- Fixture A (0x400): 2 funcs (GameMain rva 0x1088, UpdatePlayer 0x1120),
  2 data (g_world 0x2040, g_config 0x2010), 2 UDTs (CPlayer, CWorld),
  guid 8a31c2e5-6b7d-4c9f-a122-334455667788, machine x64, 8 streams,
  sections .text/.data, walker stops at 12-byte hash tail (symbols==4).
- Fixture B (0x1000): BlockSize independence, 1 func, empty globals stream
  (note only), same guid/machine/sections.

## Notes for next agents
- GUID is rendered as raw sequential bytes grouped 8-4-4-4-12 lowercase hex
  (spec wording "16 bytes, display as 8-4-4-4-12 hex"; no DIA-style endian
  swap). Fixture asserts the exact string.
- "valid" = no structural error: MSF/container/DBI/debug-header/section-stream
  failures set error; missing publics/globals/symrec streams or short info
  stream are notes only (stripped PDBs still yield partial data).
- PUB32 flags: bit0 -> "func", else "data" (bit1 documented as data marker).
- Engine wiring (src/lib/analysis/index.ts/engine.ts) intentionally NOT
  touched in this task - parsePdb is standalone and safe to import server-side
  (Buffer-based; keep it out of client bundles).
- Init script intentionally not re-run (it would spawn a second dev.sh since
  .zscripts/dev.sh exists; project already initialized).
- Quality gates: `bun run lint` clean; `bunx tsc --noEmit` shows zero new
  errors from these files (baseline noise: analyzer.tsx x11 in progress by
  frontend agent, examples/, skills/).

## Status
- Completed (fixture green on first run, re-run idempotent).
