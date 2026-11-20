# Task 4-a - Full-stack developer agent (VDEX/OAT embedded-DEX extractor)

## Scope (STRICT: only 2 new files created, zero existing files modified)
- NEW: `src/lib/analysis/vdex.ts` - ART VDEX/OAT embedded-DEX extractor, pure TS, zero deps.
- NEW: `DumperPro/.test/make_vdex_fixture.ts` - bun script: builds synthetic VDEX/OAT fixtures
  wrapping the real `DumperPro/.test/test_classes.dex` (290-byte DEX 035, file_size@32=290 verified)
  and asserts byte-identical extraction. Result: **83 PASS / 0 FAIL, exit 0**.
- NOT touched: index.ts, detect.ts, routes, components, prisma, eslint/tsconfig. `bun run lint` clean.

## Exported API (exactly as specified)
```ts
export interface VdexDexEntry { index: number; offset: number; size: number }
export interface VdexInfo { kind: "vdex"; version: string; apiHint: string;
  dexSectionVersion: string /* "000"|"002"|"" */; dexCount: number; dexes: VdexDexEntry[];
  notes: string[]; error?: string }
export interface OatInfo { kind: "oat"; version: string; apiHint: string; dexCount: number;
  scannedCount: number; dexes: VdexDexEntry[]; notes: string[]; error?: string }
export function parseVdex(buf: Buffer): VdexInfo | null   // null iff magic != "vdex"
export function parseOat(buf: Buffer): OatInfo | null     // null iff magic != "art\n"
export function isVdexOrOat(buf: Buffer): "vdex" | "oat" | "cdex" | null
export function extractDex(buf: Buffer, e: VdexDexEntry): Buffer  // subarray view, bounds-guarded
```
Never throws; corrupt internals -> `error` set + whatever valid dexes found. Layout selection:
006..010 -> 006 layout, 011..019 -> 019 layout, 020+ -> 021 layout (adaptation noted in `notes`).

## Fixtures (written into DumperPro/.test/ on each run)
| file | bytes | expect |
|---|---|---|
| test_vdex021.vdex | 334 | v021, "API 29+ (Android 10+)", 002, 1 dex @0x2c, byte-identical |
| test_vdex019.vdex | 326 | v019, "API 28 (Android 9)", 002, 1 dex @0x24, byte-identical |
| test_vdex006.vdex | 318 | v006, "API 26-27 (Android 8)", dsv "", 1 dex @0x1c, byte-identical |
| test_vdex019_nodex.vdex | 24 | v019, 000, dexes=0, NO error, note "DEX bolumu yok" |
| test_multi_vdex021.vdex | 628 | v021, 2 dexes @0x30/0x152, both byte-identical |
| test_embed.oat | 574 | art\n131, apiHint "Android 9+ (dex genelde vdex'te)", dexCount 1, scanned 1, dex @0x11c byte-identical |

Extra script checks: truncation sweep 0..len per fixture (no throw + entry invariants
offset>=0, size>0, offset+size<=len), cdex-magic detection (in-memory cdex OAT: 0 dex + error + note),
empty/zero buffers -> null, negative-offset extractDex -> empty, partial overflow clamps.
Run: `bun DumperPro/.test/make_vdex_fixture.ts` (regenerates fixtures + verifies, exit 1 on any FAIL).

## Implementation notes / deviations (all verified via fixtures)
- VDEX chain: entries 0..n-2 use header file_size; LAST entry size = section-remaining bytes
  (vdexExtractor behavior; note emitted only when remaining != header file_size).
- OAT scan: first PLAUSIBLE "dex\n" (035..039, sane file_size fitting file) within first 1MB,
  then file_size chain; header dexFileCount@20 ignored if >4096 (scan-driven, notes only).
  Deviation: spec said "first occurrence" - first occurrence that validates avoids false hits
  in key-value store. cdex detected+noted, never extracted.
- OAT last dex uses header file_size (OAT data follows dex section); VDEX uses remaining rule.
- dexCount reports raw header value (even bogus) + note; parseVdex with >4096 count -> error, 0 dexes.
- extractDex returns a zero-copy subarray view (callers must not mutate source).

## Status
- DONE. All fixture checks PASS (83/83), `bun run lint` clean, dev server unaffected.
- Wiring into detect/index/API routes intentionally left to follow-up task (no existing file modified).
