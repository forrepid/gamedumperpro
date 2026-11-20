# Task 3 - Frontend UI agent (analyzer.tsx + page.tsx)

## Scope
- ONLY modify: src/components/analyzer.tsx and src/app/page.tsx (two TabsTrigger className fixes).
- Backend API routes / prisma / lib/analysis untouched.

## Backend contracts verified
- GET /api/uploads rows now include: relPath, childCount, source "folder" group rows.
- POST /api/upload/folder { name, count } -> { ok, id, name }.
- POST /api/upload multipart supports parentId + relPath.
- DELETE /api/uploads/{id} cascades for folders.
- GET /api/uploads/{id}/sdk/{name}?raw=1 -> { ok, name, size, content } (verified in route.ts).
- AnalysisResult.extractors matches ExtractorsInfo in src/lib/analysis/types.ts (types-only, client-safe).
- SDK file naming: {safeBase}_classes.h / _structs.h / _enums.h, dump.cs, script.json, Functions.txt,
  unrealcedumper_offsets.txt, unrealcedumper_vtables.txt, memprocfs_modules.txt, memprocfs_regions.txt,
  leechcore_memmap.txt (verified in sdkgen.ts + extractors.ts).
- safeBase keeps original case, so extractor grouping lowercases both sides (claimExtractorFiles logic).

## Plan (A-H)
- A: TRIGGER_CLS constant, replace every TabsTrigger className, page.tsx triggers + text-zinc-400,
  history ScrollArea -> plain div (max-h-[440px] overflow-y-auto scrollbar-thin), compact single-line rows.
- B: tree useMemo (roots/childrenOf/folderNodes), folder + archive expandable rows, chevron with aria-expanded,
  delete clears expansion, auto-expand after bundle upload, new empty-state text.
- C: multi-file/recursive drop walk (webkitGetAsEntry), webkitdirectory "Klasor Sec" picker, uploadBundle with
  progress state, 300MB per-file skip with note, bundle name from common root segment.
- D: extractors?: ExtractorsInfo in local shape, "Cikaricilar" trigger (Layers icon) before Rapor,
  ExtractorsTab component (chips, Ortak Veriler tables, per-extractor cards + Accordion + files Goster/Indir).
- E: fileExtractorOf helper + SDK_GROUP_ORDER, grouped SDK table with group header rows, Goster/Indir buttons.
- F: SdkViewerDialog (live raw=1 fetch, 6000-line cap, search + next match, copy/download, definitions sidebar,
  tokenizeCodeLine highlighting, data-line jump + flash, initialQuery support).
- G: controlled Tabs (tabValue), hexJump -> HexTab jump prop, vftable badge -> interactive button (span role=button
  inside Radix trigger to avoid nested <button> DOM warning), sourceLabel mapping, "SDK'de ac" per struct,
  enum source labels, clickable structHint in functions.
- H: UploadRow.relPath + childCount, DetailResponse.upload.relPath + childCount?, pe sections rawPointer?.

## Status
- In progress.
