"use client";

// ----------------------------------------------------------------------------
// DumperPro Online - dosya yukleme & analiz paneli
// exe / dll / sys / apk / so / dex / zip yukle -> statik analiz + rapor
// ----------------------------------------------------------------------------

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Archive,
  Binary,
  Boxes,
  Braces,
  Bug,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  Download,
  FileArchive,
  FileCode2,
  FileText,
  Folder,
  FolderOpen,
  Gamepad2,
  HardDriveUpload,
  Hash,
  Layers,
  Loader2,
  MemoryStick,
  Package,
  RefreshCw,
  Save,
  ScanSearch,
  ShieldAlert,
  Table2,
  Terminal,
  Trash2,
  TriangleAlert,
  Wand2,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { tokenizeCodeLine, type HighlightState } from "@/lib/highlight";
import { DATA_TYPE_GROUPS, resolveDataType, type DataType } from "@/lib/analysis/hex";
import type { ExtractorId, ExtractorsInfo, GameFilesInfo, Il2CppBinaryInfo, MemInfo } from "@/lib/analysis/types";
import CodegenTab from "@/components/codegen-tab";
import SaveEditorTab from "@/components/save-editor-tab";
import PatternVisualScanner from "@/components/pattern-visual";

// ------------------------- tipler (API ile ayni sekil) -------------------------

interface UploadRow {
  id: string;
  fileName: string;
  size: number;
  source: string;
  parentId: string | null;
  relPath: string | null;
  status: string;
  error: string | null;
  createdAt: string;
  childCount: number;
  progress?: { stage: string; percent: number } | null;
  analysis: { kind: string; engine: string | null; engineVersion: string | null } | null;
}

interface DetailResponse {
  ok: boolean;
  upload: {
    id: string;
    fileName: string;
    size: number;
    source: string;
    parentId: string | null;
    relPath: string | null;
    status: string;
    error: string | null;
    createdAt: string;
    childCount?: number;
  };
  analysis: {
    id: string;
    kind: string;
    engine: string | null;
    engineVersion: string | null;
    result: AnalysisResultShape;
    report: string;
  } | null;
}

interface AnalysisResultShape {
  kind: string;
  file: { name: string; size: number; sha256: string };
  overallEntropy: number;
  pe?: {
    format: string;
    machine: string;
    arch: string;
    buildDate: string;
    characteristics: string[];
    subsystem: string;
    entryPointRva: number;
    imageBase: number;
    sizeOfImage: number;
    dllCharacteristics: string[];
    sections: { name: string; virtualSize: number; virtualAddress: number; rawSize: number; rawPointer?: number; entropy: number; flags: string[] }[];
    imports: { dll: string; count: number; functions: string[]; truncated: boolean }[];
    importDllCount: number;
    exports: { dllName: string; count: number; names: string[]; truncated: boolean; entries?: { name: string; ordinal: number; rva: number; va: number }[] } | null;
    dataDirectories?: { name: string; va: number; size: number }[];
    debugPdb?: string;
    debug?: {
      pdb?: { path: string; guid: string; age: number };
      coffSymbols: number;
      coffSymbolSamples: string[];
      reproducible: boolean;
      guid: string;
      entries: { index: number; type: string; rawType: number; size: number; rva: number; detail?: string }[];
    };
    versionInfo?: { companyName?: string; productName?: string; fileVersion?: string; productVersion?: string; fileDescription?: string; originalFilename?: string; internalName?: string; legalCopyright?: string; comments?: string } | null;
  };
  elf?: {
    class: string;
    endian: string;
    machine: string;
    type: string;
    entryPoint: number;
    sectionCount: number;
    sections: { name: string; type: string; addr: number; size: number }[];
    dynsyms?: { name: string; type: string; bind?: string; value?: number; size?: number }[];
    dynsymCount?: number;
  };
  dex?: {
    version: string;
    endian: string;
    strings: number;
    types: number;
    protos: number;
    fields: number;
    methods: number;
    classes: number;
    checksumOk: boolean;
    packages: { name: string; count: number }[];
    topLevelPackages: string[];
    engineHints: string[];
    classSamples: string[];
  };
  apk?: {
    packageName?: string;
    versionName?: string;
    versionCode?: string;
    minSdk?: number;
    targetSdk?: number;
    abis: string[];
    mainLibs: { path: string; size: number; compressed: number; method: string; engineHint?: string }[];
    dexCount: number;
    entryCount: number;
    groups: { dir: string; count: number; totalSize: number }[];
    notableFiles: string[];
    pakFiles: { path: string; size: number }[];
    scannedLibs: { path: string; engine?: string; version?: string; versionStrings: string[] }[];
  };
  zip?: {
    entryCount: number;
    groups: { dir: string; count: number; totalSize: number }[];
    notableFiles: string[];
    mainLibs: { path: string; size: number; compressed: number; method: string; engineHint?: string }[];
  };
  engine: {
    detected: string;
    version?: string;
    versionStrings: string[];
    markers: { name: string; hits: number }[];
    confidence: string;
  };
  security: {
    antiCheat: string[];
    drm: string[];
    packer: string[];
    packedHint: boolean;
    notableStrings: string[];
  };
  signatureCandidates: { name: string; pattern: string; hits: { rva: string; va: string; offset: string }[]; note: string }[];
  strings: { value: string; kind: string }[];
  functions?: {
    total: number;
    source: string;
    is64: boolean;
    detailed: number;
    disassembled: number;
    note?: string;
    functions: {
      idx: number;
      rva: number;
      va: number;
      size: number;
      label?: string;
      section: string;
      prologue: string;
      strings: string[];
      apiCalls: string[];
      callsOut: number;
      xrefsIn: number;
      asm?: string;
      pseudo?: string;
      structHint?: string;
    }[];
    topBySize?: { rva: number; size: number; label?: string }[];
  };
  rtti?: {
    available: boolean;
    total: number;
    classes: { name: string; kind: string; rttiRva: number; vftableRva?: number; vftableVa?: number; base?: string; methodCount: number; methods: { rva: number; va: number }[] }[];
    enumNames: string[];
    note?: string;
  };
  resources?: {
    total: number;
    entries: { type: string; id: string; language?: string; size: number; rva: number; offset: number; embedded?: string }[];
    biggest?: { type: string; id: string; size: number; rva: number; offset: number; pct: number };
  };
  structs?: {
    total: number;
    structs: {
      name: string;
      kind: string;
      size?: number;
      base?: string;
      vftableRva?: number;
      vftableVa?: number;
      methodCount: number;
      fields: { name: string; offset: number; size: number; type: string; reads: number }[];
      source: string;
    }[];
    note?: string;
  };
  enums?: {
    total: number;
    enums: {
      name: string;
      source: string;
      members: { name: string; value: number }[];
      note?: string;
    }[];
    note?: string;
  };
  il2cpp?: {
    version: string;
    unityHint: string;
    sanityOk: boolean;
    stringCount: number;
    literalCount: number;
    images: string[];
    classCount: number;
    methodCount: number;
    fieldCount: number;
    classes: { name: string; namespace: string; image: string; kind: string; base?: string; fields: string[]; methods: string[]; fieldCount: number; methodCount: number }[];
    enums: { name: string; namespace: string; image: string; members: { name: string; value: number | null }[]; memberCount: number }[];
    literalSamples: string[];
    notes: string[];
  };
  il2cppBin?: Il2CppBinaryInfo; // GameAssembly.dll / libil2cpp.so binary tarafi
  gameFiles?: GameFilesInfo; // pak / utoc / uasset / umap / macho
  mem?: MemInfo; // minidump / raw+memmap bellegi
  savegame?: {
    magic: boolean;
    fileVersion: number;
    ue4Version: number;
    ue5Version?: number;
    className: string;
    propCount: number;
    totalPropBytes: number;
    encrypted: boolean;
    compressed: boolean;
    engineVersion: string;
  }; // UE .sav (GVAS) ozeti
  vdf?: {
    kind: "text" | "binary";
    keyCount: number;
    maxDepth: number;
    sampleKeys: string[];
  }; // Steam VDF ozeti
  sdk?: {
    generator: string;
    files: { name: string; kind: string; size: number }[];
    note?: string;
  };
  extractors?: ExtractorsInfo; // coklu cikarici (multi-dumper) ciktilari + ortak veriler
  gamesIniSuggestion?: string;
  notes: string[];
  errors: string[];
}

// ------------------------------- yardimcilar --------------------------------

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function hex(n: number | undefined): string {
  if (n === undefined || n === null) return "-";
  return `0x${n.toString(16).toUpperCase()}`;
}

function engineBadgeClass(engine: string | null | undefined): string {
  const e = (engine ?? "").toLowerCase();
  if (e.startsWith("ue4") || e.startsWith("ue5") || e.includes("unreal"))
    return "bg-emerald-600/15 text-emerald-300 ring-1 ring-emerald-600/40";
  if (e.includes("unity")) return "bg-amber-600/15 text-amber-300 ring-1 ring-amber-600/40";
  if (e === "bilinmiyor" || !engine) return "bg-zinc-700/40 text-zinc-300 ring-1 ring-zinc-600";
  return "bg-zinc-600/20 text-zinc-200 ring-1 ring-zinc-500";
}

function entropyClass(e: number): string {
  if (e >= 7.2) return "text-red-400";
  if (e >= 6.0) return "text-amber-400";
  return "text-emerald-400";
}

function KindIcon({ kind, className }: { kind: string; className?: string }) {
  const cls = className ?? "h-4 w-4";
  if (kind === "apk" || kind === "zip") return <FileArchive className={cls} />;
  if (kind === "pak" || kind === "utoc" || kind === "ucas" || kind === "uasset" || kind === "umap") return <FileArchive className={cls} />;
  if (kind === "elf") return <Package className={cls} />;
  if (kind === "minidump" || kind === "memmap") return <MemoryStick className={cls} />;
  return <Binary className={cls} />;
}

const ACCEPT = ".exe,.dll,.sys,.apk,.so,.dex,.zip,.bin,.dat,.pak,.obb";

// koyu temada okunur sekme tetikleyicileri (tum sekmelerde ortak)
const TRIGGER_CLS =
  "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300 data-[state=active]:border-emerald-700/40";

// klasor yuklemesinde dosya basina atlama esigi
const MAX_BUNDLE_FILE = 300 * 1024 * 1024;

// SDK canli goruntuleyicide gosterilecek maksimum satir
const SDK_VIEW_MAX_LINES = 6000;

// struct/enum ham kaynak etiketi -> cikarici adi
function sourceLabel(source: string): string {
  if (source === "rtti") return "Dumper-7";
  if (source === "code") return "DumperPro";
  if (source === "mixed") return "Dumper-7+DumperPro";
  if (source === "switch") return "DumperPro";
  if (source === "il2cpp") return "Il2CppDumper";
  return source;
}

// cikarici kimligi -> kisa etiket
function extractorShortLabel(id: string): string {
  if (id === "dumper7") return "Dumper-7";
  if (id === "dumperpro") return "DumperPro";
  if (id === "il2cppdumper") return "Il2CppDumper";
  if (id === "unrealcedumper") return "UnrealCEDumper";
  if (id === "memprocfs") return "MemProcFS";
  if (id === "leechcore") return "LeechCore";
  return id;
}

// SDK dosya adi -> cikarici grubu (backend claimExtractorFiles ile ayni kurallar)
function fileExtractorOf(name: string, baseName: string): { id: ExtractorId | "other"; label: string } {
  const lowerBase = baseName.toLowerCase();
  const n = name.toLowerCase();
  if (
    n.startsWith(`${lowerBase}_classes`) ||
    n.startsWith(`${lowerBase}_structs`) ||
    n.startsWith(`${lowerBase}_enums`) ||
    n === "sdk.hpp"
  ) {
    return { id: "dumper7", label: "Dumper-7 (C++ SDK)" };
  }
  if (n === "functions.txt" || n === "decompile.txt" || n === "debug.txt" || n === "offsets.txt") {
    return { id: "dumperpro", label: "DumperPro (yerel analiz)" };
  }
  if (n === "dump.cs" || n === "il2cpp_enums.cs" || n === "script.json") {
    return { id: "il2cppdumper", label: "Il2CppDumper (dump.cs)" };
  }
  if (n.startsWith("unrealcedumper_")) return { id: "unrealcedumper", label: "UnrealCEDumper (ofset/vtable)" };
  if (n.startsWith("memprocfs_")) return { id: "memprocfs", label: "MemProcFS (modul/bolge)" };
  if (n.startsWith("leechcore_")) return { id: "leechcore", label: "LeechCore (bellek haritasi)" };
  return { id: "other", label: "Diger" };
}

const SDK_GROUP_ORDER: { id: ExtractorId | "other"; label: string }[] = [
  { id: "dumper7", label: "Dumper-7 (C++ SDK)" },
  { id: "dumperpro", label: "DumperPro (yerel analiz)" },
  { id: "il2cppdumper", label: "Il2CppDumper (dump.cs)" },
  { id: "unrealcedumper", label: "UnrealCEDumper (ofset/vtable)" },
  { id: "memprocfs", label: "MemProcFS (modul/bolge)" },
  { id: "leechcore", label: "LeechCore (bellek haritasi)" },
  { id: "other", label: "Diger" },
];

// ------------------- surukle-birak klasor gezgini (webkitGetAsEntry) -------------------

interface DroppedBundleItem {
  file: File;
  relPath: string;
}

// readEntries parcalar halinde doner; bos parca gelene kadar oku
async function readDirEntries(dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
  const reader = dir.createReader();
  const out: FileSystemEntry[] = [];
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => {
      reader.readEntries(
        (entries) => resolve(entries),
        (err) => reject(err),
      );
    });
    if (batch.length === 0) break;
    out.push(...batch);
  }
  return out;
}

async function entryFile(fileEntry: FileSystemFileEntry): Promise<File | null> {
  return new Promise<File | null>((resolve) => {
    fileEntry.file(
      (f) => resolve(f),
      () => resolve(null),
    );
  });
}

// DataTransfer icindeki tum dosyalari (alt dizinler dahil) { file, relPath } olarak toplar
async function walkDataTransfer(dt: DataTransfer): Promise<{ items: DroppedBundleItem[]; hadDirs: boolean }> {
  const items: DroppedBundleItem[] = [];
  let hadDirs = false;
  const queue: { entry: FileSystemEntry; path: string }[] = [];
  for (let i = 0; i < dt.items.length; i++) {
    const item = dt.items[i];
    const entry = item.webkitGetAsEntry();
    if (entry) queue.push({ entry, path: entry.name });
    else {
      const f = item.getAsFile();
      if (f) items.push({ file: f, relPath: f.name });
    }
  }
  while (queue.length > 0) {
    const cur = queue.shift();
    if (!cur) break;
    const { entry, path } = cur;
    if (entry.isDirectory) {
      hadDirs = true;
      try {
        const children = await readDirEntries(entry as FileSystemDirectoryEntry);
        for (const c of children) queue.push({ entry: c, path: `${path}/${c.name}` });
      } catch {
        // okunamayan alt dizin atlanir
      }
    } else if (entry.isFile) {
      const f = await entryFile(entry as FileSystemFileEntry);
      if (f) items.push({ file: f, relPath: path });
    }
  }
  return { items, hadDirs };
}

// -------------------------------- bileşen -----------------------------------

export default function Analyzer() {
  const [uploads, setUploads] = useState<UploadRow[]>([]);
  const [selected, setSelected] = useState<DetailResponse | null>(null);
  const [uploading, setUploading] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [extracting, setExtracting] = useState<string | null>(null);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({});
  const [progress, setProgress] = useState<{ done: number; total: number; current: string } | null>(null);
  // arka plan analiz isleri: {id, ad, asama, yuzde} (upload sonrasi polling)
  const [jobs, setJobs] = useState<Record<string, { name: string; stage: string; percent: number }>>({});
  const [cliRunning, setCliRunning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const refreshHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/uploads", { cache: "no-store" });
      const data = (await res.json()) as { ok: boolean; uploads: UploadRow[] };
      if (data.ok) setUploads(data.uploads);
    } catch {
      // sessiz - liste zorunlu degil
    }
  }, []);

  useEffect(() => {
    void refreshHistory();
  }, [refreshHistory]);

  const selectUpload = useCallback(
    async (id: string) => {
      setLoadingDetail(true);
      try {
        const res = await fetch(`/api/uploads/${id}`, { cache: "no-store" });
        const data = (await res.json()) as DetailResponse;
        if (data.ok) setSelected(data);
      } catch {
        toast({ title: "Detay yuklenemedi", variant: "destructive" });
      } finally {
        setLoadingDetail(false);
      }
    },
    [toast],
  );

  // arka plan analiz isini izle: progress endpoint'ini yokla, bitince UI guncelle
  const watchJob = useCallback(
    async (id: string, name: string): Promise<{ ok: boolean; kind?: string; engine?: string | null; error?: string }> => {
      const started = Date.now();
      for (;;) {
        await new Promise((r) => setTimeout(r, 1200));
        try {
          const res = await fetch(`/api/uploads/${id}/progress`, { cache: "no-store" });
          const d = (await res.json()) as {
            ok: boolean;
            status?: string;
            stage?: string;
            percent?: number;
            error?: string;
          };
          if (d.ok) {
            setJobs((prev) => ({ ...prev, [id]: { name, stage: d.stage ?? "...", percent: d.percent ?? 0 } }));
          }
          if (d.status === "done") {
            await refreshHistory();
            await selectUpload(id);
            setJobs((prev) => {
              const n = { ...prev };
              delete n[id];
              return n;
            });
            return { ok: true };
          }
          if (d.status === "error") {
            await refreshHistory();
            setJobs((prev) => {
              const n = { ...prev };
              delete n[id];
              return n;
            });
            return { ok: false, error: d.error ?? "analiz hatasi" };
          }
        } catch {
          // gecici ag hatasi - yeniden dene
        }
        if (Date.now() - started > 8 * 60 * 1000) {
          toast({ title: "Analiz zaman asimi", description: name, variant: "destructive" });
          return { ok: false, error: "zaman asimi" };
        }
      }
    },
    [refreshHistory, selectUpload, toast],
  );

  // DumperPro C++ ikilisini secili yukleme uzerinde calistir (Gorev 5)
  const runDumperProCli = useCallback(async () => {
    const id = selected?.upload.id;
    if (!id || cliRunning) return;
    setCliRunning(true);
    try {
      const res = await fetch(`/api/uploads/${id}/dumperpro`, { method: "POST" });
      const data = (await res.json()) as {
        ok: boolean;
        error?: string;
        outFiles?: { name: string; size: number }[];
        sdkCopied?: string[];
        stdoutTail?: string;
        timedOut?: boolean;
      };
      if (data.ok) {
        toast({
          title: "DumperPro CLI tamamlandi",
          description: `${data.outFiles?.length ?? 0} cikti dosyasi${(data.sdkCopied?.length ?? 0) > 0 ? ` - ${data.sdkCopied!.length} dosya SDK klasorune kopyalandi` : ""}`,
        });
        if (data.stdoutTail) {
          toast({ title: "CLI ciktisi (son satirlar)", description: data.stdoutTail.slice(0, 280) });
        }
        await selectUpload(id); // yeniden yukle - SDK manifest tazelenir
      } else {
        toast({ title: "DumperPro CLI basarisiz", description: data.error, variant: "destructive" });
      }
    } catch (e) {
      toast({
        title: "CLI hatasi",
        description: e instanceof Error ? e.message : "Bilinmeyen hata",
        variant: "destructive",
      });
    } finally {
      setCliRunning(false);
    }
  }, [selected?.upload.id, cliRunning, selectUpload, toast]);

  const handleFile = useCallback(
    async (file: File) => {
      setUploading(true);
      try {
        const form = new FormData();
        form.append("file", file);
        const res = await fetch("/api/upload", { method: "POST", body: form });
        const data = (await res.json()) as {
          ok: boolean;
          id?: string;
          error?: string;
          status?: string;
          kind?: string;
          engine?: string;
        };
        if (!data.ok || !data.id) {
          toast({ title: "Yukleme basarisiz", description: data.error, variant: "destructive" });
          return;
        }
        if (data.status === "analyzing") {
          // arka plan modu: is bitisini izle
          const r = await watchJob(data.id, file.name);
          if (r.ok) {
            toast({ title: "Analiz tamamlandi", description: `${file.name} (${formatBytes(file.size)})` });
          } else {
            toast({ title: "Analiz hata ile bitti", description: r.error, variant: "destructive" });
          }
          return;
        }
        toast({
          title: data.status === "error" ? "Analiz hata ile bitti" : "Analiz tamamlandi",
          description: `${file.name} (${formatBytes(file.size)})`,
        });
        await refreshHistory();
        await selectUpload(data.id);
      } catch (e) {
        toast({
          title: "Yukleme hatasi",
          description: e instanceof Error ? e.message : "Bilinmeyen hata",
          variant: "destructive",
        });
      } finally {
        setUploading(false);
      }
    },
    [refreshHistory, selectUpload, toast, watchJob],
  );

  // coklu dosya / klasor yuklemesi: once klasor grubu olustur, sonra dosyalari tek tek gonder
  const uploadBundle = useCallback(
    async (files: DroppedBundleItem[], name: string) => {
      if (files.length === 0) return;
      setUploading(true);
      setProgress({ done: 0, total: files.length, current: files[0]?.file.name ?? "" });
      try {
        const res = await fetch("/api/upload/folder", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, count: files.length }),
        });
        const fdata = (await res.json()) as { ok: boolean; id?: string; name?: string; error?: string };
        if (!fdata.ok || !fdata.id) {
          toast({ title: "Klasor olusturulamadi", description: fdata.error, variant: "destructive" });
          return;
        }
        const folderId = fdata.id;
        let okCount = 0;
        let firstOkId: string | null = null;
        let failCount = 0;
        const watching: Promise<unknown>[] = [];
        for (let i = 0; i < files.length; i++) {
          const item = files[i];
          setProgress({ done: i, total: files.length, current: item.file.name });
          try {
            const form = new FormData();
            form.append("file", item.file);
            form.append("parentId", folderId);
            form.append("relPath", item.relPath);
            const upRes = await fetch("/api/upload", { method: "POST", body: form });
            const upData = (await upRes.json()) as { ok: boolean; id?: string; status?: string; error?: string };
            if (upData.ok && upData.id) {
              okCount++;
              if (!firstOkId) firstOkId = upData.id;
              // arka plan analizini izle (sirali yukleme, paralel izleme)
              const childId = upData.id;
              watching.push(
                watchJob(childId, item.file.name).catch(() => undefined),
              );
            } else {
              failCount++;
            }
          } catch {
            failCount++;
          }
        }
        setProgress({ done: files.length, total: files.length, current: "" });
        await Promise.allSettled(watching);
        toast({
          title: `Klasor yuklendi: ${okCount}/${files.length} dosya analiz edildi`,
          description: failCount > 0 ? `${failCount} dosya hata verdi` : name,
          variant: failCount > 0 ? "destructive" : "default",
        });
        await refreshHistory();
        setExpandedFolders((prev) => ({ ...prev, [folderId]: true }));
        if (firstOkId) await selectUpload(firstOkId);
      } catch (e) {
        toast({
          title: "Klasor yukleme hatasi",
          description: e instanceof Error ? e.message : "Bilinmeyen hata",
          variant: "destructive",
        });
      } finally {
        setUploading(false);
        setProgress(null);
      }
    },
    [refreshHistory, selectUpload, toast],
  );

  // surukle-birak: tek dosya -> tekil yukleme; klasor / coklu dosya -> paket yukleme
  const handleDrop = useCallback(
    async (dt: DataTransfer) => {
      const { items, hadDirs } = await walkDataTransfer(dt);
      if (items.length === 0) return;
      const filtered = items.filter((it) => it.file.size <= MAX_BUNDLE_FILE);
      const skipped = items.length - filtered.length;
      if (skipped > 0) {
        toast({
          title: `${skipped} dosya atlandi`,
          description: "Klasor yuklemesinde 300 MB uzeri dosyalar atlanir",
        });
      }
      if (filtered.length === 0) return;
      if (filtered.length === 1 && !hadDirs) {
        await handleFile(filtered[0].file);
        return;
      }
      const firstSeg = filtered[0].relPath.split("/")[0];
      const allSameRoot = filtered.every((it) => it.relPath.split("/")[0] === firstSeg);
      const name = hadDirs && allSameRoot && firstSeg ? firstSeg : "Secilen Dosyalar";
      await uploadBundle(filtered, name);
    },
    [handleFile, toast, uploadBundle],
  );

  // webkitdirectory secici: klasor icerigini paket olarak yukle
  const handleFolderPick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const list = Array.from(e.target.files ?? []);
      if (list.length > 0) {
        const bundle = list
          .map((f) => ({ file: f, relPath: f.webkitRelativePath || f.name }))
          .filter((it) => it.file.size <= MAX_BUNDLE_FILE);
        const skipped = list.length - bundle.length;
        if (skipped > 0) {
          toast({
            title: `${skipped} dosya atlandi`,
            description: "Klasor yuklemesinde 300 MB uzeri dosyalar atlanir",
          });
        }
        if (bundle.length > 0) {
          const firstSeg = bundle[0].relPath.split("/")[0];
          const allSameRoot = bundle.every((it) => it.relPath.split("/")[0] === firstSeg);
          const name = firstSeg && firstSeg !== bundle[0].relPath && allSameRoot ? firstSeg : "Klasor";
          void uploadBundle(bundle, name);
        }
      }
      e.target.value = "";
    },
    [toast, uploadBundle],
  );

  const toggleFolder = useCallback((id: string) => {
    setExpandedFolders((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const deleteUpload = useCallback(
    async (id: string) => {
      try {
        await fetch(`/api/uploads/${id}`, { method: "DELETE" });
        if (selected?.upload.id === id) setSelected(null);
        setExpandedFolders((prev) => {
          const next = { ...prev };
          delete next[id];
          return next;
        });
        await refreshHistory();
        toast({ title: "Kayit silindi" });
      } catch {
        toast({ title: "Silme basarisiz", variant: "destructive" });
      }
    },
    [refreshHistory, selected?.upload.id, toast],
  );

  // gecmis listesi icin agac modeli: klasor kokleri + cocuklari
  const historyTree = useMemo(() => {
    const ids = new Set(uploads.map((u) => u.id));
    const childrenMap = new Map<string, UploadRow[]>();
    for (const u of uploads) {
      if (!u.parentId) continue;
      const arr = childrenMap.get(u.parentId);
      if (arr) arr.push(u);
      else childrenMap.set(u.parentId, [u]);
    }
    for (const arr of childrenMap.values()) {
      arr.sort((a, b) => (a.relPath || a.fileName).localeCompare(b.relPath || b.fileName));
    }
    const folderNodes = uploads
      .filter((u) => u.source === "folder")
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    const roots = uploads.filter((u) => !u.parentId || !ids.has(u.parentId));
    return {
      folderNodes,
      roots,
      childrenOf: (id: string) => childrenMap.get(id) ?? [],
    };
  }, [uploads]);

  const extractEntry = useCallback(
    async (entry: string) => {
      if (!selected) return;
      setExtracting(entry);
      try {
        const res = await fetch(`/api/uploads/${selected.upload.id}/extract`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ entry }),
        });
        const data = (await res.json()) as { ok: boolean; id?: string; error?: string };
        if (!data.ok || !data.id) {
          toast({ title: "Cikarma basarisiz", description: data.error, variant: "destructive" });
          return;
        }
        toast({ title: "Dosya cikarildi ve analiz edildi", description: entry });
        await refreshHistory();
        await selectUpload(data.id);
      } catch {
        toast({ title: "Cikarma hatasi", variant: "destructive" });
      } finally {
        setExtracting(null);
      }
    },
    [refreshHistory, selectUpload, selected, toast],
  );

  const copyText = useCallback(
    async (text: string, label: string) => {
      try {
        await navigator.clipboard.writeText(text);
        toast({ title: `${label} kopyalandi` });
      } catch {
        toast({ title: "Kopyalanamadi", variant: "destructive" });
      }
    },
    [toast],
  );

  const r = selected?.analysis?.result;

  return (
    <div className="grid gap-6 lg:grid-cols-[340px_minmax(0,1fr)]">
      {/* ---------------------------- SOL: yukleme + gecmis ---------------------------- */}
      <aside className="flex flex-col gap-4">
        <Card className="border-zinc-800 bg-zinc-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base text-zinc-100">
              <HardDriveUpload className="h-4 w-4 text-emerald-400" />
              Dosya Yukle
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div
              role="button"
              tabIndex={0}
              aria-label="Dosya yukleme alani"
              aria-disabled={uploading}
              onClick={() => {
                if (!uploading) inputRef.current?.click();
              }}
              onKeyDown={(e) => {
                if ((e.key === "Enter" || e.key === " ") && !uploading) inputRef.current?.click();
              }}
              onDragOver={(e) => {
                e.preventDefault();
                if (!uploading) setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                if (!uploading) void handleDrop(e.dataTransfer);
              }}
              className={`flex min-h-[120px] flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-4 text-center transition-colors ${
                uploading ? "pointer-events-none opacity-70" : "cursor-pointer"
              } ${
                dragOver
                  ? "border-emerald-500 bg-emerald-600/10"
                  : "border-zinc-700 bg-zinc-950/60 hover:border-emerald-600/60 hover:bg-emerald-600/5"
              }`}
            >
              {uploading ? (
                <Loader2 className="h-7 w-7 animate-spin text-emerald-400" />
              ) : (
                <ScanSearch className="h-7 w-7 text-emerald-400" />
              )}
              <p className="text-sm font-medium text-zinc-200">
                {uploading && progress
                  ? `Klasor yukleniyor ${progress.done}/${progress.total}`
                  : uploading
                    ? "Analiz ediliyor..."
                    : "Surukle & birak veya tikla"}
              </p>
              {uploading && progress?.current && (
                <p className="max-w-full truncate text-[11px] text-zinc-500" title={progress.current}>
                  {progress.current}
                </p>
              )}
              {!uploading && (
                <p className="text-[11px] leading-relaxed text-zinc-500">
                  .exe .dll .sys .apk .so .dex .zip .pak .obb
                  <br />
                  en fazla 300 MB - klasor surukleyebilirsiniz
                </p>
              )}
              <input
                ref={inputRef}
                type="file"
                className="hidden"
                accept={ACCEPT}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void handleFile(f);
                  e.target.value = "";
                }}
              />
            </div>
            <Button
              variant="outline"
              className="w-full border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              disabled={uploading}
              onClick={() => folderInputRef.current?.click()}
            >
              <FolderOpen className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
              Klasor Sec
            </Button>
            <input
              ref={folderInputRef}
              type="file"
              {...({ webkitdirectory: "" } as Record<string, string>)}
              className="hidden"
              aria-label="Klasor sec"
              onChange={handleFolderPick}
            />
            {/* arka plan analiz isleri (canli ilerleme) */}
            {Object.keys(jobs).length > 0 && (
              <div className="space-y-2 rounded-md border border-emerald-900/40 bg-zinc-950/60 p-2.5">
                {Object.entries(jobs).map(([jid, j]) => (
                  <div key={jid} className="space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <p className="max-w-[220px] truncate text-[11px] font-medium text-zinc-300" title={j.name}>
                        {j.name}
                      </p>
                      <span className="text-[10px] text-emerald-400">%{Math.max(0, Math.round(j.percent))}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
                      <div
                        className="h-full rounded-full bg-emerald-600 transition-all duration-500"
                        style={{ width: `${Math.min(100, Math.max(0, j.percent))}%` }}
                      />
                    </div>
                    <p className="text-[10px] text-zinc-500">{j.stage}</p>
                  </div>
                ))}
              </div>
            )}
            <p className="text-[11px] leading-relaxed text-zinc-500">
              Statik analiz: PE/COFF, ELF, ZIP/APK (+binary manifest), DEX. Motor tespiti,
              bolum/entropy, import-export, UE surum stringleri, imza adaylari ve rapor uretimi.
            </p>
          </CardContent>
        </Card>

        <Card className="border-zinc-800 bg-zinc-900/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="flex items-center gap-2 text-base text-zinc-100">
              <Archive className="h-4 w-4 text-emerald-400" />
              Gecmis
            </CardTitle>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Gecmisi yenile"
              onClick={() => void refreshHistory()}
              className="h-8 w-8 text-zinc-400 hover:text-emerald-400"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-[440px] overflow-y-auto overflow-x-hidden pr-1 scrollbar-thin">
              <div className="flex flex-col gap-1 px-3 pb-3">
                {uploads.length === 0 && (
                  <p className="px-1 py-6 text-center text-xs text-zinc-500">
                    Henuz yukleme yok. Dosya veya klasor yuklediginizde burada listelenir.
                  </p>
                )}
                {historyTree.roots.map((u) => {
                  const active = selected?.upload.id === u.id;
                  const isFolder = u.source === "folder";
                  const children = historyTree.childrenOf(u.id);
                  const expanded = !!expandedFolders[u.id];
                  const expandable = isFolder || children.length > 0;
                  const totalSize = children.reduce((a, c) => a + c.size, 0);
                  return (
                    <Fragment key={u.id}>
                      <div
                        className={`group flex min-h-9 items-center gap-1.5 overflow-hidden rounded-lg border px-2 py-1.5 transition-colors ${
                          active
                            ? "border-emerald-600/50 bg-emerald-600/10"
                            : "border-transparent hover:border-zinc-700 hover:bg-zinc-800/60"
                        }`}
                      >
                        {expandable ? (
                          <button
                            type="button"
                            onClick={() => toggleFolder(u.id)}
                            aria-expanded={expanded}
                            aria-label={isFolder ? `${u.fileName} klasorunu ac/kapat` : `${u.fileName} icerigini ac/kapat`}
                            className="shrink-0 rounded p-0.5 text-zinc-500 transition-colors hover:text-emerald-300"
                          >
                            {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                          </button>
                        ) : (
                          <span className="w-[19px] shrink-0" aria-hidden="true" />
                        )}
                        <button
                          type="button"
                          onClick={() => (isFolder ? toggleFolder(u.id) : void selectUpload(u.id))}
                          className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden text-left"
                          aria-label={isFolder ? `${u.fileName} klasorunu ac/kapat` : `${u.fileName} analizini ac`}
                        >
                          {isFolder ? (
                            expanded ? (
                              <FolderOpen className="h-4 w-4 shrink-0 text-emerald-400" />
                            ) : (
                              <Folder className="h-4 w-4 shrink-0 text-emerald-400" />
                            )
                          ) : (
                            <KindIcon kind={u.analysis?.kind ?? "unknown"} className="h-4 w-4 shrink-0 text-emerald-500" />
                          )}
                          <span className="min-w-0 flex-1 truncate text-xs font-medium text-zinc-200" title={u.fileName}>
                            {u.fileName}
                          </span>
                          <span className="flex shrink-0 items-center gap-1">
                            {isFolder && (
                              <Badge variant="outline" className="h-4 shrink-0 border-zinc-700 px-1.5 text-[10px] text-zinc-400">
                                {children.length || u.childCount || 0} dosya
                              </Badge>
                            )}
                            <span className="text-[10px] text-zinc-500">{formatBytes(isFolder ? totalSize : u.size)}</span>
                            {!isFolder && u.analysis && (
                              <Badge className={`h-4 shrink-0 px-1.5 text-[10px] ${engineBadgeClass(u.analysis.engine)}`}>
                                {u.analysis.engine ?? u.analysis.kind}
                                {u.analysis.engineVersion ? ` ${u.analysis.engineVersion}` : ""}
                              </Badge>
                            )}
                            {!isFolder && u.status === "analyzing" && (
                              <Badge variant="outline" className="h-4 shrink-0 gap-1 border-emerald-700/50 px-1.5 text-[10px] text-emerald-300">
                                <Loader2 className="h-2.5 w-2.5 animate-spin" />
                                {u.progress ? `${u.progress.stage} %${Math.max(0, Math.round(u.progress.percent))}` : "analiz..."}
                              </Badge>
                            )}
                            {!isFolder && u.source === "extract" && (
                              <Badge
                                variant="outline"
                                className="h-4 shrink-0 border-zinc-700 px-1.5 text-[10px] text-zinc-400"
                              >
                                cikarilan
                              </Badge>
                            )}
                            {u.status === "error" && (
                              <Badge className="h-4 shrink-0 bg-red-500/15 px-1.5 text-[10px] text-red-300 ring-1 ring-red-500/40">
                                hata
                              </Badge>
                            )}
                          </span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void deleteUpload(u.id)}
                          aria-label={isFolder ? `${u.fileName} klasorunu sil` : `${u.fileName} kaydini sil`}
                          className="shrink-0 rounded p-1 text-zinc-600 opacity-0 transition-opacity hover:text-red-400 group-hover:opacity-100"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                      {expanded && children.length > 0 && (
                        <div className="ml-3 flex flex-col gap-1 border-l border-zinc-800 pl-6">
                          {children.map((c) => {
                            const cActive = selected?.upload.id === c.id;
                            return (
                              <div
                                key={c.id}
                                className={`group flex min-h-9 items-center gap-2 overflow-hidden rounded-lg border px-2 py-1.5 transition-colors ${
                                  cActive
                                    ? "border-emerald-600/50 bg-emerald-600/10"
                                    : "border-transparent hover:border-zinc-700 hover:bg-zinc-800/60"
                                }`}
                              >
                                <button
                                  type="button"
                                  onClick={() => void selectUpload(c.id)}
                                  className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden text-left"
                                  aria-label={`${c.fileName} analizini ac`}
                                >
                                  <KindIcon kind={c.analysis?.kind ?? "unknown"} className="h-4 w-4 shrink-0 text-emerald-500" />
                                  <span
                                    className="min-w-0 flex-1 truncate text-xs text-zinc-300"
                                    title={c.relPath ?? c.fileName}
                                  >
                                    {c.relPath ?? c.fileName}
                                  </span>
                                  <span className="flex shrink-0 items-center gap-1">
                                    <span className="text-[10px] text-zinc-500">{formatBytes(c.size)}</span>
                                    {c.analysis && (
                                      <Badge className={`h-4 shrink-0 px-1.5 text-[10px] ${engineBadgeClass(c.analysis.engine)}`}>
                                        {c.analysis.engine ?? c.analysis.kind}
                                        {c.analysis.engineVersion ? ` ${c.analysis.engineVersion}` : ""}
                                      </Badge>
                                    )}
                                    {c.status === "error" && (
                                      <Badge className="h-4 shrink-0 bg-red-500/15 px-1.5 text-[10px] text-red-300 ring-1 ring-red-500/40">
                                        hata
                                      </Badge>
                                    )}
                                  </span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => void deleteUpload(c.id)}
                                  aria-label={`${c.fileName} kaydini sil`}
                                  className="shrink-0 rounded p-1 text-zinc-600 opacity-0 transition-opacity hover:text-red-400 group-hover:opacity-100"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </Fragment>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      </aside>

      {/* ---------------------------- SAG: sonuc paneli ---------------------------- */}
      <section className="min-w-0">
        {loadingDetail && (
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardContent className="flex items-center justify-center gap-3 py-16 text-sm text-zinc-400">
              <Loader2 className="h-5 w-5 animate-spin text-emerald-400" />
              Analiz sonucu yukleniyor...
            </CardContent>
          </Card>
        )}

        {!loadingDetail && !selected && (
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
              <ScanSearch className="h-10 w-10 text-zinc-600" />
              <p className="text-sm font-medium text-zinc-300">Henuz secili analiz yok</p>
              <p className="max-w-md text-xs leading-relaxed text-zinc-500">
                Soldaki alandan bir dosya yukleyin (exe / dll / apk / so / dex / zip).
                Sistem magic-byte tespiti, baslik/section parse, motor surum tespiti,
                anti-cheat/DRM imzasi, GObjects-GNames desen adaylari ve rapor uretimi yapar.
              </p>
            </CardContent>
          </Card>
        )}

        {!loadingDetail && selected && selected.upload.status === "error" && (
          <Card className="border-red-900/50 bg-red-950/20">
            <CardContent className="flex items-start gap-3 py-6">
              <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
              <div>
                <p className="text-sm font-medium text-red-200">Analiz sirasinda hata</p>
                <p className="mt-1 text-xs text-red-300/80">{selected.upload.error}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {!loadingDetail && selected && r && (
          <ResultPanel r={r} detail={selected} onExtract={extractEntry} extracting={extracting} onCopy={copyText} onRefreshHistory={refreshHistory} onRunCli={runDumperProCli} cliRunning={cliRunning} />
        )}
      </section>
    </div>
  );
}

// ------------------------------ sonuc paneli --------------------------------

function ResultPanel({
  r,
  detail,
  onExtract,
  extracting,
  onCopy,
  onRefreshHistory,
  onRunCli,
  cliRunning,
}: {
  r: AnalysisResultShape;
  detail: DetailResponse;
  onExtract: (entry: string) => void;
  extracting: string | null;
  onCopy: (text: string, label: string) => void;
  onRefreshHistory: () => void;
  onRunCli: () => void;
  cliRunning: boolean;
}) {
  const isPe = r.kind === "pe" && !!r.pe;
  const isApkish = r.kind === "apk" || r.kind === "zip" || r.kind === "dex";
  const hasImports = isPe && (r.pe?.imports.length ?? 0) > 0;
  const hasExports = isPe && !!r.pe?.exports;
  const isElf = r.kind === "elf" && !!r.elf;
  const [decompFn, setDecompFn] = useState<FunctionRow | null>(null);
  // kontrollu sekmeler: struct/hex/cikaricilar arasi gecis icin
  const [tabValue, setTabValue] = useState("genel");
  const [hexJump, setHexJump] = useState<{ off: number; nonce: number } | null>(null);
  const [viewerFile, setViewerFile] = useState<SdkViewerTarget | null>(null);
  const closeViewer = useCallback(() => setViewerFile(null), []);
  const openSdkFile = useCallback((f: SdkViewerTarget) => setViewerFile(f), []);

  const sdkBase = r.file.name.replace(/\.[^.]+$/, "");

  // vftable RVA -> dosya offseti (PE bolumleri uzerinden; bolum yoksa RVA kullanilir)
  const vftableFileOffset = (rva: number): number => {
    const secs = r.pe?.sections ?? [];
    for (const s of secs) {
      if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
        if (s.rawPointer === undefined) return rva;
        return s.rawPointer + (rva - s.virtualAddress);
      }
    }
    return rva;
  };

  // structlar icin SDK hedef dosyasi: {base}_structs.h -> {base}_classes.h -> SDK.hpp
  const sdkStructTarget = useMemo<SdkViewerTarget | null>(() => {
    if (!r.sdk) return null;
    const b = sdkBase.toLowerCase();
    const eq = (n: string) => r.sdk!.files.find((f) => f.name.toLowerCase() === n);
    const structFile = eq(`${b}_structs.h`) ?? eq(`${b}_classes.h`) ?? eq("sdk.hpp");
    return structFile ? { name: structFile.name, size: structFile.size } : null;
  }, [r.sdk, sdkBase]);

  // SDK dosyalarini cikarici bazinda grupla
  const sdkGroups = useMemo(() => {
    if (!r.sdk) return [];
    const avail = new Map<string, boolean>((r.extractors?.extractors ?? []).map((e) => [e.id, e.available]));
    return SDK_GROUP_ORDER.map((g) => ({
      id: g.id,
      label: g.label,
      files: r.sdk!.files.filter((f) => fileExtractorOf(f.name, sdkBase).id === g.id),
      available: avail.get(g.id),
    })).filter((g) => g.files.length > 0);
  }, [r.sdk, r.extractors, sdkBase]);

  return (
    <Card className="border-zinc-800 bg-zinc-900/50">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <KindIcon kind={r.kind} className="h-5 w-5 text-emerald-400" />
          <CardTitle className="min-w-0 truncate text-base text-zinc-50">{r.file.name}</CardTitle>
          <Badge className={engineBadgeClass(r.engine.detected)}>
            {r.engine.detected}
            {r.engine.version ? ` ${r.engine.version}` : ""}
          </Badge>
          <Badge variant="outline" className="border-zinc-700 text-zinc-400">
            {r.kind.toUpperCase()}
          </Badge>
          <Badge variant="outline" className="border-zinc-700 text-zinc-400">
            {formatBytes(r.file.size)}
          </Badge>
          {r.security.packedHint && (
            <Badge className="bg-red-500/15 text-red-300 ring-1 ring-red-500/40">packer sezgisi</Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <a href={`/api/uploads/${detail.upload.id}/report?format=txt`} download>
            <Button size="sm" variant="outline" className="border-zinc-700 text-zinc-300 hover:bg-zinc-800">
              <FileText className="mr-1.5 h-3.5 w-3.5" />
              TXT rapor
            </Button>
          </a>
          <a href={`/api/uploads/${detail.upload.id}/report?format=json`} download>
            <Button size="sm" variant="outline" className="border-zinc-700 text-zinc-300 hover:bg-zinc-800">
              <Download className="mr-1.5 h-3.5 w-3.5" />
              JSON rapor
            </Button>
          </a>
          {r.gamesIniSuggestion && (
            <Button
              size="sm"
              variant="outline"
              className="border-emerald-700/50 text-emerald-300 hover:bg-emerald-600/10"
              onClick={() => onCopy(r.gamesIniSuggestion ?? "", "games.ini onerisi")}
            >
              <Copy className="mr-1.5 h-3.5 w-3.5" />
              games.ini kopyala
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            disabled={cliRunning}
            onClick={onRunCli}
            title="DumperPro C++ ikilisini bu dosya uzerinde calistir (UE SDK, imza, vtable ciktilari SDK klasorune yazilir)"
          >
            <Terminal className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
            {cliRunning ? "CLI calisiyor..." : "DumperPro CLI"}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        <Tabs value={tabValue} onValueChange={setTabValue}>
          <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1 bg-zinc-950/70">
            <TabsTrigger value="genel" className={TRIGGER_CLS}>
              Genel
            </TabsTrigger>
            {(isPe || isElf) && (
              <TabsTrigger value="bolumler" className={TRIGGER_CLS}>
                Bolumler
              </TabsTrigger>
            )}
            <TabsTrigger value="hex" className={TRIGGER_CLS}>
              <Hash className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
              Hex
            </TabsTrigger>
            {(hasImports || hasExports) && (
              <TabsTrigger value="simge" className={TRIGGER_CLS}>
                Import / Export
              </TabsTrigger>
            )}
            {isApkish && (
              <TabsTrigger value="arsiv" className={TRIGGER_CLS}>
                Arsiv Icerigi
              </TabsTrigger>
            )}
            {r.gameFiles && (
              <TabsTrigger value="oyundosyalari" className={TRIGGER_CLS}>
                <Gamepad2 className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Oyun Dosyalari
              </TabsTrigger>
            )}
            {r.mem && (
              <TabsTrigger value="bellek" className={TRIGGER_CLS}>
                <MemoryStick className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Bellek
              </TabsTrigger>
            )}
            <TabsTrigger value="guvenlik" className={TRIGGER_CLS}>
              Motor & Guvenlik
            </TabsTrigger>
            {isPe && (
              <TabsTrigger value="imza" className={TRIGGER_CLS}>
                Imza / Pattern
              </TabsTrigger>
            )}
            {isPe && (r.pe?.debug || r.pe?.dataDirectories) && (
              <TabsTrigger value="debug" className={TRIGGER_CLS}>
                <Bug className="mr-1.5 h-3.5 w-3.5 text-amber-400" />
                Debug
              </TabsTrigger>
            )}
            {r.functions && r.functions.total > 0 && (
              <TabsTrigger value="fonksiyonlar" className={TRIGGER_CLS}>
                <Braces className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Fonksiyonlar ({r.functions.total})
              </TabsTrigger>
            )}
            {r.structs && r.structs.total > 0 && (
              <TabsTrigger value="structlar" className={TRIGGER_CLS}>
                <Table2 className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Structlar ({r.structs.total})
              </TabsTrigger>
            )}
            {r.enums && r.enums.total > 0 && (
              <TabsTrigger value="enumlar" className={TRIGGER_CLS}>
                <Braces className="mr-1.5 h-3.5 w-3.5 text-amber-400" />
                Enumlar ({r.enums.total})
              </TabsTrigger>
            )}
            {r.il2cpp && (
              <TabsTrigger value="il2cpp" className={TRIGGER_CLS}>
                <Package className="mr-1.5 h-3.5 w-3.5 text-amber-400" />
                IL2CPP
              </TabsTrigger>
            )}
            {!r.il2cpp && r.il2cppBin && (
              <TabsTrigger value="il2cppbin" className={TRIGGER_CLS}>
                <Binary className="mr-1.5 h-3.5 w-3.5 text-amber-400" />
                IL2CPP Binary
              </TabsTrigger>
            )}
            {r.sdk && r.sdk.files.length > 0 && (
              <TabsTrigger value="sdk" className={TRIGGER_CLS}>
                <FileCode2 className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                SDK ({r.sdk.files.length})
              </TabsTrigger>
            )}
            {(r.functions?.total || r.structs?.total || r.enums?.total || r.strings.length > 0) && (
              <TabsTrigger value="kod" className={TRIGGER_CLS}>
                <Wand2 className="mr-1.5 h-3.5 w-3.5 text-amber-400" />
                Kod Uretici
              </TabsTrigger>
            )}
            <TabsTrigger value="dizeler" className={TRIGGER_CLS}>
              Dizeler
            </TabsTrigger>
            {(r.savegame || r.vdf) && (
              <TabsTrigger value="save" className={TRIGGER_CLS}>
                <Save className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Save Editor
              </TabsTrigger>
            )}
            {r.extractors && (
              <TabsTrigger value="cikaricilar" className={TRIGGER_CLS}>
                <Layers className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Cikaricilar
              </TabsTrigger>
            )}
            <TabsTrigger value="rapor" className={TRIGGER_CLS}>
              Rapor
            </TabsTrigger>
          </TabsList>

          {/* ---------- GENEL ---------- */}
          <TabsContent value="genel" className="mt-4 space-y-4">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <MiniStat label="Format" value={r.pe ? r.pe.format : r.elf ? r.elf.class : r.kind.toUpperCase()} />
              <MiniStat label="Mimari" value={r.pe ? r.pe.machine : r.elf ? r.elf.machine : "-"} />
              <MiniStat label="Entropy" value={`${r.overallEntropy.toFixed(2)}`} valueClass={entropyClass(r.overallEntropy)} />
              <MiniStat
                label={r.pe ? "Build zamani" : "SHA-256"}
                value={
                  r.pe
                    ? r.pe.buildDate.replace(" UTC", "")
                    : `${r.file.sha256.slice(0, 12)}...`
                }
              />
              {r.pe && <MiniStat label="ImageBase" value={hex(r.pe.imageBase)} />}
              {r.pe && <MiniStat label="SizeOfImage" value={hex(r.pe.sizeOfImage)} />}
              {r.pe && <MiniStat label="Subsystem" value={r.pe.subsystem} />}
              {r.apk?.packageName && <MiniStat label="Paket" value={r.apk.packageName} />}
              {r.apk?.versionName && (
                <MiniStat label="APK surum" value={`${r.apk.versionName} (${r.apk.versionCode ?? "-"})`} />
              )}
              {r.dex && (
                <>
                  <MiniStat label="DEX siniflari" value={r.dex.classes.toLocaleString("tr-TR")} />
                  <MiniStat label="DEX metodlar" value={r.dex.methods.toLocaleString("tr-TR")} />
                  <MiniStat
                    label="DEX checksum"
                    value={r.dex.checksumOk ? "gecerli" : "uyusmuyor"}
                    valueClass={r.dex.checksumOk ? undefined : "text-red-300"}
                  />
                </>
              )}
            </div>

            {r.engine.versionStrings.length > 0 && (
              <InfoBlock
                title="UE surum stringleri"
                items={r.engine.versionStrings.slice(0, 8).map((s) => s)}
                mono
              />
            )}

            {r.notes.length > 0 && <InfoBlock title="Notlar" items={r.notes} />}

            {r.gamesIniSuggestion && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">
                  games.ini onerisi (DumperPro C++ araci icin)
                </p>
                <pre className="max-h-48 overflow-auto rounded-lg border border-zinc-800 bg-zinc-950/80 p-3 text-[11px] leading-relaxed text-emerald-200 scrollbar-thin">
                  {r.gamesIniSuggestion}
                </pre>
              </div>
            )}

            {r.errors.length > 0 && (
              <div className="rounded-lg border border-amber-700/40 bg-amber-950/20 p-3">
                <p className="mb-1 flex items-center gap-1.5 text-xs font-medium text-amber-300">
                  <TriangleAlert className="h-3.5 w-3.5" /> Kismi parse uyarilari
                </p>
                <ul className="list-inside list-disc text-[11px] text-amber-200/70">
                  {r.errors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </div>
            )}
          </TabsContent>

          {/* ---------- BOLUMLER ---------- */}
          {(isPe || isElf) && (
            <TabsContent value="bolumler" className="mt-4">
              <div className="max-h-[480px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                {r.pe ? (
                  <table className="w-full min-w-[640px] text-left text-xs">
                    <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                      <tr>
                        <Th>Ad</Th>
                        <Th>VA</Th>
                        <Th>VSize</Th>
                        <Th>Raw</Th>
                        <Th>Entropy</Th>
                        <Th>Bayraklar</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 font-mono">
                      {r.pe.sections.map((s, i) => (
                        <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                          <Td>{s.name}</Td>
                          <Td>{hex(s.virtualAddress)}</Td>
                          <Td>{hex(s.virtualSize)}</Td>
                          <Td>{hex(s.rawSize)}</Td>
                          <Td>
                            <span className={entropyClass(s.entropy)}>{s.entropy.toFixed(2)}</span>
                          </Td>
                          <Td>
                            <span className="font-sans text-[10px] text-zinc-500">{s.flags.join(" ")}</span>
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : r.elf ? (
                  <div>
                    <table className="w-full min-w-[560px] text-left text-xs">
                      <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                        <tr>
                          <Th>Ad</Th>
                          <Th>Tip</Th>
                          <Th>Adres</Th>
                          <Th>Boyut</Th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60 font-mono">
                        {r.elf.sections.map((s, i) => (
                          <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                            <Td>{s.name}</Td>
                            <Td>{s.type}</Td>
                            <Td>{hex(s.addr)}</Td>
                            <Td>{hex(s.size)}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {r.elf.dynsyms && r.elf.dynsyms.length > 0 && (
                      <div className="mt-4 border-t border-zinc-800 px-4 pt-3">
                        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">
                          Dynamic semboller (.dynsym) — ilk {r.elf.dynsyms.length} / {r.elf.dynsymCount ?? r.elf.dynsyms.length}
                        </p>
                        <div className="max-h-64 overflow-y-auto scrollbar-thin">
                          <table className="w-full min-w-[520px] text-left text-xs">
                            <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                              <tr>
                                <Th>Tip</Th>
                                <Th>Bind</Th>
                                <Th>Adres</Th>
                                <Th>Boyut</Th>
                                <Th>Ad</Th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800/60 font-mono">
                              {r.elf.dynsyms.map((s, i) => (
                                <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                                  <Td>
                                    <span className={s.type === "FUNC" ? "text-emerald-400" : "text-amber-400"}>{s.type}</span>
                                  </Td>
                                  <Td>{s.bind}</Td>
                                  <Td>{hex(s.value)}</Td>
                                  <Td>{s.size || "-"}</Td>
                                  <Td className="break-all">{s.name}</Td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {(r.elf.dynsyms.some((s) => s.name.startsWith("JNI_OnLoad")) ||
                          r.elf.dynsyms.some((s) => s.name.startsWith("il2cpp_"))) && (
                          <p className="mt-2 text-[11px] text-emerald-400/80">
                            {r.elf.dynsyms.some((s) => s.name.startsWith("JNI_OnLoad")) && "JNI_OnLoad bulundu (Android native kutuphane). "}
                            {r.elf.dynsyms.some((s) => s.name.startsWith("il2cpp_")) && "il2cpp_* API sembolleri var (Unity IL2CPP)."}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                ) : null}
              </div>
            </TabsContent>
          )}

          {/* ---------- HEX ---------- */}
          <TabsContent value="hex" className="mt-4">
            <HexTab uploadId={detail.upload.id} onRefreshHistory={onRefreshHistory} jump={hexJump} />
          </TabsContent>

          {/* ---------- IMPORT / EXPORT ---------- */}
          {(hasImports || hasExports) && (
            <TabsContent value="simge" className="mt-4">
              <div className="max-h-[480px] overflow-y-auto scrollbar-thin">
                {hasImports && (
                  <Accordion type="multiple" className="space-y-2">
                    {r.pe?.imports.map((imp) => (
                      <AccordionItem
                        key={imp.dll}
                        value={imp.dll}
                        className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-4"
                      >
                        <AccordionTrigger className="py-3 text-xs text-zinc-200 hover:text-emerald-300">
                          <span className="flex items-center gap-2">
                            <ChevronRight className="h-3.5 w-3.5 text-emerald-500" />
                            {imp.dll}
                            <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                              {imp.count} fn
                            </Badge>
                          </span>
                        </AccordionTrigger>
                        <AccordionContent className="pb-3">
                          <div className="grid gap-x-4 gap-y-0.5 font-mono text-[11px] text-zinc-400 sm:grid-cols-2 lg:grid-cols-3">
                            {imp.functions.map((f, i) => (
                              <span key={i} className="truncate">
                                {f}
                              </span>
                            ))}
                          </div>
                          {imp.truncated && (
                            <p className="mt-2 text-[10px] text-zinc-500">
                              +{imp.count - imp.functions.length} fonksiyon gizlendi (rapor tamami icerir)
                            </p>
                          )}
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                  </Accordion>
                )}
                {hasExports && (
                  <div className="mt-4">
                    <p className="mb-2 text-xs font-medium text-zinc-400">
                      Disa aktarma: {r.pe?.exports?.dllName} ({r.pe?.exports?.count} sembol)
                    </p>
                    <div className="max-h-56 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/50 p-3 scrollbar-thin">
                      <div className="grid gap-x-4 gap-y-0.5 font-mono text-[11px] text-zinc-400 sm:grid-cols-2 lg:grid-cols-3">
                        {r.pe?.exports?.names.map((n, i) => (
                          <span key={i} className="truncate">
                            {n}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </TabsContent>
          )}

          {/* ---------- ARSIV (APK/ZIP/DEX) ---------- */}
          {isApkish && (
            <TabsContent value="arsiv" className="mt-4 space-y-4">
              {r.dex && (
                <>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <MiniStat label="Surum" value={`v${r.dex.version} (${r.dex.endian})`} />
                    <MiniStat label="String havuzu" value={r.dex.strings.toLocaleString("tr-TR")} />
                    <MiniStat label="Tip/Proto" value={`${r.dex.types.toLocaleString("tr-TR")} / ${r.dex.protos.toLocaleString("tr-TR")}`} />
                    <MiniStat label="Alan/Metod" value={`${r.dex.fields.toLocaleString("tr-TR")} / ${r.dex.methods.toLocaleString("tr-TR")}`} />
                  </div>
                  {r.dex.packages.length > 0 && (
                    <InfoBlock
                      title="En cok sinif iceren paketler"
                      items={r.dex.packages.map((p) => `${p.name} - ${p.count} sinif`)}
                      mono
                    />
                  )}
                  {r.dex.classSamples.length > 0 && (
                    <InfoBlock title="Sinif ornekleri" items={r.dex.classSamples} mono />
                  )}
                  {r.dex.engineHints.length > 0 && (
                    <InfoBlock title="Motor / oyun ipuclari" items={r.dex.engineHints} />
                  )}
                </>
              )}

              {r.apk && (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <MiniStat label="Kayit sayisi" value={String(r.apk.entryCount)} />
                  <MiniStat label="DEX" value={String(r.apk.dexCount)} />
                  <MiniStat label="ABI" value={r.apk.abis.join(", ") || "-"} />
                  <MiniStat
                    label="SDK (min/target)"
                    value={`${r.apk.minSdk ?? "-"} / ${r.apk.targetSdk ?? "-"}`}
                  />
                </div>
              )}

              {(r.apk?.mainLibs.length ?? r.zip?.mainLibs.length) ? (
                <div>
                  <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-zinc-400">
                    <Boxes className="h-3.5 w-3.5 text-emerald-500" />
                    Ana kutuphaneler - &quot;Analiz Et&quot; ile .so dosyasini cikarip ayri analiz edin
                  </p>
                  <div className="max-h-[320px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                    <table className="w-full min-w-[600px] text-left text-xs">
                      <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                        <tr>
                          <Th>Yol</Th>
                          <Th>Boyut</Th>
                          <Th>Yontem</Th>
                          <Th>Ipucu</Th>
                          <Th />
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60">
                        {(r.apk?.mainLibs ?? r.zip?.mainLibs ?? []).map((m) => (
                          <tr key={m.path} className="text-zinc-300 hover:bg-zinc-800/40">
                            <Td mono>{m.path}</Td>
                            <Td>{formatBytes(m.size)}</Td>
                            <Td>{m.method}</Td>
                            <Td>
                              {m.engineHint ? (
                                <Badge className={`h-5 px-1.5 text-[10px] ${engineBadgeClass(m.engineHint)}`}>
                                  {m.engineHint}
                                </Badge>
                              ) : (
                                <span className="text-zinc-600">-</span>
                              )}
                            </Td>
                            <Td>
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={extracting !== null}
                                onClick={() => onExtract(m.path)}
                                className="h-7 border-zinc-700 px-2 text-[11px] text-emerald-300 hover:bg-emerald-600/10"
                              >
                                {extracting === m.path ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  "Analiz Et"
                                )}
                              </Button>
                            </Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}

              {r.apk?.scannedLibs.length ? (
                <InfoBlock
                  title="Taranan .so icerigi (otor string taramasi)"
                  items={r.apk.scannedLibs.flatMap((s) =>
                    [
                      `${s.path}: ${s.engine ?? "-"} ${s.version ?? ""}`.trim(),
                      ...s.versionStrings.map((v) => `  ${v}`),
                    ] as string[],
                  )}
                  mono
                />
              ) : null}

              {r.apk?.pakFiles.length ? (
                <InfoBlock
                  title={`UE .pak dosyalari (${r.apk.pakFiles.length})`}
                  items={r.apk.pakFiles.slice(0, 10).map((p) => `${p.path} - ${formatBytes(p.size)}`)}
                  mono
                />
              ) : null}

              {r.apk?.notableFiles.length || r.zip?.notableFiles.length ? (
                <InfoBlock
                  title="Dikkat ceken dosyalar"
                  items={[...(r.apk?.notableFiles ?? []), ...(r.zip?.notableFiles ?? [])].slice(0, 12)}
                  mono
                />
              ) : null}

              <div>
                <p className="mb-2 text-xs font-medium text-zinc-400">Dizin gruplari (boyuta gore)</p>
                <div className="max-h-56 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                  <table className="w-full min-w-[420px] text-left text-xs">
                    <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                      <tr>
                        <Th>Dizin</Th>
                        <Th>Dosya</Th>
                        <Th>Toplam</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60">
                      {(r.apk?.groups ?? r.zip?.groups ?? []).map((g) => (
                        <tr key={g.dir} className="text-zinc-300 hover:bg-zinc-800/40">
                          <Td mono>{g.dir}</Td>
                          <Td>{g.count}</Td>
                          <Td>{formatBytes(g.totalSize)}</Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </TabsContent>
          )}

          {/* ---------- OYUN DOSYALARI ---------- */}
          {r.gameFiles && (
            <TabsContent value="oyundosyalari" className="mt-4">
              <GameFilesTab gameFiles={r.gameFiles} />
            </TabsContent>
          )}

          {/* ---------- BELLEK ---------- */}
          {r.mem && (
            <TabsContent value="bellek" className="mt-4">
              <MemTab uploadId={detail.upload.id} mem={r.mem} onRefreshHistory={onRefreshHistory} />
            </TabsContent>
          )}

          {/* ---------- MOTOR & GUVENLIK ---------- */}
          <TabsContent value="guvenlik" className="mt-4 space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <MiniStat label="Motor" value={r.engine.detected} valueClass={engineBadgeClass(r.engine.detected).includes("emerald") ? "text-emerald-300" : undefined} />
              <MiniStat label="Surum" value={r.engine.version ?? "-"} />
              <MiniStat label="Guven" value={r.engine.confidence} />
            </div>

            {r.engine.markers.length > 0 && (
              <InfoBlock
                title="Imza eslesmeleri"
                items={r.engine.markers.map((m) => `${m.name}: ${m.hits} eslesme`)}
              />
            )}

            {(r.security.antiCheat.length > 0 || r.security.drm.length > 0 || r.security.packer.length > 0) && (
              <div className="rounded-lg border border-amber-700/40 bg-amber-950/20 p-3">
                <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-amber-300">
                  <ShieldAlert className="h-3.5 w-3.5" /> Korumalar
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {r.security.antiCheat.map((a) => (
                    <Badge key={a} className="bg-red-500/15 text-red-300 ring-1 ring-red-500/40">
                      {a}
                    </Badge>
                  ))}
                  {r.security.drm.map((d) => (
                    <Badge key={d} className="bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/40">
                      {d}
                    </Badge>
                  ))}
                  {r.security.packer.map((p) => (
                    <Badge key={p} className="bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/40">
                      {p}
                    </Badge>
                  ))}
                  {r.security.packedHint && (
                    <Badge className="bg-red-500/15 text-red-300 ring-1 ring-red-500/40">
                      yuksek entropy (packed?)
                    </Badge>
                  )}
                </div>
              </div>
            )}

            {r.pe?.dllCharacteristics.length ? (
              <InfoBlock title="PE guvenlik ozellikleri" items={r.pe.dllCharacteristics} />
            ) : null}

            {r.security.notableStrings.length > 0 && (
              <InfoBlock title="Dikkat ceken dizeler" items={r.security.notableStrings} mono />
            )}
          </TabsContent>

          {/* ---------- IMZA / PATTERN VISUAL ---------- */}
          {isPe && (
            <TabsContent value="imza" className="mt-4 space-y-3">
              <PatternVisualScanner
                uploadId={detail.upload.id}
                pe={r.pe}
                onJumpHex={(off) => {
                  setTabValue("hex");
                  setHexJump({ off, nonce: Date.now() });
                }}
              />
              <p className="text-[11px] leading-relaxed text-zinc-500">
                Statik adaylar: eslesen bayt desenleri RVA/VA&apos;ya cevrilir ancak calistirma olmadan
                dogrulanamaz. DumperPro canli modu (--process / --pid) RIP-relative cozumleme ve
                adres dogrulamasi ile bu adaylari teyit eder; kesin sonuc &lt;Oyun&gt;_sigs.txt&apos;te.
              </p>
              {r.signatureCandidates.map((c) => (
                <div key={c.name} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs font-medium text-zinc-200">{c.name}</p>
                    {c.hits.length > 0 ? (
                      <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
                        {c.hits.length} aday
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-500">
                        eslesme yok
                      </Badge>
                    )}
                  </div>
                  <p className="mt-1 font-mono text-[10px] text-zinc-500">{c.pattern}</p>
                  <p className="text-[10px] text-zinc-600">{c.note}</p>
                  {c.hits.length > 0 && (
                    <table className="mt-2 w-full min-w-[420px] text-left font-mono text-[11px]">
                      <thead className="text-zinc-600">
                        <tr>
                          <Th>RVA</Th>
                          <Th>VA (varsayilan base)</Th>
                          <Th>File Offset</Th>
                        </tr>
                      </thead>
                      <tbody className="text-zinc-300">
                        {c.hits.map((h, i) => (
                          <tr key={i}>
                            <Td>{h.rva}</Td>
                            <Td>{h.va}</Td>
                            <Td>{h.offset}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              ))}
            </TabsContent>
          )}

          {/* ---------- DEBUG ---------- */}
          {isPe && (r.pe?.debug || r.pe?.dataDirectories) && (
            <TabsContent value="debug" className="mt-4 space-y-4">
              {r.pe?.debug?.pdb && (
                <div className="rounded-lg border border-amber-800/40 bg-amber-950/10 p-3">
                  <p className="flex items-center gap-1.5 text-xs font-medium text-amber-300">
                    <Bug className="h-3.5 w-3.5" /> PDB (CODEVIEW) bilgisi
                  </p>
                  <p className="mt-2 break-all font-mono text-[11px] text-zinc-300">{r.pe.debug.pdb.path}</p>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    GUID: {r.pe.debug.pdb.guid} · Age: {r.pe.debug.pdb.age}
                  </p>
                  <p className="mt-2 text-[10px] leading-relaxed text-zinc-500">
                    Microsoft sembol sunucusu yolu:
                    <span className="mt-1 block break-all font-mono text-[10px] text-zinc-400">
                      {r.pe.debug.pdb.path.split(/[\\/]/).pop()}/{r.pe.debug.pdb.guid}
                      {r.pe.debug.pdb.age}/{r.pe.debug.pdb.path.split(/[\\/]/).pop()}
                    </span>
                  </p>
                </div>
              )}
              {(r.pe?.debug?.entries.length ?? 0) > 0 && (
                <div className="max-h-56 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                  <table className="w-full min-w-[520px] text-left text-xs">
                    <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                      <tr>
                        <Th>#</Th>
                        <Th>Tip</Th>
                        <Th>Boyut</Th>
                        <Th>RVA</Th>
                        <Th>Detay</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60">
                      {r.pe?.debug?.entries.map((e) => (
                        <tr key={e.index} className="text-zinc-300 hover:bg-zinc-800/40">
                          <Td mono>{e.index}</Td>
                          <Td>
                            <Badge variant="outline" className="border-zinc-700 text-[10px] text-amber-300">
                              {e.type}
                            </Badge>
                          </Td>
                          <Td mono>{e.size}</Td>
                          <Td mono>{hex(e.rva)}</Td>
                          <Td>
                            <span className="block max-w-[280px] truncate font-mono text-[10px] text-zinc-500" title={e.detail}>
                              {e.detail ?? "-"}
                            </span>
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {r.pe?.debug && (
                <div className="grid gap-3 sm:grid-cols-3">
                  <MiniStat
                    label="COFF sembol"
                    value={r.pe.debug.coffSymbols === 0 ? "YOK (stripped)" : String(r.pe.debug.coffSymbols)}
                  />
                  <MiniStat label="Reproducible" value={r.pe.debug.reproducible ? "evet" : "hayir"} />
                  <MiniStat label="PDB GUID" value={r.pe.debug.guid ? r.pe.debug.guid.slice(0, 16) + "..." : "-"} />
                </div>
              )}
              {r.pe?.versionInfo && Object.keys(r.pe.versionInfo).length > 0 && (
                <InfoBlock
                  title="Dosya versiyon bilgisi (VS_VERSIONINFO)"
                  items={Object.entries(r.pe.versionInfo)
                    .filter(([, v]) => !!v)
                    .map(([k, v]) => `${k}: ${v}`)}
                  mono
                />
              )}
              {(r.pe?.dataDirectories?.length ?? 0) > 0 && (
                <div className="max-h-56 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                  <table className="w-full min-w-[420px] text-left text-xs">
                    <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                      <tr>
                        <Th>Data dizini</Th>
                        <Th>RVA</Th>
                        <Th>Boyut</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 font-mono">
                      {r.pe?.dataDirectories?.map((d) => (
                        <tr key={d.name} className="text-zinc-300 hover:bg-zinc-800/40">
                          <Td>{d.name}</Td>
                          <Td>{hex(d.va)}</Td>
                          <Td>{hex(d.size)}</Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </TabsContent>
          )}

          {/* ---------- FONKSIYONLAR ---------- */}
          {r.functions && r.functions.total > 0 && (
            <TabsContent value="fonksiyonlar" className="mt-4 space-y-3">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <MiniStat label="Toplam" value={r.functions.total.toLocaleString("tr-TR")} />
                <MiniStat label="Kaynak" value={r.functions.source === "pdata" ? ".pdata (kesin)" : "heuristik"} />
                <MiniStat label="Referans analizi" value={String(r.functions.detailed)} />
                <MiniStat label="Decompile" value={`${r.functions.disassembled} fn`} />
              </div>
              <p className="text-[11px] leading-relaxed text-zinc-500">
                Fonksiyon sinirlari x64 .pdata tablosundan (kesin). Satira tiklayin:
                disassembly + tahmini pseudo-C acilir. Tam liste Functions.txt / Decompile.txt
                SDK ciktilarinda.
              </p>
              <div className="max-h-[420px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[680px] text-left text-xs">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>#</Th>
                      <Th>Ad</Th>
                      <Th>VA</Th>
                      <Th>Boyut</Th>
                      <Th>API/Dize</Th>
                      <Th>xref</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {r.functions.functions.map((f) => (
                      <tr
                        key={f.idx}
                        className={`cursor-pointer transition-colors hover:bg-emerald-600/5 ${f.asm ? "" : "opacity-70"}`}
                        onClick={() => f.asm && setDecompFn(f)}
                      >
                        <Td mono>{f.idx}</Td>
                        <Td>
                          <span className="font-mono text-[11px] text-emerald-300">
                            {f.label ?? `sub_${f.va.toString(16).toUpperCase()}`}
                          </span>
                          {f.structHint && (
                            <span
                              role="button"
                              tabIndex={0}
                              title="Structlar sekmesinde ac"
                              onClick={(ev) => {
                                ev.stopPropagation();
                                setTabValue("structlar");
                              }}
                              onKeyDown={(ev) => {
                                if (ev.key === "Enter" || ev.key === " ") {
                                  ev.preventDefault();
                                  ev.stopPropagation();
                                  setTabValue("structlar");
                                }
                              }}
                              className="ml-2 inline-flex h-4 cursor-pointer items-center rounded-full bg-amber-600/15 px-1.5 text-[10px] text-amber-300 transition-colors hover:bg-amber-600/25"
                            >
                              {f.structHint}
                            </span>
                          )}
                        </Td>
                        <Td mono>{hex(f.va)}</Td>
                        <Td mono>{f.size}</Td>
                        <Td>
                          <span className="block max-w-[220px] truncate text-[10px] text-zinc-500">
                            {[...f.apiCalls.slice(0, 2), ...f.strings.slice(0, 1).map((s) => `"${s.slice(0, 24)}"`)].join(", ") || "-"}
                          </span>
                        </Td>
                        <Td mono>
                          {f.xrefsIn > 0 ? (
                            <Badge variant="outline" className="border-emerald-800/60 text-[10px] text-emerald-300">
                              {f.xrefsIn} gelis
                            </Badge>
                          ) : (
                            <span className="text-zinc-600">-</span>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {r.functions.total > r.functions.functions.length && (
                <p className="text-[10px] text-zinc-500">
                  +{r.functions.total - r.functions.functions.length} fonksiyon gizlendi - tam liste Functions.txt ciktisinda
                </p>
              )}
            </TabsContent>
          )}

          {/* ---------- STRUCTLAR ---------- */}
          {r.structs && r.structs.total > 0 && (
            <TabsContent value="structlar" className="mt-4 space-y-3">
              <p className="text-[11px] leading-relaxed text-zinc-500">
                Kod erisimi + RTTI ile kurtarilan structlar (tahminsel: alan turleri genislige gore).
                Dumper-7 stilinde UnknownData dolgulariyla {r.sdk ? "SDK ciktisinda" : "structs.h"} yazilir.
              </p>
              <div className="space-y-2">
                {r.structs.structs.map((s) => {
                  const vftRva = s.vftableRva;
                  return (
                    <Accordion key={s.name} type="single" collapsible>
                      <AccordionItem value={s.name} className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-4">
                        <AccordionTrigger className="py-3 text-xs text-zinc-200 hover:text-emerald-300">
                          <span className="flex flex-wrap items-center gap-2">
                            <Table2 className="h-3.5 w-3.5 text-emerald-500" />
                            <span className="font-mono">{s.kind === "class" ? "class" : "struct"} {s.name}</span>
                            {s.base && <span className="text-[10px] text-zinc-500">: {s.base}</span>}
                            {s.size && <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">~{hex(s.size)}</Badge>}
                            <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">{sourceLabel(s.source)}</Badge>
                            {vftRva !== undefined && (
                              <span
                                role="button"
                                tabIndex={0}
                                title="Hex gorunumunde ac"
                                onClick={(ev) => {
                                  ev.stopPropagation();
                                  setTabValue("hex");
                                  setHexJump({ off: vftableFileOffset(vftRva), nonce: Date.now() });
                                }}
                                onKeyDown={(ev) => {
                                  if (ev.key === "Enter" || ev.key === " ") {
                                    ev.preventDefault();
                                    ev.stopPropagation();
                                    setTabValue("hex");
                                    setHexJump({ off: vftableFileOffset(vftRva), nonce: Date.now() });
                                  }
                                }}
                                className="inline-flex cursor-pointer items-center rounded-md border border-emerald-800/60 px-1.5 py-0.5 text-[10px] text-emerald-300 transition-colors hover:bg-emerald-600/10"
                              >
                                vftable {hex(s.vftableVa ?? vftRva)}
                              </span>
                            )}
                          </span>
                        </AccordionTrigger>
                        <AccordionContent className="pb-3">
                          <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 scrollbar-thin">
                            <table className="w-full min-w-[420px] text-left font-mono text-[11px]">
                              <thead className="text-zinc-600">
                                <tr>
                                  <Th>Ofset</Th>
                                  <Th>Tip</Th>
                                  <Th>Alan</Th>
                                  <Th>Erisim</Th>
                                </tr>
                              </thead>
                              <tbody className="text-zinc-300">
                                {s.fields.map((fld) => (
                                  <tr key={fld.name}>
                                    <Td mono>+{hex(fld.offset)}</Td>
                                    <Td mono>{fld.type}</Td>
                                    <Td mono>{fld.name}</Td>
                                    <Td mono>{fld.reads} fn</Td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            {vftRva !== undefined && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 border-emerald-800/60 px-2 text-[10px] text-emerald-300 hover:bg-emerald-600/10"
                                title="Hex gorunumunde ac"
                                onClick={() => {
                                  setTabValue("hex");
                                  setHexJump({ off: vftableFileOffset(vftRva), nonce: Date.now() });
                                }}
                              >
                                <Hash className="mr-1 h-3 w-3" />
                                vftable {hex(s.vftableVa ?? vftRva)} - Hex&apos;te ac
                              </Button>
                            )}
                            {sdkStructTarget && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 border-emerald-800/60 px-2 text-[10px] text-emerald-300 hover:bg-emerald-600/10"
                                title="SDK dosyasinda ac"
                                onClick={() => setViewerFile({ ...sdkStructTarget, query: s.name })}
                              >
                                <FileCode2 className="mr-1 h-3 w-3" />
                                SDK&apos;de ac
                              </Button>
                            )}
                            {s.methodCount > 0 && (
                              <p className="text-[10px] text-zinc-500">{s.methodCount} metod (vftable&apos;dan)</p>
                            )}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  );
                })}
              </div>
            </TabsContent>
          )}

          {/* ---------- ENUMLAR ---------- */}
          {r.enums && r.enums.total > 0 && (
            <TabsContent value="enumlar" className="mt-4 space-y-3">
              <p className="text-[11px] leading-relaxed text-zinc-500">{r.enums.note}</p>
              <div className="grid gap-2 lg:grid-cols-2">
                {r.enums.enums.slice(0, 100).map((e) => (
                  <div key={e.name} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-amber-300">enum {e.name}</span>
                      <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">{sourceLabel(e.source)}</Badge>
                    </div>
                    {e.members.length > 0 ? (
                      <div className="mt-2 max-h-32 overflow-y-auto font-mono text-[11px] text-zinc-400 scrollbar-thin">
                        {e.members.map((m) => (
                          <p key={m.name}>
                            {m.name} = {m.value}
                          </p>
                        ))}
                      </div>
                    ) : (
                      <p className="mt-1 text-[10px] text-zinc-500">{e.note ?? "ad kurtarildi, deger yok"}</p>
                    )}
                  </div>
                ))}
              </div>
            </TabsContent>
          )}

          {/* ---------- IL2CPP ---------- */}
          {r.il2cpp && (
            <TabsContent value="il2cpp" className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <MiniStat label="Metadata surumu" value={`v${r.il2cpp.version}`} />
                <MiniStat label="Unity" value={r.il2cpp.unityHint} />
                <MiniStat label="Sinif" value={r.il2cpp.classCount.toLocaleString("tr-TR")} />
                <MiniStat label="Metod" value={r.il2cpp.methodCount.toLocaleString("tr-TR")} />
                <MiniStat label="Alan" value={r.il2cpp.fieldCount.toLocaleString("tr-TR")} />
                <MiniStat label="String literal" value={r.il2cpp.literalCount.toLocaleString("tr-TR")} />
                <MiniStat label="Enum" value={String(r.il2cpp.enums.length)} />
                <MiniStat
                  label="Sanity"
                  value={r.il2cpp.sanityOk ? "gecerli" : "uyusmuyor"}
                  valueClass={r.il2cpp.sanityOk ? "text-emerald-300" : "text-red-300"}
                />
              </div>
              {r.il2cpp.images.length > 0 && <InfoBlock title="Imagelar (assembly)" items={r.il2cpp.images} mono />}
              {r.il2cpp.classes.length > 0 && (
                <div>
                  <p className="mb-2 text-xs font-medium text-zinc-400">
                    Siniflar (ilk {r.il2cpp.classes.length}, toplam {r.il2cpp.classCount.toLocaleString("tr-TR")})
                  </p>
                  <div className="max-h-[360px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                    <table className="w-full min-w-[520px] text-left text-xs">
                      <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                        <tr>
                          <Th>Ad</Th>
                          <Th>Namespace</Th>
                          <Th>Tip</Th>
                          <Th>Alan</Th>
                          <Th>Metod</Th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60">
                        {r.il2cpp.classes.map((c, i) => (
                          <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                            <Td mono>{c.name}</Td>
                            <Td mono>{c.namespace || "-"}</Td>
                            <Td>{c.kind}</Td>
                            <Td mono>{c.fieldCount}</Td>
                            <Td mono>{c.methodCount}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {r.il2cpp.enums.length > 0 && (
                <div>
                  <p className="mb-2 text-xs font-medium text-zinc-400">Enumlar (degerlerle)</p>
                  <div className="grid gap-2 lg:grid-cols-2">
                    {r.il2cpp.enums.slice(0, 60).map((e, i) => (
                      <div key={i} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
                        <p className="font-mono text-xs text-amber-300">
                          {e.namespace ? `${e.namespace}.` : ""}
                          {e.name}
                        </p>
                        <div className="mt-1 max-h-28 overflow-y-auto font-mono text-[11px] text-zinc-400 scrollbar-thin">
                          {e.members.map((m, j) => (
                            <p key={j}>
                              {m.name} = {m.value ?? "?"}
                            </p>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {r.il2cpp.literalSamples.length > 0 && (
                <InfoBlock title="String literal ornekleri" items={r.il2cpp.literalSamples.slice(0, 30)} mono />
              )}
              {r.il2cppBin && (
                <div className="border-t border-zinc-800 pt-4">
                  <Il2CppBinaryCard uploadId={detail.upload.id} bin={r.il2cppBin} sdkFiles={r.sdk?.files ?? []} />
                </div>
              )}
            </TabsContent>
          )}

          {/* ---------- IL2CPP BINARY ---------- */}
          {!r.il2cpp && r.il2cppBin && (
            <TabsContent value="il2cppbin" className="mt-4">
              <Il2CppBinaryCard uploadId={detail.upload.id} bin={r.il2cppBin} sdkFiles={r.sdk?.files ?? []} />
            </TabsContent>
          )}

          {/* ---------- SDK ---------- */}
          {r.sdk && r.sdk.files.length > 0 && (
            <TabsContent value="sdk" className="mt-4 space-y-3">
              <div className="rounded-lg border border-emerald-800/40 bg-emerald-950/10 p-3">
                <p className="flex items-center gap-1.5 text-xs font-medium text-emerald-300">
                  <FileCode2 className="h-3.5 w-3.5" /> {r.sdk.generator}
                </p>
                <p className="mt-1 text-[10px] text-zinc-500">{r.sdk.note}</p>
              </div>
              <div className="max-h-[420px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[520px] text-left text-xs">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>Dosya</Th>
                      <Th>Tip</Th>
                      <Th>Boyut</Th>
                      <Th />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {sdkGroups.map((g) => (
                      <Fragment key={g.id}>
                        <tr className="bg-zinc-950/80">
                          <td colSpan={4} className="px-3 py-1.5">
                            {g.available === false ? (
                              <span className="text-[11px] font-medium text-zinc-500">
                                {g.label} ({g.files.length} dosya)
                              </span>
                            ) : (
                              <span className="flex items-center gap-2 text-[11px] font-medium text-emerald-400">
                                <Layers className="h-3 w-3" />
                                {g.label} ({g.files.length} dosya)
                              </span>
                            )}
                          </td>
                        </tr>
                        {g.files.map((f) => (
                          <tr key={f.name} className="text-zinc-300 hover:bg-zinc-800/40">
                            <Td mono>
                              <span className="block max-w-[280px] truncate" title={f.name}>
                                {f.name}
                              </span>
                            </Td>
                            <Td>{f.kind}</Td>
                            <Td>{formatBytes(f.size)}</Td>
                            <Td>
                              <div className="flex items-center gap-1.5">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-7 border-emerald-700/50 px-2 text-[11px] text-emerald-300 hover:bg-emerald-600/10"
                                  onClick={() => setViewerFile({ name: f.name, size: f.size })}
                                >
                                  Goster
                                </Button>
                                <a href={`/api/uploads/${detail.upload.id}/sdk/${encodeURIComponent(f.name)}`} download>
                                  <Button size="sm" variant="outline" className="h-7 border-zinc-700 px-2 text-[11px] text-zinc-300 hover:bg-zinc-800">
                                    <Download className="mr-1 h-3 w-3" />
                                    Indir
                                  </Button>
                                </a>
                              </div>
                            </Td>
                          </tr>
                        ))}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </TabsContent>
          )}

          {/* ---------- CIKARICILAR ---------- */}
          {r.extractors && (
            <TabsContent value="cikaricilar" className="mt-4">
              <ExtractorsTab uploadId={detail.upload.id} info={r.extractors} onOpenFile={openSdkFile} />
            </TabsContent>
          )}

          {/* ---------- DIZELER ---------- */}
          <TabsContent value="dizeler" className="mt-4">
            {r.strings.length === 0 ? (
              <p className="py-8 text-center text-xs text-zinc-500">Ilginç dize bulunamadi.</p>
            ) : (
              <div className="max-h-[420px] overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 scrollbar-thin">
                <div className="grid gap-x-4 gap-y-1 font-mono text-[11px] text-zinc-400 lg:grid-cols-2">
                  {r.strings.map((s, i) => (
                    <div key={i} className="flex items-center gap-2" title={`${s.value} (${s.kind === "utf16" ? "UTF-16LE" : "ASCII"})`}>
                      <Badge
                        variant="outline"
                        className={`shrink-0 px-1.5 py-0 text-[9px] ${s.kind === "utf16" ? "border-violet-700/60 text-violet-300" : "border-zinc-700 text-zinc-500"}`}
                      >
                        {s.kind === "utf16" ? "W" : "A"}
                      </Badge>
                      <span className="truncate">{s.value}</span>
                    </div>
                  ))}
                </div>
                <p className="mt-2 text-[10px] text-zinc-600">W = UTF-16LE (genis), A = ASCII (tek bayt)</p>
              </div>
            )}
          </TabsContent>

          {/* ---------- KOD URETICI ---------- */}
          <TabsContent value="kod" className="mt-4">
            <CodegenTab uploadId={detail.upload.id} result={r} />
          </TabsContent>

          {/* ---------- SAVE EDITOR ---------- */}
          {(r.savegame || r.vdf) && (
            <TabsContent value="save" className="mt-4">
              <SaveEditorTab uploadId={detail.upload.id} isVdf={r.kind === "vdf"} />
            </TabsContent>
          )}

          {/* ---------- RAPOR ---------- */}
          <TabsContent value="rapor" className="mt-4">
            <pre className="max-h-[480px] overflow-auto rounded-lg border border-zinc-800 bg-zinc-950/80 p-4 text-[11px] leading-relaxed text-zinc-300 scrollbar-thin">
              {detail.analysis?.report}
            </pre>
            <div className="mt-3 flex gap-2">
              <a href={`/api/uploads/${detail.upload.id}/report?format=txt`} download>
                <Button size="sm" className="bg-emerald-600 text-zinc-950 hover:bg-emerald-500">
                  <Download className="mr-1.5 h-3.5 w-3.5" />
                  TXT indir
                </Button>
              </a>
              <a href={`/api/uploads/${detail.upload.id}/report?format=json`} download>
                <Button size="sm" variant="outline" className="border-zinc-700 text-zinc-300 hover:bg-zinc-800">
                  <Download className="mr-1.5 h-3.5 w-3.5" />
                  JSON indir
                </Button>
              </a>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>

      {/* fonksiyon decompile iletisim kutusu */}
      <Dialog open={decompFn !== null} onOpenChange={(o) => !o && setDecompFn(null)}>
        <DialogContent className="max-h-[85vh] overflow-hidden border-zinc-800 bg-zinc-950 sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex flex-wrap items-center gap-2 text-sm text-zinc-100">
              <Braces className="h-4 w-4 text-emerald-400" />
              <span className="font-mono">{decompFn?.label ?? `sub_${decompFn?.va.toString(16).toUpperCase()}`}</span>
              {decompFn?.va ? <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">VA {hex(decompFn.va)}</Badge> : null}
              {decompFn?.size ? <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">{decompFn.size} bayt</Badge> : null}
              {decompFn?.structHint && <Badge className="bg-amber-600/15 text-[10px] text-amber-300">{decompFn.structHint}</Badge>}
            </DialogTitle>
          </DialogHeader>
          <ScrollArea className="max-h-[62vh] pr-3">
            {decompFn?.pseudo && (
              <div className="mb-3">
                <p className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-amber-400">
                  Tahmini pseudo-C (yaklasik)
                </p>
                <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 font-mono text-[11px] leading-relaxed text-emerald-100 scrollbar-thin">
                  {decompFn.pseudo}
                </pre>
              </div>
            )}
            {decompFn?.asm && (
              <div>
                <p className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                  Disassembly (x86-64)
                </p>
                <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 scrollbar-thin">
                  {decompFn.asm}
                </pre>
              </div>
            )}
          </ScrollArea>
          {decompFn && (
            <div className="flex justify-end gap-2">
              <Button
                size="sm"
                variant="outline"
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                onClick={() => onCopy([decompFn.pseudo, decompFn.asm].filter(Boolean).join("\n\n"), "Fonksiyon ciktisi")}
              >
                <Copy className="mr-1.5 h-3.5 w-3.5" />
                Kopyala
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* SDK canli goruntuleyici (sdk / cikaricilar / structlar sekmelerinden acilir) */}
      <SdkViewerDialog
        uploadId={detail.upload.id}
        file={viewerFile}
        open={viewerFile !== null}
        onClose={closeViewer}
      />
    </Card>
  );
}

// ------------------------------- mikro parcalar ------------------------------

type FunctionRow = NonNullable<AnalysisResultShape["functions"]>["functions"][number];

function MiniStat({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-3">
      <p className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</p>
      <p className={`mt-1 truncate text-sm font-semibold ${valueClass ?? "text-zinc-100"}`} title={value}>
        {value}
      </p>
    </div>
  );
}

function InfoBlock({ title, items, mono }: { title: string; items: string[]; mono?: boolean }) {
  return (
    <div>
      <p className="mb-2 text-xs font-medium text-zinc-400">{title}</p>
      <div className="max-h-44 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 scrollbar-thin">
        <ul className={`space-y-0.5 text-[11px] text-zinc-400 ${mono ? "font-mono" : ""}`}>
          {items.map((it, i) => (
            <li key={i} className="break-all">
              {it}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Th({ children }: { children?: React.ReactNode }) {
  return <th className="px-3 py-2 font-medium">{children}</th>;
}

function Td({ children, mono, className }: { children?: React.ReactNode; mono?: boolean; className?: string }) {
  return (
    <td className={`px-3 py-1.5 ${mono ? "font-mono text-[11px]" : ""} ${className ?? ""}`}>{children}</td>
  );
}

// ----------------------------------------------------------------------------
// yeni sekmeler: hex / oyun dosyalari / bellek / il2cpp binary
// ----------------------------------------------------------------------------

interface HexViewResponse {
  ok: boolean;
  size: number;
  off: number;
  len: number;
  rows: { off: number; hex: string[]; ascii: string }[];
  rva?: string;
  va?: string;
  patchCount: number;
  patches: { off: number; bytes: number[]; orig: number[] }[];
}

interface HexSearchResponse {
  ok: boolean;
  total: number;
  truncated?: boolean;
  matches: { off: number; rva?: number; hex: string }[];
  error?: string;
}

interface MemSearchResponse {
  ok: boolean;
  total: number;
  matches: { va: number; hex: string; module?: string; rva?: number }[];
  error?: string;
}

// tipli deger yorumlama cevabi (POST action:"decode")
interface HexDecodeResponse {
  ok: boolean;
  type: string;
  typeLabel?: string;
  off: number;
  size: number;
  bitIndex?: number;
  values: { off: number; hex: string; value: string; note?: string; error?: string }[];
  error?: string;
}

/** gruptan tip secici (HexTab + MemTab ortak) */
function DataTypeSelect({ value, onChange, ariaLabel, className }: {
  value: string;
  onChange: (t: string) => void;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label={ariaLabel} className={`h-9 w-[190px] border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200 ${className ?? ""}`}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="max-h-80 border-zinc-800 bg-zinc-950 text-zinc-200">
        {DATA_TYPE_GROUPS.map((g) => (
          <SelectGroup key={g.label}>
            <SelectLabel className="text-[10px] uppercase tracking-wide text-zinc-500">{g.label}</SelectLabel>
            {g.types.map((t) => (
              <SelectItem key={t} value={t} className="font-mono text-xs focus:bg-zinc-800">
                {t}
              </SelectItem>
            ))}
          </SelectGroup>
        ))}
      </SelectContent>
    </Select>
  );
}

function hex2(b: number): string {
  return b.toString(16).padStart(2, "0");
}

// "0x1A2B" -> hex, "1A2B" -> hex harf iceriyorsa, "6699" -> desimal
function parseOffsetInput(text: string): number | null {
  const t = text.trim();
  if (!t) return null;
  const n = /^0x/i.test(t)
    ? parseInt(t.slice(2), 16)
    : /^[0-9a-f]+$/i.test(t) && /[a-f]/i.test(t)
      ? parseInt(t, 16)
      : parseInt(t, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function mbFmt(n: number): string {
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const HEX_WINDOW = 512;

function HexTab({ uploadId, onRefreshHistory, jump }: { uploadId: string; onRefreshHistory: () => void; jump?: { off: number; nonce: number } | null }) {
  const { toast } = useToast();
  const [offInput, setOffInput] = useState("0x0");
  const [view, setView] = useState<HexViewResponse | null>(null);
  const [loading, setLoading] = useState(false);
  // bekleyen yerel duzenlemeler: mutlak ofset -> yeni byte
  const [pending, setPending] = useState<Record<number, number>>({});
  const [editCell, setEditCell] = useState<number | null>(null);
  const [editValue, setEditValue] = useState("");
  const [patching, setPatching] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [aob, setAob] = useState("");
  const [aobRes, setAobRes] = useState<HexSearchResponse | null>(null);
  const [aobLoading, setAobLoading] = useState(false);
  // --- tip yorumlama (byte -> deger) ---
  const [decType, setDecType] = useState("u32");
  const [decOff, setDecOff] = useState("");
  const [decCount, setDecCount] = useState("16");
  const [decBit, setDecBit] = useState("0");
  const [decRes, setDecRes] = useState<HexDecodeResponse | null>(null);
  const [decLoading, setDecLoading] = useState(false);
  // --- tipli deger arama ---
  const [valType, setValType] = useState("i32");
  const [valInput, setValInput] = useState("");
  const [valRes, setValRes] = useState<HexSearchResponse | null>(null);
  const [valEncoded, setValEncoded] = useState<string | undefined>(undefined);
  const [valLoading, setValLoading] = useState(false);

  const fetchView = useCallback(
    async (target: number) => {
      setLoading(true);
      try {
        const res = await fetch(`/api/uploads/${uploadId}/hex?off=${Math.max(0, Math.floor(target))}&len=${HEX_WINDOW}`, {
          cache: "no-store",
        });
        const data = (await res.json()) as HexViewResponse;
        if (data.ok) {
          setView(data);
          setOffInput(`0x${data.off.toString(16).toUpperCase()}`);
        } else {
          toast({ title: "Hex gorunumu alinamadi", variant: "destructive" });
        }
      } catch {
        toast({ title: "Hex gorunumu alinamadi", variant: "destructive" });
      } finally {
        setLoading(false);
      }
    },
    [uploadId, toast],
  );

  // gorunum: ilk mount'ta jump varsa ona git (0'la yarismasin), yoksa 0'dan basla;
  // sonraki jump nonce degisikliklerinde yeniden yukle
  useEffect(() => {
    void fetchView(jump?.off ?? 0);
  }, [jump, fetchView]);

  // dosyanin ham baytlari (eski deger gosterimi icin)
  const fileBytes = useMemo(() => {
    const m: Record<number, number> = {};
    for (const row of view?.rows ?? []) {
      row.hex.forEach((h, i) => {
        if (h !== "  ") m[row.off + i] = parseInt(h, 16);
      });
    }
    return m;
  }, [view]);

  // sunucudaki uygulanmis yamalar (offset -> byte)
  const serverPatches = useMemo(() => {
    const m: Record<number, number> = {};
    for (const p of view?.patches ?? []) {
      p.bytes.forEach((b, i) => {
        m[p.off + i] = b;
      });
    }
    return m;
  }, [view]);

  const pendingCount = Object.keys(pending).length;

  const commitEdit = (abs: number) => {
    setEditCell(null);
    const t = editValue.trim().replace(/^0x/i, "");
    const val = parseInt(t, 16);
    if (!t || !Number.isFinite(val) || val < 0 || val > 0xff) {
      setEditValue("");
      return;
    }
    const b = val & 0xff;
    setPending((p) => {
      const next = { ...p };
      if (fileBytes[abs] === b) delete next[abs];
      else next[abs] = b;
      return next;
    });
    setEditValue("");
  };

  const applyPending = async () => {
    const entries = Object.entries(pending);
    if (entries.length === 0) {
      toast({ title: "Bekleyen yama yok", description: "Once bir byte hucreye tiklayip duzenleyin." });
      return;
    }
    setPatching(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/hex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "patch", patches: entries.map(([o, b]) => ({ off: Number(o), bytes: [b] })) }),
      });
      const data = (await res.json()) as { ok: boolean; applied?: number; totalPatches?: number; error?: string };
      if (!data.ok) {
        toast({ title: "Yama uygulanamadi", description: data.error, variant: "destructive" });
        return;
      }
      toast({ title: "Yama uygulandi", description: `${data.applied ?? 0} byte yazildi (toplam ${data.totalPatches ?? 0} yama)` });
      setPending({});
      await fetchView(view?.off ?? 0);
    } catch {
      toast({ title: "Yama hatasi", variant: "destructive" });
    } finally {
      setPatching(false);
    }
  };

  const savePatched = async () => {
    setSaving(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/hex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "save", name: saveName.trim() || undefined }),
      });
      const data = (await res.json()) as { ok: boolean; id?: string; patches?: number; kind?: string; error?: string };
      if (!data.ok || !data.id) {
        toast({ title: "Yamali kopya kaydedilemedi", description: data.error, variant: "destructive" });
        return;
      }
      toast({
        title: "Yamali kopya kaydedildi ve analiz edildi",
        description: `${data.id} - ${data.patches ?? 0} yama (${data.kind ?? "-"})`,
      });
      setSaveName("");
      onRefreshHistory();
    } catch {
      toast({ title: "Yamali kopya kaydedilemedi", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const runAob = async () => {
    if (!aob.trim()) return;
    setAobLoading(true);
    setAobRes(null);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/hex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "search", pattern: aob }),
      });
      const data = (await res.json()) as HexSearchResponse;
      if (!data.ok) {
        toast({ title: "AOB arama basarisiz", description: data.error, variant: "destructive" });
        return;
      }
      setAobRes(data);
    } catch {
      toast({ title: "AOB arama hatasi", variant: "destructive" });
    } finally {
      setAobLoading(false);
    }
  };

  const goOffset = () => {
    const n = parseOffsetInput(offInput);
    if (n === null) {
      toast({ title: "Gecersiz offset", description: "0x1A2B, 1A2B ya da desimal girin.", variant: "destructive" });
      return;
    }
    void fetchView(n);
  };

  // --- tip yorumla: ofsetten itibaren N adet degeri tipli oku ---
  const runDecode = async () => {
    const n = parseOffsetInput(decOff) ?? view?.off ?? 0;
    const count = Math.max(1, Math.min(256, parseInt(decCount, 10) || 16));
    const bitIndex = Math.max(0, Math.min(7, parseInt(decBit, 10) || 0));
    setDecLoading(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/hex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "decode", off: n, type: decType, count, bitIndex }),
      });
      const data = (await res.json()) as HexDecodeResponse;
      if (!data.ok) {
        toast({ title: "Tip yorumlanamadi", description: data.error, variant: "destructive" });
        return;
      }
      setDecRes(data);
    } catch {
      toast({ title: "Tip yorumlama hatasi", variant: "destructive" });
    } finally {
      setDecLoading(false);
    }
  };

  // --- tipli deger arama: "3.14" (f32), "1337" (i32), "true" (bool), ... ---
  const runValueSearch = async () => {
    if (!valInput.trim()) return;
    setValLoading(true);
    setValRes(null);
    setValEncoded(undefined);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/hex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "search", type: valType, value: valInput }),
      });
      const data = (await res.json()) as HexSearchResponse & { encoded?: string };
      if (!data.ok) {
        toast({ title: "Deger arama basarisiz", description: data.error, variant: "destructive" });
        return;
      }
      setValRes(data);
      setValEncoded(data.encoded);
    } catch {
      toast({ title: "Deger arama hatasi", variant: "destructive" });
    } finally {
      setValLoading(false);
    }
  };

  const navBtn = "h-9 w-9 border-zinc-700 text-zinc-300 hover:bg-zinc-800";

  return (
    <div className="space-y-4">
      {/* gezinme satiri */}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="icon" variant="outline" aria-label="Basa git" disabled={!view || loading} onClick={() => void fetchView(0)} className={navBtn}>
          <ChevronsLeft className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="outline" aria-label="Onceki pencere" disabled={!view || loading || view.off === 0} onClick={() => view && void fetchView(view.off - HEX_WINDOW)} className={navBtn}>
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="outline" aria-label="Sonraki pencere" disabled={!view || loading || view.off + view.len >= view.size} onClick={() => view && void fetchView(view.off + HEX_WINDOW)} className={navBtn}>
          <ChevronRight className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="outline" aria-label="Sona git" disabled={!view || loading || view.size === 0} onClick={() => view && void fetchView(Math.max(0, view.size - HEX_WINDOW))} className={navBtn}>
          <ChevronsRight className="h-4 w-4" />
        </Button>
        <Input
          value={offInput}
          onChange={(e) => setOffInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") goOffset();
          }}
          aria-label="Offset (hex veya desimal)"
          className="h-9 w-40 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
        />
        <Button variant="outline" className="h-9 border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800" onClick={goOffset}>
          Git
        </Button>
        {view?.rva && <Badge variant="outline" className="border-emerald-800/60 text-[10px] text-emerald-300">RVA {view.rva}</Badge>}
        {view?.va && <Badge variant="outline" className="border-emerald-800/60 text-[10px] text-emerald-300">VA {view.va}</Badge>}
        {loading && <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />}
        {view && <span className="font-mono text-[10px] text-zinc-500">dosya {formatBytes(view.size)} · pencere {HEX_WINDOW} B</span>}
      </div>

      {/* hex grid */}
      {!view && loading ? (
        <div className="space-y-1.5 rounded-lg border border-zinc-800 p-3">
          {Array.from({ length: 10 }).map((_, i) => (
            <Skeleton key={i} className="h-5 w-full bg-zinc-800/60" />
          ))}
        </div>
      ) : view ? (
        <div className="max-h-[480px] overflow-auto rounded-lg border border-zinc-800 scrollbar-thin">
          <table className="w-full min-w-[820px] border-collapse font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-zinc-950/90 text-zinc-500">
              <tr>
                <th className="px-2 py-1.5 text-left font-medium">Offset</th>
                <th colSpan={16} className="px-2 py-1.5 text-left font-medium">
                  Bytes (tikla + duzenle)
                </th>
                <th className="px-3 py-1.5 text-left font-medium">ASCII</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {view.rows.map((row) => (
                <tr key={row.off} className="hover:bg-zinc-800/30">
                  <td className="select-none px-2 py-0.5 text-zinc-600">{hex(row.off)}</td>
                  {row.hex.map((h, i) => {
                    const abs = row.off + i;
                    const isGap = h === "  ";
                    const pend = pending[abs];
                    const applied = serverPatches[abs];
                    const shown = pend !== undefined ? hex2(pend) : applied !== undefined ? hex2(applied) : h;
                    const cellCls =
                      pend !== undefined
                        ? "bg-amber-500/15 text-amber-300"
                        : applied !== undefined
                          ? "bg-emerald-600/15 text-emerald-300"
                          : "text-zinc-300";
                    return (
                      <td key={i} className="p-0">
                        {editCell === abs ? (
                          <input
                            autoFocus
                            value={editValue}
                            onChange={(e) => setEditValue(e.target.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 2))}
                            onBlur={() => commitEdit(abs)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") commitEdit(abs);
                              if (e.key === "Escape") setEditCell(null);
                            }}
                            aria-label={`${hex(abs)} yeni byte`}
                            className="h-6 w-9 rounded border border-emerald-600/60 bg-zinc-950 text-center font-mono text-xs text-emerald-300 outline-none"
                          />
                        ) : isGap ? (
                          <span className="block h-6 w-9" />
                        ) : (
                          <button
                            type="button"
                            title={hex(abs)}
                            onClick={() => {
                              setEditCell(abs);
                              setEditValue(shown);
                            }}
                            className={`h-6 w-9 rounded text-center font-mono text-xs transition-colors hover:bg-accent ${cellCls}`}
                          >
                            {shown}
                          </button>
                        )}
                      </td>
                    );
                  })}
                  <td className="select-none px-3 py-0.5 text-zinc-500">{row.ascii}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {/* tip yorumlama (byte -> deger) */}
      <div className="rounded-lg border border-zinc-800 p-3">
        <p className="mb-2 text-xs font-medium text-zinc-400">
          Tip yorumla — baytlari secilen tip olarak oku (little-endian)
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <DataTypeSelect value={decType} onChange={setDecType} ariaLabel="Yorumlama tipi" />
          <Input
            value={decOff}
            onChange={(e) => setDecOff(e.target.value)}
            placeholder="ofset (bos = pencere basi)"
            aria-label="Yorumlama offset"
            className="h-9 w-44 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          {decType === "bit" && (
            <Input
              value={decBit}
              onChange={(e) => setDecBit(e.target.value.replace(/[^0-7]/g, "").slice(0, 1))}
              placeholder="bit 0-7"
              aria-label="Bit indeks"
              className="h-9 w-24 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
            />
          )}
          {decType !== "str" && decType !== "str16" && (
            <Input
              value={decCount}
              onChange={(e) => setDecCount(e.target.value.replace(/[^0-9]/g, "").slice(0, 3))}
              placeholder="adet"
              aria-label="Deger adedi"
              className="h-9 w-20 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
            />
          )}
          <Button
            variant="outline"
            disabled={decLoading}
            onClick={() => void runDecode()}
            className="h-9 border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800"
          >
            {decLoading ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Hash className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />}
            Yorumla
          </Button>
        </div>
        {decRes && decRes.values.length > 0 && (
          <div className="mt-3">
            <p className="mb-1.5 font-mono text-[10px] text-zinc-500">
              {decRes.type} ({decRes.typeLabel ?? decRes.type}) @ 0x{decRes.off.toString(16).toUpperCase()}
              {decRes.type === "bit" && ` bit ${decRes.bitIndex ?? 0}`}
            </p>
            <div className="max-h-56 overflow-y-auto rounded-md border border-zinc-800 scrollbar-thin">
              <table className="w-full min-w-[420px] text-left font-mono text-[11px]">
                <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                  <tr>
                    <Th>Offset</Th>
                    <Th>Baytlar</Th>
                    <Th>Deger</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
                  {decRes.values.map((v, i) => (
                    <tr
                      key={`${v.off}-${i}`}
                      className="cursor-pointer transition-colors hover:bg-emerald-600/5"
                      onClick={() => void fetchView(v.off)}
                    >
                      <Td mono>{hex(v.off)}</Td>
                      <Td mono className="text-zinc-500">{v.hex || "-"}</Td>
                      <Td mono className="text-emerald-300">
                        {v.error ? <span className="text-amber-300">({v.error})</span> : v.value}
                        {v.note && <span className="ml-2 text-[10px] text-zinc-600">{v.note}</span>}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-1 text-[10px] text-zinc-600">degere tiklayin, hex pencere o offsete gider</p>
          </div>
        )}
      </div>

      {/* bekleyen duzenlemeler + yama islemleri */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            disabled={pendingCount === 0 || patching}
            onClick={() => void applyPending()}
            className="h-9 bg-emerald-600 px-3 text-zinc-950 hover:bg-emerald-500"
          >
            {patching && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            Yamayi Uygula ({pendingCount})
          </Button>
          <Input
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            placeholder="yeni_adi.bin (opsiyonel)"
            aria-label="Yamali kopya adi"
            className="h-9 w-56 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          <Button
            variant="outline"
            disabled={saving}
            onClick={() => void savePatched()}
            className="h-9 border-emerald-700/50 bg-emerald-600/10 px-3 text-emerald-300 hover:bg-emerald-600/20"
          >
            {saving && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            Yamali Kopyayi Kaydet + Analiz Et
          </Button>
        </div>
        {pendingCount > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {Object.entries(pending)
              .slice(0, 8)
              .map(([o, b]) => (
                <Badge key={o} variant="outline" className="border-amber-600/50 font-mono text-[10px] text-amber-300">
                  {hex(Number(o))}: {hex2(fileBytes[Number(o)] ?? 0)}→{hex2(b)}
                </Badge>
              ))}
            {pendingCount > 8 && <span className="text-[10px] text-zinc-500">+{pendingCount - 8} daha</span>}
          </div>
        )}
      </div>

      {/* uygulanan yamalar */}
      {(view?.patches.length ?? 0) > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-zinc-400">Uygulanan yamalar ({view?.patchCount})</p>
          <div className="max-h-40 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
            <table className="w-full min-w-[360px] text-left font-mono text-[11px]">
              <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                <tr>
                  <Th>Offset</Th>
                  <Th>Eski</Th>
                  <Th>Yeni</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
                {(view?.patches ?? []).slice(0, 200).map((p) => (
                  <tr key={p.off}>
                    <Td mono>{hex(p.off)}</Td>
                    <Td mono>{p.orig.map(hex2).join(" ")}</Td>
                    <Td mono>
                      <span className="text-emerald-300">{p.bytes.map(hex2).join(" ")}</span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {view && view.patches.length > 200 && <p className="mt-1 text-[10px] text-zinc-500">+{view.patches.length - 200} yama gizlendi</p>}
        </div>
      )}

      {/* tipli deger arama */}
      <div>
        <p className="mb-2 text-xs font-medium text-zinc-400">Deger arama — tipli (little-endian)</p>
        <div className="flex flex-wrap items-center gap-2">
          <DataTypeSelect value={valType} onChange={setValType} ariaLabel="Arama tipi" />
          <Input
            value={valInput}
            onChange={(e) => setValInput(e.target.value)}
            placeholder={valType === "vec3" ? "1 2 3" : valType === "bool" ? "true / false" : valType === "str" ? "Metin..." : valType === "f32" || valType === "f64" ? "3.14" : "1337"}
            aria-label="Deger"
            onKeyDown={(e) => {
              if (e.key === "Enter") void runValueSearch();
            }}
            className="h-9 w-56 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          <Button
            variant="outline"
            disabled={valLoading || !valInput.trim()}
            onClick={() => void runValueSearch()}
            className="h-9 border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800"
          >
            {valLoading ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />}
            Degerde Ara
          </Button>
          {valEncoded && (
            <span className="font-mono text-[10px] text-zinc-600">desen: {valEncoded}</span>
          )}
        </div>
        {valRes && (
          <div className="mt-3">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
              <span>{valRes.total} eslesme</span>
              {valRes.truncated && (
                <Badge className="bg-amber-500/15 text-[10px] text-amber-300 ring-1 ring-amber-500/40">ilk 256 gosteriliyor</Badge>
              )}
            </div>
            {valRes.matches.length === 0 ? (
              <p className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs text-zinc-500">Eslesme bulunamadi.</p>
            ) : (
              <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[420px] text-left font-mono text-[11px]">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>Offset</Th>
                      <Th>RVA</Th>
                      <Th>Hex</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {valRes.matches.map((m, i) => (
                      <tr
                        key={i}
                        className="cursor-pointer text-zinc-300 transition-colors hover:bg-emerald-600/5"
                        onClick={() => void fetchView(m.off)}
                      >
                        <Td mono>{hex(m.off)}</Td>
                        <Td mono>{m.rva !== undefined ? hex(m.rva) : "-"}</Td>
                        <Td>
                          <span className="block max-w-[320px] truncate" title={m.hex}>
                            {m.hex}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* AOB arama */}
      <div>
        <p className="mb-2 text-xs font-medium text-zinc-400">AOB arama (joker: ?? veya *)</p>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={aob}
            onChange={(e) => setAob(e.target.value)}
            placeholder="48 8B ?? 89 40"
            aria-label="AOB desen"
            onKeyDown={(e) => {
              if (e.key === "Enter") void runAob();
            }}
            className="h-9 w-64 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          <Button variant="outline" disabled={aobLoading || !aob.trim()} onClick={() => void runAob()} className="h-9 border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800">
            {aobLoading ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />}
            Ara
          </Button>
        </div>
        {aobRes && (
          <div className="mt-3">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
              <span>{aobRes.total} eslesme</span>
              {aobRes.truncated && (
                <Badge className="bg-amber-500/15 text-[10px] text-amber-300 ring-1 ring-amber-500/40">ilk 256 gosteriliyor</Badge>
              )}
              <span className="text-[10px] text-zinc-600">eslesmeye tiklayin, hex pencere o offsete gider</span>
            </div>
            {aobRes.matches.length === 0 ? (
              <p className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs text-zinc-500">Eslesme bulunamadi.</p>
            ) : (
              <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[420px] text-left font-mono text-[11px]">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>Offset</Th>
                      <Th>RVA</Th>
                      <Th>Hex</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {aobRes.matches.map((m, i) => (
                      <tr
                        key={i}
                        className="cursor-pointer text-zinc-300 transition-colors hover:bg-emerald-600/5"
                        onClick={() => void fetchView(m.off)}
                      >
                        <Td mono>{hex(m.off)}</Td>
                        <Td mono>{m.rva !== undefined ? hex(m.rva) : "-"}</Td>
                        <Td>
                          <span className="block max-w-[320px] truncate" title={m.hex}>
                            {m.hex}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function GameFilesTab({ gameFiles }: { gameFiles: GameFilesInfo }) {
  const pak = gameFiles.pak;
  const utoc = gameFiles.utoc;
  const uasset = gameFiles.uasset;
  const macho = gameFiles.macho;

  return (
    <div className="space-y-4">
      {/* tur + durum rozetleri */}
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="border-emerald-800/60 text-emerald-300">
          {gameFiles.type.toUpperCase()}
        </Badge>
        {pak && (
          pak.encryptedIndex ? (
            <Badge className="bg-red-500/15 text-red-300 ring-1 ring-red-500/40">index sifreli</Badge>
          ) : (
            <Badge variant="outline" className="border-zinc-700 text-zinc-400">index sifresiz</Badge>
          )
        )}
        {macho && (
          <Badge variant="outline" className="border-zinc-700 text-zinc-400">{macho.format}</Badge>
        )}
      </div>

      {/* pak */}
      {pak && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <MiniStat label="PAK surumu" value={`v${pak.version}`} />
            <MiniStat label="Kayit" value={pak.entryCount.toLocaleString("tr-TR")} />
            <MiniStat label="Isimli kayit" value={pak.namedEntries.toLocaleString("tr-TR")} />
            <MiniStat label="Mount noktasi" value={pak.mountPoint ?? "-"} />
            <MiniStat label="Index" value={`${hex(pak.indexOffset)} · ${formatBytes(pak.indexSize)}`} />
          </div>
          {pak.compressionMethods.filter(Boolean).length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-zinc-500">Sikistirma:</span>
              {pak.compressionMethods.filter(Boolean).map((c) => (
                <Badge key={c} className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
                  {c}
                </Badge>
              ))}
            </div>
          )}
          <div>
            <p className="mb-2 text-xs font-medium text-zinc-400">Kayitlar (ilk {pak.entries.length})</p>
            <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
              <table className="w-full min-w-[640px] text-left text-xs">
                <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                  <tr>
                    <Th>Ad</Th>
                    <Th>Offset</Th>
                    <Th>Boyut</Th>
                    <Th>Yontem</Th>
                    <Th>Hash</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {pak.entries.map((e, i) => (
                    <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                      <Td mono>
                        {e.name ? (
                          <span className="break-all">{e.name}</span>
                        ) : (
                          <span className="text-[10px] italic text-zinc-600">hash-only</span>
                        )}
                      </Td>
                      <Td mono>{hex(e.offset)}</Td>
                      <Td>{formatBytes(e.size)}</Td>
                      <Td>
                        <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                          {e.method}
                        </Badge>
                      </Td>
                      <Td>
                        <span className="block max-w-[180px] truncate font-mono text-[10px] text-zinc-500" title={e.hash}>
                          {e.hash ?? "-"}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {pak.entryCount > pak.entries.length && (
              <p className="mt-1 text-[10px] text-zinc-500">+{pak.entryCount - pak.entries.length} kayit gizlendi</p>
            )}
          </div>
        </>
      )}

      {/* utoc */}
      {utoc && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MiniStat label="UTOC surumu" value={`v${utoc.version}`} />
            <MiniStat
              label="Kayit / Blok"
              value={`${utoc.entryCount.toLocaleString("tr-TR")} / ${utoc.blockEntryCount.toLocaleString("tr-TR")}`}
            />
            <MiniStat label="Partisyon" value={String(utoc.partitions)} />
            <MiniStat label="TOC baslik" value={hex(utoc.tocHeaderSize)} />
          </div>
          {utoc.compressionMethods.filter(Boolean).length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-zinc-500">Sikistirma:</span>
              {utoc.compressionMethods.filter(Boolean).map((c) => (
                <Badge key={c} className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
                  {c}
                </Badge>
              ))}
            </div>
          )}
          <div>
            <p className="mb-2 text-xs font-medium text-zinc-400">Chunk kayitlari (ilk {utoc.entries.length})</p>
            <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
              <table className="w-full min-w-[560px] text-left text-xs">
                <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                  <tr>
                    <Th>Chunk ID</Th>
                    <Th>Tip</Th>
                    <Th>Offset</Th>
                    <Th>Boyut</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 font-mono">
                  {utoc.entries.map((e, i) => (
                    <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                      <Td mono>{e.chunkId}</Td>
                      <Td>
                        <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                          {e.chunkType}
                        </Badge>
                      </Td>
                      <Td mono>{hex(e.offset)}</Td>
                      <Td mono>{formatBytes(e.size)}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* uasset / umap */}
      {uasset && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            <MiniStat
              label="Legacy surum"
              value={uasset.legacyVersion < 0 ? `${uasset.legacyVersion} (UE5 hizasi)` : String(uasset.legacyVersion)}
            />
            {uasset.ue4Version !== undefined && <MiniStat label="UE4 surum" value={String(uasset.ue4Version)} />}
            {uasset.ue5Version !== undefined && <MiniStat label="UE5 surum" value={String(uasset.ue5Version)} />}
            <MiniStat label="Licensee" value={String(uasset.licenseeVersion)} />
            {uasset.totalHeaderSize !== undefined && <MiniStat label="Header boyutu" value={hex(uasset.totalHeaderSize)} />}
            {uasset.packageFlags !== undefined && <MiniStat label="PackageFlags" value={hex(uasset.packageFlags)} />}
            <MiniStat label="Isim" value={uasset.nameCount.toLocaleString("tr-TR")} />
            {uasset.importCount !== undefined && <MiniStat label="Import" value={uasset.importCount.toLocaleString("tr-TR")} />}
            {uasset.exportCount !== undefined && <MiniStat label="Export" value={uasset.exportCount.toLocaleString("tr-TR")} />}
          </div>
          {uasset.note && <p className="text-[11px] leading-relaxed text-zinc-500">{uasset.note}</p>}
          {uasset.names.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-medium text-zinc-400">Isim tablosu ({uasset.names.length})</p>
              <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 scrollbar-thin">
                <div className="grid gap-x-4 gap-y-0.5 font-mono text-[11px] text-zinc-400 sm:grid-cols-2 lg:grid-cols-3">
                  {uasset.names.map((n, i) => (
                    <span key={i} className="truncate" title={n}>
                      {n}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* macho */}
      {macho && (
        <>
          {macho.archs.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              {macho.archs.map((a) => (
                <Badge key={`${a.cpu}-${a.offset}`} variant="outline" className="border-emerald-800/60 text-[10px] text-emerald-300">
                  {a.cpu} · {hex(a.offset)} · {formatBytes(a.size)}
                </Badge>
              ))}
            </div>
          )}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <MiniStat label="File tipi" value={macho.fileType} />
            <MiniStat label="Entry" value={macho.entry !== undefined ? hex(macho.entry) : "-"} />
            <MiniStat label="Load komut" value={String(macho.ncmds)} />
          </div>
          {macho.segments.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-medium text-zinc-400">Segmentler</p>
              <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[560px] text-left text-xs">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>Ad</Th>
                      <Th>VM addr</Th>
                      <Th>VM size</Th>
                      <Th>Dosya</Th>
                      <Th>Sect</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60 font-mono">
                    {macho.segments.map((s, i) => (
                      <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                        <Td mono>{s.name}</Td>
                        <Td mono>{hex(s.vmaddr)}</Td>
                        <Td mono>{hex(s.vmsize)}</Td>
                        <Td mono>{formatBytes(s.filesize)}</Td>
                        <Td mono>{s.nsects}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {macho.dylibs.length > 0 && <InfoBlock title={`Bagli dylibler (${macho.dylibs.length})`} items={macho.dylibs} mono />}
        </>
      )}

      {/* notlar - sade liste */}
      {gameFiles.notes.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-zinc-400">Notlar</p>
          <ul className="list-inside list-disc space-y-0.5 text-[11px] text-zinc-400">
            {gameFiles.notes.map((n, i) => (
              <li key={i} className="break-all">
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function MemTab({
  uploadId,
  mem,
  onRefreshHistory,
}: {
  uploadId: string;
  mem: MemInfo;
  onRefreshHistory: () => void;
}) {
  const { toast } = useToast();
  const [dumping, setDumping] = useState<number | null>(null);
  const [pattern, setPattern] = useState("");
  const [searching, setSearching] = useState(false);
  const [res, setRes] = useState<MemSearchResponse | null>(null);
  // tipli deger arama (int/float/bool/str/vec...)
  const [mType, setMType] = useState("i32");
  const [mValue, setMValue] = useState("");

  const dumpModule = async (base: number, name: string) => {
    setDumping(base);
    try {
      const resp = await fetch(`/api/uploads/${uploadId}/mem`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "dump", base }),
      });
      const data = (await resp.json()) as { ok: boolean; id?: string; name?: string; kind?: string; engine?: string; error?: string };
      if (!data.ok || !data.id) {
        toast({ title: "Modul kurtarilamadi", description: data.error, variant: "destructive" });
        return;
      }
      toast({
        title: "Modul kurtarildi ve analiz edildi",
        description: `${data.name ?? name} - ${data.id} (${data.engine ?? data.kind ?? "-"})`,
      });
      onRefreshHistory();
    } catch {
      toast({ title: "Modul kurtarma hatasi", variant: "destructive" });
    } finally {
      setDumping(null);
    }
  };

  const runSearch = async () => {
    if (!pattern.trim() && !mValue.trim()) return;
    setSearching(true);
    setRes(null);
    try {
      const body = mValue.trim()
        ? { action: "search", type: mType, value: mValue }
        : { action: "search", pattern };
      const resp = await fetch(`/api/uploads/${uploadId}/mem`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = (await resp.json()) as MemSearchResponse;
      if (!data.ok) {
        toast({ title: "Bellek aramasi basarisiz", description: data.error, variant: "destructive" });
        return;
      }
      setRes(data);
    } catch {
      toast({ title: "Bellek aramasi hatasi", variant: "destructive" });
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* ozet kartlar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <MiniStat label="Cihaz" value={mem.device} />
        <MiniStat label="Mimari" value={mem.arch} />
        <MiniStat label="OS" value={mem.os ?? "-"} />
        <MiniStat label="Toplam bellek" value={mbFmt(mem.totalMemoryBytes)} />
        <MiniStat label="Modul" value={mem.moduleCount.toLocaleString("tr-TR")} />
        <MiniStat label="Bolge" value={mem.regionCount.toLocaleString("tr-TR")} />
      </div>

      {/* modul tablosu */}
      {mem.modules.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-zinc-400">Moduller (ilk {mem.modules.length})</p>
          <div className="max-h-[420px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
            <table className="w-full min-w-[760px] text-left text-xs">
              <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                <tr>
                  <Th>Ad</Th>
                  <Th>Base</Th>
                  <Th>Boyut</Th>
                  <Th>Timestamp</Th>
                  <Th>Kapsama</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {mem.modules.map((m) => (
                  <tr key={`${m.name}-${m.base}`} className="text-zinc-300 hover:bg-zinc-800/40">
                    <Td mono>
                      <span className="break-all">{m.name}</span>
                      {m.note && <span className="block max-w-[240px] text-[10px] text-zinc-600">{m.note}</span>}
                    </Td>
                    <Td mono>{hex(m.base)}</Td>
                    <Td mono>{hex(m.size)}</Td>
                    <Td mono>{m.timestamp ?? "-"}</Td>
                    <Td>
                      <div className="flex items-center gap-2">
                        <Progress
                          value={Math.max(0, Math.min(100, m.recoveredRangePct))}
                          aria-label={`Kapsama ${m.recoveredRangePct}%`}
                          className="h-1.5 w-16 [&>div]:bg-emerald-500"
                        />
                        <span className="font-mono text-[10px] text-zinc-500">{m.recoveredRangePct}%</span>
                      </div>
                    </Td>
                    <Td>
                      {m.recoverable ? (
                        <div className="flex items-center gap-1.5">
                          <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
                            kurtarilabilir
                          </Badge>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={dumping !== null}
                            onClick={() => void dumpModule(m.base, m.name)}
                            className="h-8 border-emerald-700/50 px-2.5 text-[11px] text-emerald-300 hover:bg-emerald-600/10"
                          >
                            {dumping === m.base ? <Loader2 className="h-3 w-3 animate-spin" /> : "Dump & Analiz"}
                          </Button>
                        </div>
                      ) : (
                        <span className="text-zinc-600">-</span>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {mem.moduleCount > mem.modules.length && (
            <p className="mt-1 text-[10px] text-zinc-500">+{mem.moduleCount - mem.modules.length} modul gizlendi</p>
          )}
        </div>
      )}

      {/* bolge tablosu */}
      {mem.regions.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-zinc-400">Bellek bolgeleri (ilk {mem.regions.length})</p>
          <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
            <table className="w-full min-w-[680px] text-left text-xs">
              <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                <tr>
                  <Th>Aralik</Th>
                  <Th>Koruma</Th>
                  <Th>Durum</Th>
                  <Th>Tip</Th>
                  <Th>Dosya</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 font-mono">
                {mem.regions.slice(0, 400).map((rg, i) => (
                  <tr key={i} className="text-zinc-300 hover:bg-zinc-800/40">
                    <Td mono>
                      {hex(rg.vaStart)}-{hex(rg.vaEnd)}
                    </Td>
                    <Td mono>{rg.protection}</Td>
                    <Td>
                      <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                        {rg.state}
                      </Badge>
                    </Td>
                    <Td>
                      <Badge
                        variant="outline"
                        className={rg.type === "MEM_IMAGE" ? "border-emerald-800/60 text-[10px] text-emerald-300" : "border-zinc-700 text-[10px] text-zinc-400"}
                      >
                        {rg.type}
                      </Badge>
                    </Td>
                    <Td>
                      <span className="block max-w-[240px] truncate text-[10px] text-zinc-500" title={rg.file}>
                        {rg.file && rg.file !== "-" ? rg.file : "-"}
                      </span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {mem.regionCount > mem.regions.length && (
            <p className="mt-1 text-[10px] text-zinc-500">+{mem.regionCount - mem.regions.length} bolge gizlendi</p>
          )}
        </div>
      )}

      {/* bellek AOB arama */}
      <div>
        <p className="mb-2 text-xs font-medium text-zinc-400">Bellek arama — tipli deger (little-endian) veya AOB</p>
        <div className="flex flex-wrap items-center gap-2">
          <DataTypeSelect value={mType} onChange={setMType} ariaLabel="Bellek arama tipi" />
          <Input
            value={mValue}
            onChange={(e) => setMValue(e.target.value)}
            placeholder={mType === "vec3" ? "1 2 3" : mType === "bool" ? "true / false" : mType === "str" ? "Metin..." : mType === "f32" || mType === "f64" ? "3.14" : "1337"}
            aria-label="Bellek degeri"
            onKeyDown={(e) => {
              if (e.key === "Enter") void runSearch();
            }}
            className="h-9 w-56 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          <Button variant="outline" disabled={searching || !mValue.trim()} onClick={() => void runSearch()} className="h-9 border-emerald-700/50 bg-emerald-600/10 px-3 text-emerald-300 hover:bg-emerald-600/20">
            {searching ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="mr-1.5 h-3.5 w-3.5" />}
            Degerde Ara
          </Button>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder="AOB: 48 8B ??"
            aria-label="Bellek AOB desen"
            onKeyDown={(e) => {
              if (e.key === "Enter") void runSearch();
            }}
            className="h-9 w-56 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          <Button variant="outline" disabled={searching || !pattern.trim()} onClick={() => void runSearch()} className="h-9 border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800">
            {searching ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />}
            AOB Ara
          </Button>
        </div>
        {res && (
          <div className="mt-3">
            <p className="mb-2 text-xs text-zinc-400">{res.total} eslesme</p>
            {res.matches.length === 0 ? (
              <p className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs text-zinc-500">Eslesme bulunamadi.</p>
            ) : (
              <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <table className="w-full min-w-[520px] text-left font-mono text-[11px]">
                  <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                    <tr>
                      <Th>VA</Th>
                      <Th>Modul</Th>
                      <Th>RVA</Th>
                      <Th>Hex</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
                    {res.matches.map((m, i) => (
                      <tr key={i}>
                        <Td mono>{hex(m.va)}</Td>
                        <Td mono>{m.module ?? "-"}</Td>
                        <Td mono>{m.rva !== undefined ? hex(m.rva) : "-"}</Td>
                        <Td>
                          <span className="block max-w-[280px] truncate" title={m.hex}>
                            {m.hex}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* notlar */}
      {mem.notes.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-zinc-400">Notlar</p>
          <ul className="list-inside list-disc space-y-0.5 text-[11px] text-zinc-400">
            {mem.notes.map((n, i) => (
              <li key={i} className="break-all">
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Il2CppBinaryCard({
  uploadId,
  bin,
  sdkFiles,
}: {
  uploadId: string;
  bin: Il2CppBinaryInfo;
  sdkFiles: { name: string; kind: string; size: number }[];
}) {
  // linked ise dump.cs / script.json indirme linkleri (SDK rotasi uzerinden)
  const links = bin.linked ? sdkFiles.filter((f) => f.name === "dump.cs" || f.name === "script.json") : [];

  return (
    <Card className="border-zinc-800 bg-zinc-950/50">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <Binary className="h-4 w-4 text-amber-400" />
          <CardTitle className="text-sm text-zinc-100">IL2CPP Binary</CardTitle>
          {bin.detected ? (
            <Badge className="bg-emerald-600/15 text-emerald-300 ring-1 ring-emerald-600/40">tespit edildi</Badge>
          ) : (
            <Badge variant="outline" className="border-zinc-700 text-zinc-400">tespit edilmedi</Badge>
          )}
          {bin.linked && (
            <Badge className="bg-emerald-600/15 text-emerald-300 ring-1 ring-emerald-600/40">metadata eslesti</Badge>
          )}
        </div>
        <p className="text-[11px] leading-relaxed text-zinc-500">{bin.reason}</p>
      </CardHeader>
      <CardContent className="space-y-4 pt-0">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <MiniStat label="Unity surumu" value={bin.unityVersion ?? "-"} />
          <MiniStat label="Pointer boyutu" value={`${bin.pointerSize} bayt`} />
          <MiniStat label="Cozulen metod ptr" value={bin.methodPointersResolved.toLocaleString("tr-TR")} />
          <MiniStat
            label="FieldOffsets tipi"
            value={bin.fieldOffsetsTypes !== undefined ? bin.fieldOffsetsTypes.toLocaleString("tr-TR") : "-"}
          />
        </div>

        {(bin.codeRegistration || bin.metadataRegistration) && (
          <div className="grid gap-3 sm:grid-cols-2">
            {bin.codeRegistration && (
              <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-3">
                <p className="text-[10px] uppercase tracking-wide text-zinc-500">CodeRegistration</p>
                <p className="mt-1 font-mono text-xs text-zinc-100">RVA {hex(bin.codeRegistration.rva)}</p>
                <p className="font-mono text-xs text-zinc-100">VA {hex(bin.codeRegistration.va)}</p>
                <p className="mt-1 text-[10px] leading-relaxed text-zinc-500">{bin.codeRegistration.fieldNote}</p>
              </div>
            )}
            {bin.metadataRegistration && (
              <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-3">
                <p className="text-[10px] uppercase tracking-wide text-zinc-500">MetadataRegistration</p>
                <p className="mt-1 font-mono text-xs text-zinc-100">RVA {hex(bin.metadataRegistration.rva)}</p>
                <p className="font-mono text-xs text-zinc-100">VA {hex(bin.metadataRegistration.va)}</p>
                <p className="mt-1 text-[10px] leading-relaxed text-zinc-500">{bin.metadataRegistration.fieldNote}</p>
              </div>
            )}
          </div>
        )}

        {bin.codeGenModules && bin.codeGenModules.modules.length > 0 && (
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <p className="text-xs font-medium text-zinc-400">
                codeGenModules ({bin.codeGenModules.count.toLocaleString("tr-TR")} modul)
              </p>
              <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                dizi RVA {hex(bin.codeGenModules.rva)}
              </Badge>
            </div>
            <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
              <table className="w-full min-w-[520px] text-left text-xs">
                <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                  <tr>
                    <Th>Modul</Th>
                    <Th>Metod</Th>
                    <Th>Cozulen</Th>
                    <Th>Pointers RVA</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {bin.codeGenModules.modules.map((m) => (
                    <tr key={m.name} className="text-zinc-300 hover:bg-zinc-800/40">
                      <Td mono>
                        <span className="break-all">{m.name}</span>
                      </Td>
                      <Td mono>{m.methodCount.toLocaleString("tr-TR")}</Td>
                      <Td mono>
                        <span className={m.resolved > 0 ? "text-emerald-300" : "text-zinc-600"}>
                          {m.resolved.toLocaleString("tr-TR")}
                        </span>
                      </Td>
                      <Td mono>{hex(m.pointersRva)}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {links.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium text-zinc-400">Metadata eslesme ciktilari</p>
            <div className="flex flex-wrap gap-2">
              {links.map((f) => (
                <a key={f.name} href={`/api/uploads/${uploadId}/sdk/${encodeURIComponent(f.name)}`} download>
                  <Button size="sm" variant="outline" className="h-8 border-emerald-700/50 px-2.5 text-[11px] text-emerald-300 hover:bg-emerald-600/10">
                    <Download className="mr-1 h-3 w-3" />
                    {f.name} ({formatBytes(f.size)})
                  </Button>
                </a>
              ))}
            </div>
          </div>
        )}

        {bin.notes.length > 0 && <InfoBlock title="Notlar" items={bin.notes} />}
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// SDK canli goruntuleyici: raw=1 ile icerik okuma, arama, tanimlar, vurgulama
// ----------------------------------------------------------------------------

interface SdkViewerTarget {
  name: string;
  size: number;
  query?: string;
}

interface SdkDefinition {
  name: string;
  line: number;
}

function SdkViewerDialog({
  uploadId,
  file,
  open,
  onClose,
}: {
  uploadId: string;
  file: SdkViewerTarget | null;
  open: boolean;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [matches, setMatches] = useState<number[]>([]);
  const [matchIdx, setMatchIdx] = useState(0);
  const [lastJump, setLastJump] = useState<number | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  // .cs / .txt / .json -> uygun tokenizer secimi (cpp tokenizer .cs ve .h icin yeterli)
  const lang = useMemo(() => {
    const n = file?.name ?? "";
    if (n.endsWith(".json")) return "plain";
    if (n.endsWith(".txt")) return "ini";
    return "cpp";
  }, [file?.name]);

  const lines = useMemo(() => (content ?? "").split("\n"), [content]);
  const truncated = lines.length > SDK_VIEW_MAX_LINES;
  const shownLines = useMemo(() => (truncated ? lines.slice(0, SDK_VIEW_MAX_LINES) : lines), [lines, truncated]);

  const tokens = useMemo(() => {
    const state: HighlightState = { inBlockComment: false };
    return shownLines.map((l) => tokenizeCodeLine(l, lang, state));
  }, [shownLines, lang]);

  // tanim satirlari: class / struct / enum bildirimleri (namespace icinde girintili olabilir)
  const definitions = useMemo<SdkDefinition[]>(() => {
    const n = file?.name ?? "";
    const re = n.endsWith(".cs")
      ? /^\s*(?:public |internal )*(?:class|enum)\s+([\w.]+)/
      : /^\s*(?:public |private |internal |static )*(?:class|struct|enum)\s+([A-Za-z_][\w<>:]*)/;
    const out: SdkDefinition[] = [];
    for (let i = 0; i < shownLines.length; i++) {
      const m = shownLines[i].match(re);
      if (m) out.push({ name: m[1], line: i + 1 });
    }
    return out.slice(0, 400);
  }, [shownLines, file?.name]);

  const jumpToLine = useCallback((line: number) => {
    const el = contentRef.current?.querySelector(`[data-line="${line}"]`);
    if (el) el.scrollIntoView({ block: "center" });
    setLastJump(line);
  }, []);

  // dosya acildiginda icerigi canli oku
  useEffect(() => {
    if (!open || !file) return;
    let cancelled = false;
    setLoading(true);
    setContent(null);
    setSearch("");
    setMatches([]);
    setMatchIdx(0);
    setLastJump(null);
    const run = async () => {
      try {
        const res = await fetch(`/api/uploads/${uploadId}/sdk/${encodeURIComponent(file.name)}?raw=1`, {
          cache: "no-store",
        });
        const data = (await res.json()) as { ok: boolean; content?: string; error?: string };
        if (cancelled) return;
        if (data.ok && typeof data.content === "string") {
          setContent(data.content);
        } else {
          toast({ title: "SDK dosyasi okunamadi", description: data.error, variant: "destructive" });
          onClose();
        }
      } catch {
        if (!cancelled) {
          toast({ title: "SDK dosyasi okunamadi", variant: "destructive" });
          onClose();
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [open, file, uploadId, toast, onClose]);

  // arama: buyuk/kucuk harf duyarsiz satir eslesmeleri
  useEffect(() => {
    if (!open || content === null) return;
    const q = search.trim().toLowerCase();
    if (!q) {
      setMatches([]);
      setMatchIdx(0);
      return;
    }
    const found: number[] = [];
    for (let i = 0; i < shownLines.length; i++) {
      if (shownLines[i].toLowerCase().includes(q)) found.push(i + 1);
    }
    setMatches(found);
    setMatchIdx(0);
  }, [open, content, search, shownLines]);

  // ilk acilista hedef sorguya git (struct adi vb.)
  useEffect(() => {
    if (!open || content === null) return;
    const q = file?.query?.trim().toLowerCase();
    if (!q) return;
    const idx = shownLines.findIndex((l) => l.toLowerCase().includes(q));
    if (idx >= 0) {
      const t = window.setTimeout(() => jumpToLine(idx + 1), 80);
      return () => window.clearTimeout(t);
    }
  }, [open, content, shownLines, jumpToLine, file]);

  const gotoNextMatch = () => {
    if (matches.length === 0) return;
    const line = matches[matchIdx % matches.length];
    jumpToLine(line);
    setMatchIdx((i) => (i + 1) % matches.length);
  };

  const copyContent = async () => {
    if (content === null) return;
    try {
      await navigator.clipboard.writeText(content);
      toast({ title: "Icerik kopyalandi" });
    } catch {
      toast({ title: "Kopyalanamadi", variant: "destructive" });
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="flex max-h-[88vh] flex-col overflow-hidden border-zinc-800 bg-zinc-950 sm:max-w-4xl">
        <DialogHeader className="pb-2">
          <DialogTitle className="flex flex-wrap items-center gap-2 text-sm text-zinc-100">
            <FileCode2 className="h-4 w-4 text-emerald-400" />
            <span className="min-w-0 truncate font-mono">{file?.name ?? "-"}</span>
            {file && (
              <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                {formatBytes(file.size)}
              </Badge>
            )}
            {truncated && (
              <Badge className="bg-amber-600/15 text-[10px] text-amber-300">
                ilk {SDK_VIEW_MAX_LINES} satir gosteriliyor
              </Badge>
            )}
          </DialogTitle>
        </DialogHeader>

        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 pb-3">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") gotoNextMatch();
            }}
            placeholder="icerikte ara..."
            aria-label="Icerikte ara"
            className="h-8 w-52 border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200"
          />
          {search.trim() !== "" && (
            <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
              {matches.length > 0 ? `${matchIdx + 1}/${matches.length} eslesme` : "eslesme yok"}
            </Badge>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={matches.length === 0}
            onClick={gotoNextMatch}
            className="h-8 border-zinc-700 px-2 text-[11px] text-zinc-300 hover:bg-zinc-800"
          >
            sonraki eslesme
          </Button>
          <div className="ml-auto flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={content === null}
              onClick={() => void copyContent()}
              className="h-8 border-zinc-700 px-2 text-[11px] text-zinc-300 hover:bg-zinc-800"
            >
              <Copy className="mr-1 h-3 w-3" />
              Kopyala
            </Button>
            {file && (
              <a href={`/api/uploads/${uploadId}/sdk/${encodeURIComponent(file.name)}`} download>
                <Button size="sm" variant="outline" className="h-8 border-emerald-700/50 px-2 text-[11px] text-emerald-300 hover:bg-emerald-600/10">
                  <Download className="mr-1 h-3 w-3" />
                  Indir
                </Button>
              </a>
            )}
          </div>
        </div>

        <div className="flex min-h-0 flex-1 gap-3 overflow-hidden">
          {definitions.length > 0 && (
            <div className="hidden w-52 shrink-0 sm:block">
              <p className="mb-1 text-[10px] uppercase tracking-wide text-zinc-500">Tanimlar ({definitions.length})</p>
              <div className="max-h-[54vh] overflow-y-auto pr-1 scrollbar-thin">
                {definitions.map((d) => (
                  <button
                    key={`${d.line}-${d.name}`}
                    type="button"
                    onClick={() => jumpToLine(d.line)}
                    title={d.name}
                    className="block w-full truncate rounded px-1.5 py-1 text-left font-mono text-[11px] text-zinc-400 transition-colors hover:bg-emerald-600/10 hover:text-emerald-300"
                  >
                    {d.name}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div
            ref={contentRef}
            className="max-h-[64vh] min-w-0 flex-1 overflow-auto rounded-lg border border-zinc-800 bg-zinc-950/80 scrollbar-thin"
          >
            {loading ? (
              <div className="flex items-center justify-center gap-2 py-10 text-sm text-zinc-400">
                <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
                SDK dosyasi okunuyor...
              </div>
            ) : (
              <div className="min-w-max py-2 font-mono text-[11px] leading-relaxed">
                {tokens.map((toks, i) => {
                  const lineNo = i + 1;
                  return (
                    <div
                      key={lineNo}
                      data-line={lineNo}
                      className={`flex whitespace-pre px-2 ${lastJump === lineNo ? "bg-emerald-600/10" : ""}`}
                    >
                      <span className="w-10 shrink-0 select-none pr-3 text-right font-mono text-[11px] text-zinc-600">
                        {lineNo}
                      </span>
                      <span className="text-zinc-300">
                        {toks.map((t, j) =>
                          t.cls ? (
                            <span key={j} className={t.cls}>
                              {t.text}
                            </span>
                          ) : (
                            <span key={j}>{t.text}</span>
                          ),
                        )}
                        {toks.length === 0 ? " " : null}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ----------------------------------------------------------------------------
// Cikaricilar: coklu dumper ciktilari + ortak veriler
// ----------------------------------------------------------------------------

function ExtractorsTab({
  uploadId,
  info,
  onOpenFile,
}: {
  uploadId: string;
  info: ExtractorsInfo;
  onOpenFile: (f: { name: string; size: number; query?: string }) => void;
}) {
  return (
    <div className="space-y-4">
      {/* ozet seritleri */}
      <div className="flex flex-wrap gap-2">
        {info.extractors.map((ex) => {
          const total = ex.sections.reduce((a, s) => a + s.total, 0);
          return (
            <div key={ex.id} className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
              <span className="text-xs font-medium text-zinc-200">{ex.name}</span>
              {ex.available ? (
                <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">cikti var</Badge>
              ) : (
                <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">uygulanamaz</Badge>
              )}
              <span className="font-mono text-[10px] text-zinc-500">{total.toLocaleString("tr-TR")} oge</span>
            </div>
          );
        })}
      </div>

      {/* ortak veriler (en onemli panel) */}
      <div>
        <p className="mb-2 text-xs font-medium text-zinc-400">Ortak Veriler</p>
        {info.common.length === 0 ? (
          <p className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3 text-xs text-zinc-500">
            Model ortak verisi yok - bu dosyada cikaricilar farkli alanlari buldu.
          </p>
        ) : (
          <div className="space-y-3">
            {info.common.map((g) => (
              <div key={`${g.kind}-${g.title}`} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
                <p className="mb-2 text-xs font-medium text-zinc-200">
                  {g.title} ({g.entries.length})
                </p>
                <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                  <table className="w-full min-w-[520px] text-left text-xs">
                    <thead className="sticky top-0 bg-zinc-950/90 text-zinc-500">
                      <tr>
                        <Th>Oge</Th>
                        <Th>Deger</Th>
                        <Th>Bulunan Cikaricilar</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60">
                      {g.entries.slice(0, 100).map((e, i) => (
                        <tr key={`${e.name}-${i}`} className="text-zinc-300 hover:bg-zinc-800/40">
                          <Td mono>
                            <span className="block max-w-[260px] truncate" title={e.name}>
                              {e.name}
                            </span>
                          </Td>
                          <Td mono>
                            <span className="block max-w-[160px] truncate" title={e.value}>
                              {e.value ?? "-"}
                            </span>
                          </Td>
                          <Td>
                            <span className="flex flex-wrap gap-1">
                              {e.foundIn.map((fid) => (
                                <Badge
                                  key={fid}
                                  className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40"
                                >
                                  {extractorShortLabel(fid)}
                                </Badge>
                              ))}
                            </span>
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {g.entries.length > 100 && <p className="mt-1 text-[10px] text-zinc-500">+{g.entries.length - 100} daha</p>}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* cikarici kartlari */}
      <div className="grid gap-3 lg:grid-cols-2">
        {info.extractors.map((ex) => (
          <div key={ex.id} className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-zinc-100">{ex.name}</span>
              <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                {ex.version}
              </Badge>
              {ex.available ? (
                <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">cikti var</Badge>
              ) : (
                <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">uygulanamaz</Badge>
              )}
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">{ex.generatorNote}</p>
            <p className="text-[10px] text-zinc-500">{ex.reason}</p>
            {ex.sections.length > 0 && (
              <Accordion
                type="multiple"
                defaultValue={[ex.sections[0].key]}
                className="mt-3 space-y-2"
              >
                {ex.sections.map((sec) => (
                  <AccordionItem key={sec.key} value={sec.key} className="rounded-lg border border-zinc-800 bg-zinc-950/60 px-3">
                    <AccordionTrigger className="py-2.5 text-xs text-zinc-200 hover:text-emerald-300">
                      <span className="flex items-center gap-2">
                        {sec.title} ({sec.total})
                      </span>
                    </AccordionTrigger>
                    <AccordionContent className="pb-3">
                      {sec.entries.length > 0 ? (
                        <>
                          <div className="max-h-56 overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                            <table className="w-full min-w-[380px] text-left font-mono text-[11px]">
                              <thead className="sticky top-0 bg-zinc-950/90 text-zinc-600">
                                <tr>
                                  <Th>Oge</Th>
                                  <Th>Deger</Th>
                                  <Th>Not</Th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-zinc-800/50 text-zinc-300">
                                {sec.entries.map((e, i) => (
                                  <tr key={`${e.name}-${i}`}>
                                    <Td mono>
                                      <span className="block max-w-[220px] truncate" title={e.name}>
                                        {e.name}
                                      </span>
                                    </Td>
                                    <Td mono>
                                      <span className="block max-w-[140px] truncate" title={e.value}>
                                        {e.value ?? "-"}
                                      </span>
                                    </Td>
                                    <Td>
                                      <span className="block max-w-[160px] truncate text-[10px] text-zinc-500" title={e.note}>
                                        {e.note ?? "-"}
                                      </span>
                                    </Td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {sec.total > sec.entries.length && (
                            <p className="mt-1 text-[10px] text-zinc-500">+{sec.total - sec.entries.length} daha</p>
                          )}
                        </>
                      ) : (
                        <p className="text-[11px] text-zinc-500">{sec.note ?? "Bu bolumde oge yok."}</p>
                      )}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            )}
            {ex.files.length > 0 && (
              <div className="mt-3 border-t border-zinc-800 pt-3">
                <p className="mb-1.5 text-[10px] uppercase tracking-wide text-zinc-500">Cikti dosyalari</p>
                <div className="space-y-1">
                  {ex.files.map((f) => (
                    <div
                      key={f.name}
                      className="flex min-h-8 items-center gap-2 overflow-hidden rounded border border-zinc-800 bg-zinc-950/70 px-2 py-1"
                    >
                      <FileCode2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-300" title={f.name}>
                        {f.name}
                      </span>
                      <span className="shrink-0 text-[10px] text-zinc-500">{formatBytes(f.size)}</span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 shrink-0 border-emerald-700/50 px-1.5 text-[10px] text-emerald-300 hover:bg-emerald-600/10"
                        onClick={() => onOpenFile({ name: f.name, size: f.size })}
                      >
                        Goster
                      </Button>
                      <a href={`/api/uploads/${uploadId}/sdk/${encodeURIComponent(f.name)}`} download className="shrink-0">
                        <Button size="sm" variant="outline" className="h-6 border-zinc-700 px-1.5 text-[10px] text-zinc-300 hover:bg-zinc-800">
                          Indir
                        </Button>
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
