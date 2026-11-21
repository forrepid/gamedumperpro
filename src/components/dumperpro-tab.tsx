"use client";

// ----------------------------------------------------------------------------
// DumperPro sekmesi: Windows C++ araci (DumperPro.exe) cikti dosyalarini ice
// aktarma + gezgin (Fonksiyonlar / GNames / Nesneler) + kod uretici.
//
// Akis: multipart POST /api/dumperpro/import -> kayit listesi -> bolum bazli
// dilimleme (sunucu tarafi) -> codegen GET. Semantik etiketler yerel sozlukten
// (analysis/semantics) gelir; opcode uretilmez (motor ciktisinde yok).
// ----------------------------------------------------------------------------

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  FileArchive,
  Loader2,
  PackageOpen,
  Play,
  RefreshCw,
  Search,
  Trash2,
  Upload,
  Wand2,
  X,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import {
  explainField,
  explainFunction,
  type SemanticInfo,
} from "@/lib/analysis/semantics";
import type { FunctionEntry } from "@/lib/analysis/types";
import type { DpFunction, DpObject } from "@/lib/dumperpro/parse";

// ---------------------------------------------------------------------------
// tipler (API yanitlari)
// ---------------------------------------------------------------------------

interface DpImportSummary {
  id: string;
  label: string;
  game: string | null;
  ueVersion: string | null;
  status: string;
  namesCount: number;
  objectsCount: number;
  functionsCount: number;
  toolVersion: string | null;
  createdAt: string;
}

interface DpMetaResponse {
  ok: boolean;
  meta: {
    id: string;
    label: string;
    toolVersion: string | null;
    mode: string | null;
    target: string | null;
    game: string | null;
    ueVersion: string | null;
    moduleName: string | null;
    moduleBase: string | null;
    status: string;
    createdAt: string;
  };
  counts: { names: number; objects: number; functions: number };
  hasNames: boolean;
  hasObjects: boolean;
  hasFunctions: boolean;
}

interface DpNamesResponse {
  ok: boolean;
  total: number;
  offset: number;
  limit: number;
  items: { index: number; name: string }[];
}

interface DpFunctionsResponse {
  ok: boolean;
  total: number;
  offset: number;
  limit: number;
  classes: string[];
  items: DpFunction[];
}

interface DpObjectsResponse {
  ok: boolean;
  total: number;
  offset: number;
  limit: number;
  items: DpObject[];
}

// ---------------------------------------------------------------------------
// sabitler + ufak yardimcilar
// ---------------------------------------------------------------------------

const PAGE_SIZE = 200;
const ALL_CLASSES = "__tumu";

const CODEGEN_LANGS = [
  { id: "cpp", label: "C++" },
  { id: "csharp", label: "C#" },
  { id: "python", label: "Python" },
  { id: "rust", label: "Rust" },
  { id: "typescript", label: "TypeScript" },
  { id: "java", label: "Java" },
  { id: "lua", label: "Lua" },
  { id: "json", label: "JSON" },
];

const CODEGEN_KINDS = [
  { id: "all", label: "Tumu" },
  { id: "functions", label: "Fonksiyonlar" },
  { id: "structs", label: "Structlar" },
  { id: "enums", label: "Enumlar" },
];

/** "0x1A2B3C" -> sayi (gecersiz -> 0). Istemci tarafindaki kopya. */
function dpHexToNum(s: string | undefined | null): number {
  if (!s) return 0;
  const t = s.trim();
  if (/^0x[0-9a-fA-F]+$/.test(t)) return parseInt(t, 16) || 0;
  const n = Number(t);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString("tr-TR");
  } catch {
    return iso;
  }
}

function statusBadgeClass(status: string): string {
  if (status === "names-only") return "border-amber-500/40 bg-amber-500/10 text-amber-300";
  return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
}

function categoryBadgeClass(cat: string): string {
  if (cat.includes("Saglik") || cat.includes("Karakter")) return "border-red-500/40 text-red-300 bg-red-500/10";
  if (cat.includes("Silah") || cat.includes("Hasar")) return "border-orange-500/40 text-orange-300 bg-orange-500/10";
  if (cat.includes("Ekonomi") || cat.includes("Para")) return "border-yellow-500/40 text-yellow-300 bg-yellow-500/10";
  if (cat.includes("Hareket") || cat.includes("Fizik")) return "border-cyan-500/40 text-cyan-300 bg-cyan-500/10";
  if (cat.includes("Konum") || cat.includes("Koordinat")) return "border-sky-500/40 text-sky-300 bg-sky-500/10";
  if (cat.includes("Ag") || cat.includes("Online")) return "border-green-500/40 text-green-300 bg-green-500/10";
  if (cat.includes("Girdi")) return "border-slate-500/40 text-slate-300 bg-slate-500/10";
  return "border-zinc-600 text-zinc-300 bg-zinc-500/10";
}

/** Debounce (arama alanlari icin). */
function useDebounced<T>(value: T, delay = 350): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return v;
}

/** DumperPro fonksiyonunu semantik sozluge uygun sekliye getirir. */
function buildFunctionEntry(f: DpFunction): FunctionEntry {
  return {
    idx: 0,
    rva: dpHexToNum(f.rva),
    va: dpHexToNum(f.va),
    size: dpHexToNum(f.paramsSize),
    label: f.cls ? `${f.cls}::${f.name}` : f.name,
    section: "",
    prologue: "",
    strings: [],
    apiCalls: [],
    callsOut: 0,
    xrefsIn: 0,
    structHint: f.params.find((p) => p.target)?.target,
  };
}

// ---------------------------------------------------------------------------
// sayfalama cubugu
// ---------------------------------------------------------------------------

function Pager({
  total,
  offset,
  limit,
  onPrev,
  onNext,
}: {
  total: number;
  offset: number;
  limit: number;
  onPrev: () => void;
  onNext: () => void;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-[11px] text-zinc-500" aria-live="polite">
        {total.toLocaleString("tr-TR")} kayit · {from.toLocaleString("tr-TR")}-
        {to.toLocaleString("tr-TR")} gosteriliyor
      </span>
      <div className="flex gap-1.5">
        <Button
          variant="outline"
          size="sm"
          className="h-7 border-zinc-700 px-2 text-[11px]"
          onClick={onPrev}
          disabled={offset === 0}
          aria-label="Onceki sayfa"
        >
          <ChevronLeft className="mr-1 h-3 w-3" />
          Onceki
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-7 border-zinc-700 px-2 text-[11px]"
          onClick={onNext}
          disabled={offset + limit >= total}
          aria-label="Sonraki sayfa"
        >
          Sonraki
          <ChevronRight className="ml-1 h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ana bilesen
// ---------------------------------------------------------------------------

type SubTab = "functions" | "names" | "objects" | "codegen";

export default function DumperProTab() {
  const { toast } = useToast();

  // --- ice aktarma ---
  const [files, setFiles] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // --- kayit listesi ---
  const [imports, setImports] = useState<DpImportSummary[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [deleteTarget, setDeleteTarget] = useState<DpImportSummary | null>(null);

  // --- gezgin ---
  const [openId, setOpenId] = useState<string | null>(null);
  const [meta, setMeta] = useState<DpMetaResponse | null>(null);
  const [metaLoading, setMetaLoading] = useState(false);
  const [subTab, setSubTab] = useState<SubTab>("functions");

  // --- fonksiyonlar ---
  const [fSearch, setFSearch] = useState("");
  const [fCls, setFCls] = useState(ALL_CLASSES);
  const [fOffset, setFOffset] = useState(0);
  const [fData, setFData] = useState<DpFunctionsResponse | null>(null);
  const [fLoading, setFLoading] = useState(false);
  const [selectedFn, setSelectedFn] = useState<DpFunction | null>(null);
  const fDeb = useDebounced(fSearch);

  // --- gnames ---
  const [nSearch, setNSearch] = useState("");
  const [nOffset, setNOffset] = useState(0);
  const [nData, setNData] = useState<DpNamesResponse | null>(null);
  const [nLoading, setNLoading] = useState(false);
  const nDeb = useDebounced(nSearch);

  // --- nesneler ---
  const [oSearch, setOSearch] = useState("");
  const [oOffset, setOOffset] = useState(0);
  const [oData, setOData] = useState<DpObjectsResponse | null>(null);
  const [oLoading, setOLoading] = useState(false);
  const oDeb = useDebounced(oSearch);

  // --- kod uret ---
  const [cLang, setCLang] = useState("cpp");
  const [cKind, setCKind] = useState("all");
  const [cText, setCText] = useState("");
  const [cFilename, setCFilename] = useState("");
  const [cCount, setCCount] = useState<number | null>(null);
  const [cLoading, setCLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // ---------------------------------------------------------------------------
  // veri cekme
  // ---------------------------------------------------------------------------

  const loadImports = useCallback(async () => {
    setListLoading(true);
    try {
      const res = await fetch("/api/dumperpro/imports");
      const d = (await res.json()) as { ok: boolean; imports?: DpImportSummary[] };
      setImports(d.imports ?? []);
    } catch {
      toast({ title: "Kayit listesi alinamadi", variant: "destructive" });
    } finally {
      setListLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void loadImports();
  }, [loadImports]);

  // kayit degistiginde gezgini sifirla
  useEffect(() => {
    if (!openId) {
      setMeta(null);
      return;
    }
    setSubTab("functions");
    setFSearch("");
    setFCls(ALL_CLASSES);
    setFOffset(0);
    setFData(null);
    setNSearch("");
    setNOffset(0);
    setNData(null);
    setOSearch("");
    setOOffset(0);
    setOData(null);
    setSelectedFn(null);
    setCText("");
    setCFilename("");
    setCCount(null);
  }, [openId]);

  // meta
  useEffect(() => {
    if (!openId) return;
    let alive = true;
    setMetaLoading(true);
    fetch(`/api/dumperpro/imports/${openId}?section=meta`)
      .then((r) => r.json())
      .then((d: DpMetaResponse) => {
        if (alive) setMeta(d.ok ? d : null);
        if (alive && !d.ok) toast({ title: "Kayit acilamadi", variant: "destructive" });
      })
      .catch(() => {
        if (alive) toast({ title: "Meta alinamadi", variant: "destructive" });
      })
      .finally(() => {
        if (alive) setMetaLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [openId, toast]);

  // fonksiyonlar
  useEffect(() => {
    if (!openId || subTab !== "functions") return;
    let alive = true;
    setFLoading(true);
    const params = new URLSearchParams({
      section: "functions",
      limit: String(PAGE_SIZE),
      offset: String(fOffset),
    });
    if (fDeb.trim()) params.set("search", fDeb.trim());
    if (fCls !== ALL_CLASSES) params.set("cls", fCls);
    fetch(`/api/dumperpro/imports/${openId}?${params.toString()}`)
      .then((r) => r.json())
      .then((d: DpFunctionsResponse) => {
        if (alive) setFData(d);
      })
      .catch(() => {
        if (alive) toast({ title: "Fonksiyonlar alinamadi", variant: "destructive" });
      })
      .finally(() => {
        if (alive) setFLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [openId, subTab, fDeb, fCls, fOffset, toast]);

  // gnames
  useEffect(() => {
    if (!openId || subTab !== "names") return;
    let alive = true;
    setNLoading(true);
    const params = new URLSearchParams({
      section: "names",
      limit: String(PAGE_SIZE),
      offset: String(nOffset),
    });
    if (nDeb.trim()) params.set("search", nDeb.trim());
    fetch(`/api/dumperpro/imports/${openId}?${params.toString()}`)
      .then((r) => r.json())
      .then((d: DpNamesResponse) => {
        if (alive) setNData(d);
      })
      .catch(() => {
        if (alive) toast({ title: "GNames alinamadi", variant: "destructive" });
      })
      .finally(() => {
        if (alive) setNLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [openId, subTab, nDeb, nOffset, toast]);

  // nesneler
  useEffect(() => {
    if (!openId || subTab !== "objects") return;
    let alive = true;
    setOLoading(true);
    const params = new URLSearchParams({
      section: "objects",
      limit: String(PAGE_SIZE),
      offset: String(oOffset),
    });
    if (oDeb.trim()) params.set("search", oDeb.trim());
    fetch(`/api/dumperpro/imports/${openId}?${params.toString()}`)
      .then((r) => r.json())
      .then((d: DpObjectsResponse) => {
        if (alive) setOData(d);
      })
      .catch(() => {
        if (alive) toast({ title: "Nesneler alinamadi", variant: "destructive" });
      })
      .finally(() => {
        if (alive) setOLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [openId, subTab, oDeb, oOffset, toast]);

  // ---------------------------------------------------------------------------
  // islemler
  // ---------------------------------------------------------------------------

  const addFiles = useCallback((list: FileList | File[]) => {
    const arr = Array.from(list);
    if (arr.length === 0) return;
    setFiles((prev) => [...prev, ...arr]);
  }, []);

  const doUpload = useCallback(async () => {
    if (files.length === 0 || uploading) return;
    setUploading(true);
    const fd = new FormData();
    for (const f of files) fd.append("files", f);
    try {
      const res = await fetch("/api/dumperpro/import", { method: "POST", body: fd });
      const d = (await res.json()) as {
        ok: boolean;
        id?: string;
        label?: string;
        status?: string;
        counts?: { names: number; objects: number; functions: number };
        error?: string;
      };
      if (d.ok && d.id) {
        const c = d.counts ?? { names: 0, objects: 0, functions: 0 };
        toast({
          title: "Ice aktarma tamamlandi",
          description: `${c.names.toLocaleString("tr-TR")} isim · ${c.objects.toLocaleString("tr-TR")} nesne · ${c.functions.toLocaleString("tr-TR")} fonksiyon (${d.status === "names-only" ? "names-only" : "full"})`,
        });
        setFiles([]);
        await loadImports();
        setOpenId(d.id);
      } else {
        toast({
          title: "Ice aktarma basarisiz",
          description: d.error ?? "Bilinmeyen hata",
          variant: "destructive",
        });
      }
    } catch {
      toast({ title: "Ice aktarma hatasi (ag)", variant: "destructive" });
    } finally {
      setUploading(false);
    }
  }, [files, uploading, toast, loadImports]);

  const doDelete = useCallback(
    async (id: string) => {
      try {
        const res = await fetch(`/api/dumperpro/imports/${id}`, { method: "DELETE" });
        const d = (await res.json()) as { ok: boolean; error?: string };
        if (d.ok) {
          toast({ title: "Kayit silindi" });
          if (openId === id) setOpenId(null);
          await loadImports();
        } else {
          toast({ title: "Silme basarisiz", description: d.error, variant: "destructive" });
        }
      } catch {
        toast({ title: "Silme hatasi (ag)", variant: "destructive" });
      }
    },
    [openId, toast, loadImports],
  );

  const genCode = useCallback(async () => {
    if (!openId || cLoading) return;
    setCLoading(true);
    try {
      const res = await fetch(
        `/api/dumperpro/imports/${openId}/codegen?lang=${cLang}&kind=${cKind}`,
      );
      const d = (await res.json()) as {
        ok: boolean;
        text?: string;
        filename?: string;
        count?: number;
        error?: string;
      };
      if (d.ok && typeof d.text === "string") {
        setCText(d.text);
        setCFilename(d.filename ?? "");
        setCCount(d.count ?? null);
      } else {
        setCText(`// ${d.error ?? "kod uretimi basarisiz"}`);
        setCFilename("");
        setCCount(null);
        toast({ title: "Kod uretimi basarisiz", description: d.error, variant: "destructive" });
      }
    } catch {
      setCText("// kod uretimi hatasi (ag)");
      toast({ title: "Kod uretimi hatasi (ag)", variant: "destructive" });
    } finally {
      setCLoading(false);
    }
  }, [openId, cLang, cKind, cLoading, toast]);

  const copyCode = useCallback(async () => {
    if (!cText) return;
    try {
      await navigator.clipboard.writeText(cText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast({ title: "Kopyalanamadi", variant: "destructive" });
    }
  }, [cText, toast]);

  const downloadCode = useCallback(() => {
    if (!cText) return;
    const blob = new Blob([cText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = cFilename || `dumperpro_${cLang}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [cText, cFilename, cLang]);

  // secili fonksiyonun semantigi (yerel sozluk)
  const selectedSem = useMemo<SemanticInfo | null>(
    () => (selectedFn ? explainFunction(buildFunctionEntry(selectedFn)) : null),
    [selectedFn],
  );

  const openRecord = useCallback((id: string, tab: SubTab = "functions") => {
    setOpenId(id);
    setSubTab(tab);
  }, []);

  // ---------------------------------------------------------------------------
  // render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      {/* ---------------- 1. ICE AKTARMA KARTI ---------------- */}
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base text-zinc-100">
            <PackageOpen className="h-4 w-4 text-emerald-400" />
            DumperPro Ice Aktar
          </CardTitle>
          <CardDescription className="text-xs text-zinc-400">
            Windows DumperPro.exe ciktilarini yukleyin: names.json, objects.json,
            functions.json, result.json veya Names.txt / Objects.txt / funcs.txt.
            Coklu dosya ve .zip demeti desteklenir.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div
            role="button"
            tabIndex={0}
            aria-label="Dosya sec veya surukle birak"
            onClick={() => inputRef.current?.click()}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                inputRef.current?.click();
              }
            }}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              addFiles(e.dataTransfer.files);
            }}
            className={`flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed px-4 py-7 text-center transition ${
              dragOver
                ? "border-emerald-500 bg-emerald-500/10"
                : "border-zinc-700 bg-zinc-950/50 hover:border-zinc-500"
            }`}
          >
            <Upload className="h-5 w-5 text-emerald-400" />
            <p className="text-xs text-zinc-300">
              Dosyalari buraya surukleyin veya secmek icin tiklayin
            </p>
            <p className="text-[10px] text-zinc-500">
              .zip / .json / .txt · birden fazla dosya secilebilir
            </p>
            <input
              ref={inputRef}
              type="file"
              multiple
              accept=".zip,.json,.txt"
              className="hidden"
              aria-label="DumperPro cikti dosyalari"
              onChange={(e) => {
                if (e.target.files) addFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </div>

          {files.length > 0 && (
            <ul className="flex flex-wrap gap-1.5" aria-label="Secilen dosyalar">
              {files.map((f, i) => (
                <li key={`${f.name}-${i}`}>
                  <Badge
                    variant="outline"
                    className="gap-1 border-zinc-700 bg-zinc-950/70 text-[10px] text-zinc-300"
                  >
                    {f.name.toLowerCase().endsWith(".zip") ? (
                      <FileArchive className="h-3 w-3 text-emerald-400" />
                    ) : null}
                    {f.name}
                    <span className="text-zinc-500">{formatBytes(f.size)}</span>
                    <button
                      type="button"
                      aria-label={`${f.name} dosyasini kaldir`}
                      className="ml-0.5 rounded text-zinc-500 hover:text-zinc-200"
                      onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                </li>
              ))}
            </ul>
          )}

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              className="bg-emerald-600 text-zinc-950 hover:bg-emerald-500"
              onClick={() => void doUpload()}
              disabled={uploading || files.length === 0}
              aria-label="DumperPro dosyalarini ice aktar"
            >
              {uploading ? (
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Upload className="mr-1.5 h-3.5 w-3.5" />
              )}
              {uploading ? "Ice aktariliyor..." : "Ice Aktar"}
            </Button>
            {files.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                className="border-zinc-700 text-zinc-300"
                onClick={() => setFiles([])}
                aria-label="Secim temizle"
              >
                Temizle
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ---------------- 2. KAYIT LISTESI ---------------- */}
      <section aria-label="Ice aktarma kayitlari">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-200">
            Ice Aktarma Kayitlari
            <span className="ml-2 text-xs font-normal text-zinc-500">
              ({imports.length} kayit)
            </span>
          </h2>
          <Button
            variant="outline"
            size="sm"
            className="h-7 border-zinc-700 px-2 text-[11px]"
            onClick={() => void loadImports()}
            aria-label="Listeyi yenile"
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Yenile
          </Button>
        </div>

        {listLoading ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-[76px] w-full rounded-xl bg-zinc-800/60" />
            ))}
          </div>
        ) : imports.length === 0 ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 text-center text-xs text-zinc-500">
            Henuz ice aktarma yok. Yukaridan DumperPro cikti dosyalarini yukleyin.
          </div>
        ) : (
          <ul className="space-y-2">
            {imports.map((rec) => (
              <li
                key={rec.id}
                className={`rounded-xl border bg-zinc-900/40 p-4 transition ${
                  openId === rec.id ? "border-emerald-500/50" : "border-zinc-800 hover:border-zinc-700"
                }`}
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-zinc-100">{rec.label}</p>
                    <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-zinc-500">
                      <span>{rec.game ?? "Bilinmeyen"}</span>
                      <span aria-hidden="true">·</span>
                      <span>{rec.ueVersion ?? "—"}</span>
                      {rec.toolVersion && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono">{rec.toolVersion}</span>
                        </>
                      )}
                      <span aria-hidden="true">·</span>
                      <span>{fmtDate(rec.createdAt)}</span>
                    </p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <Badge
                        variant="outline"
                        className={`text-[9px] ${statusBadgeClass(rec.status)}`}
                      >
                        {rec.status}
                      </Badge>
                      <Badge variant="outline" className="border-zinc-700 text-[9px] text-zinc-400">
                        {rec.namesCount.toLocaleString("tr-TR")} isim
                      </Badge>
                      <Badge variant="outline" className="border-zinc-700 text-[9px] text-zinc-400">
                        {rec.objectsCount.toLocaleString("tr-TR")} nesne
                      </Badge>
                      <Badge variant="outline" className="border-zinc-700 text-[9px] text-zinc-400">
                        {rec.functionsCount.toLocaleString("tr-TR")} fonksiyon
                      </Badge>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 border-emerald-600/50 px-3 text-[11px] text-emerald-300 hover:bg-emerald-500/10"
                      onClick={() => openRecord(rec.id, "functions")}
                      aria-label={`${rec.label} kaydini ac`}
                    >
                      <Search className="mr-1 h-3 w-3" />
                      Ac
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 border-zinc-700 px-3 text-[11px] text-zinc-300"
                      onClick={() => openRecord(rec.id, "codegen")}
                      aria-label={`${rec.label} icin kod uret`}
                    >
                      <Wand2 className="mr-1 h-3 w-3" />
                      Codegen
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 border-red-500/40 px-3 text-[11px] text-red-300 hover:bg-red-500/10"
                      onClick={() => setDeleteTarget(rec)}
                      aria-label={`${rec.label} kaydini sil`}
                    >
                      <Trash2 className="mr-1 h-3 w-3" />
                      Sil
                    </Button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* ---------------- 3. GEZGIN ---------------- */}
      {openId && (
        <section aria-label="DumperPro gezgini">
          {metaLoading || !meta ? (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
              {[0, 1, 2, 3, 4].map((i) => (
                <Skeleton key={i} className="h-20 rounded-xl bg-zinc-800/60" />
              ))}
            </div>
          ) : (
            <>
              {/* meta kartlari */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-500">Oyun</p>
                  <p className="mt-1 truncate text-sm font-semibold text-zinc-100">
                    {meta.meta.game ?? "Bilinmeyen"}
                  </p>
                  <p className="mt-0.5 truncate text-[10px] text-zinc-500">
                    mod: {meta.meta.mode ?? "—"}
                  </p>
                </div>
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-500">UE Surumu</p>
                  <p className="mt-1 truncate text-sm font-semibold text-zinc-100">
                    {meta.meta.ueVersion ?? "—"}
                  </p>
                  <p className="mt-0.5 truncate text-[10px] font-mono text-zinc-500">
                    {meta.meta.toolVersion ?? "—"}
                  </p>
                </div>
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-500">Modul</p>
                  <p className="mt-1 truncate text-sm font-semibold text-zinc-100">
                    {meta.meta.moduleName ?? "—"}
                  </p>
                  <p className="mt-0.5 truncate font-mono text-[10px] text-zinc-500">
                    base {meta.meta.moduleBase ?? "—"}
                  </p>
                </div>
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-500">Durum</p>
                  <div className="mt-1.5">
                    <Badge variant="outline" className={`text-[10px] ${statusBadgeClass(meta.meta.status)}`}>
                      {meta.meta.status}
                    </Badge>
                  </div>
                  <p className="mt-1.5 truncate text-[10px] text-zinc-500">
                    {meta.meta.target ?? "—"}
                  </p>
                </div>
                <div className="col-span-2 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 sm:col-span-1">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-500">Adetler</p>
                  <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-xs text-zinc-200">
                    <span>{meta.counts.names.toLocaleString("tr-TR")} isim</span>
                    <span>{meta.counts.objects.toLocaleString("tr-TR")} nesne</span>
                    <span>{meta.counts.functions.toLocaleString("tr-TR")} fn</span>
                  </p>
                  <p className="mt-0.5 text-[10px] text-zinc-500">
                    {meta.hasFunctions ? "functions.json" : meta.hasNames ? "names-only" : "bos"}
                  </p>
                </div>
              </div>

              {/* alt sekmeler */}
              <Tabs
                value={subTab}
                onValueChange={(v) => setSubTab(v as SubTab)}
                className="mt-4"
              >
                <TabsList className="mb-4 bg-zinc-900/70">
                  <TabsTrigger
                    value="functions"
                    className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
                  >
                    Fonksiyonlar
                  </TabsTrigger>
                  <TabsTrigger
                    value="names"
                    className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
                  >
                    GNames
                  </TabsTrigger>
                  <TabsTrigger
                    value="objects"
                    className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
                  >
                    Nesneler
                  </TabsTrigger>
                  <TabsTrigger
                    value="codegen"
                    className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
                  >
                    Kod Uret
                  </TabsTrigger>
                </TabsList>

                {/* --- FONKSIYONLAR --- */}
                <TabsContent value="functions" className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                      <Input
                        value={fSearch}
                        onChange={(e) => {
                          setFSearch(e.target.value);
                          setFOffset(0);
                        }}
                        placeholder="Fonksiyon / sinif / paket ara..."
                        aria-label="Fonksiyon ara"
                        className="h-8 w-full max-w-[240px] border-zinc-700 bg-zinc-950/70 pl-7 text-xs"
                      />
                    </div>
                    <Select
                      value={fCls}
                      onValueChange={(v) => {
                        setFCls(v);
                        setFOffset(0);
                      }}
                    >
                      <SelectTrigger
                        className="h-8 w-[200px] border-zinc-700 bg-zinc-950/70 text-xs"
                        aria-label="Sinif filtresi"
                      >
                        <SelectValue placeholder="Sinif" />
                      </SelectTrigger>
                      <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
                        <SelectItem value={ALL_CLASSES}>Tum siniflar</SelectItem>
                        {(fData?.classes ?? []).map((c) => (
                          <SelectItem key={c} value={c}>
                            {c}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <span className="text-[11px] text-zinc-500">
                      {fLoading
                        ? "yukleniyor..."
                        : `${(fData?.total ?? 0).toLocaleString("tr-TR")} fonksiyon`}
                    </span>
                  </div>

                  <div className="max-h-[460px] overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/60 scrollbar-thin">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-zinc-800 hover:bg-transparent">
                          <TableHead className="text-[10px] text-zinc-500">Fonksiyon</TableHead>
                          <TableHead className="text-[10px] text-zinc-500">Sinif</TableHead>
                          <TableHead className="text-[10px] text-zinc-500">RVA</TableHead>
                          <TableHead className="text-[10px] text-zinc-500">ParamsSize</TableHead>
                          <TableHead className="text-[10px] text-zinc-500">Param</TableHead>
                          <TableHead className="text-[10px] text-zinc-500">Native</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {fLoading && (!fData || fData.items.length === 0) ? (
                          [...Array(5)].map((_, i) => (
                            <TableRow key={i} className="border-zinc-800">
                              <TableCell colSpan={6}>
                                <Skeleton className="h-4 w-3/4 bg-zinc-800/70" />
                              </TableCell>
                            </TableRow>
                          ))
                        ) : !fData || fData.items.length === 0 ? (
                          <TableRow className="border-zinc-800">
                            <TableCell colSpan={6} className="py-6 text-center text-xs text-zinc-500">
                              Fonksiyon verisi yok (functions.json bu kayitta bulunmuyor olabilir).
                            </TableCell>
                          </TableRow>
                        ) : (
                          fData.items.map((f, i) => (
                            <TableRow
                              key={`${f.cls}-${f.name}-${f.rva}-${offsetKey(i, fOffset)}`}
                              className="cursor-pointer border-zinc-800/70 hover:bg-zinc-900/70"
                              onClick={() => setSelectedFn(f)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  setSelectedFn(f);
                                }
                              }}
                              tabIndex={0}
                              role="button"
                              aria-label={`${f.cls || "Global"} sinifindan ${f.name} fonksiyon detayini ac`}
                            >
                              <TableCell className="max-w-[220px] truncate py-2 font-mono text-xs text-zinc-200">
                                {f.name}
                              </TableCell>
                              <TableCell className="max-w-[160px] truncate py-2 text-xs text-zinc-400">
                                {f.cls || "—"}
                              </TableCell>
                              <TableCell className="py-2 font-mono text-[11px] text-emerald-300/90">
                                {f.rva}
                              </TableCell>
                              <TableCell className="py-2 font-mono text-[11px] text-zinc-400">
                                {f.paramsSize}
                              </TableCell>
                              <TableCell className="py-2 text-xs text-zinc-400">
                                {f.params.length}
                              </TableCell>
                              <TableCell className="py-2">
                                {f.native === "0x0" ? (
                                  <Badge variant="outline" className="border-amber-500/40 text-[9px] text-amber-300">
                                    BP-only
                                  </Badge>
                                ) : (
                                  <span className="font-mono text-[11px] text-zinc-400">{f.native}</span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                  {fData && (
                    <Pager
                      total={fData.total}
                      offset={fData.offset}
                      limit={fData.limit}
                      onPrev={() => setFOffset(Math.max(0, fOffset - PAGE_SIZE))}
                      onNext={() => setFOffset(fOffset + PAGE_SIZE)}
                    />
                  )}
                </TabsContent>

                {/* --- GNAMES --- */}
                <TabsContent value="names" className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                      <Input
                        value={nSearch}
                        onChange={(e) => {
                          setNSearch(e.target.value);
                          setNOffset(0);
                        }}
                        placeholder="GName ara..."
                        aria-label="GName ara"
                        className="h-8 w-full max-w-[240px] border-zinc-700 bg-zinc-950/70 pl-7 text-xs"
                      />
                    </div>
                    <span className="text-[11px] text-zinc-500">
                      {nLoading
                        ? "yukleniyor..."
                        : `${(nData?.total ?? 0).toLocaleString("tr-TR")} isim`}
                    </span>
                  </div>

                  {nLoading && (!nData || nData.items.length === 0) ? (
                    <div className="space-y-1.5">
                      {[0, 1, 2, 3, 4, 5].map((i) => (
                        <Skeleton key={i} className="h-6 w-full rounded-md bg-zinc-800/60" />
                      ))}
                    </div>
                  ) : !nData || nData.items.length === 0 ? (
                    <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-6 text-center text-xs text-zinc-500">
                      GName verisi yok (names.json / Names.txt bu kayitta bulunmuyor olabilir).
                    </div>
                  ) : (
                    <ScrollArea className="h-[460px] rounded-lg border border-zinc-800 bg-zinc-950/60">
                      <ul className="divide-y divide-zinc-800/60" aria-label="GName listesi">
                        {nData.items.map((n) => (
                          <li
                            key={n.index}
                            className="flex items-center gap-3 px-3 py-1.5 transition hover:bg-zinc-900/70"
                          >
                            <span className="w-16 shrink-0 text-right font-mono text-[11px] text-zinc-500">
                              {n.index}
                            </span>
                            <span className="truncate font-mono text-xs text-zinc-200">{n.name}</span>
                          </li>
                        ))}
                      </ul>
                    </ScrollArea>
                  )}
                  {nData && (
                    <Pager
                      total={nData.total}
                      offset={nData.offset}
                      limit={nData.limit}
                      onPrev={() => setNOffset(Math.max(0, nOffset - PAGE_SIZE))}
                      onNext={() => setNOffset(nOffset + PAGE_SIZE)}
                    />
                  )}
                </TabsContent>

                {/* --- NESNELER --- */}
                <TabsContent value="objects" className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                      <Input
                        value={oSearch}
                        onChange={(e) => {
                          setOSearch(e.target.value);
                          setOOffset(0);
                        }}
                        placeholder="Nesne / sinif / yol ara..."
                        aria-label="Nesne ara"
                        className="h-8 w-full max-w-[240px] border-zinc-700 bg-zinc-950/70 pl-7 text-xs"
                      />
                    </div>
                    <span className="text-[11px] text-zinc-500">
                      {oLoading
                        ? "yukleniyor..."
                        : `${(oData?.total ?? 0).toLocaleString("tr-TR")} nesne`}
                    </span>
                  </div>

                  {oLoading && (!oData || oData.items.length === 0) ? (
                    <div className="space-y-1.5">
                      {[0, 1, 2, 3, 4, 5].map((i) => (
                        <Skeleton key={i} className="h-6 w-full rounded-md bg-zinc-800/60" />
                      ))}
                    </div>
                  ) : !oData || oData.items.length === 0 ? (
                    <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-6 text-center text-xs text-zinc-500">
                      Nesne verisi yok (objects.json / Objects.txt bu kayitta bulunmuyor olabilir).
                    </div>
                  ) : (
                    <ScrollArea className="h-[460px] rounded-lg border border-zinc-800 bg-zinc-950/60">
                      <ul className="divide-y divide-zinc-800/60" aria-label="Nesne listesi">
                        {oData.items.map((o) => (
                          <li
                            key={o.index}
                            className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5 transition hover:bg-zinc-900/70"
                          >
                            <span className="w-14 shrink-0 text-right font-mono text-[11px] text-zinc-500">
                              {o.index}
                            </span>
                            {o.invalid ? (
                              <Badge variant="outline" className="border-red-500/40 text-[9px] text-red-300">
                                gecersiz kayit
                              </Badge>
                            ) : (
                              <>
                                <Badge
                                  variant="outline"
                                  className="shrink-0 border-zinc-700 text-[9px] text-zinc-400"
                                >
                                  {o.cls || "?"}
                                </Badge>
                                <span className="font-mono text-xs text-zinc-200">{o.name || "—"}</span>
                                {o.path && (
                                  <span className="truncate font-mono text-[10px] text-zinc-500">
                                    {o.path}
                                  </span>
                                )}
                                <span className="ml-auto shrink-0 font-mono text-[10px] text-emerald-300/80">
                                  {o.address}
                                </span>
                              </>
                            )}
                          </li>
                        ))}
                      </ul>
                    </ScrollArea>
                  )}
                  {oData && (
                    <Pager
                      total={oData.total}
                      offset={oData.offset}
                      limit={oData.limit}
                      onPrev={() => setOOffset(Math.max(0, oOffset - PAGE_SIZE))}
                      onNext={() => setOOffset(oOffset + PAGE_SIZE)}
                    />
                  )}
                </TabsContent>

                {/* --- KOD URET --- */}
                <TabsContent value="codegen" className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Select value={cLang} onValueChange={setCLang}>
                      <SelectTrigger
                        className="h-8 w-[150px] border-zinc-700 bg-zinc-950/70 text-xs"
                        aria-label="Kod dili"
                      >
                        <SelectValue placeholder="Dil" />
                      </SelectTrigger>
                      <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
                        {CODEGEN_LANGS.map((l) => (
                          <SelectItem key={l.id} value={l.id}>
                            {l.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={cKind} onValueChange={setCKind}>
                      <SelectTrigger
                        className="h-8 w-[150px] border-zinc-700 bg-zinc-950/70 text-xs"
                        aria-label="Veri turu"
                      >
                        <SelectValue placeholder="Veri turu" />
                      </SelectTrigger>
                      <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
                        {CODEGEN_KINDS.map((k) => (
                          <SelectItem key={k.id} value={k.id}>
                            {k.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      size="sm"
                      className="h-8 bg-emerald-600 text-zinc-950 hover:bg-emerald-500"
                      onClick={() => void genCode()}
                      disabled={cLoading}
                      aria-label="Kod uret"
                    >
                      {cLoading ? (
                        <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Play className="mr-1.5 h-3.5 w-3.5" />
                      )}
                      Uret
                    </Button>
                    {cCount !== null && (
                      <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
                        {cCount.toLocaleString("tr-TR")} oge
                      </Badge>
                    )}
                  </div>

                  <div className="rounded-lg border border-zinc-800 bg-zinc-950/60">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-3 py-2">
                      <p className="font-mono text-xs text-zinc-300">
                        {cFilename || "uretim icin Uret tusuna basin"}
                      </p>
                      <div className="flex items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 border-zinc-700 px-2 text-[11px]"
                          onClick={() => void copyCode()}
                          disabled={!cText}
                          aria-label="Uretilen kodu kopyala"
                        >
                          {copied ? (
                            <Check className="mr-1 h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="mr-1 h-3 w-3" />
                          )}
                          Kopyala
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 border-zinc-700 px-2 text-[11px]"
                          onClick={downloadCode}
                          disabled={!cText}
                          aria-label="Uretilen kodu indir"
                        >
                          <Download className="mr-1 h-3 w-3" />
                          Indir
                        </Button>
                      </div>
                    </div>
                    <ScrollArea className="h-[460px]">
                      <pre className="whitespace-pre p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
                        {cLoading
                          ? "// kod uretiliyor..."
                          : cText || "// Dil ve tur secin, sonra Uret tusuna basin."}
                      </pre>
                    </ScrollArea>
                  </div>
                </TabsContent>
              </Tabs>
            </>
          )}
        </section>
      )}

      {/* ---------------- FONKSIYON DETAY DIYALOGU ---------------- */}
      <Dialog open={selectedFn !== null} onOpenChange={(o) => !o && setSelectedFn(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto border-zinc-700 bg-zinc-950 text-zinc-100 sm:max-w-2xl">
          {selectedFn && (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-sm text-zinc-100">
                  {selectedFn.cls ? `${selectedFn.cls}::` : ""}
                  {selectedFn.name}
                </DialogTitle>
                <DialogDescription className="text-[11px] text-zinc-500">
                  {selectedFn.pkg || "paket bilgisi yok"}
                  {selectedFn.native === "0x0" ? " · BP-only (native 0x0)" : " · native fonksiyon"}
                </DialogDescription>
              </DialogHeader>

              {/* semantik ozet */}
              {selectedSem && (
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${categoryBadgeClass(selectedSem.category)}`}
                    >
                      {selectedSem.category} · guven {Math.round(selectedSem.confidence * 100)}%
                    </Badge>
                  </div>
                  <dl className="mt-2 space-y-1 text-[11px] leading-relaxed">
                    <div>
                      <dt className="inline font-medium text-zinc-400">Ozet: </dt>
                      <dd className="inline text-zinc-300">{selectedSem.summary}</dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-zinc-400">Hesapladigi: </dt>
                      <dd className="inline text-zinc-300">{selectedSem.computes}</dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-zinc-400">Etki: </dt>
                      <dd className="inline text-zinc-300">{selectedSem.writes}</dd>
                    </div>
                  </dl>
                </div>
              )}

              {/* adresler */}
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {[
                  { k: "RVA", v: selectedFn.rva },
                  { k: "VA", v: selectedFn.va },
                  { k: "UFunction", v: selectedFn.ufunction },
                  { k: "Native", v: selectedFn.native },
                  { k: "ParamsSize", v: selectedFn.paramsSize },
                  { k: "Flags", v: selectedFn.flags },
                ].map((x) => (
                  <div key={x.k} className="rounded-md border border-zinc-800 bg-zinc-900/60 px-2 py-1.5">
                    <p className="text-[9px] uppercase tracking-wide text-zinc-500">{x.k}</p>
                    <p className="font-mono text-[11px] text-zinc-200">{x.v || "0x0"}</p>
                  </div>
                ))}
              </div>

              {/* parametreler */}
              <div className="max-h-[280px] overflow-y-auto rounded-lg border border-zinc-800 scrollbar-thin">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-[10px] text-zinc-500">Param</TableHead>
                      <TableHead className="text-[10px] text-zinc-500">Tip</TableHead>
                      <TableHead className="text-[10px] text-zinc-500">Offset</TableHead>
                      <TableHead className="text-[10px] text-zinc-500">Boyut</TableHead>
                      <TableHead className="text-[10px] text-zinc-500">Flags</TableHead>
                      <TableHead className="text-[10px] text-zinc-500">Hedef</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedFn.params.length === 0 && !selectedFn.ret && (
                      <TableRow className="border-zinc-800">
                        <TableCell colSpan={6} className="py-4 text-center text-xs text-zinc-500">
                          Parametre yok.
                        </TableCell>
                      </TableRow>
                    )}
                    {selectedFn.params.map((p, i) => {
                      const sem = explainField(p.name, p.type, selectedFn.cls || undefined);
                      return (
                        <TableRow key={`${p.name}-${i}`} className="border-zinc-800/70">
                          <TableCell className="py-1.5 font-mono text-xs text-zinc-200">
                            {p.name}
                            <Badge
                              variant="outline"
                              className={`ml-1.5 text-[9px] ${categoryBadgeClass(sem.category)}`}
                            >
                              {sem.category}
                            </Badge>
                          </TableCell>
                          <TableCell className="py-1.5 text-xs text-zinc-400">
                            {p.type}
                            {p.target ? ` -> ${p.target}` : ""}
                          </TableCell>
                          <TableCell className="py-1.5 font-mono text-[11px] text-zinc-300">{p.offset}</TableCell>
                          <TableCell className="py-1.5 font-mono text-[11px] text-zinc-400">{p.size}</TableCell>
                          <TableCell className="py-1.5 font-mono text-[11px] text-zinc-500">{p.flags}</TableCell>
                          <TableCell className="py-1.5 font-mono text-[11px] text-zinc-500">{p.target || "—"}</TableCell>
                        </TableRow>
                      );
                    })}
                    {selectedFn.ret && (
                      <TableRow className="border-emerald-500/30 bg-emerald-500/5">
                        <TableCell className="py-1.5 font-mono text-xs text-emerald-300">
                          {selectedFn.ret.name}
                          <Badge variant="outline" className="ml-1.5 border-emerald-500/40 text-[9px] text-emerald-300">
                            donus
                          </Badge>
                        </TableCell>
                        <TableCell className="py-1.5 text-xs text-zinc-400">{selectedFn.ret.type}</TableCell>
                        <TableCell className="py-1.5 font-mono text-[11px] text-zinc-300">{selectedFn.ret.offset}</TableCell>
                        <TableCell className="py-1.5 font-mono text-[11px] text-zinc-400">{selectedFn.ret.size}</TableCell>
                        <TableCell className="py-1.5 font-mono text-[11px] text-zinc-500">{selectedFn.ret.flags}</TableCell>
                        <TableCell className="py-1.5 font-mono text-[11px] text-zinc-500">
                          {selectedFn.ret.target || "—"}
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ---------------- SILME ONAYI ---------------- */}
      <AlertDialog open={deleteTarget !== null} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <AlertDialogContent className="border-zinc-700 bg-zinc-950 text-zinc-100">
          <AlertDialogHeader>
            <AlertDialogTitle>Kaydi sil?</AlertDialogTitle>
            <AlertDialogDescription className="text-xs text-zinc-400">
              &quot;{deleteTarget?.label}&quot; kaydi ve storage/dumperpro altindaki ham
              dosyalari kalici olarak silinecek. Bu islem geri alinamaz.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800">
              Iptal
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 text-white hover:bg-red-500"
              onClick={() => {
                if (deleteTarget) void doDelete(deleteTarget.id);
                setDeleteTarget(null);
              }}
            >
              Sil
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** satir anahtari icin indeks + ofset karisimi (ayni isim+adres cakismasi). */
function offsetKey(i: number, offset: number): number {
  return offset + i;
}
