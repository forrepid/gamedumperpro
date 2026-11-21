"use client";

// ----------------------------------------------------------------------------
// Pattern Visual Scanner - desen tanımlama + görselleştirme + imza çıkarıcı
//   - IDA tarzı desen girişi (nibble mask: "4?" / "?8" destekli)
//   - canlı token önizleme + özgüllük istatistikleri
//   - eşleşme başına görsel bayt şeridi (literal / nibble / joker renk kodlu)
//   - "Sig Çıkar": eşleşme çevresinden otomatik IDA/x64dbg/C++/Python imzası
//     (C++ motoru BuildExtendedSig'in web portu)
// ----------------------------------------------------------------------------

import { useMemo, useState } from "react";
import { Crosshair, Loader2, ScanSearch } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { compilePattern, patternStats, type PatToken, type PatternStats } from "@/lib/analysis/pattern";
import type { PeInfo } from "@/lib/analysis/types";

// ---------------------------------------------------------------------------
// tipler
// ---------------------------------------------------------------------------

interface ScanMatch {
  off: number;
  rva?: number;
  va?: number;
  section?: string;
  hex: string;
  contextBefore: string;
  contextAfter: string;
}

interface ScanResponse {
  ok: boolean;
  error?: string;
  pattern?: string;
  rendered?: string;
  stats?: PatternStats;
  total?: number;
  truncated?: boolean;
  scanned?: number;
  matches?: ScanMatch[];
}

interface ExtractResponse {
  ok: boolean;
  error?: string;
  off?: number;
  rva?: number;
  va?: number;
  section?: string;
  length?: number;
  rendered?: string;
  formats?: { ida: string; x64dbg: string; cpp: string; py: string };
  stats?: PatternStats;
}

interface Preset {
  name: string;
  pattern: string;
}

// sigs.ts'teki sabit adaylar + nibble ornekleri
const PRESETS: Preset[] = [
  { name: "GObjects (GUObjectArray)", pattern: "48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8" },
  { name: "GObjects (zincir)", pattern: "48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8" },
  { name: "GNames (FNamePool UE5)", pattern: "4C 8D 35 ?? ?? ?? ?? EB 16" },
  { name: "GNames (FNamePool v2)", pattern: "48 8D 35 ?? ?? ?? ?? EB 16" },
  { name: "ProcessEvent", pattern: "4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 41 56 41 57 48 81 EC ?? ?? ?? ??" },
  { name: "PostRender", pattern: "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 48 8B F9 48 8B DA 48 8B 49 60" },
  { name: "GObjects (REX gevşek · nibble)", pattern: "4? 8B 05 ?? ?? ?? ??" },
  { name: "x64 prolog (REX.W · nibble)", pattern: "4? 89 ?? ?? 5?" },
];

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i + 1 < hex.length; i += 2) {
    out.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

function formatNum(n: number): string {
  if (n >= 2 ** 50) return `~${(n / 2 ** 50).toFixed(1)} PB`;
  if (n >= 2 ** 40) return `~${(n / 2 ** 40).toFixed(1)} TB`;
  if (n >= 2 ** 30) return `~${(n / 2 ** 30).toFixed(1)} GB`;
  if (n >= 2 ** 20) return `~${(n / 2 ** 20).toFixed(1)} MB`;
  if (n >= 2 ** 10) return `~${(n / 2 ** 10).toFixed(1)} KB`;
  return `~${Math.round(n)} B`;
}

function statLabel(s: PatternStats): string {
  return `özgüllük: ${s.specificityLabel} (${formatNum(s.specificityBytes)}'de 1)`;
}

// ---------------------------------------------------------------------------
// renk yardımcıları
// ---------------------------------------------------------------------------

function tokenClass(t: PatToken | undefined): string {
  switch (t?.kind) {
    case "exact":
      return "bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-600/40";
    case "hi":
    case "lo":
      return "bg-amber-500/10 text-amber-300 ring-1 ring-amber-600/40";
    case "wild":
      return "bg-zinc-700/40 text-zinc-400 ring-1 ring-zinc-700/60";
    default:
      return "bg-zinc-700/30 text-zinc-500 ring-1 ring-zinc-700/50";
  }
}

function tokenLabel(t: PatToken | undefined): string {
  switch (t?.kind) {
    case "exact":
      return t.value.toString(16).toUpperCase().padStart(2, "0");
    case "hi":
      return `${t.hi.toString(16).toUpperCase()}?`;
    case "lo":
      return `?${t.lo.toString(16).toUpperCase()}`;
    case "wild":
      return "??";
    default:
      return "??";
  }
}

function ByteStrip({ tokens, before, after }: { tokens: PatToken[]; before: string; after: string }) {
  const beforeBytes = hexToBytes(before);
  const afterBytes = hexToBytes(after);
  return (
    <div className="flex flex-wrap items-center gap-1 overflow-x-auto pb-1">
      {beforeBytes.map((b, i) => (
        <span key={`b${i}`} className="rounded px-1.5 py-0.5 font-mono text-[10px] text-zinc-500 ring-1 ring-zinc-800/60">
          {b.toString(16).padStart(2, "0")}
        </span>
      ))}
      {tokens.map((t, i) => (
        <span key={`m${i}`} className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${tokenClass(t)}`} title={t.kind}>
          {tokenLabel(t)}
        </span>
      ))}
      {afterBytes.map((b, i) => (
        <span key={`a${i}`} className="rounded px-1.5 py-0.5 font-mono text-[10px] text-zinc-500 ring-1 ring-zinc-800/60">
          {b.toString(16).padStart(2, "0")}
        </span>
      ))}
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-zinc-500">
      <span className="flex items-center gap-1">
        <span className="h-2.5 w-2.5 rounded ring-1 ring-emerald-600/40 bg-emerald-500/10" /> literal
      </span>
      <span className="flex items-center gap-1">
        <span className="h-2.5 w-2.5 rounded ring-1 ring-amber-600/40 bg-amber-500/10" /> nibble (4? / ?8)
      </span>
      <span className="flex items-center gap-1">
        <span className="h-2.5 w-2.5 rounded ring-1 ring-zinc-700/60 bg-zinc-700/40" /> joker (??)
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ana bileşen
// ---------------------------------------------------------------------------

export default function PatternVisualScanner({
  uploadId,
  pe,
  onJumpHex,
}: {
  uploadId: string;
  pe?: PeInfo;
  onJumpHex?: (off: number) => void;
}) {
  const { toast } = useToast();
  const [patternText, setPatternText] = useState("48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8");
  const [section, setSection] = useState("all");
  const [maxHits, setMaxHits] = useState("16");
  const [scanning, setScanning] = useState(false);
  const [scan, setScan] = useState<ScanResponse | null>(null);

  // cikarici diyalogu
  const [extMatch, setExtMatch] = useState<ScanMatch | null>(null);
  const [extBefore, setExtBefore] = useState("8");
  const [extAfter, setExtAfter] = useState("8");
  const [maskMode, setMaskMode] = useState(true);
  const [extracting, setExtracting] = useState(false);
  const [extract, setExtract] = useState<ExtractResponse | null>(null);

  const compiled = useMemo(() => compilePattern(patternText), [patternText]);

  const doScan = async () => {
    if (!compiled.ok) {
      toast({ title: "Geçersiz desen", description: compiled.error, variant: "destructive" });
      return;
    }
    setScanning(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/pattern`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "scan",
          pattern: patternText,
          section,
          maxHits: parseInt(maxHits, 10) || 16,
        }),
      });
      const data = (await res.json()) as ScanResponse;
      if (!data.ok) {
        toast({ title: "Tarama başarısız", description: data.error, variant: "destructive" });
        setScan(null);
        return;
      }
      setScan(data);
      if ((data.total ?? 0) === 0) {
        toast({ title: "Eşleşme yok", description: `${data.rendered} için ${data.scanned ?? 0} bayt tarandı` });
      }
    } catch {
      toast({ title: "Tarama hatası", variant: "destructive" });
    } finally {
      setScanning(false);
    }
  };

  const openExtractor = async (m: ScanMatch) => {
    setExtMatch(m);
    setExtract(null);
    const b = parseInt(extBefore, 10) || 8;
    const a = parseInt(extAfter, 10) || 8;
    setExtracting(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/pattern`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "extract",
          off: m.off,
          before: b,
          after: a,
          pattern: patternText,
          maskMode: maskMode ? "pattern" : "keep",
        }),
      });
      const data = (await res.json()) as ExtractResponse;
      if (!data.ok) {
        toast({ title: "Çıkarma başarısız", description: data.error, variant: "destructive" });
        return;
      }
      setExtract(data);
    } catch {
      toast({ title: "Çıkarma hatası", variant: "destructive" });
    } finally {
      setExtracting(false);
    }
  };

  const rerunExtract = async (nb: string, na: string, mm: boolean) => {
    if (!extMatch) return;
    const b = Math.max(0, Math.min(parseInt(nb, 10) || 0, 64));
    const a = Math.max(0, Math.min(parseInt(na, 10) || 0, 64));
    setExtracting(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/pattern`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "extract",
          off: extMatch.off,
          before: b,
          after: a,
          pattern: patternText,
          maskMode: mm ? "pattern" : "keep",
        }),
      });
      const data = (await res.json()) as ExtractResponse;
      setExtract(data.ok ? data : null);
      if (!data.ok) toast({ title: "Çıkarma başarısız", description: data.error, variant: "destructive" });
    } catch {
      toast({ title: "Çıkarma hatası", variant: "destructive" });
    } finally {
      setExtracting(false);
    }
  };

  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({ title: `${label} kopyalandı` });
    } catch {
      toast({ title: "Kopyalanamadı", variant: "destructive" });
    }
  };

  const extractTokens: PatToken[] | null = useMemo(() => {
    if (!extract?.rendered) return null;
    const c = compilePattern(extract.rendered);
    return c.ok ? c.tokens : null;
  }, [extract]);

  return (
    <div className="space-y-3 rounded-lg border border-emerald-800/30 bg-emerald-950/10 p-4">
      {/* ---------------- desen tanimlama ---------------- */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
          <ScanSearch className="h-3.5 w-3.5" /> Pattern Visual Scanner
        </p>
        <Legend />
      </div>
      <p className="text-[11px] leading-relaxed text-zinc-400">
        Kendi byte desenini tanımla ve görsel olarak tara: <span className="font-mono text-zinc-300">48 8B 05 ??</span> ·
        nibble maskesi destekli <span className="font-mono text-zinc-300">4? / ?8</span> (C++ motoru PatByte ile birebir) ·
        eşleşmelerden otomatik imza çıkar (IDA / x64dbg / C++ / Python).
      </p>

      <div className="flex flex-col gap-2 lg:flex-row lg:items-start">
        <div className="min-w-0 flex-1 space-y-1.5">
          <Label htmlFor="pv-pattern" className="text-[11px] text-zinc-400">
            Byte deseni
          </Label>
          <Input
            id="pv-pattern"
            value={patternText}
            onChange={(e) => {
              setPatternText(e.target.value);
              setScan(null);
            }}
            placeholder="48 8B 05 ?? ?? ?? ??"
            spellCheck={false}
            className="border-zinc-700 bg-zinc-950/70 font-mono text-xs text-zinc-100 focus-visible:ring-emerald-600/40"
          />
          {/* canli token onizleme */}
          {compiled.ok ? (
            <div className="flex flex-wrap items-center gap-1 pt-0.5">
              {compiled.tokens.map((t, i) => (
                <span key={i} className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${tokenClass(t)}`}>
                  {tokenLabel(t)}
                </span>
              ))}
            </div>
          ) : (
            <p className="pt-0.5 text-[11px] text-red-300/90">{compiled.error}</p>
          )}
        </div>
        <div className="flex flex-col gap-2 lg:w-52">
          <div className="space-y-1.5">
            <Label className="text-[11px] text-zinc-400">Bölüm</Label>
            <Select value={section} onValueChange={setSection}>
              <SelectTrigger className="h-9 border-zinc-700 bg-zinc-950/70 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-950">
                <SelectItem value="all" className="text-xs">
                  Tüm bölümler
                </SelectItem>
                {(pe?.sections ?? []).map((s) => (
                  <SelectItem key={s.name} value={s.name} className="text-xs">
                    {s.name} ({formatNum(s.rawSize)})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-end gap-2">
            <div className="w-24 space-y-1.5">
              <Label className="text-[11px] text-zinc-400">En fazla</Label>
              <Select value={maxHits} onValueChange={setMaxHits}>
                <SelectTrigger className="h-9 border-zinc-700 bg-zinc-950/70 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-950">
                  {[8, 16, 32, 64, 128].map((n) => (
                    <SelectItem key={n} value={String(n)} className="text-xs">
                      {n} eşleşme
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              className="h-9 flex-1 bg-emerald-600 text-zinc-950 hover:bg-emerald-500"
              disabled={scanning || !compiled.ok}
              onClick={doScan}
            >
              {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
              Tara
            </Button>
          </div>
        </div>
      </div>

      {/* hazir desenler */}
      <div className="space-y-1">
        <p className="text-[11px] text-zinc-500">Hazır desenler:</p>
        <div className="flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.name}
              type="button"
              title={p.pattern}
              onClick={() => {
                setPatternText(p.pattern);
                setScan(null);
              }}
              className="rounded-md border border-zinc-700/70 bg-zinc-900/70 px-2 py-1 text-[10px] text-zinc-300 transition-colors hover:border-emerald-700/60 hover:bg-emerald-600/10 hover:text-emerald-300"
            >
              {p.name}
            </button>
          ))}
        </div>
      </div>

      {/* istatistik rozetleri */}
      {compiled.ok && (
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
            {compiled.tokens.length} bayt
          </Badge>
          <Badge variant="outline" className="border-emerald-700/50 text-[10px] text-emerald-300">
            {compiled.tokens.filter((t) => t.kind === "exact").length} literal
          </Badge>
          {compiled.tokens.some((t) => t.kind === "hi" || t.kind === "lo") && (
            <Badge variant="outline" className="border-amber-700/50 text-[10px] text-amber-300">
              {compiled.tokens.filter((t) => t.kind === "hi" || t.kind === "lo").length} nibble
            </Badge>
          )}
          <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
            {compiled.tokens.filter((t) => t.kind === "wild").length} joker
          </Badge>
          <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
            {statLabel(patternStats(compiled.tokens))}
          </Badge>
        </div>
      )}

      {/* ---------------- tarama sonucu ---------------- */}
      {scan?.ok && (
        <div className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-zinc-300">
              <span className="font-semibold text-emerald-300">{scan.total}</span> eşleşme · {scan.scanned?.toLocaleString("tr-TR")} bayt tarandı
              {scan.truncated ? " · daha fazlası var (limit doldu)" : ""}
            </p>
            <p className="font-mono text-[10px] text-zinc-500">{scan.rendered}</p>
          </div>
          {(scan.matches ?? []).length === 0 ? (
            <p className="text-[11px] text-zinc-500">Bu desen için eşleşme bulunamadı.</p>
          ) : (
            <ScrollArea className="max-h-96">
              <div className="space-y-2 pr-3">
                {(scan.matches ?? []).map((m, i) => (
                  <div key={i} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px]">
                        <span className="text-zinc-300">
                          off: <span className="text-zinc-100">0x{m.off.toString(16).toUpperCase()}</span>
                        </span>
                        {m.rva !== undefined && (
                          <span className="text-zinc-400">
                            rva: <span className="text-zinc-100">0x{m.rva.toString(16).toUpperCase()}</span>
                          </span>
                        )}
                        {m.va !== undefined && (
                          <span className="text-zinc-400">
                            va: <span className="text-zinc-100">0x{m.va.toString(16).toUpperCase()}</span>
                          </span>
                        )}
                        {m.section && (
                          <Badge variant="outline" className="border-zinc-700 px-1.5 py-0 text-[9px] text-zinc-400">
                            {m.section}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {onJumpHex && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 px-2 text-[10px] text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                            onClick={() => onJumpHex(m.off)}
                          >
                            Hex&apos;e git
                          </Button>
                        )}
                        <Button
                          size="sm"
                          className="h-7 border-emerald-700/50 bg-emerald-600/15 px-2 text-[10px] text-emerald-300 hover:bg-emerald-600/25"
                          onClick={() => openExtractor(m)}
                        >
                          <Crosshair className="mr-1 h-3 w-3" /> Sig çıkar
                        </Button>
                      </div>
                    </div>
                    <div className="mt-1.5">
                      <ByteStrip tokens={compiled.tokens} before={m.contextBefore} after={m.contextAfter} />
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </div>
      )}

      {/* ---------------- imza cikarici diyalogu ---------------- */}
      <Dialog
        open={extMatch !== null}
        onOpenChange={(o) => {
          if (!o) setExtMatch(null);
        }}
      >
        <DialogContent className="max-w-2xl border-zinc-800 bg-zinc-950">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm text-zinc-100">
              <Crosshair className="h-4 w-4 text-emerald-400" /> İmza Çıkarıcı
              {extMatch && (
                <span className="font-mono text-[11px] font-normal text-zinc-400">
                  @ 0x{extMatch.off.toString(16).toUpperCase()}
                </span>
              )}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-3">
            {/* parametreler */}
            <div className="flex flex-wrap items-end gap-3">
              <div className="w-20 space-y-1">
                <Label className="text-[10px] text-zinc-400">Önce</Label>
                <Input
                  type="number"
                  min={0}
                  max={64}
                  value={extBefore}
                  onChange={(e) => {
                    setExtBefore(e.target.value);
                    rerunExtract(e.target.value, extAfter, maskMode);
                  }}
                  className="h-8 border-zinc-700 bg-zinc-900/60 font-mono text-xs"
                />
              </div>
              <div className="w-20 space-y-1">
                <Label className="text-[10px] text-zinc-400">Sonra</Label>
                <Input
                  type="number"
                  min={0}
                  max={64}
                  value={extAfter}
                  onChange={(e) => {
                    setExtAfter(e.target.value);
                    rerunExtract(extBefore, e.target.value, maskMode);
                  }}
                  className="h-8 border-zinc-700 bg-zinc-900/60 font-mono text-xs"
                />
              </div>
              <div className="flex items-center gap-2 pb-1">
                <Switch
                  checked={maskMode}
                  onCheckedChange={(v) => {
                    setMaskMode(v);
                    rerunExtract(extBefore, extAfter, v);
                  }}
                />
                <Label className="text-[10px] text-zinc-400">Jokerleri koru (rel32/imm32 hayatta kalır)</Label>
              </div>
            </div>

            {extracting ? (
              <div className="flex items-center gap-2 py-6 text-xs text-zinc-400">
                <Loader2 className="h-4 w-4 animate-spin" /> İmza çıkarılıyor...
              </div>
            ) : extract?.ok ? (
              <>
                {/* cikarilan imza seridi */}
                <div className="rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5">
                  <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-[11px] text-zinc-400">
                      0x{extract.off?.toString(16).toUpperCase()} · {extract.length} bayt
                      {extract.rva !== undefined && ` · rva 0x${extract.rva.toString(16).toUpperCase()}`}
                      {extract.section && ` · ${extract.section}`}
                    </span>
                    {extract.stats && (
                      <Badge className="bg-emerald-600/15 text-[10px] text-emerald-300 ring-1 ring-emerald-600/40">
                        {statLabel(extract.stats)}
                      </Badge>
                    )}
                  </div>
                  {extractTokens && (
                    <div className="flex flex-wrap gap-1">
                      {extractTokens.map((t, i) => (
                        <span key={i} className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${tokenClass(t)}`}>
                          {tokenLabel(t)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* format sekmeleri */}
                <Tabs defaultValue="ida" className="w-full">
                  <TabsList className="bg-zinc-900/70">
                    <TabsTrigger value="ida" className="text-[11px] data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300">
                      IDA / CE
                    </TabsTrigger>
                    <TabsTrigger value="x64dbg" className="text-[11px] data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300">
                      x64dbg
                    </TabsTrigger>
                    <TabsTrigger value="cpp" className="text-[11px] data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300">
                      C++
                    </TabsTrigger>
                    <TabsTrigger value="py" className="text-[11px] data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300">
                      Python
                    </TabsTrigger>
                  </TabsList>
                  {(["ida", "x64dbg", "cpp", "py"] as const).map((k) => (
                    <TabsContent key={k} value={k} className="mt-2">
                      <div className="flex items-start gap-2">
                        <pre className="max-h-40 min-w-0 flex-1 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950/80 p-2.5 font-mono text-[11px] leading-relaxed text-zinc-300 scrollbar-thin">
                          {extract.formats?.[k]}
                        </pre>
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                          onClick={() => copyText(extract.formats?.[k] ?? "", "İmza")}
                        >
                          Kopyala
                        </Button>
                      </div>
                    </TabsContent>
                  ))}
                </Tabs>
              </>
            ) : (
              <p className="py-4 text-xs text-zinc-500">İmza çıkarılamadı.</p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

