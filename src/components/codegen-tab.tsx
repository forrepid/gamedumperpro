"use client";

// ----------------------------------------------------------------------------
// Kod Uretici sekmesi: cikarilan fonksiyon/struct/enum/dize verilerini secilen
// programlama diline gore uretir (pointer/offset/RVA/VA/AOB/sub dahil) ve her
// ogeyi semantik olarak aciklar (yerel sozluk + istenirse AI derin aciklama).
// ----------------------------------------------------------------------------

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BadgeCheck,
  Brain,
  Check,
  Copy,
  Download,
  Loader2,
  Sparkles,
  Wand2,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { tokenizeCodegenLine } from "@/lib/codegen-highlight";
import {
  explainEnum,
  explainFunction,
  explainString,
  explainStruct,
  type SemanticInfo,
} from "@/lib/analysis/semantics";
import type { FunctionEntry, RecoveredEnum, RecoveredStruct } from "@/lib/analysis/types";

/** CodegenTab'in ihtiyac duydugu minimal sekil (analyzer'in AnalysisResultShape ile birebir uyumlu) */
export interface CodegenResultData {
  strings: { value: string; kind: string }[];
  functions?: {
    total: number;
    functions: {
      idx: number;
      rva: number;
      va: number;
      size: number;
      label?: string;
      section?: string;
      prologue?: string;
      strings: string[];
      apiCalls: string[];
      callsOut: number;
      xrefsIn: number;
      structHint?: string;
      pseudo?: string;
    }[];
  };
  structs?: {
    total: number;
    structs: {
      name: string;
      kind?: string;
      size?: number;
      vftableRva?: number;
      methodCount?: number;
      fields: { name: string; offset: number; size: number; type: string; reads: number }[];
      source?: string;
    }[];
  };
  enums?: {
    total: number;
    enums: {
      name: string;
      source?: string;
      members: { name: string; value: number }[];
    }[];
  };
}

const LANGUAGES: { id: string; label: string }[] = [
  { id: "cpp", label: "C++" },
  { id: "csharp", label: "C#" },
  { id: "python", label: "Python" },
  { id: "rust", label: "Rust" },
  { id: "typescript", label: "TypeScript" },
  { id: "java", label: "Java" },
  { id: "lua", label: "Lua" },
  { id: "json", label: "JSON" },
];

const KINDS: { id: "functions" | "structs" | "enums" | "strings"; label: string }[] = [
  { id: "functions", label: "Fonksiyonlar" },
  { id: "structs", label: "Structlar" },
  { id: "enums", label: "Enumlar" },
  { id: "strings", label: "Dizeler" },
];

interface ListItem {
  key: string;
  title: string;
  sub: string;
  sem: SemanticInfo;
  artifact: Record<string, unknown>;
  aiType: string;
}

function categoryBadgeClass(cat: string): string {
  if (cat.includes("Saglik") || cat.includes("Karakter")) return "border-red-500/40 text-red-300 bg-red-500/10";
  if (cat.includes("Silah") || cat.includes("Hasar")) return "border-orange-500/40 text-orange-300 bg-orange-500/10";
  if (cat.includes("Ekonomi") || cat.includes("Para")) return "border-yellow-500/40 text-yellow-300 bg-yellow-500/10";
  if (cat.includes("Ilerleme") || cat.includes("Seviye")) return "border-lime-500/40 text-lime-300 bg-lime-500/10";
  if (cat.includes("Envanter")) return "border-amber-500/40 text-amber-300 bg-amber-500/10";
  if (cat.includes("Konum") || cat.includes("Koordinat")) return "border-sky-500/40 text-sky-300 bg-sky-500/10";
  if (cat.includes("Hareket") || cat.includes("Fizik")) return "border-cyan-500/40 text-cyan-300 bg-cyan-500/10";
  if (cat.includes("Arac")) return "border-indigo-500/40 text-indigo-300 bg-indigo-500/10";
  if (cat.includes("Gorsel")) return "border-fuchsia-500/40 text-fuchsia-300 bg-fuchsia-500/10";
  if (cat.includes("Animasyon")) return "border-pink-500/40 text-pink-300 bg-pink-500/10";
  if (cat.includes("Grafik")) return "border-purple-500/40 text-purple-300 bg-purple-500/10";
  if (cat.includes("Kamera")) return "border-violet-500/40 text-violet-300 bg-violet-500/10";
  if (cat.includes("Hava")) return "border-blue-500/40 text-blue-300 bg-blue-500/10";
  if (cat.includes("Ses")) return "border-teal-500/40 text-teal-300 bg-teal-500/10";
  if (cat.includes("Arayuz") || cat.includes("HUD")) return "border-emerald-500/40 text-emerald-300 bg-emerald-500/10";
  if (cat.includes("Ag") || cat.includes("Online")) return "border-green-500/40 text-green-300 bg-green-500/10";
  if (cat.includes("Kayit")) return "border-stone-500/40 text-stone-300 bg-stone-500/10";
  if (cat.includes("Girdi")) return "border-slate-500/40 text-slate-300 bg-slate-500/10";
  if (cat.includes("Yapay")) return "border-rose-500/40 text-rose-300 bg-rose-500/10";
  if (cat.includes("Zaman")) return "border-orange-600/40 text-orange-200 bg-orange-600/10";
  if (cat.includes("Debug") || cat.includes("Gelistirici")) return "border-zinc-400/40 text-zinc-200 bg-zinc-400/10";
  if (cat.includes("AntiHile") || cat.includes("Koruma")) return "border-rose-600/40 text-rose-300 bg-rose-600/10";
  if (cat.includes("Bellek")) return "border-cyan-600/40 text-cyan-200 bg-cyan-600/10";
  return "border-zinc-600 text-zinc-300 bg-zinc-500/10";
}

export default function CodegenTab({ uploadId, result }: { uploadId: string; result: CodegenResultData }) {
  const { toast } = useToast();
  const [language, setLanguage] = useState("cpp");
  const [kind, setKind] = useState<(typeof KINDS)[number]["id"]>("functions");
  const [filter, setFilter] = useState("");
  const [content, setContent] = useState("");
  const [filename, setFilename] = useState("");
  const [metaNotes, setMetaNotes] = useState<string[]>([]);
  const [itemCount, setItemCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [aiText, setAiText] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // --- liste ogeleri: sonucu turet + yerel semantik sozluk ---
  const items = useMemo<ListItem[]>(() => {
    const q = filter.trim().toLowerCase();
    const match = (s: string) => !q || s.toLowerCase().includes(q);
    const out: ListItem[] = [];

    if (kind === "functions") {
      for (const f of result.functions?.functions ?? []) {
        if (!match(f.label ?? `sub_${f.rva.toString(16)}`)) continue;
        const sem = explainFunction(f as unknown as FunctionEntry, { strings: f.strings, apiCalls: f.apiCalls });
        out.push({
          key: `fn:${f.idx}:${f.rva}`,
          title: f.label ?? `sub_${f.rva.toString(16).padStart(8, "0")}`,
          sub: `RVA 0x${f.rva.toString(16)} | VA 0x${f.va.toString(16)} | ${f.size} bayt | cikis:${f.callsOut} giris:${f.xrefsIn}`,
          sem,
          artifact: f as unknown as Record<string, unknown>,
          aiType: "function",
        });
      }
    } else if (kind === "structs") {
      for (const s of result.structs?.structs ?? []) {
        if (!match(s.name)) continue;
        const sem = explainStruct(s as unknown as RecoveredStruct);
        out.push({
          key: `st:${s.name}:${s.vftableRva ?? 0}`,
          title: s.name,
          sub: `${s.fields.length} alan | ${s.size ? `boyut 0x${s.size.toString(16)}` : "boyut ?"} | kaynak: ${s.source ?? "?"}`,
          sem,
          artifact: s as unknown as Record<string, unknown>,
          aiType: "struct",
        });
      }
    } else if (kind === "enums") {
      for (const e of result.enums?.enums ?? []) {
        if (!match(e.name)) continue;
        const sem = explainEnum(e as unknown as RecoveredEnum);
        out.push({
          key: `en:${e.name}`,
          title: e.name,
          sub: `${e.members.length} uye | kaynak: ${e.source ?? "?"}`,
          sem,
          artifact: e as unknown as Record<string, unknown>,
          aiType: "enum",
        });
      }
    } else {
      for (let i = 0; i < result.strings.length; i++) {
        const s = result.strings[i]!;
        if (!match(s.value)) continue;
        const sem = explainString(s.value);
        out.push({
          key: `sr:${i}`,
          title: s.value.length > 80 ? `${s.value.slice(0, 80)}...` : s.value,
          sub: `${s.kind} | ${s.value.length} karakter`,
          sem,
          artifact: { value: s.value, kind: s.kind },
          aiType: "string",
        });
      }
    }
    return out;
  }, [kind, filter, result]);

  // secim listeyi takip etsin
  useEffect(() => {
    setSelectedKey(items.length > 0 ? items[0]!.key : null);
    setAiText(null);
    setAiError(null);
  }, [items]);

  const selected = items.find((it) => it.key === selectedKey) ?? items[0] ?? null;

  // --- kod uretimi (API) ---
  const generate = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/codegen`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ language, kind, filter: filter || undefined, limit: 500 }),
      });
      const d = (await res.json()) as {
        ok: boolean;
        content?: string;
        filename?: string;
        error?: string;
        stats?: { items: number; truncated?: boolean };
        notes?: string[];
      };
      if (d.ok && typeof d.content === "string") {
        setContent(d.content);
        setFilename(d.filename ?? "");
        setMetaNotes((d.notes ?? []).slice(0, 4));
        setItemCount(d.stats?.items ?? null);
      } else {
        setContent(`// ${d.error ?? "kod uretimi basarisiz"}`);
        setFilename("");
        setMetaNotes([]);
        setItemCount(null);
      }
    } catch {
      setContent("// kod uretimi hatasi (ag)");
      setFilename("");
      setMetaNotes([]);
      setItemCount(null);
    } finally {
      setLoading(false);
    }
  }, [uploadId, language, kind, filter]);

  useEffect(() => {
    void generate();
  }, [generate]);

  const copyCode = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast({ title: "Kopyalanamadi", variant: "destructive" });
    }
  }, [content, toast]);

  const downloadCode = useCallback(() => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || `codegen_${language}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [content, filename, language]);

  // --- AI aciklama ---
  const askAi = useCallback(async () => {
    if (!selected) return;
    setAiLoading(true);
    setAiText(null);
    setAiError(null);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: selected.aiType, artifact: selected.artifact, useAi: true }),
      });
      const d = (await res.json()) as { ok: boolean; ai?: string; aiError?: string; heuristic?: SemanticInfo };
      if (d.ai) setAiText(d.ai);
      else setAiError(d.aiError ?? "AI aciklama uretilemedi");
    } catch {
      setAiError("AI aciklama cagrisi basarisiz");
    } finally {
      setAiLoading(false);
    }
  }, [uploadId, selected]);

  const semBadge = selected ? (
    <Badge variant="outline" className={`text-[10px] ${categoryBadgeClass(selected.sem.category)}`}>
      <BadgeCheck className="mr-1 h-3 w-3" />
      {selected.sem.category} · guven {Math.round(selected.sem.confidence * 100)}%
      {selected.sem.categoryId ? ` · ${selected.sem.categoryId}` : ""}
    </Badge>
  ) : null;

  // --- kod vurgulama: yorum satirlari (RVA/AOB/opcodes meta) silik italik,
  // hex sayilar ve dizeler renkli; cok buyuk ciktilarda duz metin doner ---
  const codeLines = useMemo(() => content.split("\n"), [content]);
  const highlight = codeLines.length <= 3500;
  const highlightedLines = useMemo(
    () => (highlight ? codeLines.map((line) => tokenizeCodegenLine(line, language)) : null),
    [codeLines, highlight, language],
  );

  return (
    <div className="space-y-3">
      {/* ust cubuk: dil + tur + filtre */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={language} onValueChange={setLanguage}>
          <SelectTrigger className="h-8 w-[150px] border-zinc-700 bg-zinc-950/70 text-xs">
            <SelectValue placeholder="Dil" />
          </SelectTrigger>
          <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
            {LANGUAGES.map((l) => (
              <SelectItem key={l.id} value={l.id}>
                {l.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={kind} onValueChange={(v) => setKind(v as typeof kind)}>
          <SelectTrigger className="h-8 w-[150px] border-zinc-700 bg-zinc-950/70 text-xs">
            <SelectValue placeholder="Veri turu" />
          </SelectTrigger>
          <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
            {KINDS.map((k) => (
              <SelectItem key={k.id} value={k.id}>
                {k.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filtre (ad ara)..."
          className="h-8 w-full max-w-[220px] border-zinc-700 bg-zinc-950/70 text-xs"
        />
        <span className="text-[11px] text-zinc-500">{items.length} oge</span>
      </div>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        {/* SOL: oge listesi + semantik rozetleri */}
        <div className="max-h-[520px] space-y-1.5 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-2 scrollbar-thin">
          {items.length === 0 && (
            <p className="p-2 text-xs text-zinc-500">Bu tur icin cikarilan veri yok (filtreyi temizleyin).</p>
          )}
          {items.map((it) => (
            <button
              key={it.key}
              onClick={() => setSelectedKey(it.key)}
              className={`w-full rounded-md border px-2.5 py-2 text-left transition ${
                it.key === selected?.key
                  ? "border-emerald-500/50 bg-emerald-500/10"
                  : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-900/70"
              }`}
            >
              <p className="truncate text-xs font-medium text-zinc-200">{it.title}</p>
              <p className="truncate text-[10px] text-zinc-500">{it.sub}</p>
              <div className="mt-1">
                <Badge variant="outline" className={`text-[9px] ${categoryBadgeClass(it.sem.category)}`}>
                  {it.sem.category}
                </Badge>
              </div>
            </button>
          ))}
        </div>

        {/* SAG: kod paneli + semantik aciklama */}
        <div className="space-y-3">
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-3 py-2">
              <p className="flex items-center gap-1.5 text-xs text-zinc-300">
                <Wand2 className="h-3.5 w-3.5 text-emerald-400" />
                {filename || `codegen_${language}`}
              </p>
              <div className="flex items-center gap-1.5">
                {itemCount !== null && (
                  <Badge variant="outline" className="border-zinc-700 text-[9px] text-zinc-400">
                    {itemCount} oge
                  </Badge>
                )}
                <Button variant="outline" size="sm" className="h-7 border-zinc-700 px-2 text-[11px]" onClick={copyCode}>
                  {copied ? <Check className="mr-1 h-3 w-3 text-emerald-400" /> : <Copy className="mr-1 h-3 w-3" />}
                  Kopyala
                </Button>
                <Button variant="outline" size="sm" className="h-7 border-zinc-700 px-2 text-[11px]" onClick={downloadCode}>
                  <Download className="mr-1 h-3 w-3" />
                  Indir
                </Button>
              </div>
            </div>
            {metaNotes.length > 0 && (
              <div className="flex flex-wrap gap-x-3 gap-y-1 border-b border-zinc-800/60 bg-zinc-900/40 px-3 py-1.5">
                {metaNotes.map((n, i) => (
                  <span key={i} className="text-[10px] text-zinc-500">{n}</span>
                ))}
              </div>
            )}
            <div className="max-h-[460px] overflow-auto scrollbar-thin">
              {loading ? (
                <p className="flex items-center gap-2 p-3 text-xs text-zinc-400">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Kod uretiliyor...
                </p>
              ) : highlightedLines ? (
                <pre className="whitespace-pre p-3 text-[11px] leading-relaxed text-zinc-300">
                  {highlightedLines.map((tokens, i) => (
                    <span key={i}>
                      {tokens.map((t, j) => (
                        <span key={j} className={t.cls ?? undefined}>{t.text}</span>
                      ))}
                      {"\n"}
                    </span>
                  ))}
                </pre>
              ) : (
                <pre className="whitespace-pre p-3 text-[11px] leading-relaxed text-zinc-300">{content}</pre>
              )}
            </div>
          </div>

          {selected && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="flex items-center gap-1.5 text-xs font-medium text-zinc-200">
                  <Sparkles className="h-3.5 w-3.5 text-amber-400" />
                  Ne is yapiyor?
                </p>
                {semBadge}
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 border-amber-500/40 px-2 text-[11px] text-amber-300 hover:bg-amber-500/10"
                  onClick={askAi}
                  disabled={aiLoading}
                >
                  {aiLoading ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Brain className="mr-1 h-3 w-3" />}
                  AI ile Acikla
                </Button>
              </div>
              <dl className="mt-2 space-y-1 text-[11px] leading-relaxed">
                <div className="rounded-md border border-zinc-800 bg-zinc-900/60 px-2 py-1.5">
                  <dt className="font-medium text-zinc-400">Kategori aciklamasi: </dt>
                  <dd className="text-zinc-300">{selected.sem.description}</dd>
                </div>
                <div>
                  <dt className="inline font-medium text-zinc-400">Ozet: </dt>
                  <dd className="inline text-zinc-300">{selected.sem.summary}</dd>
                </div>
                <div>
                  <dt className="inline font-medium text-zinc-400">Hesapladigi: </dt>
                  <dd className="inline text-zinc-300">{selected.sem.computes}</dd>
                </div>
                <div>
                  <dt className="inline font-medium text-zinc-400">Nereye isliyor: </dt>
                  <dd className="inline text-zinc-300">{selected.sem.writes}</dd>
                </div>
                {selected.sem.hints && (
                  <div className="grid gap-x-3 gap-y-0.5 pt-0.5 sm:grid-cols-3">
                    <div className="rounded border border-zinc-800 bg-zinc-900/40 px-2 py-1">
                      <p className="text-[9px] uppercase tracking-wide text-zinc-500">Eylem</p>
                      <p className="text-zinc-300">{selected.sem.hints.action}</p>
                    </div>
                    <div className="rounded border border-zinc-800 bg-zinc-900/40 px-2 py-1">
                      <p className="text-[9px] uppercase tracking-wide text-zinc-500">Hesaplama</p>
                      <p className="text-zinc-300">{selected.sem.hints.computation}</p>
                    </div>
                    <div className="rounded border border-zinc-800 bg-zinc-900/40 px-2 py-1">
                      <p className="text-[9px] uppercase tracking-wide text-zinc-500">Hedef</p>
                      <p className="text-zinc-300">{selected.sem.hints.target}</p>
                    </div>
                  </div>
                )}
                {selected.sem.tags.length > 0 && (
                  <div className="pt-0.5">
                    {selected.sem.tags.slice(0, 6).map((t) => (
                      <Badge key={t} variant="outline" className="mr-1 border-zinc-700 text-[9px] text-zinc-400">
                        {t}
                      </Badge>
                    ))}
                  </div>
                )}
              </dl>
              {aiText && (
                <div className="mt-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2">
                  <p className="whitespace-pre-wrap text-[11px] leading-relaxed text-amber-100/90">{aiText}</p>
                </div>
              )}
              {aiError && (
                <p className="mt-2 text-[11px] text-red-400">AI: {aiError}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
