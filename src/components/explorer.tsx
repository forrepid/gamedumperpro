"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Boxes,
  Check,
  ChevronRight,
  Copy,
  Cpu,
  Download,
  FileCode2,
  FileText,
  Folder,
  FolderOpen,
  ListChecks,
  Puzzle,
  Search,
  ScrollText,
  Settings2,
  Shield,
  Terminal,
  Wrench,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { tokenizeCodeLine, type HighlightState } from "@/lib/highlight";
import type { ProjectFile } from "@/lib/project-files";

// ---------------------------------------------------------------------------
// Data: Önemli Notlar -> kod karşılıkları
// ---------------------------------------------------------------------------
const NOTES: { title: string; desc: string; files: string[] }[] = [
  {
    title: "UE5 FNamePool yapısı",
    desc: "2 baytlık giriş başlığı (bIsWide:1 | ProbeHash:5 | Len:10), değişken uzunluk isimler ve 64KB (0x10000) blok düzeni; entry adresi = Blocks[idx>>16] + (idx&0xFFFF)*stride.",
    files: ["src/fname.cpp", "src/ue_types.h"],
  },
  {
    title: "FName::Number konumu",
    desc: "UE5'te Number ComparisonIndex'ten SONRA (+0x4), UE4 derlemelerinde ÖNCE (-0x4). Çalışma zamanında otomatik sondalanır, games.ini ile sabitlenebilir.",
    files: ["src/offsets.cpp", "src/ue_types.h", "src/fname.cpp"],
  },
  {
    title: "ANSICHAR / WIDECHAR ayrımı",
    desc: "Her FNameEntry wide bayrağı taşır; dar girişler ANSI bayt, geniş girişler UTF-16 olarak okunur ve çıktı için UTF-8'e normalize edilir.",
    files: ["src/fname.cpp", "src/common.cpp"],
  },
  {
    title: "minIndex koruması",
    desc: "Vtable slot 0 ve 1 (D0/D1 yıkıcıları) her zaman aday listesinden reddedilir — kMinVtableIndex = 2.",
    files: ["src/vtable.h", "src/vtable.cpp"],
  },
  {
    title: "Alan başına %65 güven eşiği",
    desc: "Runtime offset keşfinde her alan yalnızca kendi güven skoru kConfidenceThreshold (0.65) değerini geçtiğinde kabul edilir.",
    files: ["src/offsets.cpp", "src/ue_types.h"],
  },
  {
    title: "games.ini yetkili değerleri",
    desc: "games.ini'ye yazılan değerler asla otomatik keşif tarafından ezilmez; kayıt işlemi kullanıcı satırlarını ve yorumlarını birebir korur.",
    files: ["src/ini.cpp", "src/offsets.cpp"],
  },
  {
    title: "400 canlı nesne ile oylama",
    desc: "Offset keşfi en fazla kMaxProbeObjects = 400 canlı nesne örnekler — küçük ve dev oyunlarda aynı hızda çalışır.",
    files: ["src/offsets.cpp"],
  },
  {
    title: "En fazla 4 aday parmak izi",
    desc: "Her hedef fonksiyon için kMaxFingerprints = 4 prologue parmak izi denenir; fazlası yok, gereksiz tarama yok.",
    files: ["src/vtable.h", "src/vtable.cpp"],
  },
  {
    title: "Pattern-seeded yedek",
    desc: "Parmak izi taraması başarısız olursa çözücü, hedefin bilinen bayt örüntüleriyle modül taramasına düşer (resolveByPatternSeed).",
    files: ["src/vtable.cpp"],
  },
  {
    title: "Thunk / adjustor çözümü",
    desc: "JMP rel8/rel32, SUB/ADD RCX imm8/imm32 ve JMP [RIP+rel32] import zincirleri çözülür; import hedefi PE tablosundan isimlendirilir.",
    files: ["src/vtable.cpp", "src/pattern.cpp"],
  },
  {
    title: "Post-thunk oylama",
    desc: "Nihai adres, birden çok bağımsız vtable örneği arasında çoğunluk oyuyla kabul edilir; tek eşleşme güven sayılmaz.",
    files: ["src/vtable.cpp"],
  },
  {
    title: "Ana + 16 bayt genişletilmiş imza",
    desc: "Her imza çift olarak saklanır: ana imza + hit'ten sonraki 16 bayt (relocation duyarlı baytlar ?? olur). Oyun güncellenseler bile yeniden çözülür.",
    files: ["src/pattern.cpp"],
  },
  {
    title: "Gömülü sürüm dizisi tespiti",
    desc: ".rdata/.data içindeki \"++UE4+Release-4.27\" / \"++UE5+Release-5.2\" dizgileri taranarak motor sürümü otomatik çıkar.",
    files: ["src/version.cpp"],
  },
  {
    title: "GSpots tarzı otomatik konumlama",
    desc: "GObjects/GNames/GWorld üç kademeli çözülür (games.ini imza -> bilinen pattern -> veri bölümü ankajı) ve her aday KATI doğrulamadan geçer.",
    files: ["src/finder.cpp"],
  },
  {
    title: "SDK çıktı detayları",
    desc: "Üye boşlukları uint8 UnknownData_XX[0xYY]; bool alanlar uint8 bName : 1 bitfield; paket başına _classes.h + _struct.h; kalıtım zinciri ve paketler arası include çözümü.",
    files: ["src/sdkgen.cpp"],
  },
  {
    title: "funcs.txt kaynak etiketleri",
    desc: "Her hedef fonksiyon kaynağıyla etiketlenir: [vtable] (bilinen slot), [vtable>pattern] (parmak izi) veya [pattern] (doğrudan imza).",
    files: ["src/vtable.cpp", "src/outputs.cpp"],
  },
];

const MODULES: { name: string; desc: string; files: string[]; icon: "zap" | "pattern" | "config" | "ue5" | "ux" | "vtable" | "offsets" | "driver" }[] = [
  { name: "Core Dumping", desc: "FName havuzu okuma, nesne yürüyüşü, UClass/UScriptStruct/UEnum ayrıştırma ve tam SDK üretimi.", files: ["fname.cpp", "classparse.cpp", "sdkgen.cpp"], icon: "zap" },
  { name: "Signature System", desc: "IDA tarzı tarama, ana imza + 16 baytlık genişletilmiş imza üretimi ve games.ini yeniden kullanımı.", files: ["pattern.cpp"], icon: "pattern" },
  { name: "Configuration", desc: "games.ini (yorum korumalı), 8 modüllü yerleşik profil, gömülü sürüm dizgisi ile otomatik motor tespiti.", files: ["ini.cpp", "version.cpp"], icon: "config" },
  { name: "UE5 Support", desc: "FNamePool 2 bayt başlık, 64KB bloklar, FName Number +0x4 ve FField/FProperty zincirleri.", files: ["fname.cpp", "ue_types.h", "classparse.cpp"], icon: "ue5" },
  { name: "UX", desc: "Renkli konsol logu, canlı ilerleme çubukları, 7 aşamalı pipeline ve ayrıntılı özet raporu.", files: ["log.h", "main.cpp"], icon: "ux" },
  { name: "VTable Function Resolver", desc: "ProcessEvent / PostRender / ProcessRemoteFunction takibi: parmak izi + thunk çözümü + oylama.", files: ["vtable.cpp"], icon: "vtable" },
  { name: "Runtime Offset Discovery", desc: "400 canlı nesne ile Index/Class/Name/Outer oylaması, %65 eşik, FName Number sondası.", files: ["offsets.cpp"], icon: "offsets" },
  { name: "Kernel Driver Support", desc: "IOCTL tabanlı çekirdek okuma köprüsü (0x222000/0x222004), SCM yükleyici, RPM otomatik yedeği.", files: ["driver.cpp", "driver/udxdrv.c"], icon: "driver" },
];

const BUILD_SNIPPETS = [
  {
    title: "MSVC (Visual Studio 2022, x64)",
    code: "cmake -B build -G \"Visual Studio 17 2022\" -A x64\ncmake --build build --config Release\n:: cikti: build/Release/UnrealDumperX.exe",
  },
  {
    title: "MinGW-w64 / clang-cl",
    code: "cmake -B build -G Ninja\ncmake --build build\n# cikti: build/UnrealDumperX.exe",
  },
  {
    title: "Kullanim",
    code: "UnrealDumperX.exe --list\nUnrealDumperX.exe --process Game-Win64-Shipping.exe\nUnrealDumperX.exe --pid 1234 --out dump --verbose\nUnrealDumperX.exe --process Game.exe --driver-load C:\\udx\\UnrealDumperX.sys\nUnrealDumperX.exe --process Game.exe --names-only",
  },
];

const MODULE_ICONS = {
  zap: Zap,
  pattern: Puzzle,
  config: Settings2,
  ue5: Cpu,
  ux: Terminal,
  vtable: Boxes,
  offsets: ListChecks,
  driver: Shield,
};

const LANG_EXT_ICON = (f: ProjectFile) => {
  if (f.lang === "md") return FileText;
  if (f.lang === "ini") return Settings2;
  if (f.lang === "c") return FileCode2;
  return FileCode2;
};

function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ---------------------------------------------------------------------------
export default function Explorer({ files }: { files: ProjectFile[] }) {
  const [tab, setTab] = useState<"code" | "notes" | "modules" | "build">("code");
  const [selected, setSelected] = useState("src/main.cpp");
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [filter, setFilter] = useState("");
  const [openDirs, setOpenDirs] = useState<Set<string>>(
    new Set(["src", "driver"]),
  );
  const codeCache = useRef<Map<string, string>>(new Map());

  const selectedFile = files.find((f) => f.path === selected);

  useEffect(() => {
    if (tab !== "code") return;
    const cached = codeCache.current.get(selected);
    if (cached !== undefined) {
      setContent(cached);
      return;
    }
    let alive = true;
    setLoading(true);
    fetch(`/api/file?path=${encodeURIComponent(selected)}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("hata"))))
      .then((data: { content: string }) => {
        if (!alive) return;
        codeCache.current.set(selected, data.content);
        setContent(data.content);
      })
      .catch(() => alive && setContent("// dosya okunamadi"))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [selected, tab]);

  const lines = useMemo(() => (content ?? "").split("\n"), [content]);
  const tokens = useMemo(() => {
    const state: HighlightState = { inBlockComment: false };
    return lines.map((l) => tokenizeCodeLine(l, selectedFile?.lang ?? "txt", state));
  }, [lines, selectedFile?.lang]);

  const copyCode = async () => {
    if (content === null) return;
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard izni yok
    }
  };

  const dirs = useMemo(() => {
    const groups = new Map<string, ProjectFile[]>();
    for (const f of files) {
      const list = groups.get(f.dir) ?? [];
      list.push(f);
      groups.set(f.dir, list);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [files]);

  const filteredDirs = useMemo(() => {
    if (!filter.trim()) return dirs;
    const q = filter.toLowerCase();
    return dirs
      .map(
        ([dir, list]) =>
          [dir, list.filter((f) => f.path.toLowerCase().includes(q))] as const,
      )
      .filter(([, list]) => list.length > 0) as [string, ProjectFile[]][];
  }, [dirs, filter]);

  const totalLines = files.reduce((a, f) => a + f.lines, 0);

  const tabs = [
    { id: "code" as const, label: "Kod", icon: FileCode2 },
    { id: "notes" as const, label: "Önemli Notlar", icon: ListChecks },
    { id: "modules" as const, label: "Modüller", icon: Boxes },
    { id: "build" as const, label: "Derleme", icon: Wrench },
  ];

  return (
    <section aria-label="Proje gezgini" className="mx-auto w-full max-w-7xl px-4 sm:px-6">
      {/* tab bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-t-xl border border-zinc-800 bg-zinc-900/60 p-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
              tab === t.id
                ? "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/40"
                : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
            }`}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <a href="/api/download" download>
            <Button
              size="sm"
              className="bg-emerald-600 text-zinc-950 hover:bg-emerald-500"
            >
              <Download className="h-4 w-4" />
              Tümünü indir (.zip)
            </Button>
          </a>
        </div>
      </div>

      <div className="rounded-b-xl border border-t-0 border-zinc-800 bg-zinc-900/30">
        {/* ---------------- CODE TAB ---------------- */}
        {tab === "code" && (
          <div className="grid lg:grid-cols-[280px_1fr]">
            {/* sidebar */}
            <aside className="border-b border-zinc-800 lg:border-b-0 lg:border-r">
              <div className="border-b border-zinc-800 p-3">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Dosya ara..."
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2 pl-8 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-600/60 focus:outline-none"
                  />
                </div>
                <p className="mt-2 text-xs text-zinc-500">
                  {files.length} dosya · {totalLines.toLocaleString("tr-TR")} satır
                </p>
              </div>
              <nav className="max-h-[420px] overflow-y-auto p-2 lg:max-h-[560px] scrollbar-thin" aria-label="Dosya ağacı">
                {filteredDirs.map(([dir, list]) => {
                  const open = openDirs.has(dir) || !!filter.trim();
                  return (
                    <div key={dir || "/"} className="mb-1">
                      {dir && (
                        <button
                          onClick={() =>
                            setOpenDirs((s) => {
                              const n = new Set(s);
                              if (n.has(dir)) n.delete(dir);
                              else n.add(dir);
                              return n;
                            })
                          }
                          className="flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-sm text-zinc-300 hover:bg-zinc-800/70"
                        >
                          {open ? (
                            <FolderOpen className="h-4 w-4 text-amber-400" />
                          ) : (
                            <Folder className="h-4 w-4 text-amber-400/70" />
                          )}
                          <span className="font-mono text-xs">{dir}/</span>
                          <ChevronRight
                            className={`ml-auto h-3.5 w-3.5 text-zinc-600 transition-transform ${open ? "rotate-90" : ""}`}
                          />
                        </button>
                      )}
                      {open &&
                        list.map((f) => {
                          const Icon = LANG_EXT_ICON(f);
                          const isSel = f.path === selected;
                          return (
                            <button
                              key={f.path}
                              onClick={() => setSelected(f.path)}
                              className={`group flex w-full items-center gap-2 rounded-md px-2 py-1.5 pl-6 text-left text-sm transition-colors ${
                                isSel
                                  ? "bg-emerald-500/15 text-emerald-300"
                                  : "text-zinc-400 hover:bg-zinc-800/70 hover:text-zinc-200"
                              }`}
                            >
                              <Icon
                                className={`h-3.5 w-3.5 shrink-0 ${
                                  isSel ? "text-emerald-400" : "text-zinc-500"
                                }`}
                              />
                              <span className="truncate font-mono text-xs">{f.name}</span>
                              <span className="ml-auto shrink-0 text-[10px] text-zinc-600">
                                {f.lines}
                              </span>
                            </button>
                          );
                        })}
                    </div>
                  );
                })}
              </nav>
            </aside>

            {/* viewer */}
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 px-4 py-2.5">
                <ScrollText className="h-4 w-4 shrink-0 text-emerald-400" />
                <span className="font-mono text-sm text-zinc-200">
                  ue-dumper/{selected}
                </span>
                {selectedFile && (
                  <>
                    <Badge
                      variant="outline"
                      className="border-zinc-700 text-[10px] text-zinc-400"
                    >
                      {selectedFile.lines} satır
                    </Badge>
                    <Badge
                      variant="outline"
                      className="border-zinc-700 text-[10px] text-zinc-400"
                    >
                      {formatSize(selectedFile.size)}
                    </Badge>
                  </>
                )}
                <div className="ml-auto flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={copyCode}
                    className="border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800 hover:text-emerald-300"
                  >
                    {copied ? (
                      <Check className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                    {copied ? "Kopyalandı" : "Kopyala"}
                  </Button>
                  <a href={`/api/download?path=${encodeURIComponent(selected)}`} download>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800 hover:text-emerald-300"
                    >
                      <Download className="h-4 w-4" />
                      İndir
                    </Button>
                  </a>
                </div>
              </div>

              <div className="max-h-[560px] overflow-auto scrollbar-thin">
                {loading && content === null ? (
                  <div className="flex h-48 items-center justify-center text-sm text-zinc-500">
                    <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
                    Yükleniyor...
                  </div>
                ) : (
                  <pre className="min-w-full py-3 font-mono text-[12px] leading-5">
                    <code>
                      {tokens.map((toks, i) => (
                        <div key={i} className="flex hover:bg-zinc-900/60">
                          <span className="sticky left-0 w-12 shrink-0 select-none bg-zinc-950/80 pr-3 text-right text-zinc-600">
                            {i + 1}
                          </span>
                          <span className="whitespace-pre pr-6 text-zinc-300">
                            {toks.map((t, j) => (
                              <span key={j} className={t.cls ?? undefined}>
                                {t.text}
                              </span>
                            ))}
                          </span>
                        </div>
                      ))}
                    </code>
                  </pre>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ---------------- NOTES TAB ---------------- */}
        {tab === "notes" && (
          <div className="p-4 sm:p-6">
            <p className="mb-4 max-w-3xl text-sm text-zinc-400">
              Aşağıdaki her önemli not, doğrudan C++ kaynak koduna gömülmüş
              durumdadır. Dosyaya tıklayarak ilgili uygulamayı görüntüleyin.
            </p>
            <div className="grid max-h-[560px] gap-3 overflow-y-auto pr-1 scrollbar-thin sm:grid-cols-2">
              {NOTES.map((n, i) => (
                <article
                  key={i}
                  className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-4 transition-colors hover:border-emerald-700/50"
                >
                  <div className="mb-1.5 flex items-center gap-2">
                    <Badge className="bg-emerald-600/20 text-emerald-300 ring-1 ring-emerald-600/40">
                      Not #{i + 1}
                    </Badge>
                    <h3 className="text-sm font-semibold text-zinc-100">{n.title}</h3>
                  </div>
                  <p className="text-xs leading-relaxed text-zinc-400">{n.desc}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {n.files.map((f) => (
                      <button
                        key={f}
                        onClick={() => {
                          setSelected(f);
                          setTab("code");
                        }}
                        className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono text-[10px] text-zinc-400 transition-colors hover:border-emerald-700/60 hover:text-emerald-300"
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          </div>
        )}

        {/* ---------------- MODULES TAB ---------------- */}
        {tab === "modules" && (
          <div className="p-4 sm:p-6">
            <p className="mb-4 max-w-3xl text-sm text-zinc-400">
              Hedef araçların (ill2cpp2dumper, Dumper-7, UE5CEDumper, UEDumper,
              patternsleuth, GSpots) özellik seti 8 modülde birleşiyor.
            </p>
            <div className="grid max-h-[560px] gap-3 overflow-y-auto pr-1 scrollbar-thin sm:grid-cols-2">
              {MODULES.map((m, i) => {
                const Icon = MODULE_ICONS[m.icon];
                return (
                  <article
                    key={i}
                    className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-4 transition-colors hover:border-emerald-700/50"
                  >
                    <div className="mb-2 flex items-center gap-2.5">
                      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600/15 text-emerald-300 ring-1 ring-emerald-600/40">
                        <Icon className="h-4 w-4" />
                      </span>
                      <div>
                        <h3 className="text-sm font-semibold text-zinc-100">
                          Modül {i + 1} · {m.name}
                        </h3>
                      </div>
                    </div>
                    <p className="text-xs leading-relaxed text-zinc-400">{m.desc}</p>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {m.files.map((f) => (
                        <span
                          key={f}
                          className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono text-[10px] text-zinc-500"
                        >
                          {f}
                        </span>
                      ))}
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        )}

        {/* ---------------- BUILD TAB ---------------- */}
        {tab === "build" && (
          <div className="max-h-[600px] space-y-4 overflow-y-auto p-4 sm:p-6 scrollbar-thin">
            <div className="rounded-xl border border-amber-700/40 bg-amber-500/5 p-4">
              <h3 className="mb-1 text-sm font-semibold text-amber-300">
                Gereksinimler
              </h3>
              <ul className="list-inside list-disc space-y-1 text-xs text-zinc-400">
                <li>Windows 10/11 x64, C++20 derleyicisi (MSVC veya MinGW-w64)</li>
                <li>CMake 3.20+, Python yok — sıfır üçüncü parti bağımlılık</li>
                <li>Kernel driver için ayrıca WDK + testsigning (opsiyonel)</li>
              </ul>
            </div>
            {BUILD_SNIPPETS.map((s, i) => (
              <div
                key={i}
                className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950/70"
              >
                <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2">
                  <Terminal className="h-4 w-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-zinc-200">{s.title}</h3>
                  <button
                    onClick={() => navigator.clipboard?.writeText(s.code)}
                    className="ml-auto rounded-md p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-emerald-300"
                    aria-label="Kopyala"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                </div>
                <pre className="overflow-x-auto p-4 font-mono text-xs leading-5 text-zinc-300 scrollbar-thin">
                  {s.code}
                </pre>
              </div>
            ))}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-4">
              <h3 className="mb-2 text-sm font-semibold text-zinc-200">
                Çıktı dosyaları
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {[
                  "Names.txt",
                  "Objects.txt",
                  "offsets.txt",
                  "signatures.txt",
                  "<Oyun>_sigs.txt",
                  "funcs.txt",
                  "vtable_funcs.txt",
                  "SDK/<Paket>/<Paket>_classes.h",
                  "SDK/<Paket>/<Paket>_struct.h",
                  "games.ini",
                ].map((f) => (
                  <span
                    key={f}
                    className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono text-[10px] text-zinc-400"
                  >
                    {f}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
