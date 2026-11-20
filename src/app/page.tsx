import { Boxes, FileCode2, Layers, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getProjectFiles } from "@/lib/project-files";
import Explorer from "@/components/explorer";
import Analyzer from "@/components/analyzer";

export const dynamic = "force-dynamic";

export default function Home() {
  const files = getProjectFiles();
  const totalLines = files.reduce((a, f) => a + f.lines, 0);
  const totalSize = files.reduce((a, f) => a + f.size, 0);
  const cppCount = files.filter((f) => f.lang === "cpp" || f.lang === "c").length;

  const stats = [
    { icon: FileCode2, label: "Kaynak dosya", value: `${files.length}` },
    { icon: Layers, label: "Satır", value: totalLines.toLocaleString("tr-TR") },
    { icon: Boxes, label: "Fonksiyonel modül", value: "8" },
    { icon: ShieldCheck, label: "Bağımlılık", value: "0" },
  ];

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      {/* ---------------- HERO ---------------- */}
      <header className="border-b border-zinc-800 bg-zinc-900/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 sm:py-10">
          <div className="flex flex-col gap-5">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className="bg-emerald-600/15 text-emerald-300 ring-1 ring-emerald-600/40">
                Windows · C++20
              </Badge>
              <Badge
                variant="outline"
                className="border-emerald-700/50 text-emerald-300"
              >
                Online analiz: exe / dll / apk
              </Badge>
              <Badge
                variant="outline"
                className="border-zinc-700 text-zinc-400"
              >
                UE4 4.20-4.27
              </Badge>
              <Badge
                variant="outline"
                className="border-zinc-700 text-zinc-400"
              >
                UE5 5.0-5.3
              </Badge>
              <Badge
                variant="outline"
                className="border-zinc-700 text-zinc-400"
              >
                Sıfır bağımlılık
              </Badge>
            </div>

            <div>
              <h1 className="text-3xl font-bold tracking-tight text-zinc-50 sm:text-4xl lg:text-5xl">
                Unreal<span className="text-emerald-400">DumperX</span>
              </h1>
              <p className="mt-3 max-w-3xl text-sm leading-relaxed text-zinc-400 sm:text-base">
                Unreal Engine oyunları için birleşik dump / SDK otomasyon aracı.
                ill2cpp2dumper, Dumper-7, UE5CEDumper, UEDumper, patternsleuth ve
                GSpots&apos;un özellik setini tek bir C++ programında toplar;
                çalışma anındaki bellekten struct, offset, pointer ve fonksiyon
                verilerini çıkarıp dosya olarak raporlar. Bu panel üzerinden
                <span className="text-emerald-300"> oyun dosyalarını (exe / dll / apk) yükleyip
                statik analiz</span> edebilirsiniz.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {stats.map((s) => (
                <div
                  key={s.label}
                  className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3.5"
                >
                  <div className="flex items-center gap-2 text-emerald-400">
                    <s.icon className="h-4 w-4" />
                    <span className="text-xl font-bold text-zinc-50">{s.value}</span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">{s.label}</p>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <a href="/api/download" download>
                <Button
                  size="lg"
                  className="bg-emerald-600 text-zinc-950 hover:bg-emerald-500"
                >
                  Kaynak kodu indir (.zip · {formatSize(totalSize)})
                </Button>
              </a>
              <span className="text-xs text-zinc-500">
                {cppCount} C++ dosyası · CMake derlemesi · kernel sürücü sözleşmesi
                (docs/KERNEL.md) dahil
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* ---------------- MAIN ---------------- */}
      <main className="flex-1 py-6 sm:py-8">
        <div className="mx-auto w-full max-w-7xl px-4 sm:px-6">
          <Tabs defaultValue="analiz" className="w-full">
            <TabsList className="mb-6 bg-zinc-900/70">
              <TabsTrigger
                value="analiz"
                className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
              >
                Dosya Analizi
              </TabsTrigger>
              <TabsTrigger
                value="kaynak"
                className="text-zinc-400 data-[state=active]:bg-emerald-600/20 data-[state=active]:text-emerald-300"
              >
                Kaynak Kod
              </TabsTrigger>
            </TabsList>
            <TabsContent value="analiz">
              <Analyzer />
            </TabsContent>
            <TabsContent value="kaynak">
              <Explorer files={files} />
            </TabsContent>
          </Tabs>
        </div>
      </main>

      {/* ---------------- FOOTER (sticky bottom) ---------------- */}
      <footer className="mt-auto border-t border-zinc-800 bg-zinc-900/60">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center justify-between gap-2 px-4 py-4 pb-[max(1rem,env(safe-area-inset-bottom))] sm:flex-row sm:px-6">
          <p className="text-xs text-zinc-500">
            UnrealDumperX v1.1.0 — UE4/UE5 dump &amp; SDK otomasyonu + online dosya
            analizi · yalnızca izinli araştırma amaçlı
          </p>
          <p className="font-mono text-[11px] text-zinc-600">
            {files.length} dosya · {totalLines.toLocaleString("tr-TR")} satır ·
            build: MSVC / MinGW-w64
          </p>
        </div>
      </footer>
    </div>
  );
}

function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
