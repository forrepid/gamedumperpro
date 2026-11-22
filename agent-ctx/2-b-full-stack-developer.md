# Görev 2-b: DumperPro "il2cpp" durumu + Canlı Hedef Rehberi

## Kapsam
Sadece iki dosya değiştirildi (başka dosyaya dokunulmadı):
- `src/lib/dumperpro/parse.ts`
- `src/components/dumperpro-tab.tsx`

## Yapılan Değişiklikler

### 1) src/lib/dumperpro/parse.ts
- `DpMeta.status` tipi: `"full" | "names-only"` -> `"full" | "names-only" | "il2cpp"` (Türkçe yorum eklendi: canlı IL2CPP hattı, serve modu, GameAssembly.dll).
- `parseResultJson`: status kabul kontrolü `"il2cpp"` değerini de geçiyor.
- `parseDumperProFiles`: `manifestStatus` yerel tipi `"il2cpp"` birleşimine genişletildi. Manifest'tan gelen status aynen meta'ya yazılıyor (default davranış korunmuş).

### 2) src/components/dumperpro-tab.tsx
- `statusBadgeClass`: `"il2cpp"` için teal rozet eklendi (`border-teal-500/40 bg-teal-500/10 text-teal-300`). Mavi/indigo kullanılmadı (proje kuralı).
- Import kartının içinde, dropzone'un hemen üstüne katlanabilir **"Canlı Hedef Rehberi (DumperPro.exe 0.5.2+)"** bölümü eklendi:
  - Yeni `Collapsible/CollapsibleTrigger/CollapsibleContent` importu (`src/components/ui/collapsible.tsx` zaten mevcuttu, @radix-ui/react-collapsible bağımlılığı var).
  - lucide importlarına `ChevronDown` ve `Terminal` eklendi (Trigger ikonu Terminal, aç/kapa göstergesi dönen ChevronDown).
  - 4 numaralı adım mono fontlu ve kopyalanabilir (kopya butonu Check/Copy geri bildirimli):
    1. `DumperPro.exe --list-processes` (--deep/--json açıklamalı)
    2. `DumperPro.exe --serve` (http://127.0.0.1:8420, POST /api/dump, DumperPro_Out/serve/)
    3. `DumperPro.exe --process Game.exe --json` + ayrı kopyalanabilir Unity satırı (`--module GameAssembly.dll --metadata global-metadata.dat`)
    4. result.json + functions.json / ZIP import akışı, process/kernel mod rozetleri, canlı IL2CPP'de status "il2cpp" notu
  - Yeni alt bileşenler: `GuideStep` tipi, `GUIDE_STEPS` sabiti, `GuideCmdRow`, `LiveTargetGuide` (kendi copied state'i, ana komponenti etkilemez). Stil: zinc-800/zinc-950 kart içi, teal vurgu, text-[11px] metinler.
- Uyumluluk düzeltmesi (aynı dosyada, 1 satır): import toast metni `d.status === "names-only" ? ... : "full"` şeklindeydi; il2cpp kayıtlarda yanlışlıkla "full" gösterecekti. Üçlü kontrol `il2cpp` / `names-only` / `full` olarak genişletildi.

## Doğrulama
- `bun run lint`: temiz (0 hata, 0 uyarı).
- `bunx tsc --noEmit`: dumperpro dosyalarında hata yok. Depoda benim dosyalarımla ilgisi olmayan önceden var olan hatalar mevcut (examples/websocket, next.config.ts, skills/image-edit, src/components/analyzer.tsx:1916, src/lib/analysis/pattern.ts:172) — bunlara dokunulmadı (kapsam dışı).
- Dev sunucu hot-reload ile sorunsuz derledi ("Compiled in 864ms"), `/api/dumperpro/imports` 200 dönüyor.

## Uyum Notları (başka dosyalara dokunmadan)
- `src/lib/dumperpro/codegen.ts:28` yorumu hâlâ `// full | names-only`; alan tipi `string` olduğu için "il2cpp" sorunsuz akıyor, sadece yorum eski — bilerek dokunulmadı (görev kapsamı dışı).
- `codegen.ts` diğer yerlerinde status'a göre davranış yok; "il2cpp" status'ü yeni alan olarak DB'ye `string` olarak yazılır, mevcut kayıtlar etkilenmez.
- Kayıt listesi ve meta kartındaki rozetler `statusBadgeClass(rec.status)` / `meta.meta.status` üzerinden gidiyor; "il2cpp" otomatik teal görünür.
- Yeni rehber metinleri görevde verilen başlık/açıklama dahil düzgün Türkçe (UTF-8); JSX düz metninde apostrof `&apos;` ile yazıldı (react/no-unescaped-entities).
