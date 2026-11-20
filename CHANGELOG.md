# Değişiklik Günlüğü

Format: [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) — semantik sürümleme (MAJOR.MINOR.PATCH).

## [0.3.0] — 2026-11-20

### Eklendi — Web platformu
- **Çoklu worker analiz kuyruğu** (`src/lib/analysis/queue.ts` + `workerEntry.ts`):
  - `node:worker_threads` tabanlı paralel analiz havuzu — `ANALYSIS_WORKERS` env değişkeni ile iş parçacığı sayısı (varsayılan `min(2, cpu)`, üst sınır 4)
  - Kuyruk pump mantığı: havuz boşaldıkça sıradaki iş otomatik başlar; her iş kendi worker thread'inde izole çalışır
  - İlerleme akışı worker'dan `postMessage` ile ana sürece taşınır → `/api/uploads/[id]/progress` aynen çalışır
  - Worker paketi yoksa otomatik süreç-içi yedeğe düşer (geri uyumlu)
  - `bun run worker:build` ile `storage/bin/analysis-worker.js` paketi üretilir
- **Kod Üretici (Codegen)** — çıkarılan verileri seçilen programlama dilinde gösterim:
  - 8 dil: C++, C#, Python, Rust, TypeScript, Java, Lua, JSON
  - 5 tür: fonksiyonlar, structlar, enumlar, dizeler, hepsi
  - Her fonksiyon/struct için RVA / VA / offset / boyut / bölüm + **AOB desen üretimi** (rel32/imm32 alanları `??` jokerli)
  - Dumper-7 stili `[Address(RVA, Offset, VA)]` attribute'ları (C#), VA hesabı `imageBase + RVA`
  - `POST /api/uploads/[id]/codegen` + UI "Kod Üretici" sekmesi (dil/tür seçici, canlı yeniden üretim)
- **Semantik açıklama motoru** (`semantics.ts` + `POST /api/uploads/[id]/explain`):
  - Sözlük tabanlı kategori sınıflandırma: karakter/sağlık, silah, para/envanter, konum/koordinat, fizik, görsel/skin, ağ vb.
  - `explainFunction/Field/Struct/Enum/String/Name` — kategori + güven skoru + Türkçe özet
  - Opsiyonel AI derinleştirme (`useAi: true`) — backend'de çalışır, istemciye sızmaz
- **Save Editor (canlı-online-editor-writer)** — Unreal/Epic/Steam save dosyaları:
  - GVAS (.sav) tam parse + serialize: header, custom version'lar, tagged property ağacı (Float/Int/Bool/Byte/Enum/Str/Name/Struct/Array/Set/Map/SoftObject)
  - Düzenleme: path tabanlı (`Health`, `Position.X`, `Inventory[1].Name`) — düzenlenmiş kopya ayrı dosyada tutulur, orijinal korunur
  - **Şifreli save desteği**: AES-256-ECB / AES-256-CBC (anahtar + IV ile çözümleme, PKCS7 tespiti); şifreli dosya anahtar girdisiyle açılır
  - Steam VDF desteği: parse + edit + serialize (`vdf.ts`)
  - `GET/PUT /api/uploads/[id]/savegame` + `GET /api/uploads/[id]/savegame/download` + UI "Save Editor" sekmesi
- **Otomatik eşleştirme ve yeniden analiz**:
  - `global-metadata.dat` ↔ `GameAssembly/libil2cpp` (IL2CPP: dump.cs + script.json üretimi)
  - `*.memmap/*.map` ↔ ham bellek dump (LeechCore memmap semantiği, 24 saat pencere)
  - `*.pdb` ↔ adına uyan PE (sem bolme: `ROB RUN.pdb` ↔ `ROB RUN.exe`)
  - Ters yön eşleştirme: metadata/memmap/pdb sonradan gelirse önceki yükleme otomatik yeniden analiz edilir
- **VDEX/OAT gömülü DEX çıkarıcı** (`vdex.ts`): ART konteynerlerinden DEX'leri ayırır, her DEX ayrı çocuk yükleme olarak analize girer

### Eklendi — Araçlar ve altyapı
- `scripts/make-samples.ts`: sentetik test materyali üretici (metadata, GameAssembly, minidump, pak, utoc, uasset, macho, memmap)
- `scripts/inspect-*.ts`, `verify-*.ts`: inceleme/doğrulama yardımcıları

### Düzeltildi
- AOB aramasında ilk-offset eşleşmesinde sonsuz döngü → döngü ilerlemesi yeniden yazıldı
- AOB eşleşmelerinde VA her zaman `undefined` kalıyordu → `imageBase` parametresi ile `imageBase + RVA` hesabı
- memmap eşleştirme zinciri kopuyordu: `analyzeBuffer` koşulu gevşetildi + 24 saatlik geriye dönük memmap araması eklendi

### Güvenlik
- GitHub'a ilk yayın öncesi git geçmişi sıfırlandı (squash): `.env` (veritabanı gizli anahtarı) eski geçmişte kalmasın diye
- `.env`, `db/`, `storage/` (yüklenen binary'ler), vendored üçüncü taraf ağaçları repoya alınmadı; `.gitignore` kapsamı genişletildi
- Remote URL'den token temizleme prosedürü eklendi

### Belgeler
- `docs/MEMPROCFS_LEECHCORE.md` — device/canlı bellek entegrasyon araştırması
- `docs/IL2CPP_BINARY.md` — metadata sürümleri, relocation
- `docs/SAVEGAME.md` — GVAS formatı, şifreli save
- `docs/GAMEFILES.md`, `docs/CODEGEN.md`, `docs/WEB_PLATFORM.md`
- `DumperPro/docs/LEECH.md` — `--device` kullanımı

## [0.2.1] — 2026-11-19

### Eklendi — C++ motoru (DumperPro)
- LeechCore okuma backend'i (`core/LeechReader`) + `--device` bayrağı uçtan uca (fpga / `file://dump.bin` / `dump://x.dmp`)
- Cihaz modunda PE'siz UE sürüm tespiti (`DetectFromRawStrings` — `++UE5+Release-X.Y` işaretleyici oylaması)
- UE5.4/UE5.5 gömülü profiller (toplam 10 profil) + `games.ini` fingerprint örneği

### Eklendi — Web platformu
- MemProcFS / LeechCore çıkarıcıları: raw + memmap eşleşmesi sonrası otomatik "available"
- 6 çıkarıcı matrisi (Dumper-7, DumperPro, Il2CppDumper, UnrealCEDumper, MemProcFS, LeechCore) + Ortak Veriler kesişim tablosu

## [0.2.0] — 2026-11-18

### Eklendi
- C++ motor: 10 modül (core/sig/ue/il2cpp/file/dump/hex/net/config/utils)
- UE4.20–4.27 / UE5.0–5.3 ObjectArray+NameArray otomatik tespiti, offset probe
- IL2CPP metadata v16–31, ELF RELA, DummyDll; SDK üretici (`<Pkg>_classes.h/_structs.h/_enums.h`)
- Hex aracı: hex/kod/ikili görünümler, AOB arama, patch, undo, save; `--serve` gömülü HTTP sunucu
- Web: 15 sekmeli ikili inceleyici, yükleme/klasör ağacı, rapor üretimi
