# Değişiklik Günlüğü

Format: [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) — semantik sürümleme (MAJOR.MINOR.PATCH).

## [0.4.1] — 2026-11-20

### Eklendi — Web platformu: kod üretimi + semantik zenginleştirme
- **Opcode önizleme**: codegen çıktısında her fonksiyonun ilk 24 baytı dosyadan
  okunur (RVA→file offset bölüm eşlemesi, `pe.ts:rvaToFileOffset`); tüm dillerde
  `// opcodes @RVA` yorum satırı + JSON türünde `fileOffset`/`opcodes` alanları;
  struct'larda `vftable OFF` notasyonu; 315 fonksiyondan 312'sinde opcode
  çözüldü (gerçek PE ile doğrulandı)
- **Semantik sözlük genişletme**: ~650 → **2720 anahtar kelime**, **23 kategori**
  (Karakter/Sağlık, Silah/Hasar, Envanter, Ekonomi, XP/İlerleme, Konum/XYZ,
  Fizik, Araç, Model/Skin, Animasyon, Grafik, Kamera, Hava/Çevre/gün-döngüsü,
  Ses, HUD, Ağ, Kayıt, Girdi, AI, Zaman, Debug, AntiHile, Bellek/allocator) —
  her kategori için Türkçe açıklama: *ne iş yapıyor / ne hesaplıyor / nereye
  yazıyor* + `hints {action, computation, target}`; head-noun skorlama
- **Yeni kod vurgulayıcı** (`codegen-highlight.ts`): yorum/hex/dize farkında
  tokenizer — meta satırları soluk italik, hex amber; semantik panelinde kategori
  rozeti + açıklama kartları

### Eklendi — Savegame canlı editor-writer (Unreal/Epic/Steam)
- **Canlı yazma modu** (`PUT .../savegame` body `live:true`): otomatik yedek
  (`storage/uploads/backups/<id>__<ad>.bak-zaman`) → orijinal dosyaya in-place
  yazma → diskten yeniden okuyup re-parse doğrulama (`verifyEdits`) → hata
  durumunda yedekten **otomatik geri yükleme**; tümü-ya-da-hiçbiri (422'de
  orijinal dokunulmadan kalır)
- **Şifreli akış korunur**: AES-256-ECB/CBC + PKCS7, aynı cipher/mod ile
  yeniden şifrelenip yazılır (test: ECB canlı yazma ✓); **Steam VDF** için de
  aynı canlı mod
- **UI**: "Canlı Yaz (orijinal dosyayı güncelle)" anahtarı + onay diyaloğu +
  yedek/doğrulama/uygulanan-değişiklik paneli (`eski → yeni`)

## [0.4.0] — 2026-11-20

### Eklendi — Modül sistemi (2-B)
- **ModuleRegistry** (`src/core/ModuleRegistry.{h,cpp}`): motor geneli merkezi modül
  kayıt sistemi — `EngineModule{name, version, description}` + idempotent
  `Register()` + deterministik `RegisterBuiltins()`; mevcut 9 modül (core, sig,
  ue, il2cpp, file, dump, hex, net, config @ 0.3.0) artık registry'de listelenir
- **`--modules` CLI bayrağı**: hizalı NAME|VERSION|DESCRIPTION tablosu yazdırır

### Eklendi — binfold modülü (2-A)
- **`src/binfold/`** — [trumank/binfold](https://github.com/trumank/binfold) (MIT)
  çekirdek algoritmalarının sıfır bağımlılık C++20 portu: RFC 4122 v5 GUID
  (inline SHA-1), WARP fonksiyon GUID'i (64-byte blok digest'leri, adres sıralı),
  x86 stateless maskeleme (E8/E9 rel32 + EB rel8), PE `.pdata` / ELF `STT_FUNC`
  fonksiyon keşfi + E8 sweep fallback, child/parent-call kısıt hash'leri ve
  iteratif fix-point eşleştirici
- **`--bindiff <a> <b>` / `--bindiff-json`**: iki binary arası fonksiyon
  eşleştirme + benzerlik yüzdesi (fonksiyon gövdesi + CDC byte benzerliği)
- Gerçek 11 MB oyun ELF'i üzerinde doğrulandı: 1393/1393 eşleşme, yamalı
  bölgeler doğru raporlandı

### Eklendi — Entegrasyon araştırması (7 repo)
- `docs/module-integration.md`: binfold, patternsleuth, UE5CEDumper, RE-UE4SS,
  CUE4Parse, FModel, REFramework analiz matrisi (lisans uyarıları + öncelikli
  port yol haritası; FModel GPL — kod kopyalama yok, temiz oda referansı)
- `docs/modules.md`: modül sistemi mimarisi + yeni modül ekleme rehberi (TR)
- `DumperPro/windows/` — Windows gerçek-makine test kiti: `build.bat` (MSVC),
  `get-leechcore.ps1` (MemProcFS v5.19, canlı doğrulanmış indirme),
  `test-device.bat` (4-testli PASS/FAIL baterisi), Türkçe README

### Eklendi — 1b gerçek oyun dumpı doğrulaması
- Gerçek Unity IL2CPP oyunu (LINE CTF 2023 "jumpit", metadata v27, 13.6 MB):
  CLI uçtan uca — 2.682 tip, 16.542 metot, %91.1 adres çözümü, 47k satır SDK
  (`research/dumps/TEST_REPORT.md`)

### Düzeltildi
- **LeechReader Linux çökmesi**: çift `dlerror()` çağrısı ikinci dönüşte NULL
  verip `std::string(nullptr)` ile terminate ediyordu (kütüphane eksikken
  exit 134); tek çağrıya sabitlendi
- **binfold PE `RvaToOff` sentinel taşması**: `0xFFFFFFFF` sentinel'in u64
  genişlemede `size - off` underflow'u tetiklemesi → `ValidOff()` kontrolü

## [0.3.1] — 2026-11-20

### Eklendi — CLI (1a/1b gerçek-dünya testleri)
- **Windows LeechCore test kiti (1a)**: `scripts/windows/1a-device-test.ps1` (T1–T4
  otomatik bateri: file:// salt-okunur, write=1, zarif-hata, opsiyonel FPGA),
  `scripts/windows/1a-leech-harness.cpp` (LcWrite round-trip + hizasız okuma/yazma
  doğrulaması), `docs/1A-WINDOWS-DEVICE-TEST.md` (adım adım Türkçe rehber)
- **1b canlı SDK scripti**: `scripts/windows/1b-live-dump.ps1` — gerçek UE5
  sürecinde GNames+GObjects+SDK üretimi ve çıktı denetimi
- **paMax-uyarlanabilir cihaz tarama penceresi**: `IMemoryReader::MaxAddress()`
  eklendi; `--device` modunda pencere cihazın raporladığı maksimum fiziksel
  adrese kısıtlanır (üst kap 512 MiB; paMax yoksa eski 64 MiB). UE5 shipping
  modül dump'ları (>64 MiB) artık tam taranır; 16 MB dosya cihazında
  "chunk unreadable" uyarıları 0'a düştü
- **Kısmi çıktı**: GObjects bulunamazsa bile GNames çözüldüyse `Names.txt` +
  `names.json` + signature dosyaları yazılır ve canlı-süreç yönlendirmesi verilir
  (eski davranış: hiçbir çıktı yok)
- **1b test raporu**: `docs/1B-UE5-SDK-TEST.md` — gerçek UE5.1 oyunu (The
  Document Demon, itch.io'dan otomatik indirildi) üzerinde uçtan uca test,
  Fling (UE4 paylaşılan build) karşılaştırması, soğuk-görüntü sınırları

### Düzeltildi — 1b'de yakalanan gerçek hatalar
- **SigFinder→parser kablolaması**: `FindGNames`/`FindGObjects` bulunan adayı
  offsets yapısına yazmıyordu; `NameArray/ObjectArray::TryInit` "unresolved"
  hatası veriyordu (yalnızca games.ini ile adres verilirse çalışıyordu).
  Artık çözülen VA `off.GNamesVA`/`off.GObjectsVA`'ya otomatik yazılır
- **FNamePool yanlış-pozitif doğrulaması**: soğuk exe'de sıfır-dolgulu .data
  bölgesi 62.207 çöp "isim" üretti. Düzeltmeler: (1) "None" çapası — FName
  index 0 her zaman `"None"`'dur, ilk giriş buna uymayan aday reddedilir;
  (2) `strictWide` — probe modunda wide (UTF-16) girişler de yazdırılabilirlik
  kontrolüne girer; (3) çünkü gerçek havuz runtime verisidir, soğuk dosyada
  geçen her aday tanım gereği yanlış pozitiftir ve artık dürüstçe reddedilir

### Doğrulandı
- Linux'ta gerçek LeechCore (ufrisk master kaynaktan `leechcore.so`) ile uçtan
  uca canlı test: dlopen/LcCreate/LcRead/LcWrite round-trip/hizasız I/O/paMax
  koruması — ALL-PASS (`DumperPro/docs/LEECH.md` §9.3)

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
