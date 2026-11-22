# Değişiklik Günlüğü

Format: [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) — semantik sürümleme (MAJOR.MINOR.PATCH).

## [0.5.2] — 2026-11-21

### Eklendi — Canlı proses seçimi + canlı oyun verisi çıkarma (motor + serve + web)

**Neden:** canlı attach zaten çalışıyordu (`--process/--pid`) ama kullanıcı çalışan
prosesleri keşfedemez, hangi prosesin UE/Unity oyunu olduğunu bilemezdi; serve modu
yalnızca dosya yükleme yapar, canlı hedef seçimi ve tek tık dump yoktu; IL2CPP hattı
yalnızca diskteki dosyalarla çalışır (paketli/şifreli GameAssembly.dll tek dosyada
okunamayan oyunlarda kullanılamazdı).

**CLI (`--list-processes [--deep]` — `core/ProcessReader.cpp` `ListLiveProcesses`):**
- Toolhelp snapshot + proses başına modül snapshot'ı: pid, ad, modül sayısı, attachable
  durumu (`OpenProcess(READ)` testi, korumalı hedefler `[korumali]` etiketli)
- **Hızlı motor ipuçları** (modül/imaj adı heuristikleri, kesinlik sırasıyla):
  `GameAssembly.dll` → **Unity IL2CPP**, `unityplayer.dll` + `mono-*` → **Unity Mono**,
  `unityplayer.dll` → Unity, `UE4Editor/UE5Editor` → **UE Editor**, `UE4.dll/UE5.dll` → UE,
  `*-Win64-Shipping.exe / *-Client.exe / ...` → **UE Game?**
- `--deep`: aday proseslerde ana modül imajı **kademeli 1 MB'lik parçalarla** (tavan 32 MB,
  4 MB'tan küçük exe'ler atlanır, kesin ipucu verilenler hariç) okunur ve
  `++UE4/5+Release-x.y.z` dizesi **bellekte doğrulanır** → "UE 5.1" ipucu
- Tablo çıktısı (ipuçlu prosesler önce) + `--json` ile `DumperPro_Out/processes.json`
  (`{"format":"dumperpro-processes","version":1,...}`)
- Doğrulama: `--list-processes` diğer hedeflerle birleştirilemez, `--deep` yalnız
  `--list-processes` ile geçerli

**Canlı IL2CPP hattı (`--process/--pid + --metadata` — `main.cpp` `RunIl2CppLiveMode`):**
- IL2CPP modülü (`--module` veya otomatik: `gameassembly`/`libil2cpp`/`il2cpp`) prosesin
  **bellekte mapped imajı** olarak okunur
- Yeni `ModuleImage::UnmapToRawFile`: mapped (RVA==offset) imaj, PE section tablosuyla
  **RAW PE dosya düzenine** geri açılır — `Il2CppBinaryMatch::Match` dosya layout'u bekler
- Metadata + binary eşleştirme + DummyDll + rapor: Il2CppDumper hattının tam yeniden
  kullanımı; çıktı klasörü `<oyun>_il2cpp_live_<zaman>/`, `result.json` **status=il2cpp**
- `--json` ile ham PE imajı da diske yazılır (offline yeniden koşum için)

**Serve modu (`--serve` — `net/HttpServer.cpp`):**
- `GET /api/processes[?deep=1]` → canlı proses listesi (aynı JSON şema)
- `POST /api/dump` `{"pid":N,"module":"...","noSdk":bool,"metadata":"..."}` → **self-spawn**:
  DumperPro.exe kendini `--pid N --json --out DumperPro_Out/serve/live_<zaman>_pid<N>` ile
  subprocess olarak yeniden başlatır (CreateProcessA + pipe, 10 dk timeout, stdout/stderr
  yakalama) — UE hattının tamamı tek tıkla çalışır, yanıt `exitCode + log + result.json`
  gömülü döner; Windows dışında zarif 400
- Gömülü sayfada **"Canlı Hedefler"** bölümü: liste (ipuçlu satırlar vurgulu) + "Derin Tara
  (UE sürümü)" + satır başına **Dump** butonu + dump logu ve result.json görüntüleyici
- Arayüz sayfası ilk açılışta listeyi otomatik çeker; 127.0.0.1 bağlaması değişmedi

**Web platformu (`dumperpro-tab` + `parse.ts`):**
- Import sekmesine **"Canlı Hedef Rehberi"** (kopyalanabilir 4 adımlı akış: listele →
  serve ile tek tık → klasik attach → result.json import)
- `result.json` status şemasına **`il2cpp`** kabulü + teal rozet; mode=process/kernel
  rozetleriyle canlı dump'lar web'e taşınır

**Doğrulama:** Linux g++ -std=c++20 ile tüm kaynaklar derlenip linklendi (Win32 yolları
stub; serve endpoint'leri curl ile doğrulandı: processes JSON şeması, deep parametresi,
dump 400 zarif hata, /health, ana sayfada Canlı Hedefler bölümü); `--deep`/kombinasyon
doğrulamaları test edildi. Windows gerçek-makine doğrulaması (canlı proses listesi +
dump) Windows kit turu ile yapılacaktır.

### Eklendi — Pattern Visual Scanner: desen tanımlama + görselleştirme + imza çıkarıcı

**Neden:** web tarafındaki imza taraması yalnızca sabit 6 desenle gidiyor, kullanıcı kendi
desenini yazamıyor, eşleşmeler ham RVA/VA tablosu olarak gösteriliyordu; C++ motorunun
nibble-mask desteği (PatByte 0xF0/0x0F) ve `BuildExtendedSig` imza çıkarıcının web karşılığı yoktu.

**Web pattern motoru (`src/lib/analysis/pattern.ts` — C++ `core/Pattern.{h,cpp}` portu):**
- IDA tarzı ayrıştırma: `48 8B 05 ??` + **nibble kısmi maske** (`4?` hi-nibble, `?8` lo-nibble;
  ayrıçalar `, . _ \x` normalize edilir), token üst sınırı 512, "tamamen joker" reddi
- `findPatternMatches`: ilk literal token `Buffer.indexOf` sabitli tarama (AOB hattıyla aynı hız
  sınıfı, 128 MB tarama penceresi); eşleşme başına off/rva/va/bölüm etiketleri
- `patternStats`: literal/nibble/joker sayımı + **özgüllük** metrikleri — rastgele veride beklenen
  eşleşme aralığı `(1/256)^literal · (1/16)^nibble` → zayıf/orta/iyi/güçlü etiketi
- `extractSignature` (BuildExtendedSig portu): eşleşme çevresinden before/after bağlam ile imza
  üretimi; **maskMode**: "pattern" — desenin joker konumları çıktıda `??` korunur (rel32/imm32
  yeniden konumlanmada hayatta kalır) / "keep" — ham baytlar; hi/lo nibble bayt değeriyle
  somutlaştırılır
- 4 çıktı formatı: **IDA/CE** (`48 8B 05 ?? ...`), **x64dbg** (bayt + mask satırı, nibble bayt
  jokerine düşürülüp not edilir), **C++** (`bytes[] + mask[]` 0xFF/0xF0/0x0F/0x00), **Python**
  (literal `b"..."` veya bytes+mask çifti)

**API (`POST /api/uploads/[id]/pattern`):**
- `action:"scan"` — custom desen tarama (bölüm filtresi + eşleşme üst sınırı; eşleşme başına
  önce/sonra 8 bayt **görsel bağlam** döner)
- `action:"extract"` — ofsetten imza çıkarma (before/after/maskMode parametreleri, RVA/VA/bölüm +
  özgüllük istatistikleriyle)

**UI (Analyzer → "Imza / Pattern" sekmesi — `src/components/pattern-visual.tsx`):**
- Desen girişinde **canlı token önizleme** — renk kodu: emerald=literal, amber=nibble, zinc=joker
  (+ hatalı token anında Türkçe uyarı); bayt/literal/nibble/joker/özgüllük rozetleri
- 8 hazır desen çipi (sabit adaylar + 2 nibble örneği: `4? 8B 05` REX-gevşek, `4? 89 ?? ?? 5?` x64 prolog)
- Tarama sonuçlarında her eşleşme için **görsel bayt şeridi**: bağlam baytları soluk, eşleşme
  bölgesi token tipine göre renkli; "Hex'e git" mevcut hex penceresine atlama (jump) tetikler
- **İmza Çıkarıcı** diyaloğu: önce/sonra bağlam ayarı (anlık yeniden çıkarma) + "jokerleri koru"
  anahtarı + çıkarılan imzanın renkli şeridi + 4 format sekmeli çıktı ve kopyalama
- `bun run lint` temiz

## [0.5.1] — 2026-11-21

### Eklendi — Merkezi veri tipi kayıt sistemi: motor + web (Cheat Engine / ReClass düzeyi)

**Denetim sonucu (neden):** tip "isimleri" vardı (UE→C++ eşleme, IL2CPP
PrimTypeName, save editor GVAS tipleri, codegen tabloları) ama **bayt→değer
yorumlama yoktu**: hex viewer ve tarama yalnızca AOB (byte deseni) destekliyor,
float/double/bit/vec hiçbir yerde okunamıyordu. Merkezi `DataType` kayıt
sistemi eklenerek bütün modüller tek tip setine bağlandı.

**Motor (C++, `src/core/DataType.{h,cpp}` — yeni modül `types`):**
- 18 tip, little-endian: `i8 i16 i32 i64 u8 u16 u32 u64` (+`byte/word/dword/
  qword/short/int/...` alias'ları), `f32/float f64/double`, `bool`, `bit`
  (bayt içi 0..7, LSB), `str` (ASCII, NUL'a kadar), `str16` (UTF-16LE),
  `ptr` (8 B hex), `vec2/vec3/vec4` (float vektör; `fvector`/`frotator`
  alias'lı)
- `Decode()` (bayt→değer + usedBytes + not), `Encode()` (değer→bayt, aralık
  kontrollü; "42"/"0x2A"/"3.14"/"true"/"1 2 3"), `TryTypedQuery()`
  (`f32:3.14`, `i32:1337`, `bool:1`, `str:Hello`, `vec3:1 2 3` sorgu ön ekleri),
  `TypeTable()`; `text:/text16:` ön ekleriyle çakışma korunması
- **HexTool**: `RenderTyped()` — `--hex-type 0x1000:16:float` tipli görünüm
  (VA + ham bayt + [tip] değer satırları; string'lerde NUL tüketicisi adım);
  `--hex-search` artık tipli değer ön eklerini de kabul ediyor (AOB yolu
  korunmuş durumda)
- **MemoryReader**: `ReadI8/I16/I64/F32/F64` + `ReadF32Or/ReadF64Or` tipli
  okuma yardımcıları
- **SDKGenerator `_basics.hpp`**: `FVector/FVector2D/FVector4/FRotator`
  byte-exact float stub'ları eklendi (StructProperty üyeleri artık derlenir)
- **ModuleRegistry**: `types 0.4.3` modülü kayıtlı; `--help` + `--modules`
  güncel
- **Birim testleri**: g++ host derlemesiyle 28/28 PASS (alias'lar, decode
  yuvarlama, str/str16 NUL tüketimi, bit, encode aralık reddi, typed-query
  önekleri, `text:` çakışma koruması); g++ `-fsyntax-only` HexTool/main/SDK
  EXIT 0

**Web (Next.js):**
- **`src/lib/analysis/hex.ts`**: `DataType` birliği + `DATA_TYPE_META` +
  `DATA_TYPE_GROUPS` (gruplu UI listesi) + alias çözümleyici `resolveDataType`
  (C++ tablosuyla birebir), `decodeValue()` (BigInt'i aşan i64/u64 dahil,
  str16 surrogate çiftleri), `encodeValue()` (aralık hataları Türkçe),
  `valueSearch()` (değer→desen→aobSearch, `encoded` desen döner)
- **API**: `POST .../hex` yeni `action:"decode"` (off+type+count+bitIndex →
  değer tablosu) ve `action:"search"` artık `type+value` kabul ediyor;
  `POST .../mem` search aynı şekilde tipli değer arıyor (modül/RVA etiketli)
- **HexTab**: **"Tip yorumla"** paneli (gruplu tip seçici + ofset + adet +
  bit 0-7 → Offset|Baytlar|Değer tablosu; satıra tıkla → hex pencere oraya
  gider) + **"Deger arama"** paneli (tip seçici + değer → eşleşme tablosu +
  `desen: xx xx` rozeti) — mevcut byte-düzenleme ve AOB arama aynen kaldı
- **MemTab**: tipli değer arama satırı (AOB satırıyla yan yana)
- **Dizeler sekmesi**: ASCII/UTF-16 rozetleri (`A`/`W`) — `kind` alanı artık
  görünür
- **structs.ts**: SSE kanıtlı tip netleştirme — `movss/addss→float`,
  `movsd/comisd→double` (eskiden movsd 16 B paketlenmiş sanılırdı); alan
  tipleri artık `float`/`double` olabiliyor
- **savegame.ts**: işaretsiz yazım düzeltmesi — `uint32/uint64/uint16` kendi
  `u32/u64/u16` yazıcılarından geçer (eski `i32/i64` daraltması büyük
  değerleri bozuyordu)
- **agent-browser E2E**: test dosyası (1337/i32 + 3.14/f32 + "Hello World!"/str
  + bit3 + vec3 1.5 2.5 3.5 + "Selam"/str16 + 0x7FF6A1B2C3D4/ptr) ile API ve
  UI uçtan uca PASS; mobilde yatay taşma yok; `bun run lint` temiz

## [0.5.0] — 2026-11-21

### Eklendi — Motor→Web köprüsü: `functions.json` + `result.json` + "DumperPro İçe Aktar" sekmesi

**Motor (C++, v0.5.0):**
- **Yeni modül `src/dump/ResultExport.{h,cpp}`**:
  - `functions.json` — GObjects üzerinden **tüm UClass UFunction listesi**: `cls`,
    `pkg` (en üst Outer), `name`, `rva` (modül içindeyken), `va`/`ufunction`/`native`,
    `paramsSize`, `flags`, tam **params** dizisi (name/type/offset/size/flags/target)
    + opsiyonel `ret`; adres/offset alanları hex-string sözleşmesiyle
    (`"0x..."` — web parser `parseInt(x,16)` ile okur); `--json` bayrağından
    **bağımsız** her tam çalışmada yazılır
  - `result.json` — sürümlü manifest: `format`/`version`/`tool`/`generated`/
    `target{mode,detail}`/`game`/`ue`/`module{name,base,size}`/`status(full|names-only)`/
    `counts`/`artifacts[]`; GObjects bulunamazsa **names-only** kısmi yolunda da yazılır
- main.cpp hook'ları (`FillRunMode`) + `--help` metni güncellendi; build.bat
  `..\src\dump\*.cpp` wildcard'ı yeni modülü otomatik kapsar
- Doğrulama: g++ tam regresyon EXIT 0; yazar birim testi (şema + JSON escape +
  hex genişlik + `native:0x0` BP-only durumu) `python json` ile PASS

**Web (Next.js):**
- **Prisma `DumperProImport` modeli** (normalize edilmiş names/objects/functions
  JSON'u + meta + sayımlar) — eklemeli `db:push`
- **API**: `POST /api/dumperpro/import` (çoklu dosya + .zip demeti; JSON'lar +
  Names.txt/Objects.txt/funcs.txt tolerant metin parser'ları), `GET imports`
  (liste), `GET imports/[id]` (meta|names|functions|objects — **sunucu taraflı
  arama/sayfalama**, ayrık sınıf listesi), `DELETE` (kayıt + storage dizini),
  `GET imports/[id]/codegen` (cpp/csharp/python/rust/typescript/java/lua/json)
- **`src/lib/dumperpro/`**: `parse.ts` (motor JSON şemaları + metin yedekleri +
  zip çıkarımı yeniden kullanımı), `codegen.ts` (fonksiyon başına
  `// RVA 0x.. VA 0x.. UFunction 0x..` yorumlu üretim)
- **3. üst sekme "DumperPro"**: sürükle-bırak içe aktarma, kayıt listesi
  (Aç/Codegen/Sil), gezgin: meta kartları + alt sekmeler (Fonksiyonlar tablosu +
  detay diyaloğu + **semantik kategori etiketleri**, GNames arama/tarama,
  Nesneler, Kod Üret) — kart p-6/gap-6, ScrollArea, mobil uyumlu
- **agent-browser E2E PASS**: içe aktarma → gezgin → arama → detay diyaloğu →
  codegen çıktısı → silme; konsol hatasız; sticky footer (kısa içerikte gap 0)
  ve mobilde yatay taşma yok; `bun run lint` temiz

## [0.4.2] — 2026-11-20

### Doğrulandı — Windows kit gerçek makinede uçtan uca (VS 2026 + 4 PASS / 0 FAIL)
- **Ortam**: Windows + VS 2026 Community (MSVC Toolset 14.52.37025), klasör
  adında **parantez** olan yerleşim (`...UnrealDumperX_src (4)\...`)
- `build.bat` → **DumperPro.exe** derlendi; `get-leechcore.ps1` →
  leechcore.dll v5.19 yerleşti; `test-device.bat` → **4 PASS / 0 FAIL**
- TEST 1'i PASS yapan hat: LcCreate (`file://` 16 MB sentetik dump) → LcRead
  tam tarama → `DMPPRO-TEST-SIG!` + `++UE5+Release-5.1.1` marker tespiti —
  yani Windows'ta cihaz hattı + imza motoru birebir çalışıyor
- TEST 4'te `--file` çıkış kodu 0 (PE temiz parse; script 0/4/5'i kabul eder)
- 4 tur gerçek-makine hata döngüsü kapanmış oldu: ① kaynak MSVC uyumluluğu
  (0.4.1), ② build.bat cmd parse, ③ BinFold `<array>`, ④ test-device.bat
  parantezli yol + blok-içi `%ERRORLEVEL%`

### Eklendi — Windows derleme: VS 2026 desteği (2. tur, gerçek-makine)
- **build.bat VS 2026 (v18) tanıma**: "x64 Native Tools Command Prompt for VS
  2026" penceresi birebir desteklenir; normal cmd/çift-tık'tan çalıştırmada
  script VS'yi otomatik bulur — **vswhere.exe** (VC.Tools.x86.x64 workload
  filtresiyle) + bilinen kurulum yolları (`...\Microsoft Visual Studio\18\
  {Community,Professional,Enterprise,BuildTools}` VS 2026, `\2022\...`,
  `\2019\...` yedek) → bulunan kurulumda `vcvarsall.bat x64` çağrılır
- **/MP paralel derleme**: tüm .cpp'ler tek cl çağrısında çok çekirdekte
  derlenir (~50 TU'da belirgin hızlanma); /utf-8, /std:c++20, /O2, /W3,
  /D_CRT_SECURE_NO_WARNINGS korunur
- windows/README.md VS 2026 ön koşul + derleme + sorun giderme bölümleriyle
  güncellendi (kit artık v0.4.2 durumuna karşılık gelir)
- *Not:* MSVC kaynak düzeltmeleri (kPage/bswap/io.h/C4244) ilk turda yapıldı —
  bkz. [0.4.1]; bu sürüm Windows test kitinin VS 2026'ya göre yenilenmesidir

### Düzeltildi — build.bat v0.4.2.1: "Baslat was unexpected at this time"
- İlk 0.4.2 scriptinde `if errorlevel 1 ( ... )` bloğu **içindeki** echo
  metinlerinde kaçışsız parantez vardı (`echo 1) Baslat ...`); cmd.exe blok
  tarayıcısı `)` ile bloğu erken kapatıp `Baslat` token'ında parse hatası
  veriyordu — script daha derleme aşamasına gelmeden ölüyordu
- **Yapısal çözüm**: büyük if-blok'ları `goto` akışına çevrildi, blok içi echo
  metinlerinden parantezler tamamen kaldırıldı; dosya CRLF satır sonlarına
  çevrildi; açılışta `build.bat v0.4.2.1` sürüm satırı basılır (doğru kopyanın
  doğrulaması için)
- **Daha sağlam VS tespiti**: vswhere bulunamazsa/boş dönerse bilinen yollar
  hem `\18\` (VS 2026) hem `\2026\` hem `\2022\` hem `\2019 (x86)\`
  dallarında denenir; cl.exe yine bulunamazsa vswhere tanı günlüğü + beklenen
  kurulum yolları ekrana yazılır (uzaktan hata ayıklama için)

### Düzeltildi — test-device.bat: parantezli klasör yolları (4. tur)
- **`\UnrealDumperX\windows\leechcore.dll was unexpected at this time.`**:
  `if defined LCDLL ( echo ... %LCDLL% ... )` bloğunda `%LCDLL%` parse
  zamanında genişletiliyordu; klasör adındaki `(4)` parantezleri (`UnrealDumperX_src (4)`)
  bloğu erken kapatıp kalan yolu "unexpected" token yapıyordu — build.bat
  v0.4.2.1'de çözülen sınıfın aynısı, bu kez başka dosyada
- **Yapısal çözüm**: `%LCDLL%` echo'su tek satırlık `if`'e taşındı (blok yok =
  parantezli yol güvenli); TEST 4 PE alt testi `goto` akışına çevrildi —
  aynı turda ikinci bir gizli bug da düzeltildi: blok içinde
  `%ERRORLEVEL%` genişletilmesi **parse anındaki** (exe çalışmadan önceki)
  değeri okuyordu, çıkış kodu yanlış raporlanıyordu
- `EnableDelayedExpansion` bilinçli olarak **kullanılmadı**: fixture üretim
  satırındaki `DMPPRO-TEST-SIG!` imzasının `!` karakteri delayed expansion'da
  bozulurdu; goto-akışı + bloksuz echo kuralı yeterli
- Kullanıcı çıktısından iki doğrulama: `get-leechcore.ps1` leechcore.dll'i
  yerleştirdi; DumperPro.exe ön kontrolü sessiz geçti → **MSVC derleme
  başarılı** (BinFold yaması gerçek makinede doğrulandı)

### Düzeltildi — BinFold.cpp C2027 (VS 2026 gerçek-makine 3. tur)
- **`std::array<u8,16>` tanımsız tür**: BinFold.cpp `Guid` için `std::array`
  kullanıyordu ama `<array>` include edilmemişti — MSVC STL'de `<utility>`
  `std::array`'i yalnız **ileri-deklare** eder (g++'ta transitive include
  geldiği için Linux'ta görünmüyordu; tüm hatalar C2027/C2079/C2109/C2676
  kaskadesi tek kökten çıktı)
- **framework.h'e `<array>` + `<utility>` eklendi** (tüm modüllerde aynı sınıf
  tuzakları önlendi) + BinFold.cpp'ye doğrudan `<array>`/`<utility>` include'ları
- g++ regresyon derlemesi + framework.h probe (std::array completeness) +
  `--bindiff` / `--modules` smoke testleri temiz

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

### Düzeltildi — Windows/MSVC (1a gerçek-makine testi, ilk tur)
- **LeechReader.cpp C2065 `kPage`**: Windows dalında `kPage` yalnız `Read()`
  gövdesinde yereldi; `readPageShim()` artık kendi 4K sabitini taşıyor (hata
  yalnız gerçek MSVC derlemesinde görünüyordu — g++ yalnız Linux dalını derler)
- **MachO.cpp C3861 `__builtin_bswap32/64`**: tasinabilir `Bswap32/Bswap64`
  sarmalayıcıları — MSVC: `_byteswap_ulong/_byteswap_uint64` (intrin.h),
  GCC/Clang: builtin
- **Logger.cpp C3861 `_isatty`**: Windows dalına `<io.h>` include eklendi
- **main.cpp C4244**: `targetMod.size = (u32)scanSize` açık cast
  (`kDeviceScanCap` 512 MiB, u32'ye güvenli)
- **build.bat**: `/D_CRT_SECURE_NO_WARNINGS` (strncpy C4996 gürültüsünü kısar)
- g++ regresyon derlemesi + `--modules` / `--bindiff` smoke testleri temiz

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
