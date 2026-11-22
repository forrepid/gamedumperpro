# DumperPro - Online Dosya Analizi (exe / dll / apk / so / dex / il2cpp / vdex / oat)

Bu dokuman, DumperPro'nun "online dosya yukleme + yuklenen dosyada islem yapma"
kabiliyetini dokumante eder. Iki bagimsiz erisim noktasi vardir ve ikisi de
AYNI format destegini paylasir:

1. **Web Analyzer (Next.js panel)** - tarayicidan yukleme, gorsel raporlar
2. **DumperPro.exe --serve [port]** - Windows aracinin kendi yerel web sunucusu
3. **DumperPro.exe --file <dosya>** - PE olmayan dosyalar icin statik analiz hatti

Yasal cerceve: yalnizca sahibi oldugunuz ya da analiz etmeye yetkili yazilimlar
icin; cok oyunculu/hile amacli kullanim kapsam disidir (README'deki DISCLAIMER'a
bakin).

---

## 1. Desteklenen formatlar ve yapilan islemler

| Format | Tanimlama | Yapilan analiz | Cikti |
|---|---|---|---|
| `.exe` `.dll` `.sys` (PE) | `MZ` + `PE\0\0` | PE32/PE32+ header, bolumler (entropy), import/export tablolar, data directories, PDB yolu, `++UE4/5+Release-X.Y` string taramasi, GObjects/GNames imza ADAYLARI (statik - dogrulanmamis), guvenlik ozellikleri (DEP/ASLR/CFG), anti-cheat/DRM/packer ipuclari | TXT rapor, games.ini taslagi, JSON |
| `.apk` (ZIP+manifest) | `PK` + `AndroidManifest.xml` | binary AXML manifest (paket adi, versionName/Code, min/targetSdk), kayit listesi + dizin gruplari, ABI'ler (`lib/<abi>/*.so`), DEX sayimi, UE `.pak` listesi, global-metadata.dat/unityplayer/OBB tespiti, en buyuk 2 `.so`yi cikarip ELF parse + UE string taramasi | TXT rapor, JSON |
| `.zip` / `.obb` | `PK` | merkezi dizin, dizin gruplari, icindeki so/exe/dll listesi | TXT rapor |
| `.so` / `.elf` | `\x7fELF` | ELF32/64, LE/BE, e_machine (x86-64/AArch64/ARM...), e_type, bolum tablosu, UE surum stringleri, motor taramasi (il2cpp/unity/unreal markerlari) | TXT rapor |
| `.dex` | `dex\n` + versiyon | header sayimlari (string/type/proto/field/method/class), adler32 checksum dogrulamasi, MUTF-8 string havuzu taramasi, paket istatistikleri (`Lcom/foo/Bar;` -> paket adi), motor ipuclari (com.epicgames, com.unity3d, il2cpp...) | TXT rapor, JSON |

ZIP icerigi cikarma: STORE (method 0) + DEFLATE (method 8). C++ tarafinda
DEFLATE cozucu yerlesiktir (RFC 1951, disa bagimli degil); web tarafinda
Node'un yerlesik `node:zlib` kullanilir. ZIP64 (4 GB+ arsivler) desteklenir.

Sinirlar (bilincli kararlar):
- Statik analiz **canli bellek erisimi yapmaz**; GObjects/GNames adresleri PE
  icin "aday" olarak verilir, canli modda (`--process`) RIP-relative
  cozumlemeyle teyit edilir.
- APK icindeki `.pak` icerikleri acilmaz (sadece listelenir) - asset acma
  kapsam disidir.
- IL2CPP metadata-yalniz moddur: Il2CppType tablosu ve metod native adresleri
  binarydedir (libil2cpp.so/GameAssembly.dll); tip isimleri yerine TypeIndex
  yazilir. Binary eslestirmesi (CodeRegistration taramasi) yol haritasindadir.
- OAT/VDEX: temel header dogrulamasi (magic/surum/sayim/alanlar); icerik
  cikarma (vdexExtractor tarzi DEX ayristma) kapsam disidir.
- OAT/VDEX/IL2CPP: v16..31 metadata + 006/010/019/021 vdex + `art\n` oat
  taninir; taninmayan surumlerde rapor uyari verir, sessiz tahmin yapmaz.

---

## 2. Web Analyzer (Next.js panel)

Panel: ana sayfa -> "Dosya Analizi" sekmeleri.

Pipeline (`src/lib/analysis/`):

```
detect.ts    magic bytes -> pe | apk | zip | elf | dex | metadata | unknown
pe.ts        PE32/PE32+ cozumleme (bolumler, import/export, data dirs,
             TAM debug dizini: PDB+GUID+POGO/IPOCG/REPRODUCIBLE kayitlari,
             COFF sembol tablosu, VS_VERSIONINFO)
elf.ts       ELF32/64 cozumleme
dex.ts       DEX header + string havuzu + paket istatistikleri
zipapk.ts    ZIP merkezi dizin + STORE/DEFLATE cikarma + binary AXML manifest
engine.ts    motor + guvenlik taramasi (UE4/UE5/Unity/Godot/Source/CryEngine/
             Frostbite, anti-cheat: EAC/BattlEye/Ricochet/VAC/vangard,
             DRM: Steam/Denuvo/EOS, packer: VMProtect/Themida/UPX)
functions.ts fonksiyon tablosu: x64 .pdata (IMAGE_RUNTIME_FUNCTION, kesin
             sinirlar) / x86 prologue heuristigi + IAT haritasi + xref grafigi
disasm.ts    x86-64 cozucu (Intel SDM alt kumesi) + tahmini pseudo-C uretici;
             string/IAT/vftable/fonksiyon etiketli komut cikti
rtti.ts      MSVC x64 RTTI: TypeDescriptor -> COL -> vftable baglantisi,
             metod RVA listesi, .?AW4 enum adlari
structs.ts   struct kurtarma: vftable referansli fonksiyonlarda [reg+disp]
             uye erisimleri -> alan ofsetleri/tipleri + UnknownData dolgu
enums.ts     enum kurtarma: RTTI .?AW4 + .rdata switch atlama tablo taramasi
metadata.ts  Unity global-metadata.dat tam parse (Il2CppDumper uyumlu,
             metadata v16..31; sinif/enum/alan/metod adlari + enum degerleri)
sdkgen.ts    Dumper-7 stili C++ SDK ciktilari + Il2CppDumper stili dump.cs
report.ts    Turkce TXT rapor + games.ini taslagi uretimi
index.ts     orkestrator: yukaridakileri tek AnalysisResult'ta birlestirir,
             secili fonksiyonlara asm+pseudo ekler, SDK dosyalarini disk yazar
```

API rotalari:

| Rota | Islev |
|---|---|
| `POST /api/upload` | dosya yukleme (multipart) + otomatik analiz |
| `GET /api/uploads` | arsiv listesi (tum yuklemeler + analiz ozetleri) |
| `GET /api/uploads/<id>` | tek yukleme detay + tam rapor |
| `POST /api/uploads/<id>/extract` | APK/ZIP icinden kayit cikarip AYRI analiz acar (`{"entry":"lib/arm64-v8a/libUE4.so"}`) |
| `GET /api/uploads/<id>/report?format=txt|json` | rapor indirme |
| `GET /api/uploads/<id>/sdk` | SDK cikti manifest (uretilen dosya listesi) |
| `GET /api/uploads/<id>/sdk/<dosya>` | tek SDK cikti dosyasi (classes.h / structs.h / enums.h / Functions.txt / Decompile.txt / Debug.txt / Offsets.txt / dump.cs) |
| `GET /api/download` | tum DumperPro kaynak kodunu zip olarak indirir |

Depolama: `storage/uploads/<id>__<guvenli-dosya-adi>`, limit 300 MB
(`src/lib/storage.ts`). Metaveri SQLite (Prisma `Upload` + `Analysis` modelleri).

UI ozellikleri (`src/components/analyzer.tsx`):
- surukle-birak yukleme, arsiv gecmisi, sekme yapisi (Genel / Bolumler /
  Import-Export / Arsiv Icerigi / Motor & Guvenlik / Imza Adaylari / **Debug** /
  **Fonksiyonlar** / **Structlar** / **Enumlar** / **IL2CPP** / **SDK** / Dizeler / Rapor)
- Debug: PDB yolu + GUID/Age + MS sembol sunucusu yolu + tum debug dizin kayitlari
- Fonksiyonlar: .pdata tablosu; satira tiklayinca disassembly + tahmini pseudo-C
  iletisim kutusu (kopyalanabilir)
- Structlar: kurtarilan alan ofsetleri (Dumper-7 UnknownData stili cikti)
- Enumlar: RTTI adlari + switch tablosu uye degerleri + IL2CPP enum degerleri
- IL2CPP: metadata v16-31 istatistikleri, sinif/enum tablolari, string literal ornekleri
- SDK: uretilen ciktilari tek tek indirme (Dumper-7 / Il2CppDumper stili)
- APK/ZIP icindeki `.so`'lar icin "Analiz Et" dugmesi (extract + yeni analiz)
- games.ini taslagini kopyalama, TXT/JSON rapor indirme

---

## 3. DumperPro.exe --serve (Windows aracinda online yukleme)

```
DumperPro.exe --serve            -> http://127.0.0.1:8420
DumperPro.exe --serve 9000       -> farkli port
```

- Yerlesik minimal HTTP sunucu (`src/net/HttpServer.cpp`): WinSock2/POSIX
  cift katman; **baglanti basina thread, ayni anda en fazla 4 eszamanli
  analiz** (saturasyonda yeni kabul kisaca bekler - bounded pool).
- `GET /` -> surukle-birak yukleme sayfasi (Turkce, tasiyiciya gomulu HTML).
- `POST /upload` -> multipart/form-data (alan adi: `file`) veya raw
  `application/octet-stream`; boyut limiti 512 MiB.
- Analiz `StaticAnalyzer` ile yapilir; rapor HTML olarak doner ve
  `DumperPro_Out/serve/<zaman>_<dosya>_report.txt` + `_report.json` +
  (IL2CPP ise) `_il2cpp/` cikti klasoru olarak diske yazilir.
- Baglama adresi yalnizca 127.0.0.1'dir - harici ag erisimi yok.

---

## 4. DumperPro.exe --file (PE olmayan dosyalar)

```
DumperPro.exe --file oyun.apk          -> APK hatti (manifest + so taramasi + IL2CPP metadata)
DumperPro.exe --file libUE4.so         -> ELF hatti
DumperPro.exe --file classes.dex       -> DEX hatti
DumperPro.exe --file global-metadata.dat -> IL2CPP metadata tam ciktilari
DumperPro.exe --file base.vdex         -> VDEX header raporu (006/010/019/021)
DumperPro.exe --file base.odex         -> OAT/VDEX otomatik tespit
DumperPro.exe --file Game-Shipping.exe -> PE tam hatti (canli modla ayni: imza
                                          taramasi, GObjects/GNames, SDK uretimi)
```

PE koklemesi dosyanin ilk 2 baytindan yapilir (`MZ`); PE olmayan her sey
`StaticAnalyzer`'a yonlenir ve cikti `DumperPro_Out/<ad>_<zaman>/`
altina `analysis_report.txt` (+ `--json` ile `analysis_report.json`,
+ IL2CPP dosyalarinda `il2cpp_report.txt`, `il2cpp_dump.cs`,
`il2cpp_metadata.json`, `il2cpp_stringliterals.txt`) yazilir.

`--json` bayragi canli modda `names.json` + `objects.json` makine-okur
semalari da uretir (roadmap 2.1: JSON cikti secenekleri).

---

## 4.1 Canli hedefler (0.5.2): proses secimi + canli veri cikarma

Canli attach (`--process/--pid`) v0.1'den beri vardi; 0.5.2 ile **kesif + secim +
tek tik dump** katmanlari eklendi. Uc ayri erisim noktasi vardir ve hepsi ayni
canli veri cikarma hattini kullanir (UE: GNames -> GObjects -> GWorld -> SDK;
Unity: canli IL2CPP metadata eslestirme).

### 4.1.1 CLI: --list-processes [--deep]

```
DumperPro.exe --list-processes            -> calisan prosesler + motor ipuclari
DumperPro.exe --list-processes --deep     -> UE surumu bellekten dogrulanir
DumperPro.exe --list-processes --json     -> DumperPro_Out/processes.json
```

Ornek tablo:

```
  PID      AD                                 MODUL MOTOR         DETAY
  --------------------------------------------------------------------------------------
  8820     MyGame-Win64-Shipping.exe          87    UE Game?      image name *-shipping.exe
  9320     UnityGame.exe                      142   Unity IL2CPP  module GameAssembly.dll
  6104     MyGame-Win64-Shipping.exe          87    UE 5.1        string ++UE5+Release-5.1.1
```

- **Hizli katman** (her zaman): proses basina modul snapshot'i (`TH32CS_SNAPMODULE`);
  `GameAssembly.dll` -> Unity IL2CPP (kesin), `unityplayer.dll`(+mono) -> Unity
  Mono/Unity, `UE4Editor/UE5Editor` -> UE Editor, `*-Shipping.exe/-Client.exe/...`
  -> UE Game?. `OpenProcess(READ)` testi ile attachable durumu da tabloda ([korumali]).
- **Deep katman** (`--deep`): aday proseslerde (ipucu bosek/kararsiz VEYA UE Game?,
  ana modul >= 4 MB, kesin Unity ipucli olanlar atlanir) ana modul imaji 1 MB'lik
  parcalarda (tavan 32 MB) okunur ve `++UE4/5+Release-x.y.z` dizesi bellekte aranir.
  Bulunursa "UE 5.1" ipucu + kaynak dize yazilir.
- JSON semasi: `{"format":"dumperpro-processes","version":1,"deep":bool,"count":N,
  "processes":[{"pid","name","modules","hint","detail","attachable","deep"}]}`
- Sinirlar: korumali proseslerde modul listesi gorunmez (moduleCount=0); --deep UE
  surumunu yalnizca ana modulun ilk 32 MB'indaki dizeden dogrular (monolitik
  surumler okunur; nadir durumlarda dize daha ileride ise bulunamaz).

### 4.1.2 Canli IL2CPP: --process/--pid + --metadata

Il2CppDumper'in "canli yarisi": IL2CPP modulu (GameAssembly.dll / libil2cpp.so)
hedef prosesin bellek imaji olarak okunur (mapped layout), `ModuleImage::UnmapToRawFile`
ile RAW PE dosya duzenine geri acilir ve metadata eslestirme hattinin TAMAMI
(CodeRegistration/MetadataRegistration taramasi -> metod adresleri + gercek tip
isimleri + DummyDll C# stub'lari) calistirilir.

```
DumperPro.exe --process Game.exe --metadata global-metadata.dat
DumperPro.exe --pid 1234 --module GameAssembly.dll --metadata global-metadata.dat --json
```

- Neden onemli: diskteki GameAssembly.dll paketli/sifreli olan oyunlarda statik
  eslestirme calismaz; bellekteki mapped imaj acilmis halde durur.
- Cikti: `<oyun>_il2cpp_live_<zaman>/` altinda `dump.cs`, `script.json`,
  `il2cpp_report.txt`, DummyDll klasoru; `--json` ile ek olarak ham PE imaji
  (`<modul>_live_raw.bin`); `result.json` **status=il2cpp** manifesti (web platform
  import sekmesi bu durumu teal rozetle gosterir).

### 4.1.3 Serve modu: /api/processes + /api/dump (tek tik canli dump)

`--serve` ana sayfasinda **"Canli Hedefler"** bolumu vardir; sayfa acilir acilmaz
liste otomatik cekilir.

| Rota | Islev |
|---|---|
| `GET /api/processes` | canli proses listesi (4.1.1'deki JSON semasi) |
| `GET /api/processes?deep=1` | UE surumunu bellekten dogrula (deep katman) |
| `POST /api/dump` | govde: `{"pid":N,"module":"...","noSdk":bool,"metadata":"..."}` |

`POST /api/dump` **self-spawn** desenini kullanir: DumperPro.exe kendini
`--pid N --json --out DumperPro_Out/serve/live_<zaman>_pid<N>` argumanlariyla
subprocess olarak yeniden baslatir (CreateProcessA + stdout/stderr pipe yakalama,
10 dakika tavan). Böylece UE hattinin tamamı (GNames/GObjects/GWorld/SDK/
functions.json/result.json) web sayfasindan tek tikla, bakim gerektirmeden kosar:

```
{"ok":true,"exitCode":0,"outDir":"DumperPro_Out/serve/live_20251121_143022_pid8820",
 "cmd":"\"C:\\...\\DumperPro.exe\" --pid 8820 --json --out \"...\"",
 "result":{ ...result.json icerigi... }, "log":"...dump logu..."}
```

- Guvenlik: rota yalnizca 127.0.0.1 baglamasinda sunulur; self-spawn yalnizca kendi
  exe'sini kendi argumanlariyla baslatir (kabuk calistirmasi yok); Windows disi
  yapilarda rota zarif 400 doner (canli proses erisimi Win32 API'ye baglidir).
- Sonraki adim: `outDir` icerisindeki `result.json` + `functions.json` dosyalarini
  web platformunun "DumperPro Import" sekmesine yukleyin (ZIP de kabul edilir).

---

## 5. Kaynaklar ve dogrulama

Format spesifikasyonlari (uygulamalar bu dokumanlara karsi yazildi):

- **PE/COFF**: Microsoft Docs "PE Format" (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS,
  IMAGE_OPTIONAL_HEADER64, section table, data directories)
- **ZIP**: PKWARE APPNOTE.TXT (EOCD `PK\x05\x06`, central dir `PK\x01\x02`,
  local header `PK\x03\x04`, ZIP64 `PK\x06\x06`/`PK\x06\x07`, extra field 0x0001)
- **DEFLATE**: RFC 1951 (Huffman, length/distance tablolari) - C++ decoder
  el yazimidir, Node tarafinda `node:zlib.inflateRawSync`
- **ELF**: TIS ELF Specification v1.2 / System V ABI (e_ident, e_machine,
  section headers, shstrtab)
- **DEX**: AOSP `dex-format.md` (header 0x70, ULEB128, MUTF-8, string_ids,
  type_ids, class_defs, adler32 checksum)
- **IL2CPP metadata**: Il2CppDumper (Perfare) `Il2Cpp/Metadata.cs` +
  `Il2Cpp/MetadataClass.cs` (jsdelivr CDN uzerinden cekildi; header cift
  sirasi, v24 alt-surum sezgileri, TypeDefinition/MethodDefinition boyutlari
  ve v31 returnParameterToken eklentisi kaynaktan birebir dogrulandi)
- **VDEX**: anestisb/vdexExtractor `src/vdex/vdex_006|010|019|021.h`
  (header struct'lari) + `src/vdex_api.c` (006->API 26, 010->API 27,
  019->API 28, 021->API 29 eslemesi kaynaktan dogrulandi)
- **OAT**: AOSP `art/runtime/oat.h` OatHeader duzeni (magic `art\n`,
  surum `NNN\0`, checksum, dex_file_count, executable_offset); AOSP sunucusu
  erisilemediginden duzen toleransli parse ile uygulandi (sadece ilk 5 alan
  varsayilir, diger alanlara dokunulmaz)
- **AXML**: AOSP binary XML format (cheku/RES_XML_TYPE) - manifest cozumleme
  guvenli-fallbacklidir (cozulemezse hata notu, analiz devam eder)
- **UE surum stringleri**: `++UE4+Release-4.27.2-0.0` / `++UE5+Release-5.3.2-0.0`
  bicimi; `+Main` ozel build'ler de tespit edilir

Kutuphane bagimliligi: **SIFIR**. Web tarafi Node'un yerlesik `zlib` ve
`crypto` modullerini; C++ tarafi STL + OS soketlerini kullanir. ZIP/PE/ELF/DEX/
AXML parserlari bu projede el yazimidir (vendor binary yok, DLL yok).

Dogrulama: portable C++ dosyalari (`ZipReader`, `UniFormat`, `OatVdex`,
`Il2Cpp`, `StaticAnalyzer`, `HttpServer`) Linux g++ -std=c++20 ile derlenip
sentetik global-metadata.dat (v27), vdex (021), oat (`art\n`+KV store) ve
metadata gomulu APK ile uc-uc-u test edilmistir: IL2CPP ciktilari (3 image,
8 tip, 10 alan, 8 metod, 4 literal) ureticiyle birebir eslesir; kesik/bozuk
dosyalar crash olmadan temiz hata verir; `--serve` paralel yuklemelerle
(thread havuzu) dogrulanmistir. Web tarafi tarayici E2E testine tabidir.
