# DumperPro — Windows Test Kiti (LeechCore `--device`)

Bu klasör, DumperPro motorunun **v0.4.2** durumuna karşılık gelen Windows tarafı
test kitidir: MSVC derleme scripti (VS 2026/2022 + otomatik VS tespiti), resmi
MemProcFS sürümünden `leechcore.dll` temini ve `--device` (LeechCore) modunun
4 adımlı otomatik test baterisi.

> Motor tarafının ne yaptığı ve neden böyle yaptığı için: **`docs/LEECH.md`**
> (mimari, API tablosu, cihaz stringleri, sınırlar). Bu README yalnızca
> "Windows makinesinde nasıl derlerim, kurarım ve test ederim" sorusunu yanıtlar.

---

## 1. Ön koşullar

| Bileşen | Gerekli mi | Not |
|---|---|---|
| Windows 10/11 **x64** | Evet | Motor yalnızca x64 olarak derlenir/test edilir |
| **VS 2026 (v18)** ya da VS 2022 / *Build Tools* + "Desktop development with C++" workload | Evet (derleme için) | "x64 Native Tools Command Prompt for VS 2026" ile çalıştırın — normal cmd'de de çalışır: script VS'yi **vswhere** ile kendisi bulur |
| `leechcore.dll` | TEST 1 için evet | `get-leechcore.ps1` ile temin edilir (GPL-3.0, ufrisk; DumperPro dağıtmaz) |
| DMA donanımı (FPGA kart / USB3380) | **Hayır** | Yalnızca TEST 2/3'ün "donanımlı" kolu içindir. `file://` testi (TEST 1) **donanım gerektirmez** |
| VC++ Redistributable | Genelde hayır | Derleme makinesinde VS zaten var; MemProcFS zip'i `vcruntime140.dll` taşır. Sorun çıkarsa `vc_redist.x64.exe` kurun |

---

## 2. leechcore.dll kurulumu (`get-leechcore.ps1`)

DumperPro, `leechcore.dll`'i çalışma zamanında `LoadLibraryA` ile bağlar;
import library/header istemez ve **hiçbir GPL ikilisini dağıtmaz**. DLL'i resmi
sürümden siz temin edersin:

```powershell
powershell -ExecutionPolicy Bypass -File get-leechcore.ps1
```

Script ne yapar:

1. GitHub API'den `ufrisk/MemProcFS` **en son sürümünü** çeker
   (`https://api.github.com/repos/ufrisk/MemProcFS/releases/latest`).
2. Windows x64 asset'ini seçer (`MemProcFS_files_and_binaries*win_x64*.zip`).
   API rate limit'e düşerse (403) otomatik yedek yöntem devreye girer:
   `releases/latest` 302 yönlendirmesinden tag çözülüp
   `MemProcFS_files_and_binaries-win_x64-latest.zip` indirilir.
3. Zip'i geçici klasöre açar, **`leechcore.dll`'i doğrular** (zip kökünde durur,
   alt klasör taraması da vardır) ve bu klasöre — yani `DumperPro.exe`'nin
   yanına — kopyalar. `LoadLibraryA` önce exe klasörüne bakar.
4. Donanım notlarını yazdırır (aşağıda).

Kurulumu doğrula:

```
dir leechcore.dll
```

### Donanım notları (yalnızca canlı DMA; `file://` için gerekmez)

- **FPGA** (`fpga`): FTDI D2XX sürücüsü kurulu olmalı (zip'teki `FTD3XX.dll`
  yardımcıdır; "Virtual COM" sürücüsü **değil** D2XX).
- **USB3380** (`usb3380:`): kart takılı + yönetici komut istemi; sürücü imzası
  gerekir (bkz. sorun giderme).
- **PMEM** (`pmem://`): zip'teki `winpmem_x64.sys` sürücüsü.
- İsteğe bağlı: `-IncludeVmm` anahtarı `vmm.dll`'i de kopyalar (MemProcFS
  seviyesi modul bilgisi — VMMDLL_* entegrasyonu yol haritası içindir; v0.3.0
  motoru yalnızca `leechcore.dll` kullanır).

---

## 3. Derleme (`build.bat`)

İki yol vardır:

- **Baslat menüsü → "x64 Native Tools Command Prompt for VS 2026"** (veya VS 2022)
  penceresi aç → bu klasöre gel → çalıştır. *veya*
- **Normal cmd / çift tık**: script `vswhere.exe` + bilinen kurulum yolları
  (`C:\Program Files\Microsoft Visual Studio\18\...` VS 2026, `\2022\...`,
  `\2019\...`) üzerinden VS'yi bulup `vcvarsall.bat x64` ile MSVC ortamını
  kendisi kurar.

```bat
cd DumperPro\windows
build.bat
```

Script `cl.exe` bulunamazsa açık bir hata mesajıyla çıkar; `..\src` altındaki
tüm `.cpp` dosyalarını `/std:c++20 /EHsc /O2 /MP /utf-8` ile derleyip bu
klasöre `DumperPro.exe` üretir. Ara dosyalar `obj\` klasörüne toplanır.

Kod gerçekleri ( neden ekstra define gerekmez):

- Windows'ta `LeechReader.cpp` / `ProcessReader.cpp` / `KernelReader.cpp`
  nativ `_WIN32` dalıyla derlenir — `USE_LEECH` gibi bir makro **yoktur**.
- `leechcore.dll` çalışma zamanında `LoadLibraryA + GetProcAddress` ile
  bağlanır: DLL yoksa bile exe açılır, `--device` kullanılınca kurulum ipucu
  verir (`Hint:` satırı, çıkış kodu 2).
- `ws2_32.lib` otomatik bağlanır (`src/net/HttpServer.cpp` içindeki
  `#pragma comment(lib, "ws2_32.lib")`).

---

## 4. Testler (`test-device.bat`)

```bat
test-device.bat
```

Her testin çıktısı `testlog_t*.log` dosyalarına yazılır; her adım `PASS/FAIL`
olarak ekranlanır ve sonda `SONUC: N PASS / M FAIL` özeti gelir (batch çıkış
kodları: hepsi PASS → 0, en az bir FAIL → 1).

### TEST 1/4 — `file://` sentetik dump (donanımsız ana test)

`test_dump.bin` adıyla **16 MB sentetik fiziksel bellek dosyası** üretir
(256-baytlık tekrarlayan desen + `DMPPRO-TEST-SIG!` @ 0x11000 +
`++UE5+Release-5.1.1-0-Test` UE5.1 sürüm işaretçisi @ 0x30000), sonra:

```bat
DumperPro.exe --device "file://%CD%\test_dump.bin" --out out_t1
```

- Ek hedef/PE bayrağı gerekmez: `--device` tek hedef kuralındadır
  (`--process/--pid/--file/--serve` ile birleştirilemez; `--hex` de yasak —
  cihaz seviyesinde modül modeli yoktur, bkz. `docs/LEECH.md` §4).
- **Beklenen çıkış kodu: 4** (`GNames not found`). Sentetik dump'ta GNames
  OLMAMASI normaldir; testin doğruladığı şey motorun LcCreate → paMax raporu →
  0x10000'den paMax'a en iyi çaba (best-effort) imza taraması → UE sürüm
  tespiti hattının uçtan uca çalışmasıdır.

Beklenen çıktı (canlı doğrulanmış biçim — saat/ yol sizde farklıdır):

```
[+] LeechCore device ready: 'file://C:\...\test_dump.bin' -> file (writable=no, maxPA=0x000001000000)
[*] Device mode: file://C:\...\test_dump.bin (LeechCore)
[!] LeechCore device '...' reports no modules: the UE SDK needs MemProcFS-level module info ...
[!] Falling back to a best-effort 15.94 MB signature scan from 0x000000010000 (device max=0x000001000000; ...)
[*] Device window: file://C:\...\test_dump.bin base=0x10000 size=15.94 MB
[+] Detected UE version: UE5.1 (UE5 mode)
[*] Searching GNames...
[X] GNames not found
  Hint: add to games.ini: ...
```

PASS ölçütleri (batch bunları otomatik arar): çıkış kodu 4 (veya 5) **ve** logda
`LeechCore device ready` + `Device window:` + `Detected UE version: UE5.1`.

### TEST 2/4 — `fpga` probe (FPGA DMA)

```bat
DumperPro.exe --device "fpga" --out out_t2
```

- Kart **takılı değilse** (normal durum): çıkış kodu **2**, logda
  `cannot open LeechCore device: fpga` + `Hint:` → **PASS** (zarif hata yolunun
  çalışması testin kendisidir; crash/askıda kalma YOK).
- Kart **takılıysa**: `LeechCore device ready: 'fpga' ...` satırı gelir, tarama
  çalışır, çıkış kodu 4 (canlı RAM penceresinde GNames bulunamaması normal) →
  **PASS**.

### TEST 3/4 — `usb3380:` probe (USB3380 DMA)

TEST 2 ile birebir aynı semantik, cihaz stringi `usb3380:`:

```bat
DumperPro.exe --device "usb3380:" --out out_t3
```

### TEST 4/4 — baz çizgisi (motor sağlığı, LeechCore'suz)

```bat
DumperPro.exe --help
DumperPro.exe --file notepad_test.exe --out out_t4
```

- `--help` çıkış kodu **0** olmalı.
- `C:\Windows\System32\notepad.exe` bu klasöre kopyalanıp `--file` ile açılır:
  `File mode:` satırı gelir, çıkış kodu **4** beklenir (notepad UE oyunu
  değildir; "GNames not found" PE okuma hattının sağlıklı çalıştığını gösterir).
  Kopyalanamazsa (izin/antivirüs) PE alt testi atlanır, `--help` yeterli sayılır.

### Çıkış kodları referansı (main.cpp)

| Kod | Anlam |
|---|---|
| 0 | Başarı (veya `--help` / `--list-profiles`) |
| 1 | Argüman hatası |
| 2 | Cihaz/okuyucu açılamadı (DLL yok, LcCreate başarısız) |
| 3 | Modül bulunamadı (yalnızca process modu) |
| 4 | GNames bulunamadı / parse edilemedi |
| 5 | GObjects bulunamadı / parse edilemedi |

---

## 5. Manuel komutlar (tek tek denemek için)

```bat
rem salt-okunur dosya cihazi (donanim gerektirmez):
DumperPro.exe --device "file://C:\dumps\ram.bin" --out C:\out\ram

rem yazilabilir dosya cihazi (write=1; LcWrite testi icin):
DumperPro.exe --device "file://C:\dumps\ram.bin,write=1" --out C:\out\ram

rem crash/minidump:
DumperPro.exe --device "dump://C:\dumps\memory.dmp"

rem canli DMA (yonetici; donanim gerekir):
DumperPro.exe --device "fpga"
DumperPro.exe --device "usb3380:"
```

Davranış notları (docs/LEECH.md ile tutarlı): dosya cihazı varsayılan
**salt-okunur** açılır (`writable=no`); LeechCore dosya cihazı 4K sayfa
granularitesi ister, hizasız/küçük okumalar motor içindeki sayfa shim'iyle
yapılır; tarama penceresi 0x10000'dan başlar ve cihazın raporladığı `paMax`
ile sınırlanır (üst kap 512 MiB).

---

## 6. Sorun giderme

| Belirti | Olası neden | Çözüm |
|---|---|---|
| `leechcore.dll not found (err 126/2)` + `Hint:` satırı | DLL exe yanında ve PATH'te yok | `get-leechcore.ps1` çalıştır; DLL'i `DumperPro.exe` yanına koy; ya da DLL klasörünü PATH'e ekle |
| Derlemede `cl.exe bulunamadi` | "x64 Native Tools" penceresi değil VE VS bulunamadı | VS Installer → VS 2026 Community + "C++ ile masaüstü geliştirme" workload; sonra doğru pencereyi aç ya da normal cmd'de tekrar dene (vswhere otomatik bulur) |
| `cannot open LeechCore device: fpga/usb3380:` | Donanım yok veya sürücü yok | Donanımsızsa normal (TEST 2/3 PASS). Kart varsa: yönetici penceresi, FTDI D2XX sürücüsü (FPGA), kartın PCIe/USB bağını kontrol et |
| USB3380 için sürücü hatası | Sürücü imzası / kod imzalama | Windows'ta test imzalı sürücü gerekiyorsa `bcdedit /set testsigning on` + yeniden başlatma (kendi sorumluluğunda; sonra kapat) |
| DLL yüklendi ama boya/eksik DLL hatası (`err 126`, vcruntime) | VC++ runtime eksik | `vc_redist.x64.exe` kur (https://aka.ms/vs/17/release/vc_redist.x64.exe) |
| `get-leechcore.ps1` indirmesi başarısız | Proxy/antivirüs/https | PowerShell'de TLS 1.2 zorunlu (script yapar); kurumsal proxy varsa elle: releases sayfasından `...win_x64....zip` indir, `leechcore.dll`'i exe yanına koy |
| Antivirüs `DumperPro.exe`/`leechcore.dll`'i siliyor | Yanlış pozitif (memory okuma araçları sık işaretlenir) | Klasörü istisna listesine ekle; yalnızca **resmi** MemProcFS sürümünü kullan |
| `--device file://...` 4 döndü | GNames bulunamadı | Sentetik/boş dump'ta **normal**; gerçek oyun dump'ında `games.ini`'ye `gnames =` satırı ekle (docs/LEECH.md) |
| `Access denied` (`--file` TEST 4) | AV/kopyalama izni | Test PE alt testini atlar (SKIPPED) — sorun değil; `--help` kolonu yeter |
| Çıkış 2 + `LcCreate failed for device '...'` | Cihaz stringi hatalı | Yazımı kontrol et: `fpga` (iki nokta yok), `usb3380:` (iki nokta var), `file://C:\yol\dosya` |

---

## 7. Güvenlik ve yasal uyarı

- Bu araç **yalnızca sahibi olduğunuz ya da analiz etmeye yetkili
  sistemler/oyunlar/yazılımlar** içindir: kendi PC'n, kendi VM'lerin, kendi
  tek oyunculu projelerin, eğitim amaçlı sentetik dump'lar.
- **Kapsam dışı:** çok oyunculu hile, anti-cheat evasion, izinsiz erişim,
  başkalarının makinelerinden bellek toplama. DMA kartlarıyla başkasının
  makinesine dokunmak yasal suçtur (yetkisiz bilgisayar erişimi).
- Canlı DMA donanımı kararsızlığa/blue-screen'e yol açabilir; önce kendi
  test sisteminde, yedekli dene. Şirket bilgisayarlarında kullanma.
- Lisans: LeechCore **GPL-3.0**, MemProcFS **AGPL-3.0**. DumperPro hiçbir
  ikilisini dağıtmaz; DLL'i kullanıcı bu scriptle/elle kendi kurar (dinamik
  bağlama notu: `docs/LEECH.md` §5).

---

## 8. Dosyalar

| Dosya | İş |
|---|---|
| `build.bat` | MSVC (x64, C++20, /O2, /MP) derleme scripti → `DumperPro.exe`; VS 2026/2022/2019 otomatik tespit (vswhere + bilinen yollar) |
| `get-leechcore.ps1` | Resmi MemProcFS sürümünden `leechcore.dll` indirme/yerleştirme |
| `test-device.bat` | 4 adımlı otomatik test baterisi ([TEST 1/4]..[TEST 4/4], PASS/FAIL özeti) |
| `README.md` | Bu dosya |

Derin/ek testler: `docs/LEECH.md` §9 (Linux canlı doğrulama kaydı) ve repo
kökündeki `scripts/windows/` altındaki PowerShell kitleri (LcWrite round-trip
harness'ı dahil). Bu klasördeki kit, tek başına çalışacak şekilde tasarlanmıştır.
