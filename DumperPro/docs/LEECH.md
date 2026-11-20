# DumperPro - LeechCore Cihaz Uydu Okuyucu (`--device`)

Bu dokuman, DumperPro'nun **opsiyonel** LeechCore tabanli bellek okuma yolunu
(`--device` bayragi, `LeechReader.cpp`) dokumante eder: ne ise yaradigi, hangi
API'ye baglandigi, kurulum ve sinirlar. DumperPro hicbir LeechCore kaynagini
dagitmaz; calisma zamaninda resmi `leechcore.dll`'i dinamik yukler.

Yasal cerceve: yalnizca sahibi oldugunuz ya da analiz etmeye yetkili yazilimlar
ve sistemler icin; cok oyunculu/hile amacli kullanim kapsam disidir (README'deki
DISCLAIMER'a bakin).

---

## 1. LeechCore nedir, ne zaman kullanilir

[LeechCore](https://github.com/ufrisk/LeechCore) (ufrisk / Ulf Frisk), farkli
bellek erisim kaynaklarini tek bir API arkasinda toplayan bir kutuphanedir:
dump dosyalari, PMEM surucusu, USB3380 / FPGA DMA kartlari, VM arka uclari ve
remote ornekler. MemProcFS'in altindaki erisim katmani ayni zamandadir.

DumperPro'da bu yol iki durumda isinir:

1. **Dump dosyalari uzerinde tam pipeline.** `raw://` ve `dump://` cihaz
   stringleri ile bir fiziksel bellek dump'i / crash dump'i acilir ve ayni
   GNames/GObjects/SDK hatti dosya modundeki gibi calistirilir.
2. **Donanim DMA (FPGA, USB3380).** Canli fiziksel bellek erisimi gerekince
   (`fpga`, `usb3380:`), Windows tarafinda cihaza dogrudan baglanilir.

Ne **degildir**: stealth/evaston araci. DumperPro yalnizca kullanicinin kendi
belirledigi cihaza, acik belgelenmis bir API uzerinden, okuma (ve varsa yazma)
yapar. Anti-cheat evasyonu ve cok oyunculu suistimal kapsam disidir.

Ne zaman **kullanilmamali**:

- `--file` modu offline analiz icin yeterliyse (hicbir ek bilesen gerekmez);
- standart process modu (`--process` / `--pid`) calisiyorsa;
- modul duzeyinde (VA -> RVA) analizin gerektigi durumlarda ve elinizde
  modul bilgisi yoksa - bkz. bolum 4 (bu durum DumperPro'nun en iyi caba
  taramasina duser).

---

## 2. Mimari

```
+------------------------------+        +----------------------------------+
| DumperPro.exe (user mode)    |        | leechcore.dll (GPL-3.0, ufrisk)  |
|                              |        |                                  |
| LeechReader (IMemoryReader)  | Load-  |  LcCreate(LC_CONFIG)             |
|   Read()  -> LcRead          | Lib +  |  LcRead / LcWrite                |
|   Write() -> LcWrite         | GetPro-|  LcClose / LcMemFree             |
|   Modules() -> {} (bos)      | cAddr  |  LcGetOption / LcSetOption       |
+------------------------------+        +----------------+-----------------+
            |                                             |  cihaz soyutlamasi
            |  fiziksel adres (PA) okuma/yazma            v
   +--------+---------+                        +---------------------------+
   | raw/dump dosyasi |                        | fpga / usb3380 / pmem /   |
   | (offline)        |                        | qemu / vmx / remote ...   |
   +------------------+                        +---------------------------+
```

- Baglama **dinamiktir**: `LoadLibraryA("leechcore.dll")` + `GetProcAddress`.
  DLL yoksa ikili dosya (binary) yine de acilir; fabrika fonksiyonu `nullptr`
  dondurur ve kurulum ipucu yazilir.
- Cihaz secimi `LC_CONFIG.szDevice` icindeki **cihaz stringi** ile yapilir;
  DumperPro bu stringi birebir LeechCore'a gecirir ( yorumlamaz).
- Hata yolu standarttir: fabrika `nullptr` dondurur, sebep loglanir, CLI
  `Hint:` mesajiyla temiz sekilde cikar (kilitlenme/crash yok).

---

## 3. API ozeti (leechcore.h v2.23'e karsi dogrulanmis)

DumperPro yalnizca asagidaki ihracatlari (exports) baglar; tam struct tanimlari
`src/core/LeechReader.h` basliginda belgelenmistir.

| Fonksiyon | Imza (ozet) | DumperPro kullanimi |
|---|---|---|
| `LcCreate` | `HANDLE LcCreate(_Inout_ PLC_CONFIG)` | Cihazi acar; `LC_CONFIG` girdi + cikti (LeechCore `fVolatile/fWritable/szDeviceName` alanlarini gunceller) |
| `LcRead` | `BOOL LcRead(HANDLE, QWORD pa, DWORD cb, PBYTE pb)` | `Read()` - 1 MiB'lik parcalar halinde, butun-all-or-nothing (bir cagri ya hepsi ya basarisiz) |
| `LcWrite` | `BOOL LcWrite(HANDLE, QWORD pa, DWORD cb, PBYTE pb)` | `Write()` - header'da **mevcuttur** (v2.23 dogrulandi); salt-okunur cihazlarda `fWritable=0` ile red |
| `LcClose` | `VOID LcClose(HANDLE)` | Yikicida (destructor) handle kapatma |
| `LcMemFree` | `VOID LcMemFree(PVOID)` | LeechCore tarafindan ayrilan hafizalar icin (baglanir; basit backend buna ihtiyac duymaz) |
| `LcGetOption` | `BOOL LcGetOption(HANDLE, QWORD opt, PQWORD val)` | `LC_OPT_CORE_ADDR_MAX` ile max fiziksel adres raporu (best-effort) |
| `LcSetOption` | `BOOL LcSetOption(HANDLE, QWORD opt, QWORD val)` | Baglanir, su an kullanilmiyor |

Dogrulanmis sabitler / notlar:

- `LC_CONFIG_VERSION = 0xc0fd0002`. Header'in yapisal yorumu "must equal
  LC_CREATE_VERSION" der, ama boyle bir makro header'da **yok**; gercek sabit
  `LC_CONFIG_VERSION`'dir. DumperPro bu gercek degeri kullanir.
- `LC_CONFIG` alan sirasi birebir korunur: `dwVersion, dwPrintfVerbosity,
  szDevice[MAX_PATH], szRemote[MAX_PATH], pfn_printf_opt, paMax, fVolatile,
  fWritable, fRemote, fRemoteDisableCompress, szDeviceName[MAX_PATH]`.
- `paMax = 0` verilmisir; LeechCore max adresi otomatik sezer.
- `LcReadScatter` / `LcReadScatterEx` (sayfa basina `LC_READ_PAGE_RESULT`) ve
  `LcAllocScatter1/2/3` header'da mevcuttur; DumperPro'nun basit arka ucu
  dogrudan `LcRead` kullanir (devami yol haritasindadir).

### 3.1 Cihaz stringleri (`LC_CONFIG.szDevice`)

Yaygin olanlar; tam ve guncel liste [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki)'de:

| String | Anlami |
|---|---|
| `fpga` | FPGA DMA karti (Squirrel/AC701/...; FTDI surucusu gerekir) |
| `usb3380:` | USB3380 tabanli DMA karti |
| `raw://C:\dump.bin` | Ham fiziksel bellek dump dosyasi |
| `dump://x.dmp` | Windows crash/minidump biciminde dosya |
| `pmem://dosya` | PMEM (WinPMEM) cikti dosyasi |
| `qemu://vm` / `vmx://vm` | QEMU / VMware sanal makine arka uclari |
| `vmm://` | VMM (MemProcFS) dongle/loopback |

Not: FPGA kartlari icin ek parametreler (orn. `fpga://0` benzeri bus:dev:fn
secimi) yine wiki'de belgelenir; DumperPro stringi degistirmeden gecirir.

---

## 4. MemProcFS iliskisi: neden `Modules()` bos donuyor

LeechCore bir **cihaz duzeyi** API'dir: girdi fiziksel adres (PA), cikti ham
baytlar. Surec/modul/VAD kavramlari bu katmanda yoktur.

Surec duzeyi katman MemProcFS'tir: `vmm.dll` ve `VMMDLL_*` API'si. MemProcFS,
LeechCore ustune oturur; DTB/proc listesi cozumler, `VMMDLL_Map_GetModule`
ile modul haritasini, `VMMDLL_Map_GetVad` ile VAD/bolge haritasini ve
`VMMDLL_MemRead` ile sanal adres okumayi saglar.

Bu yuzden DumperPro'da:

- `LeechReader::Modules()` her zaman `{}` dondurur ve `MainModuleBase()` 0'dir.
- Modul snapshot'i (PE basligi + bolumler) olmayinca ** sezgisel yapi taramalari
  (heuristic struct scan) devre disi** kalir; yalnizca desen tabanli (pattern)
  imza taramasi calisir.
- main.cpp bos modul listesini zarifce karsilar: net bir uyari yazdirir ve
  **0x10000 adresinden (okuyucunun near-null korumasi) itibaren cihazin
  raporladigi maksimum fiziksel adrese (paMax) kadar, ust siniri 512 MiB olan
  en iyi caba (best-effort) penceresi** uzerinde GObjects/GNames imza taramasi
  yapar (paMax raporlanmiyorsa eski davranis: 64 MiB); UE surumu varsa ham
  ASCII `++UE5+Release-X.Y` isaretleyicilerinden (markers) sezer. Bulunamazsa
  standart ipucu mesajlariyla temiz cikar.
- Tam SDK icin iki gecerli yol vardir: (a) MemProcFS duzeyinde modul bilgisi
  (vmm.dll entegrasyonu - yol haritasindadir), veya (b) ham dump'i `--file`
  ile acmak: `DumperPro.exe --file dump.mem` PE basligini bulabilirse modul
  gorunumune acar; web tarafindaki analiz hatti (bkz. bolum 6) memmap
  eslemesiyle bolge bazli PE kurtarma yapar.

---

## 5. Lisans durumu

| Bilesen | Lisans | DumperPro iliskisi |
|---|---|---|
| LeechCore (leechcore.dll) | **GPL-3.0** | Kaynak dagitilmaz, statik baglama yok; calisma zamaninda kullanici kaynagi LoadLibrary ile yukler |
| MemProcFS (vmm.dll, MemProcFS.exe) | **AGPL-3.0** | Sadece kullanim/kurulum belgelenir; hicbir ikili dagitilmaz |

Iki lisans da 2025-11 itibariyla resmi depolardan teyit edilmistir
(`ufrisk/LeechCore` LICENSE -> GPL-3.0, `ufrisk/MemProcFS` LICENSE -> AGPL-3.0).

**Dinamik baglama notu:** GPL-3.0, ikili dagitim + bagli kutuphane
 durumlarinda tum programin GPL'e girmesini isteyebilir. DumperPro;
- LeechCore kaynaklarini icermaz/derlemez, ikili olarak dagitmaz;
- `leechcore.dll`'i kullanici ayri olarak resmi MemProcFS surumunden temin
  eder ve sistemine kurulur;
- DumperPro calisma zamaninda bu ayri kurulumu LoadLibrary ile kullanir.
Bu, ozel kaynakli bir programin GPL kutuphaneyi "ayri program" olarak
kullanma bicimlerinden biridir; dagitim yaptiginizda kendi uyum
 sorumlulugunuz devam eder. Emin olmadiginizda hukuki danismanlik alin.

---

## 6. Kurulum

1. **MemProcFS surum zip'ini** indirin: <https://github.com/ufrisk/MemProcFS/releases>.
   Icerigi Windows x64 surumu olmali; zip icinde `leechcore.dll` ve `vmm.dll` vardir.
2. DLL'lerden biri:
   - `leechcore.dll` + `vmm.dll`'i **DumperPro.exe'nin yanina** kopyalayin (onerilen), veya
   - DLL'lerin bulundugu klasoru **PATH'e** ekleyin.
3. **MSVC runtime**: MemProcFS surumleri VC++ redistributable ister
   (`vc_redist.x64.exe`, Microsoft'tan).
4. **FPGA icin**: kart ini takmadan once FTDI D2XX surucusunu kurun
   (FTDI Web sitesindeki resmi surucu; "Virtual COM" degil D2XX). Kart +
   `leechcore.dll` ayni bit dusuk seviyeli erisimi ister; yonetici olarak
   calistirmak cogu durumda yeterlidir.
5. Dosya tabanli cihazlar (`raw://`, `dump://`) icin surucu gerekmez.

Denetim: `DumperPro.exe --device "fpga"` cikti soyle bir satir gormelidir:
`LeechCore device ready: 'fpga' -> fpga (writable=..., maxPA=...)`.

### 6.1 Kullanim ornekleri

```
DumperPro.exe --device "raw://C:\dumps\mem.bin"     ham dump uzerinde UE taramasi
DumperPro.exe --device "dump://x.dmp"                crash dump uzerinde
DumperPro.exe --device "fpga"                        canli DMA (Windows, yonetici)
DumperPro.exe --device "fpga" --out C:\out\sdk       cikti klasorunu sabitle
```

Davranis notlari:

- Cihaz acilir ama modul listesi bos gelirse (her zaman bos gelir) uyari +
  64 MiB en iyi caba (best-effort) taramasi yapilir (bkz. bolum 4).
- `--hex` ile `--device` birlestirilemez (cihaz duzeyinde modul modeli yok).
- `--process` / `--pid` / `--file` / `--serve` ile ayni anda kullanilamaz
  (tek hedef kurali).

### 6.2 Web tarafi ile iliski (TS portu)

Web analyzer'daki `src/lib/analysis/mem.ts`, LeechCore'un **dosya tabanli**
cihaz mantiginin TypeScript portudur: `dump://x.dmp`, `raw://x.bin` ve
memmap aralik esleme (`pa, cb, paRemap`) semantigi, minidump/crashdump
baslik cozumu ve bellekten PE kurtarma. Tarayici/sunucu tarafinda canli DMA
olasidir degildir (donanim erisimi gerekir); **canli DMA icin Windows'ta
`DumperPro.exe --device "fpga"` kullanin**. Web tarafi yalnizca dosya
cihazlarinin semantigini ayni tutar.

---

## 7. Sinirlar ve guvenlik notlari

- **Cihaz duzeyi**: modul/VAD haritasi yoktur; modul duzeyi analiz icin bkz.
  bolum 4. `--module` bayragi device modunda anlamsizdir ve uyarilir.
- **Tarama penceresi**: en iyi caba (best-effort) tarama 0x10000'dan baslar;
  ust sinir cihaz paMax'i (ust kap: 512 MiB), paMax raporlanmiyorsa 64 MiB.
  Gercek oyunda GObjects/GNames genellikle yuksek adreslerdedir. Tam kapsam
  icin memmap eslemesiyle genis aralik ya da `--file` yolunu kullanin.
- **Yazma**: `LcWrite` mevcuttur ama cihaz `fWritable=0` bildirirse DumperPro
  yazmayi red eder. Donanima yazma (DMA) hedef sistemin kararliiligini
  bozabilir; yalnizca kendi sisteminizde, yedek almis olarak deneyin.
- **Okunamayan sayfalar**: fiziksel olarak maplenmemis araliklarda `LcRead`
  basarisiz olur; en iyi caba (best-effort) tarama bu bolgeleri sifirla
  doldurup devam eder ve sayac rapor eder.
- **Lisans uyumu**: bolum 5'teki dinamik baglama notunu okuyun; DumperPro
  hicbir GPL/AGPL ikilisini dagitmaz.
- **Operasyonel risk**: DMA kartlari ve surucu tabanli cihazlar blue-screen
  (mavi ekran) / kararsizliga yol acabilir. once ucuz bir VM/deneme
  sisteminde test edin; sirket bilgisayarlarinda kullanmayin.
- **Kapsam disi kullanim**: anti-cheat evasyonu, cok oyunculu hile, izinsiz
  erisim. Bu dokuman ve arac yalnizca analiz/modding/arastirma icindir.

---

## 8. Hizli referans

| Oge | Deger |
|---|---|
| Istemci uygulamasi | `src/core/LeechReader.cpp` (`IMemoryReader` arka ucu) + `LeechReader.h` |
| Etkinlestiren | `--device <lc>` |
| DLL | `leechcore.dll` (MemProcFS surumu; DumperPro.exe yaninda veya PATH) |
| Baglama | `LoadLibraryA` + `GetProcAddress` (dinamik; DLL yoksa zarif nullptr) |
| Cihaz stringi | `LC_CONFIG.szDevice`: `fpga` / `usb3380:` / `raw://` / `dump://` / `pmem://` / `qemu://` / `vmx://` |
| Surum sabiti | `LC_CONFIG_VERSION = 0xc0fd0002` (header'daki `LC_CREATE_VERSION` ismi gercekte yok) |
| Okuma | `LcRead` - 1 MiB parca, near-null korumasi (PA < 0x10000 red), tasma kontrolu |
| Yazma | `LcWrite` (v2.23'te mevcut) - `fWritable=0` ise red |
| Moduller | Bos `{}` - cihaz duzeyi API; modul bilgisi MemProcFS `vmm.dll` katmanindadir |
| Bos modul davranisi | Uyari + 0x10000'dan paMax'a kadar (ust kap 512 MiB; yoksa 64 MiB) en iyi caba (best-effort) imza taramasi; sezgisel taramalar kapali |
| Lisans | LeechCore GPL-3.0, MemProcFS AGPL-3.0 (dinamik baglama notu: bolum 5) |
| Web portu | `src/lib/analysis/mem.ts` (dosya cihazi semantigi; canli DMA yalnizca Windows `--device`) |
| Dokuman | bu dosya (`docs/LEECH.md`) |

---

## 9. Linux canli dogrulama (2026-11-19, bu repo icinde gerceklestirildi)

LeechCore resmi olarak Linux derlemesini de destekler. Bu ortamda gerccci
kutuphane kaynaktan derlendi ve `LeechReader.cpp`'nin Linux dali ile
uc-uca canli test edildi:

```bash
# 1) gercek LeechCore (ufrisk master, v2.23 ABI):
git clone --depth 1 https://github.com/ufrisk/LeechCore.git
cd LeechCore/leechcore
# libusb-1.0-0-dev gerekli (root'suz: apt-get download + dpkg-deb -x)
make            # -> ../files/leechcore.so

# 2) DumperPro Linux dalini derle (dlopen + dlsym, -ldl):
g++ -std=c++20 -O1 -I src -o ../storage/bin/DumperPro \
    src/*.cpp src/*/*.cpp -lpthread -ldl

# 3) canli cihaz testi (sentetik 16 MB fiziksel bellek dosyasi):
LD_LIBRARY_PATH=<leechcore-dir> ./storage/bin/DumperPro \
    --device "file:///tmp/testdev.raw"
```

Testte dogrulananlar (gercek leechcore.so uzerinden):

| Test | Sonuc |
|---|---|
| `dlopen("leechcore.so")` + export baglama | OK (LcCreate/LcRead/LcWrite/LcClose/LcGetOption/LcSetOption/LcMemFree) |
| `LcCreate` (LC_CONFIG v0xc0fd0002, MAX_PATH=260) | OK -> `writable=no, maxPA=0x1000000` (dosya boyutu birebir) |
| `LcGetOption(LC_OPT_CORE_ADDR_MAX)` | OK (0x1000000) |
| `LcRead` imza dogrulama | OK (`DMPPRO-TEST-SIG!` @0x11000) |
| `LcWrite` (write=1) + geri okuma | OK (`0x41414141 -> 0xCAFEBABE`, ROUND-TRIP) |
| CLI `--device` modu tam akisi | OK (64 MB en-iyi-caba tarama, cikti klasoru) |

### 9.1 Bulunan gercek ABI detaylari (testte ogrenildi)

1. **Cihaz metni Linux'ta `file://`** - `raw://` on eki Linux LeechCore'da
   yok; kabul edilenler: `file://<dosya>` (eski), `file://file=<dosya>,write=1`
   (yeni, parametreli), `dump://...`, `fpga`, `usb3380:`. Windows tarafinda da
   ayni `file://` semanti kullanilir.
2. **Sayfa granularitesi**: dosya cihazinda `LcRead` yalnizca 4096 bayt
   katlarini kabul eder; daha kucuk okumalar `FALSE` dondurur. `LeechReader`
   artik hizali buyuk okumalari dogrudan, hizasiz/kucuk okumalari 4K sayfa
   okuyup icerden keserek yapar (readPageShim).
3. **Yazim granularitesi**: hizali coklu-sayfa yazimlari dogrudan;
   hizasiz/kucuk yazimlar oku-degistir-yaz (RMW) sayfa dongusuyle yapilir.
4. **fWritable**: dosya cihazi varsayilan salt-okunur; `write=1` parametresi
   ile yazilabilir acilir. LeechCore acilis sirasinda cfg'yi gunceller,
   reader bu degeri raporlar ve salt-okunur kaynakta yazmayi reddeder.

### 9.2 Kucuk test duzenegi

`TryCreateLeechReader`'i dogrudan cagiran bağımsız dogrulama duzenegi
(`/tmp/leech_harness.cpp` modeli) ile Read imza + Write round-trip testleri
tekrarlanabilir; DumperPro ikilisi icin ek bagimlilik gerekmez.

### 9.3 Yeniden dogrulama (2026-11-20) + paMax-uyarlanabilir tarama penceresi

Derleme artiklari temizlendikten sonra tum hat sifirdan yeniden kuruldu ve
tum testler tekrar ALL-PASS aldi:

- `leechcore.so` (ufrisk master) yeniden derlendi. Not: Makefile
  `pkg-config libusb-1.0` cagirir; root'suz ortamda `libusb-1.0-0-dev` deb'i
  `dpkg-deb -x` ile acilir ve duzeltilmis prefix'li bir `.pc` dosyasiyla
  `PKG_CONFIG_PATH` gosterilir. Ayrica dev paketindeki `libusb-1.0.so`
  symlink'i kirdir (runtime paketi ayridir); sistem runtime'ina isaret
  ettirilmezse linker non-PIC `.a`'ya duser ve
  `failed to set dynamic section sizes: bad value` alinir.
- `IMemoryReader` arayuzune `MaxAddress()` eklendi (LeechReader her iki daldan
  da paMax dondurur). Device modu tarama penceresi artik paMax'a kistirilir
  (ust kap 512 MiB; paMax yoksa eski 64 MiB). 16 MB'lik dosya cihazinda onceki
  49/64 "chunk unreadable" uyarisi 0'a dustu; modul dump'lari (UE5 shipping
  ekseriyetle >64 MiB) artik tam taranir.
- Ayni gun Windows test kiti eklendi: `scripts/windows/1a-device-test.ps1`
  (T1-T4 baterisi) + `scripts/windows/1a-leech-harness.cpp` (LcWrite
  round-trip) + `docs/1A-WINDOWS-DEVICE-TEST.md` (adim adim rehber).
