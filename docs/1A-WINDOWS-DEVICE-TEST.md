# 1a — Windows Gerçek Makine LeechCore Testi (`--device`)

Bu doküman, **1a görevinin** Windows tarafını adım adım anlatır: gerçek
`leechcore.dll` ile `DumperPro.exe --device` yolunun gerçek makinede canlı
test edilmesi.

> **Bu ortamda (Linux) ne yapıldı?** LeechCore kaynak koddan derlendi
> (`leechcore.so`, ufrisk master) ve Linux dalı (`dlopen`/`dlsym`) ile uçtan
> uca canlı test edildi — LcCreate/LcRead/LcWrite/LcGetOption tam ABI
> doğrulaması **ALL-PASS**. Ayrıntılar: `DumperPro/docs/LEECH.md` bölüm 9.
> Aşağıdaki Windows testi, aynı yolu **gerçek leechcore.dll** ile tekrarlar.

---

## 1. Gereksinimler

| Bileşen | Kaynak | Not |
|---|---|---|
| Windows 10/11 x64 | — | Yönetici gerekmez (file:// testleri için) |
| `DumperPro.exe` | MSVC derlemesi (README.md) | veya MinGW-w64 g++ |
| `leechcore.dll` | [MemProcFS release zip](https://github.com/ufrisk/MemProcFS/releases) | zip içinden `leechcore.dll` |
| VC++ Redistributable | [vc_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe) | MemProcFS sürümleri ister |

Kurulum: `leechcore.dll`'i **DumperPro.exe'nin yanına** kopyalayın
(önerilen) ya da bulunduğu klasörü `PATH`'e ekleyin.

---

## 2. Otomatik test baterisi (önerilen)

```powershell
cd DumperPro'nun\olduğu\klasör
powershell -ExecutionPolicy Bypass -File scripts\windows\1a-device-test.ps1
```

Script sırayla şunları yapar:

1. `leechcore.dll`'i exe klasörü + `PATH` içinde arar (yoksa kurulum ipucu
   yazar ve yalnızca zarif-hata testini koşar).
2. 16 MB'lik sentetik test düzeneği üretir (`1a-test-output\testdev.raw`):
   `0x11000`'e `DMPPRO-TEST-SIG!`, `0x30000`'e `++UE5+Release-5.1.1-0-Test`.
3. Testleri koşar ve çıktı işaretçilerine göre PASS/FAIL verir:

| Test | Ne doğrular | Beklenen çıktı işaretçisi |
|---|---|---|
| T1 `file://` salt-okunur | LcCreate + LcRead + paMax raporu + UE kokleyici | `LeechCore device ready ... (writable=no, maxPA=0x000001000000)` + `Detected UE version: UE5.1` |
| T2 `file://file=...,write=1` | LcCreate yazılabilir mod | `writable=yes` |
| T3 olmayan dosya | Zarif hata yolu (crash YOK) | `cannot open LeechCore device` + `Hint:` |
| T4 `-Fpga` (opsiyonel) | FPGA DMA canlı açılış | `LeechCore device ready: 'fpga'` (kart yoksa zarif hata normaldir) |

Beklenen sonuç satırı: `===== SONUC: N PASS / 0 FAIL =====`
Ham çıktı + tüm CLI günlüğü: `1a-test-output\1a-test-log.txt`

---

## 3. FPGA canlı test (gerçek donanım)

Sadece USB3380 / FPGA (Squirrel, AC701, PCIeSquirrel...) kartınız varsa:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\1a-device-test.ps1 -Fpga
```

- FTDI **D2XX** sürücüsü kurulu olmalı ("Virtual COM" sürümü değil).
- Kart okuma penceresi: `0x10000`'den itibaren, cihazın raporladığı
  `maxPA`'ya kadar (üst sınır 512 MiB; `docs/LEECH.md` §4).
- Hedef makinede test yapın; DMA yazma sistem kararlılığını bozabilir
  (bkz. `docs/LEECH.md` §7 güvenlik notları).

---

## 4. Gerçek oyundan dump alınması (1b köprüsü)

Tam UE SDK üretimi için **canlı süreç belleği** gerekir (GObjects yığını
heap'tedir; modül dosyasında bulunmaz). Önerilen akış:

```powershell
# 1) Oyunu başlatın, ana menüye kadar girin
# 2) Süreç modu (LeechCore gerekmez, ReadProcessMemory yolu):
DumperPro.exe --process OyunAdi-Win64-Shipping.exe --out C:\out\sdk
# 3)veya fiziksel RAM dump + memmap üretip (MemProcFS):
MemProcFS.exe -device file://C:\dumps\ram.bin -pagefile0 C:\dumps\pagefile.sys
#    ardından MemProcFS'in dump komutuyla ram.bin + *.memmap üretin ve:
DumperPro.exe --device "file://C:\dumps\ram.bin"
```

Çıktıda `GNames found`, `GObjects found` ve `SDK generated` satırlarını
görünce 1b'nin Windows ayağı tamamlanmış olur.

---

## 5. Sorun giderme

| Belirti | Sebep | Çözüm |
|---|---|---|
| `[X] cannot open LeechCore device` + dll ipucu | dll exe yanında değil | dll'i kopyalayın; `where leechcore.dll` ile doğrulayın |
| `0xC000007B` başlangıç hatası | 32/64 bit uyuşmazlığı | x64 dll + x64 DumperPro.exe |
| dll var ama `Hint:` çıkıyor | VC++ runtime eksik | `vc_redist.x64.exe` kurun |
| FPGA açılmıyor | FTDI D2XX eksik | FTDI resmi D2XX sürücüsünü kurun |
| `writable=yes` beklenirken `no` | device string yanlış | `file://file=C:\yol\dump.bin,write=1` biçimini kullanın |

---

## 6. LcWrite round-trip doğrulaması (harness)

CLI cihaz modu yalnızca okur; yazma yolunu bağımsız düzenek (harness)
doğrular. `scripts\windows\1a-leech-harness.cpp` dosyası, `TryCreateLeechReader`
üzerinden imza okuma, hizasız okuma, paMax koruması, LcWrite round-trip
(0x41414141 → 0xCAFEBABE) ve hizasız yazma (RMW) testlerini içerir:

```bat
:: MSVC (DumperPro deposu kök dizininden)
cl /std:c++20 /EHsc /O2 /I src scripts\windows\1a-leech-harness.cpp src\core\LeechReader.cpp src\core\MemoryReader.cpp src\core\PEFile.cpp src\core\Pattern.cpp src\utils\Logger.cpp src\utils\Progress.cpp /Fe:1a-leech-harness.exe

:: fixture'i üretin (2. bölümdeki script bunu yapar), sonra:
1a-leech-harness.exe 1a-test-output\testdev.raw
:: beklenen son satır: HARNESS RESULT: ALL-PASS
```

Aynı düzenek Linux'ta bu depo içinde gerçek `leechcore.so` ile koşuldu ve
**ALL-PASS** aldı (2026-11-20 yeniden doğrulama dahil).

---

## 7. Sonuç kaydı

- [ ] T1–T3 PASS (leechcore.dll, gerçek Windows makinesi)
- [ ] Harness ALL-PASS (LcWrite round-trip)
- [ ] (Opsiyonel) T4 FPGA PASS
- [ ] (1b köprüsü) Gerçek oyun sürecinde GNames/GObjects + SDK üretimi
