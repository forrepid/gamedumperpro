# DumperPro

İkili dosya / bellek / oyun dosyası analiz platformu: **C++ motoru** (CLI + gömülü web sunucu) ve **Next.js 16 web arayüzü**. Dumper-7, Il2CppDumper, UnrealCEDumper ve MemProcFS'ten esinlenmiştir; Unreal (UE4/UE5) ve Unity (IL2CPP) oyunlarının analizini, SDK üretimini, bellek incelemesini ve save düzenlemeyi tek yerde toplar.

> Sürüm: **0.3.0** — değişiklikler için [CHANGELOG.md](CHANGELOG.md)

---

## Neler yapar?

### Web platformu (tarayıcı — ana kullanım şekli)

| Özellik | Açıklama |
|---|---|
| **Yükleme & analiz** | Tek dosya veya klasör ağacı; arka planda **paralel worker kuyruğu** ile analiz, canlı ilerleme |
| **15 sekmeli inceleyici** | Genel / Bölümler / Hex / Motor & Güvenlik / İmza Adayları / Debug / Fonksiyonlar / Structlar / Enumlar / IL2CPP / SDK / Dizeler / Çıkarıcılar / Rapor |
| **Kod Üretici** | Çıkarılan fonksiyon/struct/enum/dizeleri **8 dilde** (C++, C#, Python, Rust, TS, Java, Lua, JSON) gösterir; her öğe için RVA/VA/offset/boyut + **AOB desen** üretir (Dumper-7 stili `[Address]` attribute) |
| **Semantik açıklama** | Veriyi otomatik okuyup açıklar: kategori (karakter/sağlık, silah, para, konum, fizik, görsel...), güven skoru, ne yapıp nereye yazdığı + opsiyonel AI derinleştirme |
| **Save Editor** | Unreal `.sav` (GVAS) ve Steam `.vdf` dosyalarını **canlı düzenleyip kaydetme**; **AES-256-ECB/CBC şifreli save** anahtar girdisiyle açılır |
| **Hex çalışma alanı** | AOB arama (RVA/VA çözümlemeli), patch + undo + save |
| **Eşleştirme** | `global-metadata.dat` ↔ `GameAssembly.dll`, `*.memmap` ↔ ham bellek dump, `*.pdb` ↔ PE — otomatik eşleşme ve yeniden analiz |
| **6 çıkarıcı matrisi** | Dumper-7 / DumperPro / Il2CppDumper / UnrealCEDumper / MemProcFS / LeechCore — kullanılabilirlik + Ortak Veriler kesişimi |

### C++ motoru (masaüstü CLI — `DumperPro/`, ~16k satır, 10 modül)

- `core` — PEFile, maskeli AOB desen motoru, Memory/File/Process/Kernel okuma backend'leri
- `sig` — GNames / GObjects / GWorld imza taraması
- `ue` — UE4.20–4.27 & UE5.0–5.5 ObjectArray/NameArray otomatik tespiti + offset probe
- `il2cpp` — metadata v16–31, ELF RELA, DummyDll
- `file` — APK / ZIP / ELF / DEX / Mach-O / OAT-VDEX statik analiz
- `dump` — SDK üretici (`<Pkg>_classes.h/_structs.h/_enums.h`) + vtable çözümleyici
- `hex` — etkileşimli hex aracı (görünüm/arama/patch/save)
- `net` — gömülü HTTP sunucu (`--serve`, varsayılan 8420)
- `config` — `games.ini` + 10 gömülü oyun profili

---

## Kurulum

### 1) Web platformu

**Gereksinimler:** [Bun](https://bun.sh) 1.x (veya Node 20+ + package manager)

```bash
git clone https://github.com/forrepid/gamedumperpro.git
cd gamedumperpro

bun install           # bağımlılıklar
bun run db:push       # Prisma şemasını SQLite'a yaz (db/custom.db)
bun run worker:build  # analiz worker paketi (storage/bin/analysis-worker.js)
bun run dev           # http://localhost:3000
```

Ortam değişkenleri — proje kökünde `.env` dosyası (repo'ya girmez):

```ini
DATABASE_URL="file:./db/custom.db"
# opsiyonel: analiz worker sayısı (varsayılan 2, üst sınır 4)
ANALYSIS_WORKERS=2
```

Üretim için:

```bash
bun run build
bun run start
```

### 2) Masaüstü CLI (C++ motoru)

**Gereksinimler:** C++20 destekli derleyici (g++ 11+ / MSVC), pthread (Linux)

```bash
# Linux / macOS — doğrudan derleme
g++ -std=c++20 -O1 -I DumperPro/src -o DumperPro/DumperPro \
    DumperPro/src/*.cpp DumperPro/src/*/*.cpp -lpthread -ldl

# Windows — MSVC (x64 Native Tools Command Prompt)
cl /std:c++20 /O1 /EHsc /I DumperPro\src DumperPro\src\*.cpp DumperPro\src\*\*.cpp /Fe:DumperPro.exe
```

> Not: `--device` (LeechCore) modu Windows'ta `leechcore.dll` ister; Linux'ta `file://dump.bin` / `dump://x.dmp` cihaz string'leri çalışır. Detay: `DumperPro/docs/LEECH.md`.
>
> **Windows gerçek-makine test kiti (1a):** `DumperPro/windows/` — `build.bat`
> (MSVC), `get-leechcore.ps1` (MemProcFS'ten leechcore.dll indirir),
> `test-device.bat` (4-testli PASS/FAIL baterisi). Adım adım Türkçe rehber:
> `DumperPro/windows/README.md` ve `docs/1A-WINDOWS-DEVICE-TEST.md`.

### 3) Test materyali (opsiyonel)

```bash
bun scripts/make-samples.ts   # research/samples/ altına sentetik örnekler üretir
```

---

## Kullanım

### Web (önerilen akış)

1. **Yükle** — ana sayfadaki alana dosyayı sürükle veya klasör seç. `.exe/.dll/.so/.apk/.dex/.sav/.vdf/.dmp/.memmap/.pdb/.uasset/.pak/.vdex...` desteklenir.
2. **Analizi izle** — iş worker kuyruğuna girer; satır üstünde aşama/yüzde canlı akar.
3. **Sekmelerde gez** — Genel özet, Hex (AOB arama/patch), Fonksiyonlar/Structlar/Enumlar (semantik açıklamalı), SDK (üretilen başlıkları canlı görüntüle), Kod Üretici (dil + tür seç, çıktıyı kopyala), Dizeler, Çıkarıcılar, Rapor.
4. **Eşleştir** — ikinci dosyayı yükle:
   - `GameAssembly.dll` + `global-metadata.dat` → IL2CPP dump.cs/script.json
   - Ham bellek dump + `*.memmap` → bellek cihazı + modül haritası + bellek içi AOB arama
   - `Oyun.exe` + `Oyun.pdb` → sembol çıkarımı
5. **Save düzenle** — `.sav` yükleyince **Save Editor** sekmesi açılır: değere tıkla, düzenle, `Kaydet`; `İndir` ile düzenlenmiş kopyayı al. Şifreli save için anahtar girdisini kullan.

### Kod Üretici örneği (çıktı biçimi)

```cpp
// RVA: 0x1000 | VA: 0x180001000 | SIZE: 0x10 | SEC: .text | etiket: EntryPoint
// AOB: 55 48 89 E5 5D C3 00 00 ?? ?? ?? ??
void EntryPoint();
```

```csharp
// Dumper-7 stili Address attribute
[Address(RVA = "0x1000", Offset = "0x1000", VA = "0x180001000")]
public void EntryPoint() { }
```

### Masaüstü CLI

```bash
# Dosya modu — PE / APK / ELF / DEX / VDEX statik analiz
DumperPro --file Game-Win64-Shipping.exe
DumperPro --file oyun.apk
DumperPro --file base.vdex

# Canlı mod — çalışan sürece bağlan
DumperPro --process Game.exe
DumperPro --process Game.exe --kernel          # kernel destekli erişim (docs/KERNEL.md)

# Cihaz modu — LeechCore (bellek dump / donanım)
DumperPro --device "file://dump.bin"
DumperPro --device "fpga"

# Unity IL2CPP eşleştirmesi
DumperPro --file GameAssembly.dll --metadata global-metadata.dat

# SDK üretimi + JSON çıktı + profiller
DumperPro --file Game.exe --json --probe 400 --list-profiles

# Hex modu — görünüm / arama / patch / save
DumperPro --hex --file oyun.exe --hex-view 0x1000
DumperPro --hex --file oyun.exe --hex-code 0x140001000:16
DumperPro --hex --file oyun.exe --hex-search "48 8B 05 ?? ?? ?? ?? 48 85 C0"
DumperPro --hex --file oyun.exe --hex-patch "0x1000=90 E9" --hex-save patched.exe
DumperPro --hex --process Game.exe --hex-patch "0x140001000=90" --hex-live

# Gömülü web sunucu (tarayıcıdan yükleme)
DumperPro --serve              # http://127.0.0.1:8420
DumperPro --serve 9000

# Modül sistemi + binary diff (binfold modülü)
DumperPro --modules                        # kayıtlı tüm motor modülleri
DumperPro --bindiff eski.dll yeni.dll      # WARP GUID eşleştirme + benzerlik
DumperPro --bindiff a.so b.so --bindiff-json > matches.json
```

Tüm bayraklar: `DumperPro --help`

---

## REST API (web platformu)

| Metot + Yol | İş |
|---|---|
| `POST /api/upload` | Dosya/klasör yükle → analiz kuyruğuna girer (hemen döner) |
| `GET /api/uploads` | Yükleme listesi + ağaç (ilerleme dahil) |
| `GET /api/uploads/[id]` | Tam analiz sonucu (pe/functions/structs/enums/strings/extractors...) |
| `GET /api/uploads/[id]/progress` | Canlı aşama/yüzde |
| `GET /api/uploads/[id]/hex` · `POST` | Hex veri · AOB arama/patch/save |
| `GET/PUT /api/uploads/[id]/savegame` | Save tree oku · düzenle |
| `GET /api/uploads/[id]/savegame/download` | Düzenlenmiş kopyayı indir |
| `POST /api/uploads/[id]/codegen` | Kod üretimi — gövde: `{language, kind, filter?, limit?}` (`language`: cpp/csharp/python/rust/typescript/java/lua/json) |
| `POST /api/uploads/[id]/explain` | Semantik açıklama — gövde: `{type, artifact, useAi?}` |
| `GET /api/uploads/[id]/sdk` · `/sdk/[name]` | SDK dosyaları listesi/erişimi |
| `GET /api/uploads/[id]/mem` | Bellek cihazı/modül/arama (memmap eşleşmeli) |
| `GET /api/uploads/[id]/extract` | APK/DEX/VDEX çıkarımları |
| `GET /api/uploads/[id]/report` | Metin rapor |
| `DELETE /api/uploads/[id]` | Kaydı + disk dosyasını sil (cascade) |

---

## Depo düzeni

```
DumperPro/     C++ motor (src/ 10 modül, games.ini, docs/LEECH.md)
ue-dumper/     İkincil UE dumper bileşeni (src/, driver/)
src/           Next.js uygulaması + 20+ analiz modülü (src/lib/analysis/)
prisma/        DB şeması (SQLite)
docs/          Araştırma notları: MemProcFS/LeechCore, IL2CPP, savegame, gamefiles, codegen
scripts/       Sentetik örnek üretici + inceleme/doğrulama yardımcıları
CHANGELOG.md   Sürüm geçmişi
```

## Güvenlik notu

`.env`, veritabanı, yüklenen dosyalar (`storage/`) ve vendored araştırma ağaçları bilerek **commit edilmez**. İlk yayın öncesinde git geçmişi sıfırlandı; gizli anahtarlar uzak geçmişte asla bulunmaz. Yeni token kullanıyorsan repoya yazma izni (Contents: Read and write) dışında geniş izin verme.

## Yasal

Yalnızca sahip olduğun veya analiz etmeye yetkili olduğun yazılımlar için: çevrimdışı analiz, tek oyunculu modding ve motor araştırması amaçlıdır.
