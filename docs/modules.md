# DumperPro Modül Sistemi & BinFold Modülü

> Bu belge, motorun **modül kayıt sistemi** (registry) mimarisini, `--modules`
> komutunun çıktısını ve yeni eklenen **binfold** modülünün kullanımını anlatır.
> Kod terimleri İngilizce, açıklamalar Türkçedir.
> Araştırma kaynağı: `docs/module-integration.md` §2.1 (trumank/binfold derin inceleme).

---

## 1. Modül Sistemi (Registry) Mimarisi

### 1.1 Amaç

DumperPro modüler bir dumper motorudur: her kabiliyet (PE okuma, AOB tarama,
UE offset'leri, IL2CPP, hex edit, HTTP serve, ...) bağımsız bir "modül" olarak
düşünülür. Modül sistemi bu modülleri **tek bir merkezi tabloda** toplar; böylece:

- `--modules` bayrağı ile yüklü modüller **adı + sürümü + tek satır açıklaması**
  hizalı bir tablo halinde listelenir,
- yeni bir modül eklemek **tek satırlık bir kayıt** demektir,
- gelecekteki araçlar (web serve sayfaları, dokümantasyon üretici) aynı
  accessor'ı (`ModuleRegistry::Modules()`) yeniden kullanabilir.

### 1.2 Dosyalar

| Dosya | Rol |
|---|---|
| `src/core/ModuleRegistry.h` | `EngineModule` struct'ı + `ModuleRegistry` sınıf arayüzü |
| `src/core/ModuleRegistry.cpp` | Merkezi kayıt listesi (`RegisterBuiltins`) + tablo üretici (`BuildTable`) |

### 1.3 Tasarım

```cpp
struct EngineModule {
    const char* name;        // kısa id: "core", "binfold", ...
    const char* version;     // semver: "0.3.0"
    const char* description; // tek satır açıklama (tablo için kısa tutulur)
};

class ModuleRegistry {
public:
    static void Register(const EngineModule& m);   // isim bazında idempotent
    static void RegisterBuiltins();                // gömülü modüllerin kaydı
    static const std::vector<EngineModule>& Modules();  // accessor (lazy init)
    static std::string BuildTable();               // hizalı tablo metni
};
```

- Kayıt listesi **tek bir fonksiyonda** (`RegisterBuiltins`) tutulur — macro /
  static-initialization sihri yok; sıralama deterministik, ekleme maliyeti
  bir satır.
- `Register()` aynı isimle ikinci kaydı **değiştirir** (duplicate yaratmaz):
  bir modül iki kez kaydedilirse tabloda tek satır olur.
- `Modules()` ilk çağrıda `RegisterBuiltins()`'i tetikler (lazy init);
  yeniden çağrılar güvenlidir.
- `BuildTable()` ANSI renk kullanmaz, `\n` bitişlidir — hem terminal hem
  dosya/HTTP çıktısına uygun.

### 1.4 Kayıtlı modüller

| Modül | Sürüm | Sorumluluk |
|---|---|---|
| `core` | 0.3.0 | PE parse, maskeli AOB pattern'ler, file/process/kernel bellek okuyucular |
| `sig` | 0.3.0 | GNames/GObjects/GWorld imza tarama + doğrulama |
| `ue` | 0.3.0 | UE4 4.20-4.27 / UE5 5.0-5.5 sürüm tespiti + offset profilleri |
| `il2cpp` | 0.3.0 | Unity IL2CPP metadata v16-31 parse, binary match, DummyDll çıktısı |
| `file` | 0.3.0 | APK/ZIP/ELF/DEX/Mach-O/OAT-VDEX statik analiz hattı |
| `dump` | 0.3.0 | SDK header/struct üretimi (SDKGenerator + Dumps) |
| `hex` | 0.3.0 | hex/code/binary görünüm, AOB arama, patch/undo/save (`--hex`) |
| `net` | 0.3.0 | `--serve` HTTP upload + analiz sunucusu |
| `config` | 0.3.0 | games.ini profilleri + gömülü offset profilleri |
| `binfold` | 0.1.0 | binary diff/benzerlik: WARP fonksiyon GUID'leri + constraint eşleme |

### 1.5 `--modules` örnek çıktı

```
$ ./DumperPro --modules

=============================================
  DumperPro - UE Memory & SDK Dumper
=============================================
DumperPro engine modules:

NAME     VERSION  DESCRIPTION
-------  -------  -----------
core     0.3.0    PE parsing, masked AOB patterns, file/process/kernel memory readers
sig      0.3.0    GNames/GObjects/GWorld signature scan with validation
ue       0.3.0    UE4 4.20-4.27 / UE5 5.0-5.5 version detection + offset profiles
il2cpp   0.3.0    Unity IL2CPP metadata v16-31 parser, binary match, DummyDll out
file     0.3.0    APK/ZIP/ELF/DEX/Mach-O/OAT-VDEX static analysis pipeline
dump     0.3.0    SDK header/struct generation (SDKGenerator + Dumps)
hex      0.3.0    hex/code/binary view, AOB search, patch/undo/save (--hex)
net      0.3.0    --serve HTTP upload + analysis server
config   0.3.0    games.ini profiles + built-in offset profiles
binfold  0.1.0    binary diff/similarity: WARP function GUIDs + constraint matching
```

Çıkış kodu: `0`.

---

## 2. BinFold Modülü (Binary Diff / Sembol Eşleme)

### 2.1 Ne yapar?

İki benzer binary (örn. oyunun iki sürümü) arasında **fonksiyon düzeyinde
eşleme** yapar: A (referans) tarafındaki her fonksiyonun gövdesinden bir
**GUID** (WARP türevi parmak izi) türetir; B (hedef) tarafında aynı GUID'i
taşıyan fonksiyon bulunur. GUID'i değişen fonksiyonlar, çağrı grafiği
**constraint'leri** (child_call / parent_call) üzerinden iteratif olarak
kurtarılır. Sonuç: kaç fonksiyon birebir aynı, kaçısı kurtarıldı, kaç fonksiyon
eklendi/silindi + toplam benzerlik yüzdesi.

Kaynak: [trumank/binfold](https://github.com/trumank/binfold) — **MIT lisansı**
(`Copyright (c) 2025 Truman Kilen`). Çekirdek algoritmalar bu depodan port
edilmiştir; port detayları `src/binfold/BinFold.h` başlık yorumunda
madde madde belgelenmiştir.

### 2.2 Algoritma özeti (binfold → DumperPro karşılığı)

| binfold (Rust) | DumperPro (C++20) | Durum |
|---|---|---|
| `hash.rs` UUIDv5 + domain tag'ler | SHA-1 + RFC 4122 v5, aynı root namespace (`c1a7f83a-...`) ve domain'ler (`function`, `basic_block`, `child_call`, `parent_call`) | ✅ ported |
| `warp.rs` fonksiyon GUID'i | maskeli gövde → 64-byte temel bloklar → blok digest'leri adres sırasıyla birleşir → `function` domain GUID | ✅ ported (blok bölücü disassembler'sız; aşağıda sınırlar) |
| `arch/x86.rs` X86Masker | E8/E9 rel32 + EB rel8 displacement alanlarını sıfırlama; RIP-göreli/absolute alan maskeleme decoder'sız yaklaşımla | ✅ ported (simplified) |
| `lib.rs` `match_with_database` | exact GUID seed + iteratif constraint yayma (fix-point döngüsü, unique-aday şartı) | ✅ ported (two-binary modu) |
| `binary/pe.rs` `.pdata` fonksiyon sınırları | PE x64 `RUNTIME_FUNCTION` tablosu; ELF64 `STT_FUNC`; diğerleri E8 call-sweep | ✅ ported |
| `db.rs` `.fold` on-disk DB | gerek yok — iki binary doğrudan karşılaştırılıyor (referans = DB rolü) | ⏭ deferred |
| PDB/DWARF/Breakpad sembol kaynakları ve export | DumperPro bu fazda isim *taşı*mez; eşleme `sub_ADDR` sembolik isimleriyle raporlanır | ⏭ deferred |
| `arm64.rs` A64 decoder + Arm64Masker | x86/x64 odaklı faz | ⏭ deferred |
| `binary/sweep.rs` PE32 linear sweep | E8 call-target sweep (basitleştirilmiş) | ✅ ported (simplified) |

Not: binfold gerçek bir disassembler (iced-x86) ile temel blokları böler ve
tüm RIP-göreli alanları maskeler. Bu port **disassembler'sız** çalışır: bloklar
64 byte, maskeleme E8/E9/EB displacement'ları sıfırlar. GUID şeması/namespace
aynıdır ama blok sınırları farklı olduğundan GUID'ler upstream `.fold` DB'si
ile **byte-eş değildir** (bilinçli adaptasyon, `BinFold.h` başlığında yazılı).

### 2.3 Kullanım

```
--bindiff <fileA> <fileB>      iki binary arası diff (WARP fonksiyon GUID'leri,
                               iteratif constraint eşleme, benzerlik skoru)
--bindiff-json <f>             (--bindiff ile) makine-okur JSON raporu da yazar
```

Kurallar:
- `--bindiff` tek başına bir moddur; `--process/--pid/--file/--device/--serve`
  ile birlikte kullanılamaz.
- Dosyalar 1 GiB'a kadar okunur (HexTool ile aynı cap).
- IO hatasında çıkış kodu `2`, normal bitişte `0`.

### 2.4 Örnek çıktı (40 fonksiyonlu sentetik PE çifti; 38 GUID aynı, 2 fonksiyon hafif değişmiş)

```
$ ./DumperPro --bindiff /tmp/peA.bin /tmp/peB.bin

=============================================
  DumperPro - BinFold Binary Diff
=============================================
16:46:01 [*] File A (reference): /tmp/peA.bin (64.00 KB)
16:46:01 [*] File B (target)   : /tmp/peB.bin (64.00 KB)

BINFOLD DIFF REPORT
File A (reference): peA.bin  [PE x64 (.pdata, 40 entries)]
File B (target)   : peB.bin  [PE x64 (.pdata, 40 entries)]

---- functions ----
Functions A : 40
Functions B : 40
Exact match : 38  (identical WARP GUID)
Inferred    : 2  (constraint propagation)
Inserted    : 0  (only in B)
Deleted     : 0  (only in A)
Similarity  : 100.0% (function bodies) / 87.5% (bytes, CDC, reloc-masked)

---- first matched entries (max 20) ----
  sub_1000 -> sub_1000  exact    4f3d8...
  sub_1100 -> sub_1100  exact    0a21c...
  ...
---- top changed/modified pairs (max 10) ----
  0x1300 -> 0x1300  size 240 -> 240  inferred  conf 100.0%
  0x2500 -> 0x2500  size 240 -> 240  inferred  conf 100.0%

Summary: similarity 100.0% | matched 40/40 (exact 38, inferred 2) | inserted 0 | deleted 0
```

Buradaki kritik nokta: gövdesi 2 byte değişen `0x1300` ve `0x2500` fonksiyonlarının
GUID'i değiştiği için exact eşleşmedi — ama **child_call/parent_call
constraint'leri** (komşu fonksiyonların GUID'leri) tek adaya işaret ettiği için
iterasyon bunları "inferred" olarak kurtardı. Bu, binfold'un README'sindeki
>%50 eşleşme oranını mümkün kılan fix-point döngüsünün aynısıdır.

### 2.5 Fonksiyon keşfi (format desteği)

| Format | Yöntem | Rapor etiketi |
|---|---|---|
| PE x64 | `.pdata` exception directory (exact sınırlar) | `PE x64 (.pdata, N entries)` |
| PE x86/ARM64 | E8 call-target sweep (exec section'lar) | `PE <arch> (call-sweep)` |
| ELF64 | `STT_FUNC` sembolleri (symtab > dynsym); stripped ise exec PT_LOAD E8 sweep | `ELF64 (symtab, N funcs)` |
| Ham binary | tam-buffer E8 rel32 sweep | `raw (x86 call-sweep)` |

---

## 3. Yeni Modül Nasıl Eklenir? (adım adım)

1. **Kodunu yerleştir.** Yeni klasör: `DumperPro/src/<moduladi>/`.
   Tüm dosyalar `namespace dumper::...` kullanır, header guard `#pragma once`,
   include'lar `../framework.h` ile başlar (proje geneli ortak tipler: `u8`,
   `u32`, `u64`, `i32`, `fs`, ...).

   ```
   DumperPro/src/<moduladi>/ModulAdi.h
   DumperPro/src/<moduladi>/ModulAdi.cpp
   ```

2. **Registry'ye kaydet.** `src/core/ModuleRegistry.cpp` içinde
   `RegisterBuiltins()`'e **tek satır** ekle:

   ```cpp
   Register({"<moduladi>", "0.1.0", "tek satir aciklama"});
   ```

   - Mevcut çekirdek modüller motorla birlikte sürümlenir (`0.3.0`);
     bağımsız yeni modüller kendi sürümünü taşır (örn. `binfold 0.1.0`).
   - Açıklamayı kısa tut — tablo hizası bozulmasın.

3. **CLI yüzeyini bağla.** `src/main.cpp` içinde (additive):
   - `main` başındaki opsiyon struct'ına alan ekle,
   - `ParseArgs`'a `else if (a == "--<flag>")` dalı ekle,
   - help metnine bir satır ekle,
   - modun çalıştırılacağı noktayı (bkz. `RunBindiff`, `RunHex`) `main`'e ekle
     ve `ValidateOptions`'taki mod sayacına dahil et.
   - Karşılıklı dışlayan modları `modes` sayacına ekle (yalnız bir mod aktif
     olabilir; aksi halde motor hata verir).

4. **Derle.** Motor tek komutla derlenir (statik glob; ek dosya için
   Makefile/CMake değişikliği gerekmez):

   ```
   g++ -std=c++20 -O1 -I DumperPro/src -o DumperPro/DumperPro \
       DumperPro/src/*.cpp DumperPro/src/*/*.cpp -lpthread -ldl
   ```

5. **Doğrula.**

   ```
   ./DumperPro --modules          # yeni satır tabloda görünüyor mu?
   ./DumperPro --<flag> ...       # modun kendi smoke test'i
   ```

6. **Dokümante et.** Bu dosyaya (`docs/modules.md`) modül tablosuna bir satır
   ve gerekirse bir kullanım bölümü ekle. Dış koddan port yapıldıysa
   (lisans + kaynak) başlık yorumuna attribution yaz — örneğin
   `src/binfold/BinFold.h` başlığı ve `docs/module-integration.md` §2.1.

**Kural özeti:** mevcut modüllerin adı/tası yapılmaz; registry ekleme
additive'dir; her modül kendi namespace'inde yaşar; sıfır bağımlılık
(yalnız C++20 std + Win32/POSIX) korunur.
