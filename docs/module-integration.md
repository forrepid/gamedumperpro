# DumperPro — Modül Entegrasyon Yol Haritası (Task 2-R)

> **Kapsam:** 7 GitHub deposunun araştırması ve DumperPro (C++20, sıfır-bağımlılık) motoruna
> modül entegrasyon planı. Bu belge **yalnızca araştırma** çıktısıdır; motor koduna hiçbir
> kod kopyalanmamıştır. Kaynak klonlar `research/repos/` altındadır (gitignored).
>
> **Analiz tarihi:** HEAD snapshot'ları `--depth 1` ile klonlandı (bknz. research/repos/).
> Efor skalası: **S** = 1-2 gün, **M** = 1-2 hafta, **L** = 1+ ay.
> Port kararı skalası: PORTABLE-EASY/MEDIUM/HARD · VENDOR-DEPS · CLEAN-ROOM-ONLY · NO-GO.

---

## 1. Giriş

DumperPro'nun mevcut modülleri: `core`, `sig` (AOB tarama), `ue` (GObjects/GNames/SDK),
`il2cpp`, `file` (PE okuma), `dump`, `hex`, `net`, `config` (games.ini). Bu çalışmada 7 dış
depo incelendi; her biri için amaç, lisans, mimari ve "hangi bileşeni hangi modülümüze nasıl
taşıyabiliriz" kararı çıkarıldı. Genel strateji: **permissif lisanslı (MIT/Apache) Rust/C#/
C++ kodunu C++20'ye sıfır-bağımlılık port etmek**; dil geçişi zaten "port" kabul edildiği
için kopyalama riski düşük, ama yine de lisans zorunlulukları (attribution NOTICE) tutulacak.

Depo özet tablosu (ayrıntı aşağıda):

| # | Depo | Lisans | Dil | Boyut | Bizim için ana değer |
|---|------|--------|-----|-------|----------------------|
| 1 | trumank/binfold | **MIT** | Rust | ~7.6k LOC | Sembol taşıma: WARP GUID + constraint DB (sig/ue) |
| 2 | trumank/patternsleuth | MIT OR Apache-2.0 (manifest) | Rust | ~3k LOC (core) | Test edilmiş UE pattern kütüphanesi (sig/ue) |
| 3 | forrepid/UE5CEDumper | **MIT** (kullanıcının kendi reposu) | C++23 + C# | ~105k DLL + ~240k UI | CE .CT export, AOB preset DB,DynOff |
| 4 | UE4SS-RE/RE-UE4SS | MIT | C++ | ~131k LOC | UE pattern seti + Lua mod API tasarımı |
| 5 | FabianFG/CUE4Parse | Apache-2.0 | C# | ~152k LOC | pak/iosore/AES/oodle referansı (file) |
| 6 | 4sval/FModel | **GPL-3.0** | C# | ~26k LOC | UI/UX özellik referansı (kod KOPYALANAMAZ) |
| 7 | praydog/REFramework | MIT | C++ | ~61k LOC | Lua eklenti API + runtime hook mimarisi |

---

## 2. Depo Analizleri

### 2.1 trumank/binfold — ★ DERİN İNCELEME (bir sonraki port edilecek modül)

**Lisans: MIT** (`LICENSE`, "Copyright (c) 2025 Truman Kilen"). *Permissive — kod birebir
kopyalanabilir/dağıtılabilir/satılabilir; tek zorunluluk telif + izin notunun tüm kopyalarda
tutulması.* ⇒ DumperPro'ya port için **herhangi bir engel yok** (alternatif paralel port
ajanına da not: MIT, doğrudan çeviri serbest).

**Amaç (README + kaynak doğrulandı):** Benzer iki binary arasında sembol isimlerini hızlı ve
ölçeklenebilir biçimde taşıyan araç. WARP yaklaşımına dayanır: fonksiyon gövdesinden
"GUID" (hash) türetir, PDB'li exe'lerden bir veritabanı (`.fold`) kurar, isimsiz hedef exe'nin
fonksiyonlarını DB ile eşleştirip isim üretir; PDB/DWARF/Breakpad çıktısı verir. Performans:
100 MB exe ~4 sn, UE oyunlarında >%50 eşleşme.

**Dil/boyut:** Rust, 21 kaynak dosya, **7.570 LOC** (`wc -l src/*.rs src/**/*.rs`).

#### 2.1.1 Dosya-dosya rol tablosu

| Dosya | LOC | Rol | C++ port hedefi (öneri) |
|---|---|---|---|
| `src/hash.rs` | 282 | `HashAlgo` trait: domain-tkılı (tag) GUID'ler (`Guid<Tag,H>`), `XxHash64` (DB formatı sabit) ve `UuidV5` (root ns `c1a7f83a-38a2-4bed-b6a3-babc0df6860f`) + 9 domain tag (`function`, `basic_block`, `symbol`, `child_call`, `parent_call`, `symbol_child_call`, `symbol_parent_call`, `data_const`, `binary`) | `src/binfold/Guid.hpp` + `src/binfold/XxHash64.hpp` |
| `src/warp.rs` | 257 | Çekirdek: `compute_warp_uuid` — fonksiyonun her basic-block byte'ını arch masker ile maskeleyip hash'ler, blok digest'lerini sırayla birleştirip fonksiyon GUID'i üretir; `read_string_data` (UTF-8/UTF-16 string heuristiği) | `src/binfold/Warp.hpp/.cpp` |
| `src/db.rs` | 1312 | `.fold` on-disk formatı: çok katmanlı (layer) append-only DB; sekmeler: strings/constraints/constraint_strings/function_constraints/functions/binaries; binary-search okuma, `batch_query_constraints` (merge-join + string interning + flat array sonucu), `Layer::write_body`, `append_layer`, testler | `src/binfold/FoldDb.hpp/.cpp` |
| `src/lib.rs` | 715 | `BinfoldAnalyzer` (analyze pipeline) + **`match_with_database`** — iteratif eşleme döngüsü (aşağıda) + `DatabaseBuilder` (gen-db, DashSet triple dedup + interner + append) | `src/binfold/Analyzer.hpp/.cpp` |
| `src/build_pipeline.rs` | 173 | Tüm sembol kaynakları için ortak boru hattı: isimli fonksiyon → GUID+kod-şekli constraint'leri; ters çağrı grafiği → parent-call + symbol-child/parent-call constraint türetme | `src/binfold/BuildPipeline.hpp/.cpp` |
| `src/binary/mod.rs` | 613 | `Binary` yükleyici (mmap + `object` crate), RVA↔file offset, segment perms, `.eh_frame` FDE fonksiyon sınırları, `AnalysisCache` (addr→FunctionAnalysis memoize), PE/ELF fonksiyon keşfi (`find_all_functions`) | `src/binfold/Binary.hpp/.cpp` (bizde `file` modülüne incedelegate) |
| `src/binary/pe.rs` | 370 | PE özel: `PdbDebugInfo` (debug directory RSDS), x64 `RUNTIME_FUNCTION`/`.pdata` fonksiyon sınırları, PE32 section bilgisi, jump-table kurtarma yardımcıları | `src/binfold/PeSupport.cpp` (file modülü kullanarak) |
| `src/binary/elf.rs` | 129 | ELF `.eh_frame` FDE tablosu okuma | şimdilik opsiyonel/sonra |
| `src/binary/sweep.rs` | 205 | PE32 linear-sweep fonksiyon keşfi (call-target toplama → analiz → gap rescan, `IntervalMap` ile çakışma yönetimi) | `src/binfold/Sweep.cpp` (x86 hedefliyse) |
| `src/arch/mod.rs` | 198 | Arch-neutral sözleşme: `FunctionAnalysis{size, basic_blocks(BTreeMap), calls, data_refs, jump_tables}`, `MemoryView` trait, `BlockMasker` trait | `src/binfold/Analysis.hpp` |
| `src/arch/x86.rs` | 672 | x86/x64 recursive-descent: iced-x86 decode, call/data-ref toplama, RIP-göreli çözümleme, **X86Masker** (RIP-göreli disp32 → 0 maskeleme; PE32 için section-tabanlı absolute maskeleme) | `src/binfold/ArchX86.cpp` (bizde `sig` decoder var; iced yerine kendi decoder'ımız kullanılabilir) |
| `src/arch/arm64.rs` | 928 | A64 decoder (sabit 4 byte), **Arm64Masker** (ADRP register-taint + lo12 maskeleme, capstone-benzeri kendi çözümü `disarm64`) | sonraya (biz x86 hedefi) |
| `src/symbols/pdb.rs` | 102 | PDB'den `name_by_addr` çıkarımı (`pdb` crate + `pdb-sdk`) | **Port zor** — C++ tarafta kendi PDB okuyucumuz ya da Microsoft cvpdb gerekir; VENDOR-DEPS adayı |
| `src/symbols/elf.rs` | 221 | ELF `.dynsym`/symtab isimleri | sonraya |
| `src/export/*.rs` | ~700 | PDB yazıcı (MSF/PDB stream'leri elle), DWARF (gimli), Breakpad `.sym` — eşleşen isimleri debug info olarak geri yazma | `.sym` yazıcı kolay (Breakpad metin formatı); PDB yazıcı **VENDOR-DEPS/CLEAN-ROOM** |
| `src/mmap_source.rs` | 72 | mmap tabanlı `MemoryView` | Windows `CreateFileMapping` ile `file` modülü |
| `src/progress.rs` | 144 | progress arayüzü | trivial / mevcut utils |
| `src/main.rs` | 472 | CLI: `gen-db`, `analyze (--generate-pdb/--output)`, `dump-db` (JSON), `db-info` | `DumperPro --binfold-*` altkomutları |

**Kritik bağımlılıklar (port'ta ikame edilecek):** `iced-x86` (decoder → bizde `sig`/disasm var),
`object` (PE/ELF → bizde `file` modülü), `memmap2` → Win32, `twox-hash` → **XXH64'ü kendimiz
yazarız (BSD-2 license reference implementation, sıfır dep)**, `uuid` (v5 = SHA-1 tabanlı, tek
fonksiyon), `pdb`/`pdb-sdk` (→ kendi PDB okuyucu ya da opsiyonel vendor), `rayon`/`dashmap` →
std::thread + sharded map, `iset` IntervalMap → kendi STL BTreeMap tabanlı interval map.

#### 2.1.2 Çekirdek algoritma (kesin anlatım)

1. **Fonksiyon GUID'i (WARP türevi):**
   - Fonksiyon recursive-descent ile basic block'lara ayrılır (`BTreeMap<u64,u64>` start→end).
   - Her blok için ham byte'lar alınır; `BlockMasker` **yeniden konumlabilir alanları sıfırlar**:
     x86/x64'te RIP-göreli displacement'lar ve (PE32'de) section aralığına düşen absolute
     immediate'lar; arm64'te ADRP sayfa tabanları + `add/ldr` lo12 immediate'ları (bloklar
     arası register-taint izleme ile).
   - Maskeli blok byte'ları domain-salt'lı XXH64 (`basic_block` domain) ile digest'lenir.
   - Blok digest'lerinin byte'ları **adres sırasına göre** (low→high — WARP spesifikasyonunun
     tersi, BN uyumluluğu için) birleştirilir ve `function` domain'iyle yeniden hash'lenir ⇒
     `FunctionGuid` (u64, DB formatı XxHash64'e sabit).
2. **Constraint'ler (fonksiyon GUID'ini bağlamla zenginleştirir):**
   - `child_call`: fonksiyonun her direkt `CALL` hedefinin kendi GUID'i, `child_call` domain'ine
     türetilir (`ConstraintGuid = H(child_call || FunctionGuid)`), offset = call-site − fonksiyon
     başı. Hedef segment dışıysa (import thunk) constraint düşürülür (deterministik).
   - `data_const`: read-only data referansı string'e benziyorsa (UTF-8/UTF-16 heuristiği,
     max 4 KB) string byte'ları hash'lenir.
   - `parent_call`: ters çağrı grafiğinden; build ve analyze tarafında aynı offset konvansiyonu.
   - `symbol_child_call` / `symbol_parent_call`: hedef/parent'ın **isim** hash'i (`symbol`
     domain) — DB'de ve eşleme sırasında iteratif eklenir.
3. **DB (`.fold`) formatı:** `BINFOLD` magic + versiyon(3) + katman dizini; her katman kendi
   içinde 6 sekme tutar. Fonksiyonlar GUID sıralı (binary search), `(func,constraint,symbol)`
   triple'ları sıralı+dedup. **Append-only:** yeni binary eklemek mevcut dizini kesip yeni
   katman gövdesi yazar; iki katman aynı GUID'i taşıyabilir (merge okuma anında).
4. **Eşleme (`match_with_database`) — iteratif fix-point döngüsü:**
   - Tüm analiz edilen fonksiyon GUID'leri için tek seferde **batch constraint yükleme**
     (sıralı sorgu × sıralı DB merge-join, sequential page-fault, string interning → u32 id).
   - Döngü: eşleşmemiş her fonksiyon için mevcut constraint'lerine, **bu turda yeni eşleşen**
     komşularının isim hash'lerinden türeyen symbol-child/parent constraint'leri eklenir.
   - Bir constraint'in DB'deki aday kümesi **tek elemanlı** ise isim bulunur. Yoksa tüm
     constraint'lerin aday kümeleri boyuta göre sıralanır ve **kümelerin kesişiminde tek
     eleman** kalan isim (find_unique) seçilir.
   - Yeni eşleşme yoksa dur. Böylece tek GUID çakışmaları, komşuluk bilgisiyle kademeli
     çözülür (README'deki >%50 eşleşme bundan gelir).
5. **gen-db:** PDB'li exe'ler paralel işlenir; GUID+constraint'ler `(func_id, constraint_id,
   symbol_id)` triple DashSet'ine yazılır (incremental dedup), sonunda tek katman olarak
   append edilir; BinaryGuid = içerik XXH64'ü ile tekrar işleme atlama.

**CLI yüzeyi:** `binfold gen-db -e <exe|dir>... -d db.fold [--parallel N]` ·
`binfold analyze --exe X --database db.fold [--generate-pdb | --output X.sym|.debug|.pdb]` ·
`binfold dump-db -d db.fold [--function 0x..] [-o out.json]` · `binfold db-info -d db.fold`.

**Sıfır-bağımlılık C++20 modül eşlemesi (önerilen hedef ağaç):**

```
DumperPro/src/binfold/
├── Binfold.hpp            // modül facade: BinfoldAnalyzer, AnalysisResult, MatchInfo
├── Guid.hpp/.cpp          // hash.rs: TagGuid<u64 Tag>, domain salt, UuidV5 (SHA-1'li) opsiyonel
├── XxHash64.hpp/.cpp      // kendi XXH64 (ikix-hash ikamesi, header-only ~80 satır)
├── Warp.hpp/.cpp          // warp.rs: block UUID + fonksiyon GUID + string heuristiği
├── Analysis.hpp           // arch/mod.rs sözleşme: FunctionAnalysis, BlockMasker
├── ArchX86.cpp            // arch/x86.rs (bizim disassembler/sig decoder ile)
├── Binary.cpp             // binary/mod.rs + pe.rs (file modülü + .pdata üzerinden)
├── Sweep.cpp              // binary/sweep.rs (PE32 linear sweep — opsiyonel faz 2)
├── BuildPipeline.cpp      // build_pipeline.rs (caller map + constraint türetme)
├── FoldDb.hpp/.cpp        // db.rs: format v3 okuma/yazma/append + batch query + interner
├── Matcher.cpp            // lib.rs::match_with_database (iteratif eşleme çekirdeği)
└── ExportSym.cpp          // export/breakpad.rs (.sym) — faz 2; PDB yazma vendor'a bırakılır
```

Tahmini port eforu: **M (çekirdek GUID+DB+matcher ~2-3k LOC C++'a iner)**; PDB *okuma*
(generate-db için) ayrı bir L alt-projesi; ilk faz "analyze + mevcut .fold DB'leriyle eşleştirme"
+ "bizim UE SDK çıktısından gen-db" olarak daraltılabilir (PDB yerine DumperPro SDK dump'ı
sembol kaynağı olur — bu, PDB bağımlılığını tamamen ortadan kaldıran en değerli uyarlamadır).

**Bileşen kararları:**
- WARP GUID + masker (x86/x64): **PORTABLE-MEDIUM** — decoder ikamesi dışında düz çeviri, M.
- `.fold` DB okuma/yazma/append: **PORTABLE-EASY** — saf byte format + binary search, S-M.
- İteratif matcher + batch loader: **PORTABLE-MEDIUM** — mantık birebir taşınabilir, M.
- x86 recursive-descent analyzer: **PORTABLE-MEDIUM** (iced-x86 yerine kendi decoder), M.
- arm64 path: **PORTABLE-HARD / sonraya** (928 LOC A64 decoder; bizde ihtiyaç düşük), L.
- PDB okuma (symbols/pdb.rs): **VENDOR-DEPS** (LLVM DebugInfoPDB veya Microsoft CC çekirdeği
  zorundasın ya da DumperPro SDK dump'ını sembol kaynağı yap), L.
- PDB/DWARF yazma (export/): **VENDOR-DEPS / CLEAN-ROOM-ONLY** (gimli/pdb crate'lerin C++
  muadili yok), L. Breakpad `.sym` yazıcı: PORTABLE-EASY (S).
- CLI: bizim `main.cpp`'ye altkomut — PORTABLE-EASY (S).

---

### 2.2 trumank/patternsleuth

**Lisans:** `Cargo.toml` workspace'te `license = "MIT OR Apache-2.0"`; ayrı LICENSE dosyası
**yok** (SIL/plansız değil — SPDX manifest beyanı geçerli, ama attribution'ı izlemek şart).
**Amaç:** UE oyunlarındaki kritik global/fonksiyon adreslerini (GObjects, GNames, GWorld,
GEngine, FMemory, AES, FName pool, pak, engine version vb.) **canlı process veya disk image**
içinde robust pattern setleriyle bulan test-suite/araç; UE4SS ile kullanım için tasarlanmış.

**Dil/boyut:** Rust workspace; çekirdek `patternsleuth` (~3.0k LOC) + `patternsleuth_scanner`
(pattern motoru) + CLI + `examples/dll_hook` (GUI'li in-process örneği).

**Mimari / bizim için kritik parçalar:**
- `patternsleuth_scanner/src/lib.rs`: AOB pattern motoru — `sig/mask` byte dizileri, nibble
  maskesi (`0x0f`/`0xf0`/bit-level), `|` yakalama noktası, `[ ... ]` sabit-aralık captures,
  tagged scan API. Bu, bizim `sig` modülümüzün zaten yaptığı işin Rust hali; fikir
  açısından **nibble mask + captures** genişletmesi değerli.
- `patternsleuth/src/resolvers/unreal/*.rs` (**en değerli varlık**): 20+ resolver, her biri
  el ile doğrulanmış pattern setleri + operand çözümleme içerir:
  `guobject_array` (6 Win + 2 Linux pattern + "Num−available" stat pattern'i ile FChunked/
  FFixed ayrımı), `fname` (FName pool), `gengine`, `gmalloc`, `engine_version`, `pak`, `aes`,
  `kismet`, `static_find_object`, `save_game`, `ftext`, blueprint_library vb.
  Pattern'ler sürümden bağımsızlık için **birden çok alternatif + validator** mantığıyla
  (ensure_one/try_ensure_one) çözülür.
- `patternsleuth/src/image/{pe,elf}.rs`: disk image + canlı process soyutlaması.

**Karar:**
- Resolver pattern veritabanı (pattern metinleri + validator mantığı): **PORTABLE-EASY** —
  MIT/Apache; pattern string'leri ve çözümleme mantığı bizim `sig`+`ue` modüllerine S-M
  eforla taşınır. *Not: pattern'ler UE4SS'in de çalışma zamanı pattern'leriyle çakışıyor;
  iki kaynağı tek "preset DB"de birleştirmek mantıklı.*
- Scanner çekirdeği: bizde zaten var (`sig`) — **NO-GO/port gereksiz**, sadece capture-group
  genişletmesi fikri alınır.
- Canlı process okuma kısmı: bizim `core` kapsamında — referans değerli, port gereksiz.

---

### 2.3 forrepid/UE5CEDumper (KULLANICININ KENDİ REPOSU)

**Lisans: MIT** (`LICENSE`, "Copyright (c) 2026 bbfox0703"). Kendi reposumuz olduğundan
entegrasyon/uyarlama tamamen serbest.

**Amaç (README doğrulandı):** UE 4.11–5.8 (Windows x64) oyunlarına inject edilen bir DLL +
C# Avalonia UI (UE5DumpUI): GObjects/GNames/GWorld/GEngine/SparseDelegates'i otomatik bulur
(**153 AOB pattern + 1 CallFollow + 6 symbol export**, "Scan Hint Cache" ile tekrar taramada
3× hızlı), reflection'ı okuyup Live Walker / Value Search (CE tarzı First/Next Scan) / teleport
/ cheat yönetimi yapar; **Cheat Engine entegrasyonu** ana hedef: pointer-chain XML, Structure
Dissect (CSX), Auto Assembler script, çok satırlı `.CT` tabloları üretir (AOBMaker plugin'i ile
doğrudan CE'ye gönderir); ayrıca SDK header, USMAP ve offline metadata dump (`.jsonl`) yazar.

**Dil/boyut:** C++23 DLL `dll/src/` **~105k LOC** (gözden kaçırılmamış kod; dosya adları
Almanca-gizli: `Genau`=OffsetFinder/AOB, `Grimoire`/`Orden`/`Aura`=CE export zinciri,
`Fern`=pipe IPC, `Mimic`=export servisleri) + C# UI `ui/UE5DumpUI/` **~240k LOC** (626 .cs).
Önemli dosyalar: `dll/src/Genau.h/.cpp` (EnginePointers + AOB scan + validator fallback
zinciri), `ui/UE5DumpUI/Services/CheatTableBuilder.cs` + `CeXmlExportService.cs` (.CT/XML),
`SdkExportService.cs` (SDK), `DumpService.cs` (.jsonl), `docs/Features.md` (özellik matrisi).

**Mimari:** DLL (MinHook, named-pipe server) ⇄ UI (pipe client) ⇄ Cheat Engine (CB/AA script
veya dosya). DLL tarafı pure C++/Win32; UI tarafı .NET 10 Avalonia; vendor: nlohmann/json.

**Bizim için kritik parçalar ve kararlar:**
- **AOB preset veritabanı + validator/fallback zinciri** (`Genau.*`): DumperPro `ue` modülünün
  GObjects/GNames bulma mantığıyla **aynı problem**; 150+ pattern verisi ve "hint cache"
  fikri doğrudan games.ini preset'lerine taşınabilir. **PORTABLE-EASY** (kendi reposu, MIT), S.
- **CE `.CT`/XML/CSX/AA üretimi** (`CheatTableBuilder.cs`, `CeXmlExportService.cs`): aşağıdaki
  entegrasyon önerisinin konusu. **PORTABLE-EASY** (C# mantık → C++/config), S-M.
- DynOff (FField/FProperty runtime offset probing): `ue` modülüne değerli fikir.
  **PORTABLE-MEDIUM**, M.
- Live process inspection / Value Search: `dump`/`core` ile örtüşüyor; UI tarafı kapsam dışı.

**Entegrasyon önerisi (somut):** — bkz. §5.

---

### 2.4 UE4SS-RE/RE-UE4SS

**Lisans: MIT** ("Copyright (c) 2022 Narknon"). **Amaç:** UE4/UE5 oyunlarına inject edilen,
self-contained bir Live View (canlı obje/property gezgini) + Lua modding runtime:
GObjects/GNames taraması, tam UObject API'si, Lua/C++ mod yükleyici, SDK üretici, USMAP
generator, crash dumper.

**Dil/boyut:** C++ (CMake/xmake), `UE4SS/src` **~131k LOC** (generated SDK hariç);
vendor/agent: `deps/third` (Lua 5.4, sol2, MinHook, etc.).

**Mimari / bizim için kritik parçalar:**
- `UE4SS/src/Signatures.cpp` (459 LOC): sürüm ailelerine göre GObjects/GNames/ProcessEvent
  vb. pattern setleri — patternsleuth ile aynı sorun uzayı; preset verisi olarak iyi bir
  ikinci kaynak. **PORTABLE-EASY** (veri), S.
- `UE4SS/src/LuaLibrary.cpp` + `LuaType/*` (32 dosya): Lua'ya expose edilen UObject wrapper
  mimarisi; REFramework'ün SDK binding'ine benzer. Modding API'si istenirse tasarım referansı.
  **PORTABLE-MEDIUM** (yalnızca Lua eklenti modülü eklersek), M-L.
- `SDKGenerator/` (C++ header + JSON dumper) ve `USMapGenerator/`: bizim `dump`/SDK
  çıktılarımızla örtüşüyor — karşılaştırma referansı, port gereksiz.
- `UnrealCustom/` (sürümden bağımsız UE struct tanımları): bizim `ue` modülüyle aynı işlev;
  offset tablolarını karşılaştırmak için faydalı. PORTABLE-EASY (veri), S.

---

### 2.5 FabianFG/CUE4Parse

**Lisans: Apache-2.0** (LICENSE + NOTICE mevcut). **Amaç:** UE arşiv konteynerlerini (pak,
IoStore/utoc, ucas) açan C# kütüphanesi: AES anahtarları, Oodle/LZ4/zlib çözme, FIOStore
index parse, paket/asset okuma (uasset/uexp/ubulk), mapping (.usmap) desteği, oyun-özel
custom sürüm yönetimi, FModel'in arkasındaki motor.

**Dil/boyut:** C# (.NET), çekirdek `CUE4Parse/` **~152k LOC** (2.284 dosya), ayrıca
CUE4Parse-Conversion (texture/model export, Kanan bağımlılıkları) ve CUE4Parse-Natives
(oodle native).

**Mimari / bizim için kritik parçalar:**
- `FileProvider/Vfs/` + `Pak/` + `UE4/IO/`: pak v8-v11 + IoStore index okuma; bizde tamamen
  **yok** — disk-tabanlı UE analizine açılırsa en büyük kapsam genişlemesi.
- `Encryption/Aes/`: FAES anahtar sözlüğü ve AES-256-ECB pak çözme (AES'i kendimiz yazarız —
  public domain referans implementasyonu mevcut).
- `Compression/`: Oodle (native DLL çağrısı — **sıfır-dep hedefle çelişir**), LZ4/zlib
  (port edilebilir ya da vendored single-file).
- `UE4/Objects/` + `Kismet/`: property serialization + blueprint bytecode — SDK dumper için
  opsiyonel derinlik.

**Karar:** Dili C# → C++ port tam bir **yeniden yazım** sayılır (satır-satır kopya değil);
Apache-2.0 izin veriyor, NOTICE korunmalı. Yine de kapsam devasa: sadece **pak/utoc index
okuma + AES + (opsiyonel) LZ4/zlib** alt kümesi hedeflenmeli.
- pak/IoStore index + VFS: **PORTABLE-HARD** (L; C#→C++ tam port, IoStore tablo mantığı
  karmaşık; ama MIT/Apache serbest).
- AES-256: **PORTABLE-EASY** (S; algoritma sabit, CUE4Parse anahtar JSON formatı örnek
  alınabilir).
- Oodle: **VENDOR-DEPS** (kapalı kaynak SDK DLL zorunlu; sıfır-dep hedefe aykırı → isteğe
  bağlı runtime load).
- .usmap okuma: **PORTABLE-MEDIUM** (M; format basit ikili şema).

---

### 2.6 4sval/FModel

**Lisans: GPL-3.0** (LICENSE). ⚠️ **KOPYALAMA YASAK** — temiz oda (clean-room) dışında tek
satır bile taşınamaz; hatta türev tartışması olmasın diye kod *okuma seviyesinde* bile
arşivleme yapmak en güvenlisi. **Amaç:** UE arşiv gezgini masaüstü uygulaması (WPF→Avalonia
geçişli): paket ağacı, JSON görüntüleyici, mesh/texture/anim/audio önizleme-export; CUE4Parse
üzerine kurulu. **Değer:** özellik seti ve UX akışı (mapping/aes seçim akışı, detay panelleri,
game profile kavramı) — bizim `dump`/UI tarafına **fikir** kaynağı. CUE4Parse'ın Apache
kütüphanesi zaten ihtiyacın tamamını verdiği için FModel'in kendisi port edilmeyecek.
**Karar: CLEAN-ROOM-ONLY / NO-GO** (kod için); özellik referansı serbest (fikirler telif
kapsamında değil), efor N/A.

---

### 2.7 praydog/REFramework

**Lisans: MIT** ("Copyright (c) 2019 praydog"). **Amaç:** RE Engine (ve MT Framework, Unity
de destekli) oyunları için D3D11/D3D12 hook + ImGui overlay + **Lua script mod runtime** +
güçlü SDK binding sistemi; kananlib/minhook/sol2/asmjit vendor'lı. RE Engine tip sistemi
(`shared/sdk/RE*`, regenny ile üretilen oyun başına struct tanımları, `REType`/`ManagedObject`
reflection wrapper'ları) dahil.

**Dil/boyut:** C++ (`src` ~61k LOC) + büyük `shared/sdk` regenny üretimleri.

**Mimari / bizim için kritik parçalar:**
- **Mod/ScriptRunner mimarisi** (`src/mods/Mod.hpp`, `ScriptRunner.cpp`, `bindings/Sdk.cpp`):
  mod döngüsü + `on_present/on_pre_update` event API + Lua sandbox — DumperPro'ya ileride
  "plugin/mod" yüzü eklersek en iyi C++ referans. **PORTABLE-MEDIUM** (MIT; ama sol2+Lua
  vendor'ı gerekir → Lua tek-CDep (lua 5.4, tek C lib) kabul edilirse M, edilmezse NO-GO).
- RE Engine (`re2/...`) tipleri ve `REContext`/`REArray` çözümleme: RE Engine hedeflersek
  **tek kapsamlı kaynak**; şu an ürün kapsamımız UE+IL2CPP → **PORTABLE-MEDIUM, sonraya**.
- D3D11/12 + WindowsMessage + ExceptionHandler hook'ları: overlay/GUI istenirse; sıfır-dep
  minhook port'u mümkün. **PORTABLE-MEDIUM** (M).
- Pattern scanning: kananlib'e bağlı (vendored) — bizde `sig` var, port gereksiz.

---

## 3. Entegrasyon Matrisi

| Depo | Lisans | En yüksek değerli bileşen | Port kararı | Efor |
|---|---|---|---|---|
| binfold | MIT | WARP GUID + constraint DB + iteratif matcher (`.fold`) | **PORTABLE-MEDIUM** (x86 çekirdek) | M (PDB okuma ayrı: L/vendor) |
| patternsleuth | MIT OR Apache-2.0 (manifest; LICENSE dosyası yok) | UE resolver pattern DB (GObjects/GNames/GWorld/aes/pak...) | **PORTABLE-EASY** (veri+validator → sig/ue) | S-M |
| UE5CEDumper | MIT (kendi reposu) | AOB preset DB + CE .CT/XML/CSX üretimi | **PORTABLE-EASY** (kendi kodumuz) | S-M |
| RE-UE4SS | MIT | 2. UE pattern seti + UnrealCustom offset tabloları | **PORTABLE-EASY** (veri); Lua API=M-L (isteğe bağlı) | S |
| CUE4Parse | Apache-2.0 | pak/IoStore index + AES + usmap | **PORTABLE-HARD** (alt küme) | L (AES: S) |
| FModel | **GPL-3.0** | UI/UX özellik referansı | **NO-GO (kod) / CLEAN-ROOM** | N/A |
| REFramework | MIT | Lua mod/ScriptRunner mimarisi; RE Engine tipleri | **PORTABLE-MEDIUM** (vendor: Lua/sol2) | M (isteğe bağlı) |

---

## 4. Lisans Uyarıları — Neyi Kopyalayabiliriz / Kopyalayamazız

- **Serbest (attribution yeterli — telif + LICENSE metni korunsun):**
  binfold (MIT), patternsleuth (MIT OR Apache-2.0, LICENSE dosyası yok → Cargo beyanı;
  kopyalarken kendi NOTICE'ımıza "patternsleuth © Truman Kilen, MIT OR Apache-2.0" ekle),
  UE5CEDumper (MIT, kendi reposu), RE-UE4SS (MIT), CUE4Parse (Apache-2.0 → NOTICE dosyası
  ve patent/ifade sınırlamaları geçerli), REFramework (MIT; vendor'ları ayrı lisanslı:
  sol2 MIT, Lua MIT, ImGui MIT, MinHook BSD-3, asmjit GPLv3/zlib dual — **asmjit vendor'ı
  sıfır-dep hedefe aykırı**, kullanmaktan kaçın).
- **KOPYALANAMAZ:**
  - **FModel (GPL-3.0):** kod kopyalamak DumperPro'nun da GPL'e bulaşması demek. Clean-room
    (özellik listesi/tanımdan bağımsız yazım) dışında temas yok.
  - **REFramework içindeki asmjit** (GPLv3 seçeneğiyle dual): yalnız zlib seçeneğiyle ve
    tek dosya vendor ile mümkün; yoksa kaçın.
  - **Oodle (CUE4Parse-Conversion/Natives üzerinden):** kapalı kaynak, kırmızı çizgi —
    runtime'da kullanıcı sağlayan DLL yükleme modeli (CUE4Parse'ün yaptığı gibi) kopyalama
    sayılmaz, ama binary olarak repo'ya koymak yasak.
- **PDB crate'leri (binfold'un kullandığı `pdb`/`pdb-sdk`):** MIT, ama C++ karşılığı yok;
  C++ tarafta LLVM (Apache/MIT uyarısı: LLVM DebugInfoPDB Apache-2.0 w/ LLVM exceptions —
  vendor etmek ağır) veya kendi parser. Sıfır-dep tercih: sembol kaynağı olarak **kendi
  SDK dump'ımız** (§2.1.2 son paragraf).
- Genel kural: her port edilen dosyanın başına `// Ported from <repo> (<SPDX>), (c) <yazar>`
  satırı; `docs/NOTICE.md` içine lisans metinleri. Hiçbir GPL dosyasına dokunulmaz.

---

## 5. UE5CEDumper Entegrasyon Önerisi (kullanıcının reposu — en hızlı kazanım)

**Fikir: "CE köprüsü" — games.ini profile üretimi + doğrudan .CT çıktısı, iki yön.**

1. **`--ct-import <file.ct|dump.jsonl>` (DumperPro `config`+`ue`):**
   UE5CEDumper'ın ürettiği Çok Satırlı `.CT` (Cheat Table XML) ve `Dump All` `.jsonl`
   metadata dump'ını okuyup DumperPro `games.ini` profiline çevirir:
   - `.CT` içindeki pointer-chain kayıtları (GObjects/GNames/GWorld/base+offset zincirleri,
     AA script bloklarındaki `aobscanmodule`/`registersymbol` sembolleri) ayrıştırılır →
     `games.ini` `[game.X]` bölümüne `gobjects_pattern=`, `gnames_pattern=`, `offsets.*`
     olarak yazılır. Böylece bir oyun UE5CEDumper ile çözüldüyse DumperPro'da **yeniden
     çözümleme yapmadan** çalışır (İki araç arası profil alışverişi).
   - `.jsonl` (class/struct/enum üyeleri + fonksiyon parametreleri) okunup `--sdk-from-jsonl`
     ile SDK üretiminde girdi olarak kullanılabilir (canlı process olmadan offline SDK).
   - Parser: CE .CT = XML (RetryDecode: `<CheatTable><CheatEntries><CheatEntry>
     <AddressShow>`/`<Address>`/`<Offset>`/`<AssemblerScript>`). Sıfır-dep: küçük
     el-yazımı XML reader (config modülü zaten INI parser'ı var — XML reader S-M efor).
2. **`--ct-export` (ters yön):** DumperPro'nun bulduğu GObjects/GNames AOB'leri ve SDK
   sınıf hiyerarşisinden **CE uyumlu .CT + CSX + pointer-chain XML** üretir (UE5CEDumper'ın
   `CheatTableBuilder.cs`/`CeXmlExportService.cs` mantığının C++20'ye taşınması — MIT ve
   kendi kodumuz, PORTABLE-EASY). Çıktıları UE5CEDumper UI ve CE direkt açabilir.
3. **Preset DB birleşimi:** UE5CEDumper'ın 153 AOB pattern'i + patternsleuth + RE-UE4SS
   pattern'leri tek `sig` preset tablosunda birleştirilir; games.ini'de `preset=ue5cedumper`
   seçilebilir. Scan Hint Cache (kazanan pattern'i oyun başına önbellek) fikri de alınır.

Sıra 1'de yapılacak somut adım: **`--ct-import`** (tek dosya: `src/config/CtImport.cpp` +
`games.ini` writer; .jsonl okuyucu ikinci adım).

---

## 6. Önceliklendirilmiş Yol Haritası

| Sıra | Ne | Kaynak | Neden bu sırada | Efor | Hedef modül |
|---|---|---|---|---|---|
| **1** | binfold çekirdeği: XXH64 + GUID domain + WARP(x86) + `.fold` DB + matcher | binfold (MIT) | "Sembol taşıma" en büyük doğrudan değer; diğer ajan paralel port ediyor — bizim notlar referans. PDB yerine SDK-dump sembol kaynağı ile sıfır-dep tamamlanır | M | `binfold/` (yeni) |
| **2** | UE pattern preset DB birleşimi (patternsleuth + UE4SS Signatures + UE5CEDumper 153 AOB) + validator/hint-cache | 3 depo (MIT/Apache) | Sig modülünün isabet oranını UC 4.11–5.8 aralığında sıçratarak tüm akışı güçlendirir; saf veri taşıma, risk düşük | S-M | `sig/`, `ue/`, `config/` |
| **3** | `--ct-import` / `--ct-export` CE köprüsü | UE5CEDumper (MIT, kendi reposu) | Kullanıcı akışı: CE ekosistemiyle çift yönlü uyum; config/dump modüllerine dokunuyor, çekirdek riski sıfır | S-M | `config/`, `dump/` |
| **4** | AES-256 pak çözme + (opsiyonel) LZ4/zlib + pak v8-v11 index okuma (alt küme) | CUE4Parse (Apache-2.0) | Disk-tabanlı UE analizi açılır (canlı process şartı kalkar); IoStore tablo mantığı zahmetli olduğu için alt kümeyle başla | AES: S, pak: M→L | `file/` (yeni pak alt modülü) |
| **5** | Breakpad `.sym` + DWARF-temel export; SDK-dump→binfold gen-db köprüsü | binfold + kendi SDK çıktısı | Sıra 1'in değerini dış araçlara (BN/IDA/Ghidra/gdb) taşıyan çıkış formatları | S-M | `binfold/Export*`, `dump/` |
| **6** | Lua mod/plugin API (Mod lifecycle + UObject binding tasarımı) | REFramework + RE-UE4SS (MIT) | Eklenti ekosistemi; Lua vendor'ı (tek C kütüphanesi) kabulü gerektirir — sıfır-dep hedefin istisnası olarak tartışılır | M-L | yeni `plugin/` |
| **7** | arm64 path (binfold masker+decoder) ve/veya RE Engine tip sistemi | binfold / REFramework | Genişleme fazı; x86/UE çekirdeği sağlamlaşmadan başlanmaz | L | `binfold/ArchArm64`, `ue/` |

**Başlangıç yapılacak ilk iş (Sıra 1 uyarlama notu):** port, "analyze + mevcut .fold DB ile
eşleştirme" dar kapsamıyla başlar (PDB okuma yok): `XxHash64` + `Guid` + `Warp` + `FoldDb`
+ `Matcher` ≈ 2-3k LOC C++20; sembol kaynağı olarak `dump` modülünün SDK çıktısından
`gen-db` beslenir. Bu, hem sıfır-dep şartı sağlar hem de PDB alt-projesini (L) erteleyip
değeri hemen ortaya koyar.

---

*Kaynak klon konumları: `research/repos/{binfold, patternsleuth, UE5CEDumper, RE-UE4SS,
CUE4Parse, FModel, REFramework}`. Bu belge dışında motora (DumperPro/) hiçbir dosya
eklenmedi/değiştirilmedi.*
