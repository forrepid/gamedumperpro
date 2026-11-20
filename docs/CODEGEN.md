# DumperPro Online - Kod Uretici + Semantik Aciklama Motoru (Arastirma + Tasarim)

Bu dokuman, cikarilan verilerin secilen programlama diline gore kod uretimi
(Gorev 2) ve "bu veri ne is yapiyor / ne hesapliyor / nereye isliyor"
semantik aciklama motorunun arastirma, tasarim ve dogrulama sonuclarini
toplar.

Moduller:
- `src/lib/analysis/codegen.ts`  - cok dilli kod uretici (1129 satir)
- `src/lib/analysis/semantics.ts` - Turkce semantik tahmin motoru (769 satir)
- `src/components/codegen-tab.tsx` - Kod Uretici sekmesi (UI)
- `src/app/api/uploads/[id]/codegen` - kod uretim API'si
- `src/app/api/uploads/[id]/explain` - heuristic + AI aciklama API'si

---

## 1. Kod uretimi (codegen.ts)

### 1.1 Veri kaynaklari

Analiz sonucundan (`AnalysisResult`) beslenen girdi kumeleri:

| Tur | Kaynak | Kapsam |
|---|---|---|
| Fonksiyonlar | `result.functions.functions` | rva/va/boyut/prologue/strings/apiCalls/callsOut/xrefsIn/asm/pseudo |
| Structlar | `result.structs.structs` | alanlar (offset/size/type/reads) + vftable + kaynak |
| Enumlar | `result.enums.enums` | uyeler + degerler + kaynak (rtti/switch/il2cpp) |
| Dizeler | `result.strings` | deger + kodlama (ascii/utf16) |

### 1.2 Uretilen adres/AOB metadata (pointer-offset-opcode-aob-sub)

Her fonksiyon icin:

- `RVA` (section uzerinden) + `VA = imageBase + RVA`
- `sub_<RVA8hex>` otomatik ad (label yoksa; Windows/Dumper-7 konvansiyonu)
- **AOB deseni**: prologue 12 baytdan uretilir - rel32/imm32 alanlari `??`
  jokerlenir (`48 8B 05 ?? ?? ?? ?? ...`); ASLR'de adres gecici oldugu icin
  desenler statik tarama icin adaydir (imza sekmesi zaten dogrulama yapar)
- opcode/prologue satiri cikti basligina gomulu
- callsOut/xrefsIn sayilari cikti icin saglanir (call graph ipucu)

### 1.3 Desteklenen diller (8)

| Dil | Cikti bicimi | Dogrulama |
|---|---|---|
| C++ | prototipler + `struct` + `static_assert(offsetof(...))` (padding alanlari `pad_0x` ile) | `g++ -fsyntax-only` GERCEK derleyici ile gecti |
| C# | Dumper-7 stili `[Address(RVA=..., Offset=..., VA=...)]` + `[StructLayout(LayoutKind.Explicit)]` + `[FieldOffset]` + `AddressAttribute` tanimi | bicim kontrolu |
| Python | `ctypes.Structure` + `_fields_` + offset yorumlari + `IntEnum` | `python3 -m py_compile` GERCEK ile gecti |
| Rust | `#[repr(C)] pub struct` + `pub enum` + `extern "system" { }` bloklari | bicim kontrolu |
| TypeScript | offset tablolari + interface + const enum benzeri nesneler | `bun build` ile gecti |
| Java | adres tablosu (static final) + siniflar + enumlar | bicim kontrolu |
| Lua | tablo sozlukleri (`X = { Health = { off = 0x0, type = "uint32" } }`) | bicim kontrolu |
| JSON | makine-okunur tam veri (uretilmis aob/sub dahil) | `JSON.parse` gecti |

Cikti dosya adlari: `<kind>_<language>.<ext>` (`functions_cpp.h`,
`structs_py.py`, `all_rs.rs` ...). `limit` (varsayilan 500) + adi filtre
(case-insensitive) + `imageBase` desteklenir.

## 2. Semantik aciklama motoru (semantics.ts)

### 2.1 Arastirma baglam

Kullanici istegi: cikarilan her veri icin "ne is yapiyor, ne hesapliyor,
nereye isliyor" bilgi-si (character/weapon/level/money/car/position/x-y-z/
physics/model/skin/weather... oyun-program-grafik tum veri kumeleri).
Bu, oyun hile/analiz topluluklarinin Cheat Engine tablo adlari, UE UPROPERTY
adlandirma konvansiyonlari, IL2CPP alan adlari ve tersine muhendislik
sozlugulerinden derlenen genis bir anahtar kelime -> kategori eslemesiyle
cozulur; yoksa LLM katmani (opsiyonel) devreye girer.

### 2.2 Sozluk tasarimi

- **666 anahtar kelime -> 23 kategori + "Genel" fallback**
- Kategoriler: Karakter/Saglik, Silah/Hasar, Envanter/Esya, Ekonomi/Para,
  Ilerleme/Seviye, Konum/Koordinat, Hareket/Fizik, Arac/Tasima, Gorsel/Model,
  Animasyon, Grafik/Render, Kamera, Hava/Cevre, Ses, Arayuz/HUD, Ag/Online,
  Kayit/Konfig, Girdi/Kontrol, Yapay Zeka, Zaman/Sayac, Gelistirici/Debug,
  AntiHile/Koruma, Bellek/Bellegi
- Skorlama: tam eslesme (3) > onek (2) > icerme (1); kazanan kategori +
  diger eslesenler `tags` + confidence 0.05-0.97 (eslesme sayisi/pozisyonu)
- MSVC (`?fn@Cls@@`), Itanium (`_ZN...`) ve JNI ad dekorasyonu temizligi
- Fiil sablonlari (21): get/set/update/apply/init/tick/lerp/damage/heal/
  spawn/destroy/load/save/serialize/process/handle/compute/check/toggle/...
  -> "X degerini okur" / "X alanini gunceller" cumleleri
- callsOut/xrefsIn yorumlari (merkezi yardimci fonksiyon ayrimi)

### 2.3 AI katmani (opsiyonel, derin aciklama)

`POST /api/uploads/:id/explain` - `{type, artifact, useAi:true}`:

1. **Heuristic katman her zaman doner** (cevrimdisi, anlik).
2. `useAi:true` ise backend'de z-ai-web-dev-sdk ile Turkce, madde madde,
   "olasilik dili" iceren derin aciklama uretilir (istemcide SDK ASLA
   calismaz - kurallara uygun).
3. Ortam kimlik bilgisi eksikse (`X-Token` 401) UI zarif sekilde hata
   gosterir; heuristic aciklama etkilenmez.

## 3. UI (Kod Uretici sekmesi)

- Dil secici (8 dil) + veri turu secici + ad filtresi
- SOL: oge listesi - her satirda yerel semantik kategori rozeti (renk kodlu)
- SAG: uretilen kod paneli (Kopyala + Indir) + secili oge icin
  "Ozet / Hesapladigi / Nereye isliyor" paneli + etiketler + **AI ile Acikla**
- Veri turu/koruma degisince kod otomatik yeniden uretilir (POST codegen)

## 4. Dogrulama

### 4.1 Birim (alt ajan: 56/56 GECTI)

- 8 dilde cikti + dosya adlari + items + limit/filter davranisi
- fonksiyon satirlarinda RVA/VA/AOB gorunumu
- etiketsiz adlandirma (`sub_00001040`)
- C++ `static_assert(offsetof(Player, Health) == 0x8, ...)`
- C# Dumper-7 `[Address(RVA=...)]` + JSON parse
- `?updateHealth@Player@@QEAAXH@Z` -> **Karakter/Saglik**
- `fMoney/float` -> **Ekonomi/Para**
- NaN/undefined taramasi temiz
- **Gercek derleyici teyitleri**: uretilen Python `py_compile` OK,
  uretilen C++ `g++ -fsyntax-only` OK, uretilen TS `bun build` OK

### 4.2 API e2e (curl)

- `test_rtti.exe` -> `{"language":"cpp","kind":"all"}` -> `all_cpp.h`
  uretildi (dize 2); Dizeler turu ile `STR_000/001` satirlari dogrulandi
- `explain` heuristic: `?updateHealth@Player@@QEAAXH@Z` -> Karakter/Saglik,
  guven 0.58

### 4.3 Tarayici e2e (agent-browser)

- Kod Uretici sekmesi: dil/tur comboboxlari, kod paneli, Kopyala/Indir
- Dizeler turu: 2 oge + kategori rozeti ("Genel", guven %) + kod metni
- Semantik panel: "Ozet / Hesapladigi / Nereye isliyor" dolu
- AI ile Acikla: 401 ortaminda zarif hata ("AI: API request failed...")
- Mobil 390px yerlesim + footer dogal itme dogrulandi

## 5. Bilinen sinirlar

- Semantik tahminler sezgiseldir; kesinlik iddiasi tasimaz (UI'da guven %).
- Statik PE'de .pdata olmayan/strip edilmis dosyalarda fonksiyon/struct
  verisi cikmayabilir (Kod Uretici "veri yok" mesaji verir).
- AI aciklamasi icin gecerli Z-AI kimlik bilgisi gerekir (ayrca ozel bir
  sonuc degildir; heuristik katman ana veri kaynagidir).
