# DumperPro Online - UE/Epic/Steam Save Game Editor (Arastirma + Tasarim)

Bu dokuman, save game editor modulunun (Gorev 3) arastirma sonularini, format
belgelerini ve uygulama kararlariyla dogrulama testlerini dokumante eder.

Yasal cerceve: yalnizca SAHIP OLUNDUGUNUZ oyunlarin kayitlarini duzenlemek
icin; online/cok oyunculu oyun kayitlarini bozmak kapsam disidir.

---

## 1. Unreal Engine GVAS (.sav) formati

Kaynaklar: UE kaynak kodu `FPropertyTag::operator<<` (Object.h/Obj.cpp),
`FSaveGameSerializer`, uesave-rs (tracel-ai) referans okuyucu, UAssetAPI.
Modulumuz `src/lib/analysis/savegame.ts` bu belgelerle birebir dogrulandi
(bkz. bolum 4 - byte-perfect round-trip).

### 1.1 Header

| Alan | Tip | Not |
|---|---|---|
| magic | 4 bayt | `"GVAS"` (0x47 56 41 53) |
| saveGameFileVersion | i32 | genelde 3 (UE5); >= 3 ise UE5 versiyon alanlari |
| packageFileUE4Version | i32 | ornek 522 (UE5.3) |
| packageFileUE5Version | i32 | fileVersion >= 3 ise |
| engineVersion | u16+u16+u16+u32+FString | major.minor.patch-changelist + branch |
| customVersionFormat | i32 | orijinal degeri KORUNUR (yazimda geri yazilir) |
| customVersions | i32 adet x {GUID 16B, i32} | |
| saveGameClassName | FString | `/Script/MFObserver.SaveGame` tarzi |

### 1.2 Property tag duzeni (kritik sira!)

```
FString name
FString type            ("IntProperty", "StructProperty", ...)
i64     size            (govde boyu; degistirilmemis dugumde orijinal korunur)
[StructProperty] FString structType + GUID 16B   <- TAG icinde!
[BoolProperty]   u8 boolVal                      <- TAG icinde (UE quirk!)
u8      hasPropertyGuid (1 ise GUID 16B)          <- tag kuyrugu
GOVDE (size kadar):
  IntProperty/Int64/Int16/Int8/UInt*/Float/Double : deger + 1 dolgu bayti (pad, genelde 0x00)
  BoolProperty   : (govde yok - deger tag icinde, size=0)
  ByteProperty   : [Size!=1 ise] FString enumName + u8 deger
  EnumProperty   : FString enumName + FString deger
  Str/Name/Object: FString
  SoftObject     : FString path + FString subPath
  StructProperty : tag'li alt proplar ... "None"
  Array/Set      : FString innerType + i32 count + ogeler
                   (StructProperty ic tur: her oge = tag'siz struct govdesi + None)
  MapProperty    : FString keyType + FString valueType + i32 count +
                   her cift icin tam tag'li key + tam tag'li value
```

Kritik ince noktalar (testte teyit edilen):

1. **BoolProperty degeri tag icindedir** (size'dan SONRA, hasPropertyGuid'dan
   ONCE) ve govde boyu 0'dir. uesave-rs ile ayni semantik.
2. **StructProperty'nin structType+structGuid'i tag icindedir** (size'dan
   sonra, hasPropertyGuid'dan once). Govde yalnizca alt proplardir.
3. **ByteProperty/EnumProperty enumName'i govdededir** (tag kuyrugundan sonra).
   Enum'suz ByteProperty govdesi tek bayttir (Size==1 ayirt edicisi).
4. **Sayisal tipler govde sonunda 1 dolgu baytasi tasir** (uesave-rs padding).
5. **Array/Set/Map ic tur adi govdededir** (tag kuyrugundan sonra).

### 1.3 FString kodlamasi

- i32 len; len > 0: ASCII/UTF-8 baytlar + null (latin1 bayt-korumali okuma)
- len < 0: UTF-16LE, karakter sayisi -len (null dahil)
- byte-perfect icin orijinal baytlar `rawStringBytes` (hex) olarak korunur;
  duzenleme yapilmayan FString'ler ayni baytlarla geri yazilir.

### 1.4 Sifreleme / sikistirma

UE `FAES::DecryptData` stili AES-256. Gercek oyunlarda uc senaryo:

| Senaryo | Tespit | Cozum |
|---|---|---|
| Duz GVAS | magic | dogrudan parse |
| zlib ile sikistirilmis | `0x78 0x01/0x9C/0xDA` | inflateSync -> GVAS |
| AES-256-ECB sifreli | GVAS yok + .sav uzantisi | kullanici anahtari (32 bayt hex) |
| AES + zlib zinciri | anahtar ile decrypt sonrasi 0x78 | decrypt -> inflate -> parse |

Kaydetme akisi ters sirayla: serialize -> (deflate) -> (AES ile yeniden
sifrele, ayni anahtar/cipher). PKCS#7 dolgusu varsa meta'da isaretlenir ve
kaydet'te geri uygulanir.

### 1.5 Byte-perfect strateji

- Her dugumde `sizeRaw` (orijinal Size alani) + `edited` bayragi tutulur;
  degistirilmemis dugumlerde Size orijinal degeri ile yazilir.
- `opaque` tipler (taninmayan property) ham bayt olarak saklanir/geri yazilir.
- FString'ler `rawStringBytes` ile bayt-bire geri yazilir.
- customVersionFormat + branch/className orijinal baytlariyla korunur.

## 2. Steam VDF (Valve Data Format)

Kaynaklar: SteamKit2 BinKV semantigi, ValveDataFormat topluluk dokumantasyonu,
gercek shortcuts.vdf ornekleri. Modul: `src/lib/analysis/vdf.ts`.

### 2.1 Metin VDF (localconfig.vdf, loginusers.vdf...)

- quote'lu/quote'suz anahtar-deger, `{}` bloklari, `//` ve `/* */` yorumlar,
  escape (`\t \n \" \\`).
- YAZIMda yorumlar/girinti korunmaz (bilinen kisit - UI'da belirtilir);
  agac yapisini ve degerleri birebir korur.

### 2.2 Ikili VDF (shortcuts.vdf, remotecache.vdf)

Kayit duzeni (SteamKit2 BinKV ile ayni):

```
tip bayti (0x00 blok, 0x01 str, 0x02 int32, 0x03 float, 0x04 ptr,
           0x05 widestring, 0x06 color, 0x07 uint64, 0x08 blok sonu)
FString anahtar
deger (tipe gore; blok ise alt kayitlar ... 0x08)
kok blogun sonu da 0x08
```

- FString: i32 len; negatif = UTF-16LE.
- byte-perfect: her dugum orijinal tipini (`t`) tasir; yazim tip baytini
  aynen geri yazar (int->int, wstr->wstr...).

## 3. API arayuzu

| Uc nokta | Islev |
|---|---|
| `GET /api/uploads/:id/savegame?keyHex=&cipher=` | agac JSON'u (20 MB uzeri kisaltilir); `editedFile` bayragi |
| `PUT /api/uploads/:id/savegame` | `{edits:[{path,value}], keyHex?, cipher?}` -> parse+apply+serialize -> `<savedPath>.edited.sav/.vdf` yazar |
| `GET /api/uploads/:id/savegame/download` | duzenlenen kopyayi (yoksa orijinali) `*_edited.sav/.vdf` adiyla indirir |

Edit yolu sozdizimi: `Health`, `PlayerState.Level`, `Inventory[1].Name`,
`Loot[key=9]`. Degerler string olarak gonderilir; hedef tip sayisal/bool'a
cevirilir. `applyEdits` yol boyunca tum atalari `edited` isaretler - boylece
degisen string uzunluklari StructProperty Size alanlarina dogru yansir.

## 4. Dogrulama sonuclari

### 4.1 Birim / round-trip (bun scriptleri, `/home/z/tmp/test_sav.ts`)

28/28 test GECTI:

- byte-perfect round-trip (duz dosya)
- deger dogrulamalari (int/float/bool/utf16-str/struct/array/set/map/enum/byte)
- propGuid'li tag kuyrugu korunumu
- applyEdits (kok + dizi + map yolu) sonrasi degerler + yeni round-trip
- AES-256-ECB sifreli: parse + byte-perfect geri yazim + yanlis anahtar hata mesaji
- sifreli+zlib zinciri + sifresiz zlib (byte-perfect)
- ozet (propCount/className)

### 4.2 VDF round-trip (`/home/z/tmp/test_vdf.ts`)

18/18 test GECTI: metin parse/round-trip/edit, ikili (shortcuts semantigi)
byte-perfect round-trip/edit, utf16 widestring.

### 4.3 API e2e (curl ile)

- `plain.sav` yukleme -> kind=savegame -> GET agac (28 prop) -> PUT 3 edit
  (kok int + Inventory[1].Name + Loot[key=9]) -> download: 3 duzenleme
  dogrulandi (`Health=250`, `Efsanevi Kalkan`, `Canli Yayin`).
- `shortcuts.vdf` -> kind=vdf -> GET agac (tip dagilimi block:3,str:4,int:2)
  -> PUT edit -> download "Editor Ile Degisti".

### 4.4 Tarayici e2e (agent-browser)

- Save Editor sekmesi: GVAS agaci (Health/Money/bGodMode/Inventory/Loot pairs)
- Health alanini 777 yap -> `Kaydet (1)` -> toast: "1 degisiklik .edited
  kopyaya yazildi" -> `duzenlenmis kopya gosteriliyor` rozeti
- Indir butonu -> `*_edited.sav`

## 5. Bilinen sinirlar

- Metin VDF yorumlari/girintisi kaydet'te korunmaz.
- UE StructProperty icindeki ozel struct'lar (Vector, DateTime...) genel
  "struct govdesi" olarak parse edilir - alan tipi etiketleri UI'da ham gosterilir.
- Sifreli kayitlarda anahtari sadece oyun verir (klasorlere gore ayriyettir);
  editor anahtari dogru ise seffaf calisir.
- Oodle ile sikistirilmis save'ler (nadir) desteklenmez (yalnizca zlib).
