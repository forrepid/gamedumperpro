# DumperPro - IL2CPP ve ART Konteynerleri (OAT / VDEX / CDEX)

Bu dokuman, Unity IL2CPP metadata parser'i ve ART konteyner desteklerini
anlatir. Tum layout'lar kaynak kodlardan cekilip DOGRULANMISTIR (asagidaki
"Kaynaklar ve dogrulama" bolumune bakiniz).

Yasal cerceve: yalnizca sahibi oldugunuz ya da analiz etmeye yetkili
yazilimlar icin; cok oyunculu/hile amacli kullanim kapsam disidir
(README'deki DISCLAIMER'a bakin).

---

## 1. IL2CPP metadata modu (global-metadata.dat)

### Kullanim

```
DumperPro.exe --file global-metadata.dat
DumperPro.exe --file oyun.apk            <- APK icinden otomatik tespit
DumperPro.exe --serve                    <- tarayicidan yukleme (ayni hat)
```

### Cikti dosyalari

| Dosya | Icerik |
|---|---|
| `il2cpp_report.txt` | Turkce ozet: surum, sayimlar, image listesi, ornek tipler, literal ornekleri |
| `il2cpp_dump.cs` | dump.cs benzeri iskelet: namespace/kind/alan/metod/param + token + slot |
| `il2cpp_metadata.json` | makine-okur sema: counts + images + types (cap 100k) |
| `il2cpp_stringliterals.txt` | string literaller (ilk 100.000) |

### Desteklenen surumler ve dogrulanmis struct boyutlari

Metadata surumleri **16..31** (Il2CppDumper ile ayni aralik). Header
(offset,size) cift sirasi ve struct boyutlari Il2CppDumper'in
`MetadataClass.cs`'inden birebir alindi:

| Struct | Surum | Boyut (bayt) |
|---|---|---|
| Il2CppTypeDefinition | <= 24.0 | 104 |
| Il2CppTypeDefinition | 24.1 | 100 |
| Il2CppTypeDefinition | 24.2 - 24.5 | 92 |
| Il2CppTypeDefinition | 25+ | 88 |
| Il2CppMethodDefinition | <= 24.0 | 56 |
| Il2CppMethodDefinition | 24.1 | 52 |
| Il2CppMethodDefinition | 25 - 30 | 32 |
| Il2CppMethodDefinition | 31 | 36 (+returnParameterToken) |
| Il2CppFieldDefinition | <= 24.0 | 16 (24.1+: 12) |
| Il2CppParameterDefinition | <= 24.0 | 16 (24.1+: 12) |
| Il2CppImageDefinition | < 24 | 20/24 (24.0: 32, 24.1+: 40) |
| Il2CppStringLiteral | tumu | 8 (`u32 length; i32 dataIndex`) |

v24 alt-surum tespiti (Il2CppDumper Metadata.cs ile ayni sezgiler):
- `stringLiteralOffset == 264` -> v24.2 (header layout'u kayar:
  rgctxEntries cifti v24.2+'da yoktur)
- image token != 1 -> v24.1 (image stride 32 -> 40)
- v24.1'de asSEMBLY boyut sezgileri Il2CppDumper ile aynidir; bu arac
  assembly tablosunu okumadigindan yalnizca tip/metod/field stride'lari
  etkilenir (bunlar yukaridaki tabloyla surumden hesaplanir)

### ONEMLI NOTLAR (metadata-yalniz sinir)

1. **global-metadata.dat yalnizca METADATA tutar.** Il2CppType tablosu
   (alan/metod/param tipleri) ve metod native adresleri binarydedir
   (libil2cpp.so / GameAssembly.dll). Bu yuzden ciktilarda tip isimleri
   yerine `T<idx>` (TypeIndex) yazilir - bilincli kisaltma, hata degildir.
2. Binary eslestirmesi ARTIK UYGULANDI (bkz. yukaridaki bolum);
   metadata-yalniz mod yalnizca binary verilmediginde kullanilir.
3. Unity surum tahmini metadata surumunden yaklasiktir ("yaklasik"
   etiketiyle raporlanir; garanti degildir).
4. Kati dogrulama: sanity 0xFAB11BAF + surum 16..31. Baska degerlerde
   pars reddeder, sessiz tahmin yapmaz. Kesik/bozuk dosyalarda temiz
   hata mesaji doner (crash yok).
5. AP'ler icinde metadata **512 MiB** ile sinirli cikarilir (zip-bomb
   korumasi ZipReader'dadir).

### Binary eslestirmesi (Il2CppDumper'in "ikinci yarisi" - TAMAMLANDI)

Metadata artik yalnizca degil; binary ile eslestirilince tam cikti:

```
DumperPro.exe --file GameAssembly.dll --metadata global-metadata.dat
DumperPro.exe --file libil2cpp.so  --metadata global-metadata.dat
DumperPro.exe --file oyun.apk      (metadata + libil2cpp.so varsa OTOMATIK)
```

Tarama yontemi (`src/il2cpp/Il2CppBinary.cpp`):

1. **Il2CppCodeGenModule (metadata v24.1+)**: metadata image adlari
   ("mscorlib.dll", ...) binary .rodata'da C string olarak aranir; bu
   stringlere isaret eden slotlar Il2CppCodeGenModule baslangicidir.
   Layout tum v24.1+ surumlerde ilk 3 alanda sabittir:
   `moduleName(+0x00), methodPointerCount(+0x08 u32), methodPointers(+0x10)`.
   Dogrulama: orneklenen methodPointer'larin >=%30'u exec bolumlere isaret
   etmeli; image basina metod sayisina en yakin aday secilir.
   Metod adresi: `token 0x06000000|RID -> methodPointers[RID-1]`.
2. **Duz (flat) methodPointers (metadata v16-24.0)**:
   `u32 count == metadata metod sayisi` + gosterci dizi kalibi taranir;
   exec isabet orani en yuksek aday kullanilir, metod indexi dogrudan
   dizi indexidir.
3. **Il2CppMetadataRegistration**: `typesCount` orneklem dogrulamasi +
   `fieldOffsetsCount == metadata tip sayisi` GUCLU kontrolu. Bulunursa
   Il2CppType tablosu okunur ve dump.cs'te GERCEK tip isimleri + alan
   ofsetleri kullanilir.
4. **Il2CppType isim cozumu** (rekursif, dongu korumali, derinlik 10):
   CLASS/VALUETYPE -> Il2CppClass (image+0, gc_desc+8, name+0x10,
   namespaze+0x18; v<23'te data dogrudan TypeDefinitionIndex'tir),
   GENERICINST -> Il2CppGenericClass{type, context.class_inst} +
   Il2CppGenericInst{argc, argv[]}, SZARRAY/PTR -> Il2CppType* rekursiyon,
   ARRAY -> Il2CppArrayType, VAR/MVAR -> !i / !!i.

ELF (PIE .so) icin relocation destegi: SHT_RELA (4) bolumundeki
RELATIVE kayitlari okunur (x86-64: type 8, AArch64: 1027, RISC-V: 3) ve
slot okumalarinda addend kullanilir; PE tarafinda ImageBase normalizasyonu
yapilir. Tum surumlerde (.so ve GameAssembly.dll) adres ciktisi RVA/VA/
dosya ofseti olarak verilir; ELF kayitlari `[reloc]` etiketlidir.

#### Ilave cikti dosyalari

| Dosya | Icerik |
|---|---|
| `il2cpp_dump.cs` | binary eslestirmeli: gercek tipler + alan ofsetleri + `// RVA: 0x.. Offset: 0x.. VA: 0x..` |
| `il2cpp_methodaddresses.txt` | Image / Tip / Metod / RVA / VA / Offset / token tablosu |
| `il2cpp_script.json` | Il2CppDumper uyumlu `ScriptMethod` + (v19-24.5) `ScriptString` / `ScriptMetadata` / `ScriptMetadataMethod` semalari (IDA/Ghidra) |
| `il2cpp_usages.txt` | v19-24.5 metadata usage slotlari: Slot / Tip / Index / HucreVA / referans adi |
| `il2cpp_binary_report.txt` | tarama raporu: moduller, registration, usages, istatistik |
| `DummyDll/` | image basina DERLENEBILIR C# kaynak stub'lar (Il2CppDumper DummyDll paritesi - asagida) |

### metadataUsages (v19-24.5) - Il2CppDumper StructGenerator paritesi

Metadata v19..24.5'te `metadataUsageLists` + `metadataUsagePairs` tablolari
vardir (v25+'ta kaldirilmistir). Binary tarafinda
`Il2CppMetadataRegistration.metadataUsages` (x64: count +0x70, ptr +0x78)
bir gosterci dizisidir; her elemanin DEGERI kodgen global hucrenin VA'sidir
(`g_MyClass_TypeInfo` gibi; cogunlukla .bss'te).

Il2CppDumper Metadata.cs ile ayni cozumleme:

- `Il2CppMetadataUsageList { u32 start; u32 count; }` (8B)
- `Il2CppMetadataUsagePair { u32 destinationIndex; u32 encodedSourceIndex; }` (8B)
- `usageType = (encodedSourceIndex & 0xE0000000) >> 29` (1..6)
- `decodedIndex = encodedSourceIndex & 0x1FFFFFFF` (v<27)
- Tipler: 1=TypeInfo, 2=Il2CppType, 3=MethodDef, 4=FieldInfo,
  5=StringLiteral, 6=MethodRef (MethodRef = binary Il2CppMethodSpec
  indexi; spec 12B: `methodDefinitionIndex, classIndexIndex, methodIndexIndex`)

DumperPro slot degerlerini reloc-uyumlu okur (ELF RELA RELATIVE addend),
hucreleri `InDataCell` (map'lenmis VEYA .bss - NOBITS bolgeleri) ile
dogrular ve CATI dogrulamasi olarak binary struct'taki count'un metadata
slot sayisina esitligini ister. Sonuclar:

- `il2cpp_usages.txt`: hucre VA + cozulen referans adi (tip/metod/alan/literal)
- `il2cpp_script.json`: `ScriptString` (literal degerleri),
  `ScriptMetadata` (TypeInfo/Il2CppType/FieldInfo hucreleri),
  `ScriptMetadataMethod` (MethodDef/MethodRef + metod adresleri) -
  Il2CppDumper StructGenerator.cs AddMetadataUsage* semantigiyle ayni

### DummyDll uretimi (Il2CppDumper paritesi - kaynak duzeyi)

Il2CppDumper DummyDll ciktisi dnlib ile gercek .NET assembly yazarken,
DumperPro bunun KAYNAK duzeyi karsiligini uretir:
`outDir/DummyDll/` altinda image basina DERLENEBILIR C# kaynak dosyalari
(+ `_attributes.cs`, `build.bat`, `_readme.txt`). Derleyince dnSpy/ILSpy'da
tipler, alanlar, metodlar; `[Address]`/`[Token]`/`[FieldOffset]`
attribute'lari ile gorunur olur (attribute semasi Il2CppDumper
`Il2CppDummyDll` namespace'iyle ayni isimler).

```
cd DummyDll
build.bat        :: her image icin ayri DLL (csc gerekir)
:: veya:
csc /nologo /target:library /out:MyGame.dll _attributes.cs MyGame.dll.cs
```

Bilincli kisaltmalar (stub dogasi, _readme.txt'te de yazar): metod
govdele bos; enum degerleri 0..n; cozulemeyen tip referanslari `object`
olur; generic tipler non-generic stub olarak cikar; nested tipler
namespace duzeyinde duzlestirilir.

#### Dogrulama testleri (sentetik, Linux g++ -std=c++20)

- Sentetik v27 metadata (2 image, 4 tip, 8 alan, 10 metod) + sentetik
  ELF64 (raw pointer modu): 8/10 adres, 2 govdesiz - beklenenle birebir
- Ayni binary RELA-relocation modunda (slotlar 0, addend relocation'da):
  ayni 8/10 sonuc, `[reloc]` etiketi dogru
- Sentetik PE64 (GameAssembly.dll bicimi, ImageBase 0x140000000): 8/10 +
  Il2CppType tablosu
- Sentetik v22 metadata (flat mode) + ELF64: 3/3 adres; v16-24.0
  MethodDefinition token ofseti (44) bu testte dogrulandi - eski kodda
  token+24 okunuyordu, Il2CppDumper MetadataClass.cs alan sirasiyla
  eslestirilerek DUZELTILDI
- APK oto-es cifti: arm64-v8a onceligi ile reloc .so cikarilir, tarama
  uclardan uca dogrulandi (--file ve --serve yollari)
- Alan ofsetleri: int32_t** dizilerinden 0x10/0x18/0x20 degerleri
  dump.cs yorumlarina dogru tasindi
- Sentetik metadata v24.0 + usage list/pair (TypeInfo/StringLiteral/
  MethodDef/Il2CppType) + ELF64 + .bss hucreleri: 4/4 usage slotu dogru
  isimle cozuldu (Game.MyClass / Hello / Game.MyClass::GetHp /
  Game.MyEnum); il2cpp_usages.txt + script.json ScriptMetadata bolumleri
  dogrulandi
- Ayni ciftte DummyDll: Test_dll.cs [FieldOffset]/[Token]/[Address]
  attribute'li derlenebilir C# stub uretimi dogrulandi; enum uyeleri
  value__ haric listelendi

---

## 2. ART konteynerleri (OAT / VDEX / CDEX)

### Kullanim

```
DumperPro.exe --file base.vdex
DumperPro.exe --file base.odex           <- oat/vdex/cdex otomatik tespit
DumperPro.exe --file arm64.oat
```

### Kapsam: temel header dogrulamasi

| Format | Magic | Dogrulanmis alanlar |
|---|---|---|
| VDEX 006 | `vdex` "006\0" | #dex, dexSize, verifierDeps, quickening (24B header) |
| VDEX 010 | `vdex` "010\0" | ayni 24B duzen |
| VDEX 019 | `vdex` "019\0" | verifierDepsVersion, dexSectionVersion, #dex, verifierDeps (20B) |
| VDEX 021 | `vdex` "021\0" | + bootClasspathChecksums, classLoaderContext (28B) |
| OAT | `art\n` "NNN\0" | checksum, dex_file_count, executable_offset + key/value store ornekleri |
| CDEX | `cdex` | temel header (magic/surum/checksum) |

API eslemesi (vdexExtractor `src/vdex_api.c`'den dogrulanmis):
`006 -> API 26 (Android 8.0)`, `010 -> API 27 (8.1)`,
`019 -> API 28 (Android 9)`, `021 -> API 29 (Android 10)`.

ONEMLI NOT: OAT surumu -> Android eslemesi RAPORLANMAZ (oat surum haritasi
surumden surume degisir); yalnizca ham surum string'i gosterilir. VDEX
eslemesi kaynaktan dogrulanmis oldugu icin gosterilir. Icerik cikarma
(vdexExtractor tarzi DEX ayristma) kapsam disidir.

---

## 3. Kaynaklar ve dogrulama ("araştır-bul-incele-doğrula" akisi)

| Konu | Kaynak | Dogrulama yolu |
|---|---|---|
| IL2CPP header + struct'lar | Perfare/Il2CppDumper `Il2Cpp/Metadata.cs`, `Il2Cpp/MetadataClass.cs` | jsdelivr CDN uzerinden tam dosya cekildi (HTTP 200); alan sirasi + surum kosullari birebir uygulandi |
| IL2CPP sanity/surum | Il2CppDumper Metadata.cs | sanity 0xFAB11BAF; surum 16..31 kontrolu ayni |
| VDEX header'lar | anestisb/vdexExtractor `src/vdex/vdex_006|010|019|021.h` | struct'lar birebir (24B/20B/28B) |
| VDEX -> API esleme | vdexExtractor `src/vdex_api.c` | `printApiLevel` bolumunden birebir |
| OAT header | AOSP `art/runtime/oat.h` (OatHeader) | AOSP erisilemedi (rate limit); yalnizca ilk 5 alan toleransli parse edildi |
| ART surum bicimi | `art\n` + `NNN\0` | vdexExtractor/AOSP ortak bicimi |
| Il2CppCodeGenModule / MetadataRegistration / Il2CppType / Il2CppClass / Il2CppGenericClass / Il2CppGenericInst layout'lari | il2cpp runtime header'lari (Il2CppDumper Il2CppDef yansimalari) | struct alan siralari birebir uygulandi; sentetik ELF64/PE64/v27/v22 testleriyle ucardan uca dogrulandi |
| ELF RELATIVE relocation tipleri | glibc elf.h (R_X86_64_RELATIVE=8, R_AARCH64_RELATIVE=1027, R_RISCV_RELATIVE=3) | sentetik RELA-reloc .so testinde slotlar addend ile dogru cozuldu |
| v16-24.0 Il2CppMethodDefinition token ofseti | Il2CppDumper MetadataClass.cs (11 i32 alan + token@44) | sentetik v22 testinde token'lar dogru; eski +24 okumasi DUZELTILDI |
| metadataUsages list/pair + decode | Il2CppDumper Metadata.cs (`ProcessingMetadataUsage`, `GetEncodedIndexType`, `GetDecodedMethodIndex`) | github raw'dan tam kaynak cekildi (HTTP 200); formuller birebir uygulandi; sentetik v24 usage testiyle 4/4 slot dogrulandi |
| MetadataRegistration.metadataUsages offsetleri | Il2CppDumper Il2CppClass.cs (`Il2CppMetadataRegistration`: v19+ metadataUsagesCount/metadataUsages son iki alan) | struct alan sirasi birebir; x64 +0x70/+0x78, x86 +0x38/+0x3C |
| Il2CppMethodSpec (MethodRef) | Il2CppDumper Il2CppClass.cs (`Il2CppMethodSpec`: methodDefinitionIndex, classIndexIndex, methodIndexIndex) | 12B layout birebir; sentetik MethodRef testi eklenecek kapsamda not edildi |
| Il2CppFieldRef (FieldInfo) | Il2CppDumper MetadataClass.cs (`Il2CppFieldRef`: typeIndex, fieldIndex) | 8B layout birebir |
| DummyDll attribute semasi | Il2CppDumper Outputs/ScriptJson.cs + DummyDll cikti bicimi (AddressAttribute/TokenAttribute/FieldOffsetAttribute) | ayni isimler/alanlar; ScriptMetadata/ScriptMetadataMethod/ScriptString JSON semasi ScriptJson.cs ile birebir |
| usages hucre dogrulamasi (.bss) | il2cpp runtime kodgen global'leri .bss'te yasar | BinaryView'a NOBITS (ELF) + virtual-size > raw-size (PE) bss araliklari eklendi; sentetik testte 4/4 hucre dogrulandi |

Dogrulama testleri (Linux g++ -std=c++20):
- Sentetik v27 metadata (3 image, 8 tip, 10 alan, 8 metod, 4 param, 4
  literal) -> tum ciktilar ureticiyle birebir eslesti; tip kind'leri
  (class/struct/enum/interface) ve token'lar dogru
- Sentetik vdex 021 / oat (`art\n`+KV) -> alanlar dogru, API eslemesi dogru
- Metadata gomulu sentetik APK -> otomatik cikarma + parse + "es cifti"
  tespiti dogru
- Kesik metadata / junk dosya / taninmayan vdex surumu -> crash yok,
  temiz uyari mesajlari
- `--serve` paralel yuklemeler (bounded thread havuzu, max 4) dogrulandi
