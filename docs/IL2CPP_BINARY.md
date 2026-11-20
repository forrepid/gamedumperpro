# IL2CPP Binary Analizi (GameAssembly.dll / libil2cpp.so)

> Arastirma + dogrulama belgesi. Referans kaynaklar `research/` altinda
> indirildi ve incelendi; algoritma Il2CppDumper'dan (Perfare, MIT) uyarlandi.

## 1. Arastirilan kaynaklar

| Kaynak | Yer | Kullanilan bilgi |
|---|---|---|
| Il2CppDumper | research/il2cppdumper (codeload.zip) | `Il2Cpp/Il2CppClass.cs` struct layoutlari; `Utils/SectionHelper.cs` CodeRegistration/MetadataRegistration tarama algoritmasi; `ExecutableFormats/PE.cs` bolum secimi |
| Unity il2cpp yapisalari | Il2CppDumper icindeki metadata siniflari | Il2CppCodeGenModule, Il2CppMetadataRegistration, Il2CppTypeDefinition/MethodDefinition/ImageDefinition alan siralari ve versiyon kosullari |

`raw.githubusercontent.com` bu ortamda 404 donduruyor; `codeload.github.com`
zip indirme yolu kullanildi (Il2CppDumper master, ~110 KB).

## 2. CodeRegistration tarama algoritmasi (uygulanan)

Il2CppDumper `FindCodeRegistration2019` zincirinin portudur:

1. Veri bolumlerinde `mscorlib.dll\0` stringi bulunur -> string VA listesi.
2. Bu VA'yi QWORD olarak tasiyan konumlar = Il2CppCodeGenModule yapilarinin
   baslari (moduleName ilk alan; struct adresi = string referansi).
3. Struct adreslerini QWORD olarak tasiyan konumlar = codeGenModules
   dizisinin eleman slotlari.
4. Slot VA - i*ps (i = 0..imageCount) dizi tabanidir; tabani QWORD olarak
   tasiyan konum = CodeRegistration.icindeki `codeGenModules` alani,
   onundeki QWORD `codeGenModulesCount` (== imageCount) ile dogrulanir.
5. CodeRegistration tabani: codeGenModules alanindan geriye dogru
   `{count, ptr}` ciftleri gezilir (kendi oz-dogrulamali yuruyusumuz;
   Il2CppDumper'in sabit `refva3 - 13/14*ps` aritmetigi yerine).
6. MetadataRegistration: `FindMetadataRegistrationV21` portudur -
   veride `[x]==typeDefCount` ve `[x+2ps]==typeDefCount` ve `[x+3ps]`
   gecerli bir veri isaretcisi -> x = fieldOffsetsCount, base = x - 10ps.

## 3. Dogrulanmis struct bilgileri (Il2CppClass.cs)

- **Il2CppCodeGenModule** (ilk 3 alan sabit): moduleName ptr,
  methodPointerCount (i64/i32), methodPointers ptr. Alan sayisi:
  v24.2-24.4 = 11, v24.5 = 13 (+adjustorThunk), v27-27.2 = 16
  (+cacoGen/modInit/staticCtor/metareg/codereg), v28+ = 15.
- **Il2CppMetadataRegistration** (v19+, 8B alanlar): genericClasses,
  genericInsts, genericMethodTable, types, methodSpecs, fieldOffsets,
  typeDefinitionsSizes, metadataUsages (count/ptr ciftleri).
- **Il2CppType** = {data u64, bits u32} (12B, tekil isaretci ile okunur);
  bits>>16 & 0xff = tip; 0x11 VALUETYPE / 0x12 CLASS -> data = typedef indeksi.
- fieldOffsets: v27+ u64 isaretci dizisi (tip basina u32 ofset listesi);
  eski surumlerde u32 isaretci dizisi (32-bit binary) - ikisi de denenir.

## 4. Bagli eslestirme (metadata <-> binary)

- metadata v27 == il2cpp v27 (Il2CppDumper ayni eslemeyi kullanir).
- metod RVA: `codeGenModule.methodPointers[(token & 0xFFFFFF) - 1]`
  (token RID tabanli; v24.1- dizinler image methodStart farkiyla ayni sonucu verir).
- Ciktilar: `dump.cs` (Il2CppDumper stili: RVA/Offset/VA + field ofsetleri +
  parent sinif adlari) ve `script.json` (adresler + metod haritasi).
- Cift eslestirme yukleme rotasinda otomatiktir: metadata yuklendiginde son
  24 saatteki GameAssembly/libil2cpp yuklemesi yeniden analiz edilir (ve tersi).

## 5. Sinirlar

- Generic metodlar (methodSpecs) bu pass'te cozulmez; Il2CppDumper'in
  genericMethodTable akisi sonraki adim olarak planli.
- metadataUsages (v24-27) string/type usage tablolari henuz okunmuyor.
- Obfuscate edilmiş metadata'larda (isim sifreleme) alan adlari anlamsizdir;
  tarama yine de adresleri bulur.
