# DumperPro Online - Web Analiz Platformu: Kaynaklar ve Teknik Kararlar

> Bu dokuman, web tabanli dosya yukleme/analiz platformunun arastirma ve dogrulama
> surecini, kullanilan format spesifikasyonlarini ve kutuphane kararlarini belgeler.
> Amaclanan: offline analiz, tek oyunculu modding, interop ve motor arastirmasi.
> Cok oyunculu/hile amacli kullanim kapsam disidir.

## 1. Kutuphane Kararlari (arastirma + dogrulama sonucu)

| Ihtiyac        | Adaylar                   | Secilen | Gerekce |
|----------------|---------------------------|---------|---------|
| ZIP okuma (APK)| adm-zip, jszip, unzipper, fflate | **sifir-bagimlilik el yapimi parser** | APK merkezi dizini satir seviyesinde okumak tek dosya (ondemand inflate) cikarmaya izin verir; devasa APK'nin TAMAMINI bellege acmak gerekmez. node:zlib (built-in) deflate-raw acar. Ek bagimlilik = 0 |
| PE parse       | node-pe-parser, pe-library| **el yapimi parser** | MS PE/COFF spec dogrudan uygulanir (Buffer uzerinden); DumperPro'nun C++ PEFile.cpp mantiginin TS portudur; ayni alanlar/siralar kullanilir |
| ELF parse      | (adaylar sinirli)         | **el yapimi parser** | Sadece ehdr + section tablo okumasi; 64 satir; bagimlilik gereksiz |
| AXML manifest  | (npm'de guvenilir paket yok)| **el yapimi parser** | Binary XML chunk yapis resource_types.h'de belgeli; best-effort parse + try/catch |
| Sikistirma     | node:zlib                 | **node:zlib** | built-in; inflateRawSync ZIP deflate-raw akisi icin |
| Hash           | node:crypto               | **node:crypto** | SHA-256 kimlik tespiti |
| DB             | Prisma + SQLite           | **Prisma** | Proje standardi; Upload/Analysis modelleri |
| UI             | shadcn/ui + Tailwind 4    | **shadcn/ui** | Proje standardi; zinc/emerald temasi |

## 2. Format Spesifikasyonlari (uygulanmis alanlar)

### PE/COFF (Microsoft "PE Format" dokumani)
- IMAGE_DOS_HEADER (64 B), e_magic "MZ", e_lfanew @0x3C -> "PE\0\0"
- IMAGE_FILE_HEADER (20 B): machine, NumberOfSections, TimeDateStamp,
  SizeOfOptionalHeader, Characteristics
- OptionalHeader magic 0x20B (PE32+, ImageBase u64) / 0x10B (PE32, ImageBase u32)
- Subsystem @opt+68, DllCharacteristics @opt+70 (ASLR/DEP/CFG bayraklari)
- 16 DataDirectory (Export/Import/Resource/.../Debug/IAT/...)
- Section tablosu 40 B/entry: VA, VSize, RawPtr, RawSize, Characteristics; entropy
  hesabi Shannon (1 MB ornekleme)
- Import: IMAGE_IMPORT_DESCRIPTOR 20 B dongu, thunk 8 B (PE32+) / 4 B (PE32),
  ordinal bit kontrolu, IMAGE_IMPORT_BY_NAME (hint + ascii)
- Export: IMAGE_EXPORT_DIRECTORY 40 B: NumberOfFunctions/Names, AddressOfNames
- Debug: IMAGE_DEBUG_DIRECTORY 28 B, Type 2 (CODEVIEW) -> "RSDS"+GUID+age+PDB yolu

### ZIP / APK (PKWARE APPNOTE.TXT v6.3.x + AOSP apk yapis)
- EOCD 0x06054b50 sondan arama (yorum payi toleransli), ZIP64 EOCD locator 0x07064b50
- Central Directory 0x02014b50: method/size/localOffset; ZIP64 extra (id 0x0001)
- Local File Header 0x04034b50: data = 30 + nameLen + extraLen sonrasi
- method 0 (STORE) dogrudan, method 8 (DEFLATE) inflateRawSync
- APK tespiti: AndroidManifest.xml + *.dex varligi; lib/<abi>/*.so -> ABI listesi
- assets icinde *.pak (UE paketleri), global-metadata.dat (Unity) takibi

### AXML (Android binary XML)
- RES_XML_TYPE 0x0003, StringPool 0x0001 (UTF8_FLAG 0x100), START_ELEMENT 0x0102
- manifest elementinin attributeleri: package, versionName, versionCode,
  minSdkVersion/targetSdkVersion (REFERENCE/STRING/INT_DEC typed value ayrimi)

### ELF (TIS/spec + man elf)
- \x7fELF + ei_class (1=32,2=64) + ei_data (LE/BE); e_machine, e_type, e_entry
- Section header (64 B sh64 / 40 B sh32) + shstrtab isim cozumu

### DEX
- "dex\n" + "035\0" tarz surum imzasi

## 3. Unreal Engine Tespit Mantigi

- UnrealBuildTool uretimi surum stringi: `++UE4+Release-4.27.2-CL-0-Windows`,
  `++UE5+Release-5.3.2-CL-0-Windows`; custom dallar (Main, Licensor) da eslesir.
- ASCII + UTF-16LE tarama (ayni string bazen genis kodlamada bulunur).
- Motor markerlari: UnrealEngine/Engine\Content/FNamePool/GUObjectArray,
  libUE4.so/libUE5.so, Unity (global-metadata.dat, il2cpp, UnityPlayer),
  Godot, Source, CryEngine, Frostbite, RED, id Tech.
- APK yolu: en buyuk ilgi ceken .so (libUE4.so/libUE5.so veya >8 MB) arsivden
  cikarilir, buffer uzerinde ayni surum string taramasi calisir.
- Guvenlik: EasyAntiCheat/EOS, BattlEye, Vanguard, XIGNCODE3, nProtect, FACEIT,
  ESEA, TenProtect, ACE, mhyprot; DRM: Denuvo/Steam/EOS/UWP; Packer: VMProtect,
  Themida, UPX, Enigma. Packer sezgisi: .text entropy > 7.2.

## 4. Imza Adaylari (statik)

DumperPro games.ini/C++ SigFinder ile ayni desen havuzu:
- GObjects: `48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8`, zincir varyanti
- GNames (FNamePool): `4C 8D 35 ?? ?? ?? ?? EB 16`, `48 8D 35 ?? ?? ?? ?? EB 16`
- ProcessEvent / PostRender parmak izleri (canli mod vtable cozumculugu icin)

Kosullu joker (??) eslesme .text/.rdata gibi bolumlerin RAW verisinde calisir,
file offset -> RVA -> VA (varsayilan ImageBase) cevrilir. Statik adaylar
DOGRULANMAMISTIR; canli modda RIP-relative cozumleme + adres dogrulamasi ile
teyit edilir, kesin sonuc `<Oyun>_sigs.txt` dosyasina yazilir.

## 5. API ve Veri Modeli

| Yol | Yontem | Is |
|-----|--------|----|
| /api/upload | POST | multipart upload -> kaydet -> analiz -> DB |
| /api/uploads | GET | gecmis (son 50) |
| /api/uploads/[id] | GET/DELETE | tam analiz JSON / sil |
| /api/uploads/[id]/report | GET | TXT veya JSON rapor indirme |
| /api/uploads/[id]/extract | POST | APK/ZIP icinden kayit cikar -> yeni analiz |

DB: Upload(id, fileName, savedPath, size, mime, source, parentId, status, error)
Analysis(uploadId, kind, engine, engineVersion, summary JSON, report TXT)

Upload siniri: 300 MB; tek kayit acma siniri: 128 MB; string tarama penceresi
96 MB; entropy ornekleme: 1 MB (bolum) / 8 MB (genel).

## 6. Sinirlar ve Notlar

- Statik analiz: calisan surece baglanmaz; GObjects/GNames ADRESLERI yalnizca
  canli modda (Windows C++ araci, --process/--pid) kesinlesir.
- LZMA/bzip2 ZIP kayitlari (nadir) acilmaz; bu kayitlarda cikarma atlanir.
- AXML parse best-effort'tur (obfuscate manifestlerde alanlar eksik olabilir).
- OrijinalliK Kontrolu: tuketici cihazinda analytik calisma yoktur; yuklenen
  dosya yalnizca sunucu tarafinda, analiz amacli okunur.
