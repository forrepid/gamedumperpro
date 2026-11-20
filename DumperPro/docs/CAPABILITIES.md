# DumperPro - Tam Yetenek Listesi (Yapilanlar / Yapilacaklar)

Bu dokuman projenin o anki durumunu "yapilanlar" ve "yapilacaklar" olarak
ayrintili listeler. Lisans/etik sinirlari icin README DISCLAIMER'a bakiniz.

---

## 1. YAPILANLAR (calisan yetenekler)

### 1.1 Cekirdek Dumping (Modul 1)
- Canli proses erisimi: `--process <Ad>.exe` (substring, buyuk/kucuk harf
  duyarsiz) ve `--pid <pid>`; OpenProcess + ReadProcessMemory tabanli
  (`src/core/ProcessReader.cpp`)
- Kernel destekli okuma: `--kernel` bayragi, istemci tarafi tamamlanmis
  (`src/core/KernelReader.cpp`), WDK referans surucusu + kurulum/guvenlik
  notlari (`docs/KERNEL.md`) - korumali prosesler icin
- Dosya modu: `--file` ile diskteki PE imajinin tam analizi (VA->RVA->file
  offset cevirimi, bss/bolum bosluklarina sifir doldurma - `FileReader.cpp`)
- PE cozumleme: PE32/PE32+, bolumler, export tablosu, UE surum stringleri
  (`src/core/PEFile.cpp`, windows.h'siz portable)
- Cikti dosyalari: `Names.txt`, `Objects.txt`, `SDK/<Pkg>_classes.h|_structs.h|
  _enums.h`, `SDK/SDK.hpp`, `signatures.txt`, `<Oyun>_sigs.txt`, `offsets.txt`,
  `vtable_funcs.txt`, `funcs.txt`

### 1.2 Signature System (Modul 2)
- Desen (pattern) tarama + dogrulama: `48 8B 05 ?? ?? ?? ??` bicimi, jokerli
  desenler, dogrulanmis hitler (`src/sig/SigFinder.cpp`)
- Ana imza + 16 bayt genisletilmis baglam imzasi; `games.ini`'ye geri
  yazilabilir (`<Oyun>_sigs.txt`)
- Hedef fonksiyonlar: `UObject::ProcessEvent`, `UGameViewportClient::PostRender`,
  `UNetDriver::ProcessRemoteFunction`
- Statik PE yuklemelerinde imza ADAYLARI (web + serve modunda RVA/VA ile)

### 1.3 Configuration (Modul 3)
- `games.ini`: derleme gerektirmeden oyuna ozel offsetler; dosya ici
  (noktali anahtarlar) ve bolum tabanli profile destegi
- 8 yerlesik profil: UE4 4.20-4.27 + UE5 5.0-5.3; modul icine gomulu surum
  stringi (`"Release-4.27"`) otomatik tanima
- Oncelik sirasi: games.ini (authoritative) -> yerlesik profil -> varsayilanlar;
  ini asla otomatik uzerine yazilmaz

### 1.4 UE5 Support (Modul 4)
- FNamePool (UE4.23+ / UE5): 2 baytlik giris header'lari, degisken uzunluk,
  64KB chunk, FName Number +0x4, UTF-16 genis adlar
- Eski TNameEntryArray (4.20-4.22) geri donusumu
- Nesne dizisi oto-algila: UE5 chunk 65536, UE4 stride 0x18/chunk 0x2800
  adaylari; katilim oylamasi ile secim

### 1.5 UX (Modul 5)
- Ilerleme cubuklari: `[####....] 45.2% | ETA 12s` (`src/utils/Progress.cpp`)
- Hata mesajlarina eyleme gecirilebilir `Hint:` satirlari (orn. games.ini
  ekleme talimati)
- Renkli banner/log katmani (`Logger.cpp`), `--verbose` ayrinti modu
- Web panelinde ayni deneyimin tarayici versiyonu (asagiya bakin)

### 1.6 VTable Function Resolver (Modul 6)
- Sabit slot varsayimi YOK: yedekli byte parmak izi taramasi + MSVC
  adjustor/thunk cozumleme + coklu vtable oylama, minIndex guven esigi
- Sonucta kaynak etiketi: `[vtable>pattern]`, `[vtable]`, `[pattern]`

### 1.7 Runtime Offset Discovery (Modul 7)
- Kucuk orneklemle alan oylama (<=400 canli nesne), %65 guven esigi - esigi
  gecemeyen alan atanmaz, uyari listesine dusar
- `games.ini` degerleri her zaman probe'un uzerindedir

### 1.8 Online Dosya Analizi (YENI - bu donem eklendi)
Web panel (Next.js):
- exe/dll/sys/apk/so/dex/zip/pak/obb yukleme (surukle-birak, 300 MB)
- PE: bolumler+entropy, import/export, data dirs, PDB, DEP/ASLR/CFG,
  UE surum stringleri, GObjects/GNames/GWorld/ProcessEvent imza ADAYLARI
- APK: binary AXML manifest (paket adi/versiyon/SDK), ABI'ler, DEX sayimi,
  UE .pak listesi, notable dosyalar (global-metadata.dat, unityplayer, .obb),
  icindeki `.so`leri tek tikla cikarip ayr analize gonderme
- ZIP/OBB: kayit + dizin gruplari
- ELF: mimari/bolum tablosu, UE stringleri
- DEX (tek basina yukleme): header sayimlari, adler32 dogrulamasi, MUTF-8
  string havuzu, paket istatistikleri, motor ipuclari (com.epicgames,
  com.unity3d, il2cpp)
- Motor/guvenlik taramasi: UE4/UE5/Unity/Godot/Source/CryEngine/Frostbite;
  EAC/BattlEye/Ricochet/VAC/Vanguard; Steam/Denuvo/EOS; VMProtect/Themida/UPX
- Turkce TXT rapor + games.ini taslagi + JSON indirme; yukleme gecmisi
  (SQLite/Prisma); API: /api/upload, /api/uploads[...], extract, report,
  /api/download

DumperPro.exe (C++ tarafi, YENI):
- `--serve [port]`: yerlesik HTTP sunucu ile online yukleme modu (default
  127.0.0.1:8420); gomulu surukle-birak sayfasi; rapor diske + tarayiciya;
  **thread havuzu ile eszamanli analiz (en fazla 4 istemci)**
- `--file` PE olmayan dosyalari `StaticAnalyzer` hattina yonlendirir
  (apk/zip/so/dex/il2cpp/vdex/oat -> `analysis_report.txt` + IL2CPP ciktilari)
- Portable ZIP okuyucu: EOCD/ZIP64 + STORE/DEFLATE (el yazimi RFC 1951
  decoder, zip-bomb limiti)
- Portable ELF (32/64, LE/BE) + DEX cozumleyici; UE surum string tarayici
- Yukardaki tum C++ dosyalari Linux g++ ile derlenip ornek dosyalarla test
  edildi (bkz. docs/ONLINE.md Dogrulama bolumu)

### 1.9 IL2CPP modu (YENI - Il2CppDumper kaynaklarina karsi dogrulanmis)
- `--file global-metadata.dat` veya APK icerisinden otomatik tespit:
  metadata surumleri 16..31 (v24.1/24.2 alt-surum sezgileri dahil)
- Header (offset,size) cift sirasi MetadataClass.cs'den birebir;
  sanity 0xFAB11BAF kati dogrulama
- Ciktilar: `il2cpp_report.txt` (Turkce ozet), `il2cpp_dump.cs`
  (namespace/kind/alan/metod/param iskeleti + token/slot),
  `il2cpp_metadata.json` (makine-okur sema), `il2cpp_stringliterals.txt`
- Tip tespiti: class/struct/enum/interface (bitfield + TypeAttributes),
  static/virtual/abstract/private-protected-internal modifier'lar
- Unity surum tahmini (metadata surumu -> yaklasik Unity araligi, raporda
  "yaklasik" olarak isaretli)
- Metadata-yalniz siniri KALDIRILDI: binary eslestirmesi (1.13) ile
  Il2CppType tablosu ve metod native adresleri de cozuluyor

### 1.10 ART konteynerleri: OAT / VDEX / CDEX (YENI)
- `--file base.vdex|base.odex|base.oat`: temel header dogrulamasi
- VDEX 006/010/019/021 header struct'lari vdexExtractor'dan birebir;
  API eslemesi kaynaktan dogrulandi (006->API 26, 010->API 27,
  019->API 28, 021->API 29)
- OAT: magic `art\n` + surum + checksum + dex_file_count + executable_offset
  + key/value store ornekleri (dex2oat-cmdline, image-location)
- Taninmayan surumlerde uyari; sessiz tahmin yok

### 1.11 JSON ciktilari (YENI)
- `--json` bayragi: canli modda `names.json` + `objects.json`; statik modda
  `analysis_report.json`; IL2CPP ciktilarinda `il2cpp_metadata.json`
- serve modunda her yukleme icin `_report.json` otomatik yazilir

### 1.13 IL2CPP binary eslestirmesi (YENI - Il2CppDumper'in "ikinci yarisi", TAMAMLANDI)
- `--file GameAssembly.dll --metadata global-metadata.dat` veya
  `--file libil2cpp.so --metadata global-metadata.dat`; APK icinde metadata +
  libil2cpp.so birlikte ise OTOMATIK es cifti taramasi (ABI onceligi:
  arm64-v8a > x86_64 > armeabi-v7a)
- `src/il2cpp/Il2CppBinary.cpp`: Il2CppCodeGenModule taramasi (v24.1+,
  moduleName string xref + methodPointerCount/methodPointers dogrulama) ve
  flat methodPointers taramasi (v16-24.0, count == metod sayisi + exec orani)
- Metod native adresleri: token RID -> methodPointers[RID-1]; RVA/VA/dosya
  ofseti + ELF relocation etiketi
- MetadataRegistration taramasi: typesCount orneklem dogrulamasi +
  fieldOffsetsCount == tip sayisi GUCKU kontrolu
- Il2CppType isim cozumu: CLASS/VALUETYPE (Il2CppClass name/namespaze,
  v<23'te klassIndex), GENERICINST (Il2CppGenericClass + Il2CppGenericInst
  argumanlari), SZARRAY/PTR/ARRAY/BYREF/VAR/MVAR - rekursif, dongu korumali
- Alan ofsetleri (fieldOffsets) dump.cs yorumlarinda ("// 0x10")
- ELF PIE destegi: SHT_RELA RELATIVE relocation'lari (x86-64 8, AArch64
  1027, RISC-V 3); PE tarafinda ImageBase normalizasyonu
- Ciktilar: `il2cpp_dump.cs` (gercek tipler + "// RVA: .. Offset: .. VA: .."),
  `il2cpp_methodaddresses.txt`, `il2cpp_script.json` (Il2CppDumper uyumlu
  ScriptMethod semasi), `il2cpp_binary_report.txt`

### 1.14 Live hex/byte/code/binary/AOB view-editor-save (YENI - TAMAMLANDI)
- `src/hex/HexTool.cpp` + `--hex` CLI modu; kaynak: dosya (--file) veya
  canli proses modul bolgesi (--process/--pid [--module])
- View: `--hex-view` (offset + hex + ASCII klasik tablo), `--hex-code`
  (x86/x64 kaba ayristirici: uzunluk cozumu tum yaygin opkodlar icin dogru,
  rip-goreli hedef VA, call/jmp/jcc hedefleri; bilinmeyende db fallback -
  tam ayristirici DEGIL, belgeli sinir), `--hex-binary` (bit duzeyi)
- Search: `--hex-search` jokerli AOB ("48 8B 05 ?? ?? ?? ??"), bosluksuz
  hex ("488B05????????"), "text:..." ASCII; memchr-cephe hizli tarama
- Edit: `--hex-patch "0x1000=90 E9"` (coklu, ';' ile) - undo yigini, aralik
  disi reddi; canli modda `--hex-live` ile IMemoryReader::Write uygulanir
- Save: `--hex-save <dosya>` yamali kopyayi YENI dosyaya yazar (orijinal
  korunur); yamalar kaydedilmeden kalirsa arac uyari verir
- ONEMLI NOTLAR: canli yama yalnizca sahibi olunan/analiz yetkili tek
  oyunculu hedefler icin; KernelReader yazmayi desteklemez (read-only)

### 1.15 Dokumanlar
- `README.md` (DISCLAIMER dahil), `docs/KERNEL.md`, `docs/REFERENCES.md`
  (9 referans aracin karsilastirmali incelemesi + 13. bolum uc-arac parite
tablosu), `docs/ALGORITHM.md`,
  `docs/ONLINE.md` (online analiz sistemi), `docs/IL2CPP.md` (IL2CPP/ART
  modulleri), bu dokuman

### 1.16 Yeni arama/cikarma veri tipleri (bu donem eklendi)

PE tarafina (src/core/PEFile.*) 7 yeni veri tipi eklendi:
- **Debug directory + CodeView (RSDS/NB10/NB11/MISC)**: `DebugDirectory()` -
  PDB yolu, GUID, age. Unity/UE player ornekleyicisinde tam dogrulandi
  (ROB_RUN.exe: WindowsPlayer_player_Master_il2cpp_x64.pdb, GUID + age +
  "Unity (IL2CPP)" guclu motor tespiti PDB yoluyla).
- **Import tablosu (IAT)**: `Imports()` - DLL listesi + fonksiyon adlari
  (OriginalFirstThunk/FirstThunk, ordinal destegi; cap 256 DLL / 128 fn).
  Anti-cheat/motor/gfx DLL tespiti buradan beslenir.
- **Resource: VS_VERSIONINFO**: `VersionResource()` - FileVersion/
  ProductVersion (VS_FIXEDFILEINFO) + CompanyName/ProductName/
  FileDescription/InternalName/OriginalFilename/LegalCopyright.
- **Rich Header**: `RichHeader()` - MSVC toolchain parmak izi (DanS/Rich
  XOR; compiler/linker prodId+build+count).
- **TLS callbacks**: `TlsCallbacks()` - main-oncesi calisan callback'ler
  (anti-tamper gostergesi), bolum adi cozumlu.
- **Bolum entropisi**: `SectionEntropy()` - Shannon entropisi (1 MiB
  orneklem); >= 7.2 "paketlenmis suphe" + packer ipucu (VMProtect/Themida/
  UPX/ASPack/Enigma bolum adlari).
- **MSVC RTTI taramasi**: `RttiClasses()` - tek gecisli COL->TypeDescriptor
  esleştirme (x64 self-referans dogrulamali), demangle (class/struct/enum/
  const/template + namespace ters cevirme), CHD numBases. UE olmayan C++
  oyunlarinda sinif isimleri + vtable baglantisi (colRva) saglar.

Dosya formati tarafina yeni tip eklendi:
- **Mach-O 32/64 + FAT universal binary** (yeni modul `src/file/MachO.*`):
  MH_MAGIC(_64)/MH_CIGAM(64) LE+BE, FAT (CafeBabe, Java class ayrimi),
  LC_SEGMENT(64)+bolumler, LC_UUID, LC_MAIN entry, LC_BUILD_VERSION
  (platform/minos/sdk/tool'lar), LC_VERSION_MIN_*, LC_SOURCE_VERSION,
  LC_SYMTAB sayimi, LC_DYLD_INFO(_ONLY) export trie yuruyusu (visited-set
  dongu korumali), LC_LOAD/WEAK/REEXPORT_DYLIB kutuphaneler.
  iOS/macOS oyunlari artik statik taramaya dahil.

UniFormat genisletmesi (src/file/UniFormat.*):
- **ELF dynamic symbols (.dynsym/.dynstr)**: `ParseElfDynSym()` - GLOBAL/
  WEAK FUNC/OBJECT sembolleri (JNI_OnLoad + il2cpp_* API ipuclari dahil).
- **DEX string havuzu (MUTF-8)**: `ParseDexStrings()` - uleb128 +
  string_data_item cozumu, paket/motor ipuclari (com.*, unity, unreal,
  epicgames, tencent...). Surrogate ciftleri birlestirilir.
- `SniffMagic` artik "macho" / "macho-fat" donduruyor.

StaticAnalyzer genisletmesi (src/file/StaticAnalyzer.*):
- **UTF-16LE genel string taramasi**: `ExtractWideStrings()` - Windows
  genis stringleri (api-ms-win-* dll'leri, gun/ay adlari, tarih formatlari
  ROB_RUN.exe'de dogrulandi); kalite filtresi (%70 alfanumerik).
- **Guvenlik/koruma ipuclari**: EasyAntiCheat/BattlEye/Vanguard/Steam/
  Denuvo/EOS + DirectX/Vulkan/OpenGL + packer bolumleri tespiti.
- PDB yolundan guclu motor tespiti (dusuk-guven string tahminini ezer).
- `BuildJsonReport` yeni alanlar: pdb, imports, versionResource,
  richHeader, tlsCallbacks, sectionEntropy, rtti, wideStrings, elfDynsym,
  dexStrings, macho (summary/fatArchs/exports/linkedLibs), securityHints.

HexTool arama tipi genislemesi (src/hex/HexTool.cpp):
- `text16:...` - UTF-16LE sorgu (Unity prefs anahtarlari / UE config
  yollari icin); "text:" ASCII davranisi degismedi.

Performans duzeltmesi: VS_VERSIONINFO UTF-16 anahtar aramasi O(n^2)'den
tek gecise indirildi (Dumper-7.dll 1.5 MB analiz: kilitlenme -> <40 ms).

Dogrulama (sentetik + gercek ornekleyiciler):
- ROB_RUN.exe (Unity 6000.3.18 player): PDB+GUID, import, VERSIONINFO,
  Rich, entropy, RTTI (std::exception hiyerarsisi), UTF-16 stringler.
- Dumper-7.dll: 14 DLL import, wide string; analiz < 40 ms.
- testlib.so (g++): 9 dynsym + JNI_OnLoad ipucu.
- test_macho64 / test_macho_fat (python uretici): segment/bolum/UUID/
  build/main/source/dylib + export trie (3 export) + FAT 2 arch.
- test_classes.dex: 6 string, com/unity ipuclari.
- test_rtti.exe (python uretici): 2 RTTI sinifi + RSDS PDB okuma.

---

## 2. YAPILACAKLAR (yol haritasi)

### 2.1 Kisa vade
- [x] OAT/VDex dosyalari icin temel header parse - **TAMAMLANDI** (bkz. 1.10)
- [x] IL2CPP modu: global-metadata.dat parse (Il2CppDumper hizasi,
      metadata-yalniz; docs/REFERENCES.md 12.1) - **TAMAMLANDI** (bkz. 1.9)
- [x] JSON cikti secenekleri (dump formatlari icin makine-okur semalar)
      - **TAMAMLANDI** (bkz. 1.11)
- [x] `--serve` icin eszamanli yuklemeler (thread havuzu) - **TAMAMLANDI**
- [x] IL2CPP binary eslestirmesi: libil2cpp.so/GameAssembly.dll icinden
      Il2CppType tablosu + CodeRegistration/MetadataRegistration taramasi
      (metod native adresleri, tam dump.cs) - Il2CppDumper'in ikinci yari
      - **TAMAMLANDI** (bkz. 1.13)
- [ ] AXML manifest cozumlemesini gercek AOSP agac modeliyle genisletmek
      (su an guvenli fallback + temel alanlar)
- [ ] Dummy DLL uretimi (Il2CppDumper hizasi; yonlendirilebilir C#
      assembly yazici gerektirir - orta vadeye tasindi)
- [ ] metadataUsages string->adres baglamasi (yalnizca metadata v<27
      hedeflerinde gereklidir; v27+ bu mekanizmayi kaldirdi)
- [ ] Hex modu icin tarayici tabanli GUI (--serve entegrasyonu; mevcut
      --hex CLI tam calisir durumda)

### 2.2 Orta vade
- [ ] Dummy DLL uretimi (Il2CppDumper hizasi; C# assembly yazici)
- [ ] GWorld/GEngine/GInstance icin patternsleuth-tipi sekil dogrulayicilar
      (REFERENCES 12.3)
- [ ] CDO (ClassDefaultObject) deger cikarimi -> SDK'ya varsayilan degerler
      (REFERENCES 12.4)
- [ ] ELF canli destek: Android emulatore GDB/ptrace benzeri okuma katmani
- [ ] Blueprint yuzey taramasi (UBlueprintGeneratedClass fonksiyon bayraklari)
      (REFERENCES 12.5)
- [ ] UE surum tablosunu 5.4+ icin genisletmek (yalnizca veri ekleme,
      mimari degismez)

### 2.3 Uzun vade
- [ ] Kapali FName havuzlari icin sifir cozme/anahtardan cozme arastirmasi
- [ ] Surucu imzali yukleme paketi (kernel modulu icin sertifikali akis)
- [ ] Paket (.pak/utoc/ucas) icerik listeleme (FModel hizasi; asset acma
      kapsam disi kalir)

---

## 3. Yasal / kullanim notlari (onemli notlar - tekrar)

- Yalnizca offline analiz, tek oyunculu modding, interop ve motor arastirmasi.
- Cok oyunculu oyunlarda hile amacli kullanim kapsam disidir; anti-cheat
  tespiti hesaba katilmistir (raporda bilgi amacli gosterilir).
- Kernel modu yalnizca sahibi oldugunuz makinede, sizin derlediginiz surucu ile.
- Tum ciktilar ("dump") yalnizca sahibi olunan/yetkili yazilim icin uygulanir.
