# UnrealDumperX

Windows icin Unreal Engine dump/SDK otomasyon araci - ill2cpp2dumper, Dumper-7,
UE5CEDumper, UEDumper, patternsleuth ve GSpots'un birlesik ozellik seti.

- **Motor destegi**: UE4 4.20-4.27 ve UE5 5.0-5.3
- **Dil/derleyici**: C++20, MSVC (VS2022) veya MinGW-w64 / clang-cl
- **Cikti**: Names.txt, Objects.txt, SDK (`_classes.h` / `_struct.h`), offsets.txt,
  signatures.txt, `<Oyun>_sigs.txt`, funcs.txt, vtable_funcs.txt, games.ini

## Moduller

| # | Modul | Nerede |
|---|-------|--------|
| 1 | Core Dumping (isim havuzu, nesne yuruyusu, SDK uretimi) | `fname.cpp`, `finder.cpp`, `classparse.cpp`, `sdkgen.cpp` |
| 2 | Signature System (ana + 16 bayt genisletilmis imza, games.ini yeniden kullanim) | `pattern.cpp` |
| 3 | Configuration (games.ini, yerlesik profil, surum dizisi tespiti) | `ini.cpp`, `version.cpp` |
| 4 | UE5 Support (FNamePool 2-bayt baslik, 64KB blok, FName Number +0x4) | `fname.cpp`, `ue_types.h` |
| 5 | UX (renkli log, ilerleme cubuklari, 7 asamali pipeline) | `log.h`, `main.cpp` |
| 6 | VTable Function Resolver (parmak izi + thunk + oylama) | `vtable.cpp` |
| 7 | Runtime Offset Discovery (<=400 nesne oylamasi, %65 esik) | `offsets.cpp` |
| 8 | Kernel Driver Support (IOCTL koprusu, yukleyici) | `driver.h/cpp`, `driver/udxdrv.c` |

## Onemli Notlar -> Kod Karsiliklari

| Not | Aciklama | Kod |
|-----|----------|-----|
| 1 | UE5 FNamePool: 2 bayt baslik, degisken uzunluk isim, 64KB blok | `fname.cpp` (`decodeEntryAt`, `drainPool`) |
| 2 | FName::Number: UE5 `+0x4`, UE4 `-0x4` (otomatik sonda) | `offsets.cpp` (`probeFNameNumberDelta`) |
| 3 | ANSICHAR / WIDECHAR ayrimi + UTF-8 normalizasyonu | `fname.cpp` (`decodeEntryAt` wide dal) |
| 4 | minIndex korumasi: vtable slot 0-1 (D0/D1) reddedilir | `vtable.cpp` (`kMinVtableIndex`) |
| 5 | Alan basina %65 guven esigi | `offsets.cpp` (`kConfidenceThreshold`) |
| 6 | games.ini yetkili degerleri asla ezilmez | `ini.cpp` (satir korumali kayit) + `Offsets::applyIni` |
| 7 | En fazla 400 canli nesne ile oylama | `offsets.cpp` (`kMaxProbeObjects`) |
| 8 | En fazla 4 aday parmak izi | `vtable.cpp` (`kMaxFingerprints`) |
| 9 | Parmak izi basarisizsa pattern-seeded yedek | `vtable.cpp` (`resolveByPatternSeed`) |
| 10 | Thunk/adjustor cozumu: JMP rel8/rel32, SUB/ADD RCX, JMP [RIP+rel32] | `vtable.cpp` (`unchain`) |
| 11 | Post-thunk oylama (bagimsiz vtable'lar arasi cogunluk) | `vtable.cpp` (`resolveByFingerprints`) |
| 12 | Ana imza + 16 bayt genisletilmis imza cifti | `pattern.cpp` (`buildExtendedSignature`) |
| 13 | Gomulu surum dizisi tespiti ("Release-4.27" vb.) | `version.cpp` (`detectVersion`) |
| 14 | GSpots tarzi otomatik GObjects/GNames/GWorld + katı dogrulama | `finder.cpp` |
| 15 | SDK: UnknownData_XX padding, bitfield `: N`, paket basina dosyalar | `sdkgen.cpp` |
| 16 | funcs.txt kaynak etiketleri: `[vtable>pattern]` / `[vtable]` / `[pattern]` | `vtable.cpp`, `outputs.cpp` |

## Derleme

```bat
:: MSVC (VS2022 x64)
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

```bash
# MinGW-w64
cmake -B build -G Ninja
cmake --build build
```

## Kullanim

```bat
UnrealDumperX.exe --list
UnrealDumperX.exe --process Game-Win64-Shipping.exe
UnrealDumperX.exe --pid 1234 --out dump --verbose
UnrealDumperX.exe --process Game.exe --driver-load C:\udx\UnrealDumperX.sys
UnrealDumperX.exe --process Game.exe --names-only
```

Ilk calistirma her seyi otomatik bulur ve imzalari games.ini'ye yazar; oyun
guncellendiginde ayni komut imza ciftlerini yeniden cozer (yeni imza gerekirse
tek satir guncelleme yeterli).

## Kernel driver

`driver/udxdrv.c` referans kopru (IOCTL_UdX_READ 0x222000 / IOCTL_UdX_BASE
0x222004). Yukleme icin yonetici + testsigning gerekir:

```bat
bcdedit /set testsigning on
UnrealDumperX.exe --process Game.exe --driver-load C:\udx\UnrealDumperX.sys
```

Driver yuklu degilken arac ReadProcessMemory ile calisir; driver varken
basarisiz sayfa okumalari otomatik olarak kopruye dusenir.

## Yasal not

Yalnizca kendi uygulamalarin, CTF ortamlari veya acik izinli arastirma
hedefleri icin kullanin.
