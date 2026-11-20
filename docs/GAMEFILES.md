# Ortak Oyun Dosyalari (pak/utoc/ucas/uasset/macho)

> Tum oyunlar icin genel dosya formatlarinin arastirma ve dogrulama notlari.
> Uygulama: `src/lib/analysis/gamefiles.ts`, tespit: `src/lib/analysis/detect.ts`.

## 1. Kapsam kararlarini

| Format | Kaynak/teyit | Destek |
|---|---|---|
| UE .pak (v1-v11) | FPakInfo footer layout; magic 0x5A6F12E1; Dumper-7 SDKGenerator pak yapisalari (research/dumper7) | footer + surum + index offset/size + encrypted bayragi + compression methods (v8+ 5x32B); primary index kayitlari (isim, offset, boyut, yontem, SHA-1) |
| UE .utoc/.ucas | FIoStoreTocResourceHeader: "UTOC" magic, v1-v5; toc entry 20B (ChunkId 12 + Offset u32 + Size u32); comp isimleri entries SONRASINDA | header + kayitlar + chunk tipleri + compression isimleri |
| UE .uasset/.umap | PackageFileSummary: magic 0x9E2A83C1; LegacyFileVersion (-7 UE4, -8 UE5 hizasi) | ozet alanlari + isim tablosu (i16 len, negatif = UTF-16LE) |
| Mach-O / fat | mach-o/loader.h: 0xFEEDFACF (thin 64), 0xCAFEBABE/BF (fat, BE degerler) | fat mimari listesi; thin: LC_SEGMENT/64, LC_MAIN, LC_LOAD_DYLIB; iOS ipa icindeki libil2cpp tespiti icin temel |
| .obb / .ipa | ZIP tabanli | mevcut ZIP/APK hatti zaten listeler (zipapk.ts); not olarak isaretlenir |

## 2. Dogrulanmus alan ofsetleri

- **FPakInfo** (footer): [EncryptionKeyGuid 16B v9+][bEncryptedIndex 1B]
  [Magic 4B][Version 4B][IndexOffset 8B][IndexSize 8B][IndexHash 20B]
  [CompressionMethods 5x32B v8+]. bEncryptedIndex: v9+ magic-17, v3-8 magic-1.
- **Pak entry (v<10)**: path FString, offset u64, size u64,
  compressionBlockSize u32, compMethodIndex u32, hash 20B.
  v10+: blockSize yok, compIndex bit alani (0x3f mask), offsetler
  IndexOffset'e gore relative olabilir (iki yorum denenir).
- **Utoc header**: Magic, Version, TocHeaderSize(220), TocEntryCount,
  TocCompressedBlockEntryCount, TocCompressedBlockEntrySize, PartitionSize(u32),
  PartitionCount, CompressionMethodNameCount, CompressionBlockSize...
- **Uasset ozet**: magic, LegacyFileVersion, LegacyUE3, FileVersionUE4,
  [FileVersionUE5 (-8 ise)], Licensee, CustomVersions(count + 20B kayit),
  TotalHeaderSize, FolderName(FString), PackageFlags, NameCount, NameOffset,
  [UE5 LocalizationId], GatherableTextCount/Offset (UE4.17+).
- **Mach-O 64 header** = 32 B (magic, cputype, cpusub, filetype, ncmds,
  sizeofcmds, flags, RESERVED u32). section_64 = 80 B (3 reserved alan).

## 3. Bilinen sinirlar

- Oodle/LZMA sikistirilmiş pak kayitlari ACILMAZ (liste amacli);
  zlib kayitlari icin de boyut bilgisi vermekle yetinildi.
- AES sifreli pak index listelenemez (surum + bayrak raporlanir).
- v10/11 path-hash index ve directory index tam cozulmedi; isimsiz
  kayitlar "hash-only" olarak listelenir.
- uasset export/import sayilari surume gore kayan alanlarda oldugundan
  best-effort'tur (isim tablosu kesindir).
- .ucas veri konteynerinde magic yoktur; .utoc ile eslenir.
