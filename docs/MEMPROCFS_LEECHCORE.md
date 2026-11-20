# MemProcFS + LeechCore Ozellik Entegrasyonu

> Arastirma + tasarim belgesi. Kaynaklar `research/leechcore` ve
> `research/memprocfs` altinda tam kaynak kodu olarak indirildi (codeload).

## 1. Arastirma ozeti

| Proje | Lisans | Bize dokunan ozellikler |
|---|---|---|
| LeechCore (ufrisk) | LGPL-3.0 | Cihaz soyutlamasi: `LcCreate` + szDevice stringleri (`file://`, `dump://`, `memmap://`, `raw://`, `pmem`, `fpga`...), `LcRead/LcWrite/LcReadScatter`, `LcMemMap_AddRange(pa, cb, paRemap)` (4KB hizali, 1M aralik), memmap.c: `%016llx-%016llx -> %016llx` esleme formati |
| MemProcFS (ufrisk) | LGPL-3.0 (vmm) | VMM API: `VMMDLL_Map_GetModule` (vaBase, cbImageSize, uszText), `VMMDLL_Map_GetVad` (vaStart/vaEnd/Protection/State/Type), `VMMDLL_MemReadScatter`, bellekten PE kurtarma (modul memdump), bellek arama |

## 2. Neden dogrudan linkleme degil, TS portu?

- LeechCore/MemProcFS Windows surucu + DMA donanim (fpga/usb3380) odaklidir;
  Linux sunucuda bu cihazlar kullanilamaz.
- Ancak DOSYA-TEMelli cihazlar (minidump, kernel crashdump, raw+memmap)
  tamamen platform bagimsizdir - bunlar TS olarak birebir port edildi.
- Lisans temizligi: birebir kod kopyasi degil, API SEMANTIGI korunarak
  sifirdan TS implementasyonu (crash dump / minidump spec + memory map
  format belgelerinden).

## 3. Uygulanan katmanlar (`src/lib/analysis/mem.ts`)

### 3.1 LcDevice (LeechCore `device_file.c` mantigi)
- `openMiniDump(buf)`: MINIDUMP_HEADER "MDMP" + stream directory;
  Memory64ListStream(9) araliklari VA->dosya eslemesi olur.
- `openRawWithMemmap(raw, mapText)`: `memmap.txt` satirlari
  `start-end[:label]` veya `start-end->remap` (LeechCore verbose formati
  dahil); remap = dosya icinde veri offseti.
- `read(va, len)` / `readScatter(addrs[], len)` / `write(va, data)` /
  `coverage(vaStart, vaEnd)`.

### 3.2 Minidump parser (Microsoft spec)
- Stream'ler: ModuleList(4, 108B kayit + MINIDUMP_STRING utf16 isim),
  Memory64List(9, BaseRva MUTLAKTIR), MemoryInfoList(16, 48B kayit ->
  VAD benzeri bolge tablosu: State/Protect/Type), SystemInfo(7, arch
  @+0 u16, major @+10 u32, platform @+22), Exception(6, kod @+8,
  adres @+24).
- Kernel crashdump "PAGE"+"DU64" tespiti + fiziksel run listesi (0x88).

### 3.3 MemProcFS ozellikleri
- **Modul haritasi**: base/size/timestamp + kapsama yuzdesi; kurtarilabilir
  ise panel butonu ile "Dump & Analiz".
- **PE kurtarma** (`recoverModulePe`): bellek gorunumlu dump uretir -
  bolum raw ofsetleri = VA ofsetleri, checksum sifirlanir, `>= %50` bellek
  kapsamasi sarti. Kurtarilan dosya otomatik olarak yeniden analiz edilir
  (kind=pe -> fonksiyon tablosu + RTTI + struct/enum hatti tam calisir).
- **Bellek arama** (`searchMemory`): tum erisilebilir araliklarda AOB
  (?? joker), modul etiketli sonuclar.
- **VAD/bolge tablosu**: MemoryInfoList -> vaStart/vaEnd/protection/state/type.

## 4. API ve UI

| Yol | Is |
|---|---|
| POST /api/uploads/[id]/mem {action:"search", pattern} | bellek icinde AOB |
| POST /api/uploads/[id]/mem {action:"dump", base, size?, name?} | PE kurtar -> yeni yukleme + tam analiz |

Panel "Bellek" sekmesi: ozet kartlari, modul tablosu (kapsama progress +
Dump & Analiz), bolge tablosu, AOB arama. Cift eslestirme: raw dump ile
ayni oturumda .memmap/.map yuklenirse otomatik baglanir (iki yonlu).

## 5. Sinirlar

- EPROCESS/FNamePool gibi kernel yapisal taramalar yok (MemProcFS'in
  tamWindows-temel taramasi DMA bellek gerektirir).
- Kernel crashdump'ta tam veri okuma icin memmap eslemesi sart (bitmapsiz
  FULL dump haric - ileride eklenebilir).
- readScatter sayfa bazli (0x1000) degil, aralik bazli; performans icin
  gerekirse sayfa bazina gecilecek.
