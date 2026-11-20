# 1b — Gerçek UE5 Oyun Dumpu: CLI Köprü SDK Üretim Testi

Bu doküman, **1b görevinin** sonuçlarını raporlar: internette otomatik
bulunup indirilen **gerçek UE5 oyunu** üzerinde DumperPro CLI hattının uçtan
uca test edilmesi, bu testte yakalanan **2 gerçek hata** ve düzeltmeleri,
soğuk (cold) modül görüntüsünün temel sınırları ve tam SDK için Windows
tarafı akışı.

Test tarihi: 2026-11-20 · Ortam: Linux sandbox (DumperPro Linux derlemesi,
gerçek `leechcore.so` ile cihaz yolu ayrıca doğrulandı — bkz. 1a).

---

## 1. Test materyali (internetten otomatik bulundu + indirildi)

| Hedef | Kaynak | Boyut | Motor | Not |
|---|---|---|---|---|
| **The Document Demon** (kingpoki) | [itch.io](https://kingpoki.itch.io/the-document-demon) — 2023 Epic MegaJam | 218 MB zip | **UE 5.1** (exe içi `Release-5.1` marker + DumperPro tespiti) | `FutureFaxOperator-Win64-Shipping.exe` (103 MB, PE32+ x64, 9 bölüm) |
| **Fling** (Sapix) | [itch.io](https://sapiix.itch.io/fling) | 133 MB zip | UE 4.2x (paylaşılan build) | `UnrealGame-Win64-Shipping.exe` (84 MB) — karşılaştırma hedefi |

İndirme akışı itch.io'nun halka açık indirme sayfası üzerinden
csrf-token + presigned CDN URL (R2 mirror) ile otomatikleştirildi; her iki
zip de `PK\x03\x04` ile doğrulandı. Materyal `research/` altındadır
(gitignore — repoya girmez).

---

## 2. Gerçek UE5.1 shipping exe'sinde CLI testi — sonuçlar

```
$ DumperPro --file FutureFaxOperator-Win64-Shipping.exe --out out-file

[+] parsed ...: image base 0x000140000000, size 106.62 MB, 9 sections
[+] Detected UE version: UE5.1 (UE5 mode)          ← GERÇEK tespit
[*] Offsets profile: builtin [UE5.1]
[*] Searching GNames...
[D] 40+ FNamePool adayı değerlendirildi...
[X] GNames: no valid candidate (sigs + struct scan failed)
```

Doğrulananlar:

1. **PE parse**: 103 MB gerçek shipping ikilisi, 9 bölüm, image base
   `0x140000000` ✔
2. **Motor tespiti**: exe içi marker'dan **UE5.1** — birebir doğru ✔
3. **Offsets profili**: yerleşik UE5.1 profili yüklendi ✔
4. **İmza + heuristic tarama**: veri bölümlerinde 40+ FNamePool şeklinde
   aday değerlendirildi, hepsi **gerçek "None" çapası ile reddedildi** ✔
   (bkz. bölüm 3)
5. **Cihaz yolu** (aynı modül → flat dump → `--device "file://..."`, gerçek
   `leechcore.so`): pencere paMax'a kısıtlı, tarama temiz ✔

## 3. Testte yakalanan 2 gerçek hata ve düzeltmeleri

### 3.1 `GNamesVA` kablolama hatası (SigFinder → NameArray)

**Belirti**: heuristic tarama geçerli bir FNamePool adayı bulup
`GNames @ 0x1457DC078` yazdırdıktan sonra parse
`"no GNames address (GNamesVA unresolved)"` ile ölüyor.

**Kök neden**: `FindGNames()`/`FindGObjects()` bulunan adayı **sadece
döndürüyordu**; `NameArray::TryInit` / `ObjectArray::TryInit` ise adresi
`off.GNamesVA` / `off.GObjectsVA`'dan okuyordu. Bulunan aday asla offsets
yapısına yazılmıyordu (yalnızca `games.ini` ile verilirse çalışıyordu).

**Düzeltme**: `FindGNames`/`FindGObjects` artık çözülen VA'yı
`off_.GNamesVA`/`off_.GObjectsVA`'ya yazan ince sarmalayıcılar
(`FindGNamesImpl`/`FindGObjectsImpl`). (`src/sig/SigFinder.cpp`)

### 3.2 FNamePool yanlış-pozitif doğrulaması (çöp isimler)

**Belirti**: 3.1 düzeltildikten sonra soğuk exe'de bir aday "VALID" geçti ve
**62.207 "isim"** üretildi — tamamı CJK bozukluğu (UTF-16 yanlış okuması
çöp veri).

**Kök nedenler**:
- `WalkEntriesLocal` **wide (UTF-16) girişlerin yazdırılabilirliğini hiç
  kontrol etmiyordu** — çöp başlıkların yarısı wide bitli olduğundan
  `bad` sayacı hiç artmıyordu.
- Sıfır-dolgulu `.data` bölgeleri `len=0` boş girişler zinciri üretip
  `bad==0` ile temiz yürüyordu (`kMinNamesValid=16` sonradan aşıldı).
- Soğuk (derlenmiş) exe'de **gerçek FNamePool boştur** (CurrentBlock=0,
  Blocks=null; runtime durumdur) → statik dosyada geçen HER aday tanım
  gereği yanlış pozitiftir.

**Düzeltme** (`src/ue/NameArray.cpp`):
1. **"None" çapası**: gerçek UE havuzlarında FName index 0 her zaman
   `"None"`'dur. `ProbeFirstBlock` artık ilk girişi çözüp ANSI `None`
   değilse adayı reddeder — çöp veri bu çapayı asla üretemez.
2. **strictWide**: probe modunda wide girişler de yazdırılabilirlik
   kontrolüne girer (ilk blokta çekirdek isimler yalnızca ANSI'dir).
3. **Kısmi çıktı** (`main.cpp`): GObjects bulunamazsa bile Names.txt +
   names.json + signature dosyaları yazılıp net yönlendirme verilir
   (eski davranış: hiçbir çıktı yok).

### 3.3 Doğrulama: yanlış pozitif artık reddediliyor

Düzeltme sonrası aynı exe:

```
[D] GNames candidate @ 0x... rejected: first entry is not ANSI 'None' (pool anchor)
[X] GNames: no valid candidate (sigs + struct scan failed)
```

Soğuk görüntü için **dürüst sonuç**: GNames/GObjects runtime verisidir;
statik dosyada bulunması beklenmez. Regresyon: sentetik 16 MB cihaz
testi + harness ALL-PASS (1a) etkilenmedi.

---

## 4. Temel sınır: neden "tam SDK" soğuk modülden çıkamaz

| Yapı | Modül dosyasında | Canlı süreçte |
|---|---|---|
| Kod/bölümler, vtable'lar, imports | ✔ var | ✔ var |
| `FNamePool` yapısı (global) | ✔ (adres bulunur) | ✔ |
| FNamePool blok içerikleri | ✖ (runtime heap) | ✔ |
| `GUObjectArray` global | ✔ (adres bulunur) | ✔ |
| UObject dizisi (heap chunk'ları) | ✖ | ✔ |
| UObject graph (Class/Name/Outer) | ✖ | ✔ |

**SDK üretimi UObject graph'ı yürür** → canlı süreç (`--process`/`--pid`)
veya tam RAM dump (`--device "file://ram.bin"`) gerekir. Ayrıca Fling
testindeki gerçek bulgu: paylaşılan-build shipping exe'lerinde motor
marker'ı bulunmayabilir ("UE version not detected") — sürüm bu durumda
pak içeriğinden (.utoc IoStore → 4.26+) çıkarılabilir.

---

## 5. Tam SDK akışı (Windows tarafı, 1b'nin canlı ayağı)

`scripts/windows/1b-live-dump.ps1` hazırlandı; oyunu **kendi Windows
makinenizde** çalıştırıp süreç moduyla tam SDK üretir:

```powershell
# Oyunu başlatın (ana menü yeterli), sonra:
powershell -ExecutionPolicy Bypass -File scripts\windows\1b-live-dump.ps1 `
    -Process FutureFaxOperator-Win64-Shipping.exe -Out C:\out\demon-sdk
```

Script: süreç teyidi → `DumperPro.exe --process ... --out ...` → çıktı
denetimi (Names.txt / Objects.txt / offsets.txt / SDK\*.h / signatures.txt)
→ PASS/FAIL özeti. Beklenen: `Names parsed`, `Objects parsed`,
`SDK generated` satırları; SDK klasöründe Dumper-7 benzeri başlıklar.

> Not: 1a test kitindeki FPGA/RAM-dump yolu (`docs/1A-WINDOWS-DEVICE-TEST.md`
> §4) tam RAM dump tercih edilirse kullanılır.

---

## 6. Sonuç kaydı (sandbox içinde kapananlar)

- [x] Gerçek UE5 oyunu internetten otomatik bulundu + indirildi (218 MB)
- [x] Gerçek UE5.1 shipping exe: PE parse + motor tespiti (UE5.1) ✔
- [x] Gerçek UE4 (Fling) karşılaştırması: paylaşılan build marker bulgusu ✔
- [x] Hata 1 düzeltildi: aday→offsets kablolaması (SigFinder) ✔
- [x] Hata 2 düzeltildi: FNamePool yanlış-pozitif doğrulaması ("None" çapası) ✔
- [x] Kısmi çıktı iyileştirmesi: GNames bulunduysa Names.txt yazılır ✔
- [x] Cihaz yolu regresyonu: sentetik test + harness ALL-PASS ✔
- [ ] **Canlı ayağı (kullanıcı)**: `1b-live-dump.ps1` ile gerçek süreçte
      GNames+GObjects+SDK (Windows gerektirir)
- [ ] (Opsiyonel ileri) Orbi-Puss (UE 5.5/5.6) ile UE5.5 profili testi
