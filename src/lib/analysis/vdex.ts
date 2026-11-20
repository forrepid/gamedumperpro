// ----------------------------------------------------------------------------
// DumperPro Online - ART VDEX / OAT gomulu DEX cikarici (saf TypeScript, depsiz)
//
// Kaynak/teyit: anestisb/vdexExtractor (src/vdex/vdex_006.h/.c, vdex_019.h/.c,
// vdex_021.h/.c) ve AOSP art/runtime/vdex_file.h + art/runtime/oat.h.
// Tum tamsayilar little-endian (LE).
//
// VDEX duzenleri:
//   006/010 (Android 8.x) - 24 bayt baslik:
//     magic[4]="vdex" | version[4]="006\0"/"010\0" | u32 numberOfDexFiles @8
//     u32 dexSize @12 | u32 verifierDepsSize @16 | u32 quickeningInfoSize @20
//     sonrasinda numDex * u32 location checksum; DexBegin = 24 + numDex*4,
//     DexEnd = DexBegin + dexSize. DEX'ler file_size zinciri ile ayrilir
//     (son DEX'in boyu bolum sonuna kadar kalan baytlardan alinir).
//   019 (Android 9) - 20 bayt baslik:
//     magic[4] | verifierDepsVersion[4]="019\0" | dexSectionVersion[4]
//     ("002\0" = dex bolumu var, "000\0" = yok) | u32 numberOfDexFiles @12
//     u32 verifierDepsSize @16 | sonrasinda numDex * u32 checksum.
//     dex bolumu varsa 12 bayt DexSectionHeader {dexSize, dexSharedDataSize,
//     quickeningInfoSize}; DexBegin = 20 + numDex*4 + 12.
//   021 (Android 10+) - 28 bayt baslik (019 + 2 alan):
//     u32 bootclasspathChecksumsSize @20 | u32 classLoaderContextSize @24
//     checksumlar @28; DexBegin = 28 + numDex*4 + 12.
//
// DEX zincir kurali: her DEX "dex\n" + "0xx\0" (035..039) ile baslar ve u32
// file_size degeri offset 32'dedir; sonraki DEX = onceki offset + file_size.
//
// OAT: "art\n" + "NNN\0" magic; OatHeader sabit on eki: magic@0, version@4,
// adler32@8, instructionSet@12, instructionSetFeatures@16, dexFileCount u32
// @20, executableOffset u32 @24. DEX'ler surume gore degisen bir ofsette
// oldugu icin pragmatik yol: ilk 1 MB taranir, ilk gecerli "dex\n" (035..039)
// basligindan itibaren file_size zinciri izlenir. Compact DEX ("cdex")
// cikarilmiyor; yalnizca tespit edilip nota dusuluyor.
//
// Guvence: modul hicbir zaman throw etmez; tum okumalar sinir denetimlidir.
// Bozuk ic yapida error alani set edilir ve bulunan kadar gecerli DEX doner.
// ----------------------------------------------------------------------------

/** Bir gomulu DEX girdisi (mutlak dosya ofseti + boy). */
export interface VdexDexEntry {
  index: number;
  offset: number;
  size: number;
}

/** VDEX ("vdex" magic) ayristirma sonucu. */
export interface VdexInfo {
  kind: "vdex";
  version: string; // "006" | "010" | "019" | "021" (basliktan okunan 3 hane)
  apiHint: string; // "API 28 (Android 9)" benzeri ipucu
  dexSectionVersion: string; // "000" | "002" | "" (006/010 duzeninde alan yok)
  dexCount: number; // basliktaki numberOfDexFiles
  dexes: VdexDexEntry[];
  notes: string[];
  error?: string;
}

/** OAT ("art\n" magic) pragmatik tarama sonucu. */
export interface OatInfo {
  kind: "oat";
  version: string; // "071".."131" benzeri basliktan okunan 3 hane
  apiHint: string;
  dexCount: number; // OatHeader.dex_file_count_ (@20)
  scannedCount: number; // zincir taramasinda bulunan DEX sayisi
  dexes: VdexDexEntry[];
  notes: string[];
  error?: string;
}

const MAX_DEX_COUNT = 4096; // numberOfDexFiles/dexFileCount dogrulama siniri
const MAX_DEX_SIZE = 512 * 1024 * 1024; // tek DEX icin 512 MB dogrulama siniri
const OAT_SCAN_LIMIT = 1024 * 1024; // OAT'te ilk 1 MB taranir
const DEX_HEADER_MIN = 40; // magic(8) + file_size@32 okumasi icin guvenli marj
const VDEX_SECTION_HEADER_SIZE = 12; // {dexSize, dexSharedDataSize, quickeningInfoSize}

const VDEX_API_HINTS: Record<string, string> = {
  "006": "API 26-27 (Android 8)",
  "010": "API 27 (Android 8.1)",
  "019": "API 28 (Android 9)",
  "021": "API 29+ (Android 10+)",
};

// ----------------------------------------------------------------------------
// ic yardimcilar (dissariya export edilmez)
// ----------------------------------------------------------------------------

/** Sinir denetimli u32 okuma; tasma/varsa undefined. */
function u32At(buf: Buffer, off: number): number | undefined {
  if (off < 0 || off + 4 > buf.length) return undefined;
  return buf.readUInt32LE(off);
}

function isAsciiDigit(b: number): boolean {
  return b >= 0x30 && b <= 0x39;
}

/**
 * "dex\n" + "0xx\0" (035..039) DEX basligi kontrolu.
 * offset 32'deki file_size alaninin okunabilmesini de garantiler (DEX_HEADER_MIN).
 */
function looksLikeDexHeader(buf: Buffer, off: number): boolean {
  if (off < 0 || off + 8 > buf.length) return false;
  // 'd' 'e' 'x' '\n'
  if (buf[off] !== 0x64 || buf[off + 1] !== 0x65 || buf[off + 2] !== 0x78 || buf[off + 3] !== 0x0a) return false;
  if (buf[off + 4] !== 0x30) return false; // '0'
  if (!isAsciiDigit(buf[off + 5]) || !isAsciiDigit(buf[off + 6])) return false;
  if (buf[off + 7] !== 0x00) return false; // NUL
  const ver2 = (buf[off + 5] - 0x30) * 10 + (buf[off + 6] - 0x30);
  return ver2 >= 35 && ver2 <= 39;
}

/**
 * OAT tarama adayi: magic + versiyon dogru VE file_size akla yatkin
 * (0 < fs <= 512MB ve off+fs dosya icinde). Boylece key-value deposu icindeki
 * rastgele "dex\n" dizilimleri aday sayilmaz.
 */
function plausibleDexEntry(buf: Buffer, off: number): boolean {
  if (!looksLikeDexHeader(buf, off)) return false;
  const fs = u32At(buf, off + 32);
  if (fs === undefined || fs === 0 || fs > MAX_DEX_SIZE) return false;
  return off + fs <= buf.length;
}

interface ChainOpts {
  /** true (VDEX): son DEX'in boyu bolum sonuna kadar kalan baytlardan alinir. */
  lastFromRemaining: boolean;
  /** true (VDEX): zincir beklenenden erken biterse error set et. */
  strict: boolean;
}

/**
 * file_size zincirini izleyerek DEX girdilerini toplar.
 * Her girdi icin: offset+size <= limit <= buf.length, magic "dex\n", size <= 512MB.
 * Hic throw etmez; bozuk noktada durur ve bulunan kadar girdi dondurur.
 */
function collectDexChain(
  buf: Buffer,
  start: number,
  endLimit: number,
  want: number,
  notes: string[],
  opts: ChainOpts,
): { dexes: VdexDexEntry[]; error?: string } {
  const dexes: VdexDexEntry[] = [];
  let error: string | undefined;
  let off = Math.max(0, start);
  const limit = Math.min(Math.max(off, endLimit), buf.length);

  for (let i = 0; i < want; i++) {
    if (off + DEX_HEADER_MIN > limit) {
      const msg = `DEX zinciri ${dexes.length} girdiden sonra bitti (beklenen ${want}, offset 0x${off.toString(16)})`;
      notes.push(msg);
      if (dexes.length === 0) error = `DEX basligi icin yeterli bayt yok (offset 0x${off.toString(16)})`;
      else if (opts.strict) error = msg;
      break;
    }
    if (!looksLikeDexHeader(buf, off)) {
      const msg = `DEX zinciri ${dexes.length}. girdiden sonra kesildi: 0x${off.toString(16)} konumunda gecerli DEX magic yok`;
      notes.push(msg);
      if (dexes.length === 0) error = `Gecerli DEX basligi bulunamadi (offset 0x${off.toString(16)})`;
      else if (opts.strict) error = msg;
      break;
    }

    const fileSize = buf.readUInt32LE(off + 32);
    const remaining = limit - off;
    const isLast = i === want - 1;

    if (opts.lastFromRemaining && isLast) {
      // VDEX: son DEX'in boyu bolum sonuna kadar kalan baytlardan alinir
      // (vdexExtractor davranisi; header file_size'i ile eslesmeyebilir).
      if (fileSize !== remaining) {
        notes.push(`Son DEX boyutu bolum sonundan alindi (header file_size=${fileSize}, kalan=${remaining} bayt)`);
      }
      if (remaining > MAX_DEX_SIZE) {
        notes.push(`Son DEX boyutu (${remaining} bayt) 512MB dogrulama sinirini asiyor - kalan baytlar kullanildi`);
      }
      dexes.push({ index: i, offset: off, size: remaining });
      off += remaining;
      continue;
    }

    if (fileSize === 0 || fileSize > MAX_DEX_SIZE) {
      const msg = `${i}. DEX'in file_size degeri gecersiz (${fileSize})`;
      notes.push(msg);
      error = msg;
      break;
    }
    if (off + fileSize > limit) {
      const msg = `${i}. DEX bolum/dosya sinirlarini asiyor (file_size=${fileSize}, kalan=${remaining} bayt)`;
      notes.push(msg);
      error = msg;
      break;
    }
    dexes.push({ index: i, offset: off, size: fileSize });
    off += fileSize;
  }

  return error === undefined ? { dexes } : { dexes, error };
}

/** VDEX surumune gore duzen secimi; bilinen araliklara adaptasyon yapar. */
function vdexLayoutOf(version: string): "006" | "019" | "021" | null {
  if (!/^[0-9]{3}$/.test(version)) return null;
  const n = parseInt(version, 10);
  if (n >= 6 && n <= 10) return "006"; // 006/010 (Android 8.x)
  if (n >= 11 && n <= 19) return "019"; // Android 9.x
  if (n >= 20) return "021"; // Android 10+ (020/021/...)
  return null; // 001-005 desteklenmiyor (VDEX O'dan once yoktu)
}

function oatApiHint(v: number): string {
  if (v >= 131) return "Android 9+ (dex genelde vdex'te)";
  if (v >= 117) return "Android 7-8";
  if (v >= 88) return "Android 6-7";
  if (v >= 71) return "Android 5-6";
  return `Bilinmeyen OAT surumu (${v})`;
}

// ----------------------------------------------------------------------------
// VDEX
// ----------------------------------------------------------------------------

/**
 * VDEX dosyasini ayristirir. Magic "vdex" degilse null doner; magic esler ama
 * ic yapi bozuksa error set edilmis VdexInfo doner (hic throw etmez).
 */
export function parseVdex(buf: Buffer): VdexInfo | null {
  if (!buf || buf.length < 4) return null;
  if (buf.toString("latin1", 0, 4) !== "vdex") return null;

  const notes: string[] = [];
  const dexes: VdexDexEntry[] = [];
  let error: string | undefined;
  let dexCount = 0;
  let dexSectionVersion = "";

  const version = buf.length >= 7 ? buf.toString("latin1", 4, 7).replace(/\x00/g, "") : "";
  const layout = vdexLayoutOf(version);
  const apiHint = layout
    ? VDEX_API_HINTS[version] ?? `API bilgisi bilinmiyor (${version})`
    : `Bilinmeyen VDEX surumu (${version || "okunamadi"})`;

  const finish = (): VdexInfo => {
    const info: VdexInfo = { kind: "vdex", version, apiHint, dexSectionVersion, dexCount, dexes, notes };
    if (error !== undefined) info.error = error;
    return info;
  };

  if (buf.length < 20) {
    error = "VDEX basligi kisa (en az 20 bayt gerekli)";
    return finish();
  }
  if (!layout) {
    error = `Desteklenmeyen VDEX surumu "${version}" - duzen cikarilamadi`;
    return finish();
  }
  if (!VDEX_API_HINTS[version]) {
    notes.push(`Bilinmeyen VDEX surumu "${version}" - "${layout}" duzeni varsayilarak okundu`);
  }

  // --- VDEX 006/010: 24 bayt baslik, numDex @8, dexSize @12 -----------------
  if (layout === "006") {
    if (buf.length < 24) {
      error = "VDEX 006/010 basligi kisa (24 bayt gerekli)";
      return finish();
    }
    const numDex = buf.readUInt32LE(8);
    const dexSize = buf.readUInt32LE(12);
    const verifierDepsSize = buf.readUInt32LE(16);
    const quickeningInfoSize = buf.readUInt32LE(20);
    dexCount = numDex;
    if (verifierDepsSize > 0) notes.push(`Verifier deps mevcut (${verifierDepsSize} bayt)`);
    if (quickeningInfoSize > 0) notes.push(`Quickening info mevcut (${quickeningInfoSize} bayt)`);
    if (numDex > MAX_DEX_COUNT) {
      error = `numberOfDexFiles cok yuksek (${numDex} > ${MAX_DEX_COUNT}) - baslik guvenilir degil`;
      return finish();
    }
    const checksumsEnd = 24 + numDex * 4;
    if (checksumsEnd > buf.length) {
      error = `Checksum tablosu dosya sinirlari disinda (${numDex} girdi)`;
      return finish();
    }
    if (numDex === 0) {
      notes.push("numberOfDexFiles = 0 - DEX yok");
      return finish();
    }
    if (dexSize === 0) {
      error = "dexSize = 0 ama numberOfDexFiles > 0";
      return finish();
    }
    let dexEnd = checksumsEnd + dexSize;
    if (dexEnd > buf.length) {
      dexEnd = buf.length;
      error = `dex bolumu (dexSize=${dexSize}) dosya sinirlarini asiyor - dosya sonuna sinirlandi`;
    }
    const res = collectDexChain(buf, checksumsEnd, dexEnd, numDex, notes, {
      lastFromRemaining: true,
      strict: true,
    });
    for (const d of res.dexes) dexes.push(d);
    if (error === undefined && res.error !== undefined) error = res.error;
    if (dexEnd < buf.length) {
      notes.push(`DEX bolumu sonrasi ${buf.length - dexEnd} bayt ek veri var (verifier deps / quickening info)`);
    }
    return finish();
  }

  // --- VDEX 019 / 021 (ve adaptasyonlar) ------------------------------------
  const is21 = layout === "021";
  const headerSize = is21 ? 28 : 20;
  if (buf.length < headerSize) {
    error = `VDEX ${is21 ? "021" : "019"} basligi kisa (${headerSize} bayt gerekli)`;
    return finish();
  }
  dexSectionVersion = buf.toString("latin1", 8, 11);
  const numDex = buf.readUInt32LE(12);
  const verifierDepsSize = buf.readUInt32LE(16);
  dexCount = numDex;
  if (verifierDepsSize > 0) notes.push(`Verifier deps mevcut (${verifierDepsSize} bayt)`);
  if (is21) {
    const bootChecksumsSize = buf.readUInt32LE(20);
    const classLoaderContextSize = buf.readUInt32LE(24);
    if (bootChecksumsSize > 0) notes.push(`Boot classpath checksumlari mevcut (${bootChecksumsSize} bayt)`);
    if (classLoaderContextSize > 0) notes.push(`ClassLoader context mevcut (${classLoaderContextSize} bayt)`);
  }
  if (numDex > MAX_DEX_COUNT) {
    error = `numberOfDexFiles cok yuksek (${numDex} > ${MAX_DEX_COUNT}) - baslik guvenilir degil`;
    return finish();
  }
  if (dexSectionVersion !== "000" && dexSectionVersion !== "002") {
    error = `Bilinmeyen dexSectionVersion "${dexSectionVersion}" (000 veya 002 bekleniyor)`;
    return finish();
  }
  const checksumsEnd = headerSize + numDex * 4;
  if (checksumsEnd > buf.length) {
    error = `Checksum tablosu dosya sinirlari disinda (${numDex} girdi)`;
    return finish();
  }
  if (dexSectionVersion === "000") {
    notes.push("DEX bolumu yok (dexSectionVersion 000) - DEX cikarilamaz");
    return finish();
  }
  if (numDex === 0) {
    notes.push("numberOfDexFiles = 0 - DEX yok");
    return finish();
  }

  const dshOff = checksumsEnd; // DexSectionHeader ofseti
  if (dshOff + VDEX_SECTION_HEADER_SIZE > buf.length) {
    error = "DexSectionHeader okunamadi (12 bayt gerekli)";
    return finish();
  }
  const dexSize = buf.readUInt32LE(dshOff);
  const dexSharedDataSize = buf.readUInt32LE(dshOff + 4);
  const quickeningInfoSize = buf.readUInt32LE(dshOff + 8);
  if (dexSharedDataSize > 0) notes.push(`Dex shared data mevcut (${dexSharedDataSize} bayt)`);
  if (quickeningInfoSize > 0) notes.push(`Quickening info mevcut (${quickeningInfoSize} bayt)`);
  if (dexSize === 0) {
    error = "dexSize = 0 ama numberOfDexFiles > 0";
    return finish();
  }
  let dexEnd = dshOff + VDEX_SECTION_HEADER_SIZE + dexSize;
  if (dexEnd > buf.length) {
    dexEnd = buf.length;
    error = `dex bolumu (dexSize=${dexSize}) dosya sinirlarini asiyor - dosya sonuna sinirlandi`;
  }
  const res = collectDexChain(buf, dshOff + VDEX_SECTION_HEADER_SIZE, dexEnd, numDex, notes, {
    lastFromRemaining: true,
    strict: true,
  });
  for (const d of res.dexes) dexes.push(d);
  if (error === undefined && res.error !== undefined) error = res.error;
  if (dexEnd < buf.length) {
    notes.push(`DEX bolumu sonrasi ${buf.length - dexEnd} bayt ek veri var (shared data / quickening / verifier deps)`);
  }
  return finish();
}

// ----------------------------------------------------------------------------
// OAT
// ----------------------------------------------------------------------------

/**
 * OAT dosyasini pragmatik scan+chain yontemiyle ayristirir. Magic "art\n"
 * degilse null doner; aksi halde bulunan DEX'lerle OatInfo doner (throw yok).
 */
export function parseOat(buf: Buffer): OatInfo | null {
  if (!buf || buf.length < 4) return null;
  if (buf.toString("latin1", 0, 4) !== "art\n") return null;

  const notes: string[] = [];
  const dexes: VdexDexEntry[] = [];
  let error: string | undefined;

  const version = buf.length >= 7 ? buf.toString("latin1", 4, 7).replace(/\x00/g, "") : "";
  const verNum = /^[0-9]{3}$/.test(version) ? parseInt(version, 10) : NaN;
  const apiHint = Number.isNaN(verNum) ? `Bilinmeyen OAT surumu (${version || "okunamadi"})` : oatApiHint(verNum);

  let dexCount = 0;
  if (buf.length >= 28) {
    dexCount = buf.readUInt32LE(20); // OatHeader.dex_file_count_
    // executableOffset (@24) pragmatik taramada kullanilmiyor
  } else {
    error = "OAT basligi kisa (28 bayt gerekli - dexFileCount okunamadi)";
  }

  if (!error) {
    const scanEnd = Math.min(buf.length, OAT_SCAN_LIMIT);
    let dexOff = -1;
    let cdexOff = -1;
    // Ilk gecerli "dex\n" (035..039) adayini ve varsa ilk "cdex" magicini tara
    for (let i = 0; i + 4 <= scanEnd; i++) {
      const b0 = buf[i];
      if (dexOff < 0 && b0 === 0x64 && buf[i + 1] === 0x65 && buf[i + 2] === 0x78 && buf[i + 3] === 0x0a) {
        if (plausibleDexEntry(buf, i)) {
          dexOff = i;
          if (cdexOff >= 0) break;
        }
      } else if (cdexOff < 0 && b0 === 0x63 && buf[i + 1] === 0x64 && buf[i + 2] === 0x65 && buf[i + 3] === 0x78) {
        cdexOff = i;
        if (dexOff >= 0) break;
      }
    }

    if (cdexOff >= 0) {
      notes.push(`Compact DEX (cdex) tespit edildi @0x${cdexOff.toString(16)} - compact-dex cikarma desteklenmiyor`);
    }
    if (dexOff >= 0) {
      notes.push(`DEX bolumu taramada 0x${dexOff.toString(16)} konumunda bulundu (ilk ${scanEnd} bayt tarandi)`);
    }

    if (dexOff < 0) {
      if (cdexOff >= 0) {
        if (dexCount > 0) error = "Standart DEX bulunamadi - OAT compact-dex (cdex) iceriyor, cikarma desteklenmiyor";
        else notes.push("Standart DEX yok (compact-dex iceriyor)");
      } else if (dexCount > 0) {
        error = `Ilk ${scanEnd} baytta gecerli 'dex\\n' (035-039) basligi bulunamadi`;
      } else {
        notes.push(`Ilk ${scanEnd} baytta DEX bulunamadi (dexFileCount = 0)`);
      }
    } else {
      const trusted = dexCount > 0 && dexCount <= MAX_DEX_COUNT;
      if (!trusted && dexCount > MAX_DEX_COUNT) {
        notes.push(`dexFileCount gecersiz (${dexCount} > ${MAX_DEX_COUNT}) - yoksayildi, zincir taramasi kullaniliyor`);
      } else if (dexCount === 0) {
        notes.push("dexFileCount = 0 - DEX'ler zincir taramasindan toplanacak");
      }
      const want = trusted ? dexCount : MAX_DEX_COUNT;
      const res = collectDexChain(buf, dexOff, buf.length, want, notes, {
        lastFromRemaining: false, // OAT'te son DEX'ten sonra oat data vardir; header file_size kullanilir
        strict: false,
      });
      for (const d of res.dexes) dexes.push(d);
      if (res.error !== undefined) error = res.error;
      if (dexes.length !== dexCount) {
        notes.push(`dexFileCount=${dexCount}, zincir taramasinda ${dexes.length} DEX bulundu`);
      }
    }
  }

  const info: OatInfo = { kind: "oat", version, apiHint, dexCount, scannedCount: dexes.length, dexes, notes };
  if (error !== undefined) info.error = error;
  return info;
}

// ----------------------------------------------------------------------------
// ortak yardimcilar
// ----------------------------------------------------------------------------

/**
 * Buffer'in ilk 4 baytina bakarak tur belirler:
 *   "vdex" -> "vdex", "art\n" -> "oat", "cdex" -> "cdex", aksi halde null.
 */
export function isVdexOrOat(buf: Buffer): "vdex" | "oat" | "cdex" | null {
  if (!buf || buf.length < 4) return null;
  const magic = buf.toString("latin1", 0, 4);
  if (magic === "vdex") return "vdex";
  if (magic === "art\n") return "oat";
  if (magic === "cdex") return "cdex";
  return null;
}

/**
 * Verilen girdiyi buffer'dan keser (bounds guard'li; hic throw etmez).
 * Donen buffer, kaynak buffer'in uzerindeki bir gorunumdur (subarray).
 */
export function extractDex(buf: Buffer, e: VdexDexEntry): Buffer {
  if (!buf || !e || !Number.isFinite(e.offset) || !Number.isFinite(e.size)) return Buffer.alloc(0);
  const off = Math.trunc(e.offset);
  const size = Math.trunc(e.size);
  if (off < 0 || size < 0) return Buffer.alloc(0); // gecersiz girdi: parser bunlari uretmez
  const start = Math.min(off, buf.length);
  const end = Math.min(Math.max(start, off + size), buf.length);
  return buf.subarray(start, end);
}
