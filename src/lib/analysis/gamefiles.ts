// ----------------------------------------------------------------------------
// DumperPro Online - ortak oyun dosya formatlari (tum oyunlar icin)
//
// Kapsam: UE .pak (v1-v11 index), .utoc/.ucas (IoStore), .uasset/.umap
// (PackageFileSummary + isim tablosu), Mach-O / fat (iOS ipa icindeki
// libil2cpp vb.). OBB/IPA zaten ZIP hattinda analiz edilir (zipapk.ts).
//
// Kaynak/teyit:
//   - FPakInfo/Footer: UE pak magic 0x5A6F12E1; footer alanlari surume gore
//     buyur (v8.0+ compression methods 5x32B, v9+ EncryptionKeyGuid 16B,
//     v10+ primary index degisikligi). Il2CppDumper/UE dosya arastirmalari +
//     research/dumper7 (Dumper-7) SDKGenerator pak okuma yapisindan teyit.
//   - FIoStoreTocResourceHeader: ".UTOC" magic 0x544F4321 (LE: 55 54 4F 43
//     degil - dosyada "UTOC" baytlari); toc entry 20 B (ChunkId 12 + Offset 4
//     + Size 4, v1) / v2+ sonuna kadar benzer.
//   - PackageFileSummary: magic 0x9E2A83C1; LegacyFileVersion (-7 UE4.x,
//     -8 UE5); alan yuruyusu serial size tablosuna gore best-effort.
//   - Mach-O: mach-o/loader.h magic 0xFEEDFACE/FacF + fat 0xCAFEBABE/BF.
//
// ONEMLI NOTLAR:
//   1) Oodle/LZMA sikistirilmis pak kayitlari ACILMAZ (yalnizca liste);
//      zlib kayitlari icin boyut bilgisi verilir. Amac icerik haritasi.
//   2) v10/v11 pak index'inde entry offsetleri IndexOffset'e gore relative
//     olabilir; iki yorum da denenir, gecerli olan secilir (not dusulur).
//   3) Encrypted index (AES) cozulmez - not dusulur.
// ----------------------------------------------------------------------------

import type {
  GameFilesInfo,
  PakFileInfo,
  PakEntryInfo,
  UtocInfo,
  UassetInfo,
  MachoInfo,
  MachoArch,
} from "./types";

// ---------------------------------------------------------------------------
// UE .pak
// ---------------------------------------------------------------------------

const PAK_MAGIC = 0x5a6f12e1;
const PAK_COMPRESSION_METHOD_NONE = 0x00;

function findPakFooter(buf: Buffer): number | null {
  // son 512 baytta magic ara (footer boyutu surume gore 45..221+)
  const scanStart = Math.max(0, buf.length - 1024);
  for (let i = buf.length - 4; i >= scanStart; i--) {
    if (buf.readUInt32LE(i) === PAK_MAGIC) return i;
  }
  return null;
}

function readFString(buf: Buffer, off: number): { value: string | null; next: number } {
  if (off + 4 > buf.length) return { value: null, next: off + 4 };
  const len = buf.readInt32LE(off);
  const absLen = Math.abs(len);
  if (absLen <= 0 || absLen > 4096 || off + 4 + absLen > buf.length) {
    return { value: null, next: off + 4 };
  }
  if (len < 0) {
    // UTF-16LE, son char null terminator dahil
    const raw = buf.subarray(off + 4, off + 4 + absLen);
    let s = "";
    for (let i = 0; i + 1 < raw.length; i += 2) s += String.fromCharCode(raw[i]);
    return { value: s.replace(/\0+$/, ""), next: off + 4 + absLen };
  }
  const s = buf.subarray(off + 4, off + 4 + absLen).toString("latin1");
  return { value: s.replace(/\0+$/, ""), next: off + 4 + absLen };
}

function parsePak(buf: Buffer, notes: string[]): PakFileInfo | null {
  const footerPos = findPakFooter(buf);
  if (footerPos === null) return null;

  // footer alani surume gore degisir; magic'ten onceki EncryptionKeyGuid
  // (16B) ve sonraki version kullanilir. Footer layout (v11):
  //   [EncryptionKeyGuid 16B v9+][bEncryptedIndex 1B][Magic 4B][Version 4B]
  //   [IndexOffset 8B][IndexSize 8B][IndexHash 20B][CompressionMethods 5x32B v8+]
  // FPakInfo layout: [EncryptionKeyGuid 16B v9+][bEncryptedIndex 1B][Magic 4B]
  //   [Version 4B][IndexOffset 8B][IndexSize 8B][IndexHash 20B][CompressionMethods 5x32B v8+]
  const magic = buf.readUInt32LE(footerPos);
  if (magic !== PAK_MAGIC) return null;
  const version = buf.readInt32LE(footerPos + 4);
  const indexOffset = Number(buf.readBigUInt64LE(footerPos + 8));
  const indexSize = Number(buf.readBigUInt64LE(footerPos + 16));

  const pak: PakFileInfo = {
    version,
    indexOffset,
    indexSize,
    encryptedIndex: false,
    compressionMethods: [],
    entryCount: 0,
    namedEntries: 0,
    entries: [],
  };

  // bEncryptedIndex: magic'ten 1 once (v3+), EncryptionKeyGuid magic'ten 16 once (v9+)
  if (version >= 9) {
    pak.encryptedIndex = buf.readUInt8(footerPos - 17) !== 0;
  } else if (version >= 3) {
    pak.encryptedIndex = buf.readUInt8(footerPos - 1) !== 0;
  }
  if (version >= 8) {
    const compsBase = footerPos + 44; // version(4)+off(8)+size(8)+hash(20)
    for (let c = 0; c < 5; c++) {
      const base = compsBase + c * 32;
      if (base + 32 > buf.length) break;
      const name = buf.subarray(base, base + 32).toString("latin1").replace(/\0+$/, "");
      if (name) pak.compressionMethods.push(name);
    }
  }

  if (pak.encryptedIndex) {
    notes.push("PAK index sifreli (AES) - icerik listesi cozulemez; surum/bilgi verildi");
    return pak;
  }
  if (indexOffset <= 0 || indexOffset >= buf.length || indexSize <= 0) {
    notes.push("PAK index offset/boyut gecersiz");
    return pak;
  }

  // primary index: mount point FString, entry count, [path hash seed u64 v10+], entries...
  let pos = indexOffset;
  const mp = readFString(buf, pos);
  if (mp.value !== null) pak.mountPoint = mp.value;
  pos = mp.next;
  if (pos + 4 > buf.length) {
    notes.push("PAK primary index okunamadi");
    return pak;
  }
  const entryCount = buf.readInt32LE(pos);
  pos += 4;
  if (entryCount < 0 || entryCount > 2_000_000) {
    notes.push(`PAK entry sayisi gecersiz: ${entryCount}`);
    pak.entryCount = Math.max(0, entryCount);
    return pak;
  }
  pak.entryCount = entryCount;
  if (version >= 10) pos += 8; // path hash seed

  // v10+ offsetleri IndexOffset'e gore relative; eski surumlerde absolute.
  // Dogru yorumu secmek icin ilk kayitla deneriz.
  const relFirst = indexOffset + Number(buf.readBigUInt64LE(pos));
  const absFirst = Number(buf.readBigUInt64LE(pos));
  const relative =
    version >= 10 &&
    relFirst > 0 && relFirst < buf.length &&
    !(absFirst > 0 && absFirst < buf.length && absFirst < indexOffset);
  if (relative) notes.push("PAK v10+: entry offsetleri IndexOffset'e gore relative olarak cozuldu");

  const compName = (idx: number): string => {
    if (idx === PAK_COMPRESSION_METHOD_NONE) return "None";
    return pak.compressionMethods[idx - 1] ?? `Comp${idx}`;
  };

  let named = 0;
  for (let i = 0; i < entryCount; i++) {
    if (i >= 400) break; // cikti butcesi
    // entry: encoded path FString (v10+ hash adlari bos dondurebilir),
    // offset u64, size u64, [compressionBlockSize u32 v<10], compMethodIndex u32,
    // hash 20B, [block tablolari...]
    const e = readFString(buf, pos);
    pos = e.next;
    if (pos + 16 > buf.length) break;
    const rawOff = Number(buf.readBigUInt64LE(pos));
    const size = Number(buf.readBigUInt64LE(pos + 8));
    pos += 16;
    let method = "None";
    let compressed: number | undefined;
    if (version < 10) {
      if (pos + 8 > buf.length) break;
      pos += 4; // compressionBlockSize
      const compIdx = buf.readUInt32LE(pos);
      pos += 4;
      method = compName(compIdx);
      if (compIdx !== PAK_COMPRESSION_METHOD_NONE) compressed = size;
    } else {
      if (pos + 4 > buf.length) break;
      const compIdx = buf.readUInt32LE(pos);
      pos += 4;
      method = compName(compIdx & 0x3f);
      if ((compIdx & 0x3f) !== PAK_COMPRESSION_METHOD_NONE) compressed = size;
    }
    let hash: string | undefined;
    if (pos + 20 <= buf.length) {
      hash = buf.subarray(pos, pos + 20).toString("hex").slice(0, 16);
      pos += 20;
    }
    // v10+ alignment pad (bAlign): 1 byte? aslinda v10 entry sonunda alignment byte'i
    // index formatina gore degisir; bozuk isimli kayitlarda sessiz gecilir.
    const entry: PakEntryInfo = {
      name: e.value && e.value.length > 0 ? pak.mountPoint + e.value.replace(/^\//, "") : null,
      offset: relative ? rawOff + indexOffset : rawOff,
      size,
      method,
      compressed,
      hash,
    };
    if (entry.offset < 0 || entry.offset > buf.length) entry.offset = 0;
    if (entry.name) named++;
    pak.entries.push(entry);
  }
  pak.namedEntries = named;
  notes.push(`PAK v${version}: ${entryCount} kayit, ${named} isimli (ilk ${pak.entries.length} listelendi)`);
  if (entryCount > 400) notes.push("PAK kayit cikti butcesi 400 - tam liste icin FModel/repak kullanin");
  return pak;
}

// ---------------------------------------------------------------------------
// UE .utoc / .ucas (IoStore)
// ---------------------------------------------------------------------------

const CHUNK_TYPES: Record<number, string> = {
  0: "Invalid",
  1: "PackageData",
  2: "ContainerIndex",
  3: "InternalPackageData",
  4: "PackageStoreEntry",
  5: "MicroPatchData",
  255: "EditorOnly",
};

function parseUtoc(buf: Buffer, notes: string[]): UtocInfo | null {
  // FIoStoreTocResourceHeader: Magic 4B ("UTOC"), Version 4B, TocHeaderSize 4B,
  // TocEntryCount 4B, TocCompressedBlockEntryCount 4B, TocCompressedBlockEntrySize 4B,
  // PartitionSize 8B, PartitionCount 4B, CompressionMethodNameCount 4B,
  // CompressionBlockSize 4B, Reserved.., EncryptionKeyGuid 16B, bEncryptedIndex 1B
  if (buf.length < 64) return null;
  if (buf.subarray(0, 4).toString("latin1") !== "UTOC") return null;
  const version = buf.readInt32LE(4);
  const tocHeaderSize = buf.readInt32LE(8);
  const entryCount = buf.readInt32LE(12);
  const blockEntryCount = buf.readInt32LE(16);
  const partitions = buf.readInt32LE(28);
  const compCount = buf.readInt32LE(32);

  const info: UtocInfo = {
    version,
    tocHeaderSize,
    entryCount,
    blockEntryCount,
    compressionMethods: [],
    partitions,
    entries: [],
  };
  const entryBase = Math.max(tocHeaderSize, 64);
  // isimler entries + compressed block entries SONRASINDA (FIoStoreTocResource layout)
  const namesBase = entryBase + Math.max(0, entryCount) * 20 + Math.max(0, blockEntryCount) * 4;
  for (let c = 0; c < Math.min(compCount, 8); c++) {
    const base = namesBase + c * 32;
    if (base + 32 <= buf.length) {
      info.compressionMethods.push(buf.subarray(base, base + 32).toString("latin1").replace(/\0+$/, ""));
    }
  }
  for (let i = 0; i < Math.min(entryCount, 400); i++) {
    const rec = entryBase + i * 20; // ChunkId 12 + Offset u32 + Size u32
    if (rec + 20 > buf.length) break;
    const chunkId = buf.subarray(rec, rec + 12).toString("hex");
    const offset = buf.readUInt32LE(rec + 12);
    const size = buf.readUInt32LE(rec + 14 + 2); // 12+4=16 -> offset@12, size@16
    const chunkTypeByte = buf[rec + 11]; // ChunkId son byte = ChunkType
    info.entries.push({
      chunkId,
      chunkType: CHUNK_TYPES[chunkTypeByte] ?? `0x${chunkTypeByte.toString(16)}`,
      offset,
      size,
    });
  }
  notes.push(`UTOC v${version}: ${entryCount} chunk, ${blockEntryCount} sikisik blok, ${partitions} partition`);
  notes.push("UCAS veri konteyneri toc offsetleriyle eslenir; acma icin ZenTools/UnrealPak kullanin");
  return info;
}

// ---------------------------------------------------------------------------
// UE .uasset / .umap
// ---------------------------------------------------------------------------

function parseUasset(buf: Buffer, fileName: string, notes: string[]): UassetInfo | null {
  if (buf.length < 64) return null;
  const magic = buf.readUInt32LE(0);
  if (magic !== 0x9e2a83c1) return null;
  const legacy = buf.readInt32LE(4);
  const ue3 = buf.readInt32LE(8);
  void ue3;
  let pos = 12;
  const ue4 = buf.readInt32LE(pos); pos += 4;
  let ue5: number | undefined;
  if (legacy <= -8) {
    ue5 = buf.readInt32LE(pos); pos += 4;
  }
  const licensee = buf.readInt32LE(pos); pos += 4;
  // custom versions: count + (16B guid + i32 version) each
  const cvCount = buf.readInt32LE(pos); pos += 4;
  if (cvCount < 0 || cvCount > 4096) {
    notes.push("UAsset custom version sayisi gecersiz - kisim parse");
    return null;
  }
  pos += cvCount * 20;
  if (pos + 4 > buf.length) return null;
  const totalHeaderSize = buf.readInt32LE(pos); pos += 4;
  // FolderName FString
  const fn = readFString(buf, pos);
  pos = fn.next;
  if (pos + 4 > buf.length) return null;
  const packageFlags = buf.readUInt32LE(pos); pos += 4;
  const nameCount = buf.readInt32LE(pos); pos += 4;
  const nameOffset = buf.readInt32LE(pos); pos += 4;
  if (legacy <= -8) pos += 16 + 4; // LocalizationId FString(16 sabit?) + GatherableText... UE5: LocalizationId countless FString degil; atla (best effort)

  const info: UassetInfo = {
    legacyVersion: legacy,
    ue4Version: ue4,
    ue5Version: ue5,
    licenseeVersion: licensee,
    totalHeaderSize,
    packageFlags,
    nameCount,
    nameOffset,
    names: [],
  };
  if (legacy > -8) pos += 8; // GatherableTextCount + GatherableTextOffset (UE4.17+)

  // isim tablosu
  if (nameCount > 0 && nameCount < 500_000 && nameOffset > 0 && nameOffset < buf.length) {
    let npos = nameOffset;
    for (let i = 0; i < Math.min(nameCount, 200); i++) {
      if (npos + 2 > buf.length) break;
      const len = buf.readInt16LE(npos); npos += 2;
      const abs = Math.abs(len);
      if (abs <= 0 || abs > 1024 || npos + abs > buf.length) break;
      let s: string;
      if (len < 0) {
        const raw = buf.subarray(npos, npos + abs);
        s = "";
        for (let j = 0; j + 1 < raw.length; j += 2) s += String.fromCharCode(raw[j]);
        s = s.replace(/\0+$/, "");
      } else {
        s = buf.subarray(npos, npos + abs).toString("latin1").replace(/\0+$/, "");
      }
      npos += abs;
      info.names.push(s);
    }
  }

  // export/import sayilari: kesin konum surume gore degisir; header icinde
  // sirali yuruyusle best-effort bulunamaz -> toplam boyut bilgisi verilir.
  notes.push(
    `UAsset (${fileName}): LegacyFileVersion ${legacy}${ue5 !== undefined ? " (UE5 hizasi)" : " (UE4 hizasi)"}, ` +
      `${nameCount} isim (ilk ${info.names.length} listelendi), header ${totalHeaderSize} B`,
  );
  const isMap = fileName.toLowerCase().endsWith(".umap");
  if (isMap) notes.push("UMAP: seviye haritasi - exportlar Actor/Dataset bloklari");
  return info;
}

// ---------------------------------------------------------------------------
// Mach-O / fat binary (iOS ipa, macOS)
// ---------------------------------------------------------------------------

const CPU_TYPES: Record<number, string> = {
  1: "x86", 7: "x86", 0x01000007: "x86_64", 12: "ARM", 0x0100000c: "ARM64", 0x01000008: "x86_64h",
};
const MACHO_FILETYPES: Record<number, string> = {
  1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 8: "MH_DYLINKER", 0xb: "MH_DSYM",
};

function parseMachoThin(buf: Buffer, archOffset: number, notes: string[]): { info: Partial<MachoInfo>; ok: boolean } {
  // header: magic 4, cputype 4, cpusub 4, filetype 4, ncmds 4, sizeofcmds 4, flags 4 (32B)
  if (archOffset + 32 > buf.length) return { info: {}, ok: false };
  const cpuType = buf.readUInt32LE(archOffset + 4);
  const fileType = buf.readUInt32LE(archOffset + 12);
  const ncmds = buf.readUInt32LE(archOffset + 16);
  const info: Partial<MachoInfo> = {
    fileType: MACHO_FILETYPES[fileType] ?? `0x${fileType.toString(16)}`,
    archs: [{ cpu: CPU_TYPES[cpuType] ?? `0x${cpuType.toString(16)}`, offset: archOffset, size: buf.length - archOffset }],
    segments: [],
    sections: [],
    dylibs: [],
    ncmds,
  };
  let pos = archOffset + 32;
  let dylibCount = 0;
  for (let i = 0; i < Math.min(ncmds, 512) && pos + 8 <= buf.length; i++) {
    const cmd = buf.readUInt32LE(pos);
    const cmdSize = buf.readUInt32LE(pos + 4);
    if (cmdSize < 8 || pos + cmdSize > buf.length) break;
    if (cmd === 0x19 /* LC_SEGMENT_64 */ && pos + 72 <= buf.length) {
      const segName = buf.subarray(pos + 8, pos + 24).toString("latin1").replace(/\0+$/, "");
      const vmaddr = Number(buf.readBigUInt64LE(pos + 24));
      const vmsize = Number(buf.readBigUInt64LE(pos + 32));
      const filesize = Number(buf.readBigUInt64LE(pos + 40));
      const nsects = buf.readUInt32LE(pos + 64);
      info.segments!.push({ name: segName, vmaddr, vmsize, filesize, nsects });
      let spos = pos + 72;
      for (let s = 0; s < Math.min(nsects, 64) && spos + 80 <= pos + cmdSize; s++) {
        const sName = buf.subarray(spos, spos + 16).toString("latin1").replace(/\0+$/, "");
        const sSeg = buf.subarray(spos + 16, spos + 32).toString("latin1").replace(/\0+$/, "");
        const sAddr = Number(buf.readBigUInt64LE(spos + 32));
        const sSize = Number(buf.readBigUInt64LE(spos + 40));
        info.sections!.push({ seg: sSeg, name: sName, addr: sAddr, size: sSize });
        spos += 80;
      }
    } else if (cmd === 0x1 /* LC_SEGMENT */ && pos + 56 <= buf.length) {
      const segName = buf.subarray(pos + 8, pos + 24).toString("latin1").replace(/\0+$/, "");
      const vmaddr = buf.readUInt32LE(pos + 24);
      const vmsize = buf.readUInt32LE(pos + 28);
      const filesize = buf.readUInt32LE(pos + 36);
      const nsects = buf.readUInt32LE(pos + 48);
      info.segments!.push({ name: segName, vmaddr, vmsize, filesize, nsects });
    } else if ((cmd === 0xc /* LC_LOAD_DYLIB */ || cmd === 0x18 /* LC_LOAD_WEAK_DYLIB */) && dylibCount < 48) {
      const nameOff = buf.readUInt32LE(pos + 8);
      if (nameOff > 0 && pos + nameOff < buf.length) {
        const s = readCstrAt(buf, pos + nameOff, 256);
        if (s) info.dylibs!.push(s);
        dylibCount++;
      }
    } else if (cmd === 0x80000028 /* LC_MAIN */ && pos + 24 <= buf.length) {
      info.entry = Number(buf.readBigUInt64LE(pos + 8));
    }
    pos += cmdSize;
  }
  return { info, ok: true };
}

function readCstrAt(buf: Buffer, off: number, cap: number): string | null {
  if (off < 0 || off >= buf.length) return null;
  const max = Math.min(buf.length - off, cap);
  let end = 0;
  while (end < max && buf[off + end] !== 0) end++;
  return end > 0 ? buf.subarray(off, off + end).toString("latin1") : null;
}

function parseMacho(buf: Buffer, notes: string[]): MachoInfo | null {
  if (buf.length < 32) return null;
  const m0 = buf.readUInt32LE(0);
  // thin: LE okununca 0xCEFAEDFE (x86), 0xCFFAEDFE (x64); BE makinalarda ters
  const isThin = m0 === 0xcefaedfe || m0 === 0xcffaedfe;
  const isFat = m0 === 0xbebaface || m0 === 0xbebafacf; // CAFEBABE/BF LE okunmus
  if (!isThin && !isFat) return null;

  if (isThin) {
    const { info } = parseMachoThin(buf, 0, notes);
    if (!info.fileType) return null;
    notes.push(`Mach-O thin (${info.archs?.[0]?.cpu}), ${info.fileType}, ${info.ncmds} load komutu`);
    notes.push("iOS oyunlari icin: libil2cpp.so/UnityFramework burada; metadata ile eslestirilebilir");
    return {
      format: "thin",
      archs: info.archs ?? [],
      fileType: info.fileType ?? "",
      segments: info.segments ?? [],
      sections: (info.sections ?? []).slice(0, 64),
      dylibs: info.dylibs ?? [],
      entry: info.entry,
      ncmds: info.ncmds ?? 0,
    };
  }

  // fat: nfat_arch + arsivler (BE degerler!)
  const nfat = buf.readUInt32BE(4);
  const archs: MachoArch[] = [];
  let firstThin: MachoInfo | null = null;
  for (let i = 0; i < Math.min(nfat, 8); i++) {
    const rec = 8 + i * 20;
    if (rec + 20 > buf.length) break;
    const cpuType = buf.readUInt32BE(rec);
    const offset = buf.readUInt32BE(rec + 8);
    const size = buf.readUInt32BE(rec + 12);
    archs.push({ cpu: CPU_TYPES[cpuType] ?? `0x${cpuType.toString(16)}`, offset, size });
    if (!firstThin && offset > 0 && offset < buf.length) {
      const sub = buf.subarray(offset);
      const r = parseMachoThin(sub, 0, notes);
      if (r.ok && r.info.fileType) {
        firstThin = {
          format: "thin",
          archs: r.info.archs ?? [],
          fileType: r.info.fileType ?? "",
          segments: r.info.segments ?? [],
          sections: (r.info.sections ?? []).slice(0, 64),
          dylibs: r.info.dylibs ?? [],
          entry: r.info.entry,
          ncmds: r.info.ncmds ?? 0,
        };
      }
    }
  }
  notes.push(`Mach-O fat: ${nfat} mimari (${archs.map((a) => a.cpu).join(", ")})`);
  return {
    format: "fat",
    archs,
    fileType: firstThin?.fileType ?? "fat container",
    segments: firstThin?.segments ?? [],
    sections: firstThin?.sections ?? [],
    dylibs: firstThin?.dylibs ?? [],
    entry: firstThin?.entry,
    ncmds: firstThin?.ncmds ?? 0,
  };
}

// ---------------------------------------------------------------------------
// ana giris
// ---------------------------------------------------------------------------

export function parseGameFiles(buf: Buffer, kind: string, fileName: string, notes: string[]): GameFilesInfo | null {
  try {
    if (kind === "pak") {
      const pak = parsePak(buf, notes);
      if (!pak) {
        notes.push("PAK footer bulunamadi (magic 0x5A6F12E1) - dosya bozuk veya taninamadi");
        return null;
      }
      return { type: "pak", pak, notes };
    }
    if (kind === "utoc") {
      const utoc = parseUtoc(buf, notes);
      if (!utoc) {
        notes.push("UTOC basligi okunamadi");
        return null;
      }
      return { type: "utoc", utoc, notes };
    }
    if (kind === "ucas") {
      // .ucas veri konteyneri: magic yok; sadece boyut/bilgi
      notes.push(`UCAS: ${buf.length} bayt veri konteyneri (chunk verisi) - TOC icin .utoc yukleyin`);
      return { type: "ucas", notes };
    }
    if (kind === "uasset" || kind === "umap") {
      const uasset = parseUasset(buf, fileName, notes);
      if (!uasset) {
        notes.push("UAsset PackageFileSummary okunamadi");
        return null;
      }
      return { type: kind === "umap" ? "umap" : "uasset", uasset, notes };
    }
    if (kind === "macho") {
      const macho = parseMacho(buf, notes);
      if (!macho) {
        notes.push("Mach-O header okunamadi");
        return null;
      }
      return { type: "macho", macho, notes };
    }
  } catch (e) {
    notes.push(`Oyun dosyasi parse hatasi: ${e instanceof Error ? e.message : String(e)}`);
  }
  return null;
}
