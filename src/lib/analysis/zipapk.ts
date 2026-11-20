// ----------------------------------------------------------------------------
// DumperPro Online - ZIP merkezi dizin parser + APK tespiti (sifir bagimlilik)
//
// Kaynak/teyit:
//  - ZIP: PKWARE APPNOTE.TXT v6.3.x
//      EOCD  sig 0x06054b50 (22 B)
//      CD    sig 0x02014b50 (46 B + isim + extra + yorum)
//      LFH   sig 0x04034b50 (30 B + isim + extra)
//  - APK: AOSP yapisi = ZIP + AndroidManifest.xml + classes.dex + res/ + lib/<abi>/*.so
//  - AXML (binary XML): resource_types.h (RES_TABLE_TYPE 0x0002, RES_XML_TYPE 0x0003,
//      RES_STRING_POOL_TYPE 0x0001, RES_XML_START_ELEMENT_TYPE 0x0102)
// ----------------------------------------------------------------------------

import zlib from "node:zlib";

export interface ZipEntryRaw {
  name: string;
  compressedSize: number;
  size: number;
  method: number;
  localOffset: number;
  crc: number;
}

export class ZipParseError extends Error {}

export function parseZipCentralDirectory(buf: Buffer): ZipEntryRaw[] {
  // EOCD'yi sondan ara (yorum alanina izin ver)
  let eocd = -1;
  const minEocd = Math.max(0, buf.length - 66);
  for (let i = buf.length - 22; i >= minEocd; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipParseError("EOCD bulunamadi (gecerli ZIP degil veya hasarli)");

  const entryCount = buf.readUInt16LE(eocd + 10);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // ZIP64 EOCD locator kontrolu (22 B @eocd+20)
  if (
    eocd + 20 + 20 <= buf.length &&
    buf.readUInt32LE(eocd + 20) === 0x07064b50
  ) {
    const z64Off = Number(buf.readBigUInt64LE(eocd + 20 + 8));
    if (z64Off + 56 <= buf.length && buf.readUInt32LE(z64Off) === 0x06064b50) {
      cdOffset = Number(buf.readBigUInt64LE(z64Off + 48));
    }
  }

  const entries: ZipEntryRaw[] = [];
  let off = cdOffset;
  for (let i = 0; i < entryCount && off + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const crc = buf.readUInt32LE(off + 16);
    let compressedSize = buf.readUInt32LE(off + 20);
    let size = buf.readUInt32LE(off + 24);
    let nameLen = buf.readUInt16LE(off + 28);
    let extraLen = buf.readUInt16LE(off + 30);
    let commentLen = buf.readUInt16LE(off + 32);
    let localOffset = buf.readUInt32LE(off + 42);
    let name = buf.subarray(off + 46, off + 46 + nameLen).toString("utf8");

    // ZIP64 extra alan (id 0x0001) - best effort
    let extraEnd = off + 46 + nameLen + extraLen;
    if (size === 0xffffffff || compressedSize === 0xffffffff || localOffset === 0xffffffff) {
      let p = off + 46 + nameLen;
      while (p + 4 <= extraEnd) {
        const id = buf.readUInt16LE(p);
        const sz = buf.readUInt16LE(p + 2);
        if (id === 0x0001 && p + 4 + sz <= extraEnd) {
          let q = p + 4;
          if (size === 0xffffffff && q + 8 <= p + 4 + sz) { size = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (compressedSize === 0xffffffff && q + 8 <= p + 4 + sz) { compressedSize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (localOffset === 0xffffffff && q + 8 <= p + 4 + sz) { localOffset = Number(buf.readBigUInt64LE(q)); q += 8; }
          break;
        }
        p += 4 + sz;
      }
    }

    entries.push({ name, compressedSize, size, method, localOffset, crc });
    off = extraEnd + commentLen;
  }
  return entries;
}

export interface ExtractedEntry {
  name: string;
  data: Buffer;
}

/** Tek bir ZIP kaydini acar (STORE veya DEFLATE). Cap: 128 MB. */
export function extractZipEntry(buf: Buffer, entry: ZipEntryRaw): ExtractedEntry | null {
  if (entry.localOffset + 30 > buf.length) return null;
  if (buf.readUInt32LE(entry.localOffset) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(entry.localOffset + 26);
  const extraLen = buf.readUInt16LE(entry.localOffset + 28);
  const dataStart = entry.localOffset + 30 + nameLen + extraLen;
  if (entry.size > 128 * 1024 * 1024) return null;
  if (dataStart + entry.compressedSize > buf.length) return null;
  const raw = buf.subarray(dataStart, dataStart + entry.compressedSize);
  if (entry.method === 0) return { name: entry.name, data: Buffer.from(raw) };
  if (entry.method === 8) {
    try {
      const data = zlib.inflateRawSync(raw);
      return { name: entry.name, data };
    } catch {
      return null;
    }
  }
  return null; // bzip2/lzma desteklenmiyor
}

// ----------------------------------------------------------------------------
// AXML (Android binary XML) - manifest bilgisi (best effort)
// ----------------------------------------------------------------------------

export interface AxmlManifest {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: number;
  targetSdk?: number;
}

interface StringPool {
  strings: string[];
}

function parseStringPool(buf: Buffer, chunkStart: number): StringPool | null {
  try {
    const stringCount = buf.readUInt32LE(chunkStart + 8);
    const flags = buf.readUInt32LE(chunkStart + 16);
    const stringsStart = buf.readUInt32LE(chunkStart + 20);
    const isUtf8 = (flags & 0x100) !== 0;
    const offsetsBase = chunkStart + 28;
    const strings: string[] = [];
    for (let i = 0; i < Math.min(stringCount, 8192); i++) {
      const off = offsetsBase + i * 4;
      if (off + 4 > buf.length) break;
      const rel = buf.readUInt32LE(off);
      const abs = chunkStart + stringsStart + rel;
      if (abs >= buf.length) { strings.push(""); continue; }
      if (isUtf8) {
        // u8len (1-2 B) + u16len (1-2 B) sonra utf8 veri
        let p = abs;
        const skipVar = () => {
          const first = buf[p];
          if ((first & 0x80) !== 0) p += 2; else p += 1;
        };
        skipVar(); skipVar();
        let end = p;
        while (end < buf.length && buf[end] !== 0 && end - abs < 1024) end++;
        strings.push(buf.subarray(p, end).toString("utf8"));
      } else {
        const len = buf.readUInt16LE(abs);
        const dataStart = abs + 2;
        let s = "";
        for (let j = 0; j < len && dataStart + j * 2 + 1 < buf.length; j++) {
          s += String.fromCharCode(buf.readUInt16LE(dataStart + j * 2));
        }
        strings.push(s);
      }
    }
    return { strings };
  } catch {
    return null;
  }
}

function typedValueAsString(
  buf: Buffer,
  pool: StringPool,
  valOff: number,
): { str?: string; num?: number } {
  const dataType = buf[valOff + 3];
  const data = buf.readUInt32LE(valOff + 4);
  if (dataType === 0x03) return { str: pool.strings[data] }; // STRING
  if (dataType === 0x10) return { num: data | 0 }; // INT_DEC
  if (dataType === 0x11) return { num: data }; // INT_HEX
  if (dataType === 0x12) return { num: data ? 1 : 0 }; // BOOLEAN
  if (dataType === 0x01) return { num: undefined }; // REFERENCE -> atla
  return { num: data };
}

/** AndroidManifest.xml (binary) iceriginden paket adi/surum bilgisi. */
export function parseAxmlManifest(data: Buffer): AxmlManifest | null {
  try {
    if (data.length < 8) return null;
    if (data.readUInt16LE(0) !== 0x0003) return null; // RES_XML_TYPE
    let off = 8;
    let pool: StringPool | null = null;
    const result: AxmlManifest = {};
    let inManifest = false;
    let manifestNameIdx = -1;

    while (off + 8 <= data.length) {
      const type = data.readUInt16LE(off);
      const headerSize = data.readUInt16LE(off + 2);
      const size = data.readUInt32LE(off + 4);
      if (size < 8 || off + size > data.length) break;

      if (type === 0x0001 && !pool) {
        pool = parseStringPool(data, off);
      } else if (type === 0x0102 && pool) {
        // START_ELEMENT: 20 B header(8) + ext
        const ext = off + headerSize; // headerSize = 16 (8+8) genelde
        if (ext + 20 <= off + size) {
          const nameIdx = data.readUInt32LE(ext + 4);
          const attrStart = data.readUInt16LE(ext + 8);
          const attrSize = data.readUInt16LE(ext + 10);
          const attrCount = data.readUInt16LE(ext + 12);
          const elemName = pool.strings[nameIdx] ?? "";
          if (elemName === "manifest") {
            inManifest = true;
            manifestNameIdx = nameIdx;
            for (let a = 0; a < Math.min(attrCount, 32); a++) {
              const aOff = ext + attrStart + a * attrSize;
              if (aOff + 20 > off + size) break;
              const attrNameIdx = data.readUInt32LE(aOff + 4);
              const rawValueIdx = data.readUInt32LE(aOff + 8);
              const attrName = pool.strings[attrNameIdx] ?? "";
              const val = typedValueAsString(data, pool, aOff + 12);
              const rawStr = rawValueIdx !== 0xffffffff ? pool.strings[rawValueIdx] : undefined;
              switch (attrName) {
                case "package": result.packageName = rawStr ?? val.str; break;
                case "versionName": result.versionName = rawStr ?? val.str; break;
                case "versionCode": result.versionCode = rawStr ?? String(val.num ?? ""); break;
                case "minSdkVersion": result.minSdk = val.num; break;
                case "targetSdkVersion": result.targetSdk = val.num; break;
                case "compileSdkVersion": if (!result.targetSdk) result.targetSdk = val.num; break;
              }
            }
          }
        }
      }
      if (inManifest && type === 0x0103) {
        // END_ELEMENT manifest bitti mi? (kaba kontrol)
        if (pool && data.readUInt32LE(off + headerSize + 4) === manifestNameIdx) inManifest = false;
      }
      off += size;
    }
    return result;
  } catch {
    return null;
  }
}
