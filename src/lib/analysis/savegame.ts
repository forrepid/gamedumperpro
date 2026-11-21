// ----------------------------------------------------------------------------
// DumperPro Online - Unreal Engine save game (GVAS .sav) parser + serializer
//
// Unreal/Epic/Steam save game dosyalarini (sifreli/sifresiz) okur, agac
// seklinde duzenlenebilir property listesi uretir ve byte-perfect geri yazar.
//
// Format kaynagi: uesave-rs (PropertyTag/Header semantigi) + UE FSaveGameSerializer
// (UObject::SerializeTaggedProperties) davranisi. Yerlesim:
//
//   Header : "GVAS" | i32 saveGameFileVersion | i32 packageFileUE4Version
//            (fileVersion >= 3 ise i32 packageFileUE5Version)
//            | u16 major u16 minor u16 patch u32 changelist | FString branch
//            | i32 customVersionFormat | i32 count x { 16B GUID + i32 version }
//            | FString saveGameClassName
//   Props  : property tag'leri (name/type/size + tip extras + guid bayragi)
//            "None" FString'i ile biter.
//
// Property tag yerlesimi (uesave-rs ile ayni):
//   FString name, FString type, i64 size, sonra:
//     StructProperty  -> FString structType + 16B structGuid
//     BoolProperty    -> u8 boolVal (DEGER tag icinde; govde bos)
//     ByteProperty / EnumProperty -> FString enumName
//   ardindan u8 hasPropertyGuid (1 ise 16B guid) ve govde.
//   Dikkat: guid bayragi sayisal degerden ONCE gelir (uesave-rs siralamasi).
//
// Byte-perfect stratejisi:
//  - FString'ler ham baytlariyla korunur (rawStringBytes; latin1/utf16 imzasi
//    yazim sirasinda (deger, ham bayt) eslesmesinden turetilir).
//  - Taninmayan tipler "opaque" isaretlenir, ham baytlar saklanir ve oldugu
//    gibi geri yazilir (boylece oyun-ozel tipler bozulmaz).
//  - Sifreleme/sikistirma meta bayraklarina gore serializer tarafindan geri
//    uygulanir.
// ----------------------------------------------------------------------------

import crypto from "node:crypto";
import zlib from "node:zlib";

// ---------------------------------------------------------------------------
// tipler
// ---------------------------------------------------------------------------

export type SaveCipher = "aes-256-ecb" | "aes-256-cbc";

export type SavePropKind =
  | "int" | "int64" | "int16" | "int8" | "uint32" | "uint64" | "uint16"
  | "float" | "double" | "bool" | "byte" | "enum" | "str" | "name" | "object"
  | "softobject" | "struct" | "array" | "set" | "map" | "opaque";

export interface SavePropNode {
  kind: SavePropKind;
  name: string;
  /** ham tip adi ("IntProperty", "StructProperty", ...) */
  type: string;
  /** okunan/duzenlenebilir deger (sayisal/bool/string; kap tiplerinde tanimsiz) */
  value?: number | string | boolean | null;
  enumName?: string;
  structType?: string;
  structGuid?: string; // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  innerType?: string;
  /** struct icin tagged proplar / array-set ogeleri / softobject path+subPath */
  children?: SavePropNode[];
  /** map ciftleri */
  pairs?: { key: SavePropNode; value: SavePropNode }[];
  /** map anahtar/deger tip adlari ("IntProperty" vb) */
  keyType?: string;
  valueType?: string;
  /** opaque dugumun tum tag+govde ham baytlari (hex) - byte-perfect geri yazim */
  opaqueBytes?: string;
  /** FString orijinal encoding korumasi (latin1 hex; null terminator dahil) */
  rawStringBytes?: string;
  /** UE sayisal tiplerin govde sonundaki dolgu baytasi (1 bayt hex, genelde "00") */
  padHex?: string;
  /** dosyadaki orijinal Size alani (byte-perfect geri yazim icin) */
  sizeRaw?: number;
  /** applyEdits duzenlemesi yapildi mi (Size yeniden hesabi) */
  edited?: boolean;
  /** tag kuyrugu: hasPropertyGuid bayti (+ varsa 16B guid) hex - byte-perfect */
  tagTailHex?: string;
  /** duz metin tamponundaki mutlak offset (tag baslangici) */
  offset: number;
  /** tag+govde toplam bayt */
  size: number;
}

export interface SaveGameCustomVersion {
  guid: string;
  version: number;
}

export interface SaveGameHeader {
  fileVersion: number;
  ue4Version: number;
  ue5Version?: number;
  engineMajor: number;
  engineMinor: number;
  enginePatch: number;
  changelist: number;
  branch: string;
  /** FString orijinal baytlari (byte-perfect geri yazim; null dahil, uzunluk oneksiz) */
  branchRawHex?: string;
  customVersionFormat: number;
  customVersions: SaveGameCustomVersion[];
  className: string;
  classNameRawHex?: string;
}

export interface SaveGameMeta {
  originalSize: number;
  /** AES ile cozulduyse sifre adi ("aes-256-ecb" / "aes-256-cbc") */
  decryptedFrom?: string;
  inflated?: boolean;
  encrypted: boolean;
  compressed: boolean;
  propCount: number;
  /** cozum sonrasi gecerli PKCS#7 dolgu kesildi mi (kaydet'te geri uygulanir) */
  pkcsPadding?: boolean;
  /** meta uzerinden cipher/IV tasima (serialize varsayilanlari icin) */
  cipher?: SaveCipher;
  ivHex?: string;
}

export interface SaveGameDoc {
  header: SaveGameHeader;
  props: SavePropNode[];
  meta: SaveGameMeta;
}

export interface ParseSaveGameOpts {
  /** sifreli dosya icin 32 bayt (64 hex) anahtar */
  keyHex?: string;
  cipher?: SaveCipher;
  /** CBC icin 16 bayt (32 hex) IV; verilmezse sifir-IV denenir, olmazsa dosyanin ilk 16 bayti */
  ivHex?: string;
  /** UI gostergesi: FString'leri utf8 dene, olmazsa latin1'e dus (round-trip yine raw uzerinden) */
  decodeUtf8?: boolean;
}

export interface SerializeSaveGameOpts {
  keyHex?: string;
  cipher?: SaveCipher;
  ivHex?: string;
}

export interface SaveGameSummary {
  fileVersion: number;
  ue4Version: number;
  ue5Version?: number;
  engineVersion: string;
  className: string;
  propCount: number;
  structCount: number;
  arrayCount: number;
  mapCount: number;
  opaqueCount: number;
  stringSample: string[];
  encrypted: boolean;
  compressed: boolean;
}

// ---------------------------------------------------------------------------
// sabitler / kucuk yardimcilar
// ---------------------------------------------------------------------------

const GVAS_MAGIC = Buffer.from("GVAS", "latin1");
/** FString "None": len=5 + "None\0" */
const NONE_FSTRING = Buffer.from([0x05, 0x00, 0x00, 0x00, 0x4e, 0x6f, 0x6e, 0x65, 0x00]);
const NONE_SIZE = NONE_FSTRING.length; // 9

const MIN_I64 = -(2n ** 63n);
const MAX_I64 = 2n ** 63n - 1n;
const MAX_U64 = 2n ** 64n - 1n;

const utf8Strict = new TextDecoder("utf-8", { fatal: true });

function looksGvas(buf: Buffer): boolean {
  return buf.length >= 4 && buf.subarray(0, 4).equals(GVAS_MAGIC);
}

function looksZlib(buf: Buffer): boolean {
  return (
    buf.length >= 2 &&
    buf[0] === 0x78 &&
    (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda)
  );
}

function isAsciiOnly(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

function hexToGuid(hex: Buffer): string {
  const h = hex.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function guidToBytes(guid: string): Buffer {
  const clean = guid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(clean)) {
    throw new Error(`Gecersiz GUID: "${guid}" (32 hex karakter bekleniyor)`);
  }
  return Buffer.from(clean, "hex");
}

function fail(pos: number, msg: string): Error {
  return new Error(`SaveGame okuma hatasi @0x${pos.toString(16)}: ${msg}`);
}

// ---------------------------------------------------------------------------
// okuyucu / yazici
// ---------------------------------------------------------------------------

class Reader {
  pos = 0;
  constructor(private readonly buf: Buffer) {}

  remaining(): number {
    return this.buf.length - this.pos;
  }

  need(n: number, what: string): void {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw fail(this.pos, `yetersiz veri (${what}: ${n} bayt gerekli, ${this.remaining()} kaldi)`);
    }
  }

  slice(from: number, to: number): Buffer {
    if (from < 0 || to > this.buf.length || to < from) {
      throw fail(from, "gecersiz bayt araligi");
    }
    return this.buf.subarray(from, to);
  }

  u8(): number { this.need(1, "u8"); return this.buf[this.pos++]; }
  i8(): number { this.need(1, "i8"); return this.buf.readInt8(this.pos++); }
  u16(): number { this.need(2, "u16"); const v = this.buf.readUInt16LE(this.pos); this.pos += 2; return v; }
  i16(): number { this.need(2, "i16"); const v = this.buf.readInt16LE(this.pos); this.pos += 2; return v; }
  i32(): number { this.need(4, "i32"); const v = this.buf.readInt32LE(this.pos); this.pos += 4; return v; }
  u32(): number { this.need(4, "u32"); const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  f32(): number { this.need(4, "f32"); const v = this.buf.readFloatLE(this.pos); this.pos += 4; return v; }
  f64(): number { this.need(8, "f64"); const v = this.buf.readDoubleLE(this.pos); this.pos += 8; return v; }
  i64(): number { this.need(8, "i64"); const v = this.buf.readBigInt64LE(this.pos); this.pos += 8; return Number(v); }
  u64(): number { this.need(8, "u64"); const v = this.buf.readBigUInt64LE(this.pos); this.pos += 8; return Number(v); }
  bytes(n: number): Buffer { this.need(n, "ham bayt"); const b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b; }
}

class Writer {
  private parts: Buffer[] = [];
  private len = 0;

  raw(b: Buffer): void { this.parts.push(b); this.len += b.length; }
  u8(v: number): void { const b = Buffer.alloc(1); b.writeUInt8(v & 0xff); this.raw(b); }
  i8(v: number): void { const b = Buffer.alloc(1); b.writeInt8(v | 0); this.raw(b); }
  i16(v: number): void { const b = Buffer.alloc(2); b.writeInt16LE(v | 0); this.raw(b); }
  u16(v: number): void { const b = Buffer.alloc(2); b.writeUInt16LE(v >>> 0); this.raw(b); }
  i32(v: number): void { const b = Buffer.alloc(4); b.writeInt32LE(v | 0); this.raw(b); }
  u32(v: number): void { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); this.raw(b); }
  f32(v: number): void { const b = Buffer.alloc(4); b.writeFloatLE(v); this.raw(b); }
  f64(v: number): void { const b = Buffer.alloc(8); b.writeDoubleLE(v); this.raw(b); }
  i64(v: number): void {
    const b = Buffer.alloc(8);
    let big = BigInt(Math.trunc(Number.isFinite(v) ? v : 0));
    if (big < MIN_I64) big = MIN_I64;
    if (big > MAX_I64) big = MAX_I64;
    b.writeBigInt64LE(big);
    this.raw(b);
  }
  u64(v: number): void {
    const b = Buffer.alloc(8);
    let big = BigInt(Math.trunc(Number.isFinite(v) ? Math.max(v, 0) : 0));
    if (big > MAX_U64) big = MAX_U64;
    b.writeBigUInt64LE(big);
    this.raw(b);
  }
  toBuffer(): Buffer { return Buffer.concat(this.parts, this.len); }
}

// ---------------------------------------------------------------------------
// FString (raw korumali)
// ---------------------------------------------------------------------------

interface FStringRead { text: string; rawHex: string }

function readFString(r: Reader, decodeUtf8: boolean): FStringRead {
  const len = r.i32();
  if (len === 0) return { text: "", rawHex: "" };
  if (len > 0) {
    if (len > r.remaining()) throw fail(r.pos - 4, `FString uzunlugu dosya disinda (${len})`);
    const raw = r.bytes(len);
    const body = raw.subarray(0, len - 1); // null terminator haric
    let text: string;
    if (decodeUtf8) {
      try {
        text = utf8Strict.decode(body);
      } catch {
        text = body.toString("latin1");
      }
    } else {
      // latin1: bayt korumali (utf8 yorumu yok - byte-perfect hedefi)
      text = body.toString("latin1");
    }
    return { text, rawHex: raw.toString("hex") };
  }
  // negatif len: UTF-16LE, karakter sayisi -len (null dahil)
  const chars = -len;
  const raw = r.bytes(chars * 2);
  const text = chars > 1 ? raw.subarray(0, (chars - 1) * 2).toString("utf16le") : "";
  return { text, rawHex: raw.toString("hex") };
}

/**
 * Yazim icin FString encoding secimi. rawStringBytes varsa (deger, ham bayt)
 * eslesmesinden orijinal imza (pozitif=1 bayt / negatif=utf16) turetilir; eslesme
 * yoksa (deger duzenlenmistir) uesave-rs konvansiyonu uygulanir: tam ASCII ->
 * pozitif, degilse UTF-16 negatif.
 */
function fstringEncodingFor(value: string, rawHex?: string): { len: number; bytes: Buffer } {
  if (rawHex) {
    const raw = Buffer.from(rawHex, "hex");
    if (raw.length > 0) {
      // negatif hipotez: utf16le(value) + 00 00
      const u16 = Buffer.from(value, "utf16le");
      if (
        raw.length === u16.length + 2 &&
        raw[raw.length - 1] === 0 &&
        raw[raw.length - 2] === 0 &&
        raw.subarray(0, u16.length).equals(u16)
      ) {
        return { len: -(value.length + 1), bytes: raw };
      }
      // pozitif hipotez 1: latin1(value) + 00 (bayt korumali okuma)
      const l1 = Buffer.from(value, "latin1");
      if (
        raw.length === l1.length + 1 &&
        raw[raw.length - 1] === 0 &&
        raw.subarray(0, l1.length).equals(l1)
      ) {
        return { len: raw.length, bytes: raw };
      }
      // pozitif hipotez 2: utf8(value) + 00 (decodeUtf8 okumasi)
      const u8 = Buffer.from(value, "utf8");
      if (
        raw.length === u8.length + 1 &&
        raw[raw.length - 1] === 0 &&
        raw.subarray(0, u8.length).equals(u8)
      ) {
        return { len: raw.length, bytes: raw };
      }
    }
  }
  if (isAsciiOnly(value)) {
    return { len: value.length + 1, bytes: Buffer.concat([Buffer.from(value, "latin1"), Buffer.from([0])]) };
  }
  return { len: -(value.length + 1), bytes: Buffer.concat([Buffer.from(value, "utf16le"), Buffer.from([0, 0])]) };
}

function writeFStringOf(w: Writer, value: string, rawHex?: string): void {
  const enc = fstringEncodingFor(value, rawHex);
  w.i32(enc.len);
  w.raw(enc.bytes);
}

function fstringEncodedSize(value: string, rawHex?: string): number {
  return 4 + fstringEncodingFor(value, rawHex).bytes.length;
}

/** yapisal adlar (tip adi, structType, enum adi, class adi...) icin ASCII FString */
function writeAsciiFString(w: Writer, s: string): void {
  const b = Buffer.from(s, "utf8");
  w.i32(b.length + 1);
  w.raw(b);
  w.u8(0);
}

function asciiFStringSize(s: string): number {
  return 4 + Buffer.byteLength(s, "utf8") + 1;
}

// ---------------------------------------------------------------------------
// tip tablosu
// ---------------------------------------------------------------------------

const NUMERIC_KINDS: Record<string, { kind: SavePropKind; size: number }> = {
  IntProperty: { kind: "int", size: 4 },
  Int64Property: { kind: "int64", size: 8 },
  Int16Property: { kind: "int16", size: 2 },
  Int8Property: { kind: "int8", size: 1 },
  UInt32Property: { kind: "uint32", size: 4 },
  UInt64Property: { kind: "uint64", size: 8 },
  UInt16Property: { kind: "uint16", size: 2 },
  FloatProperty: { kind: "float", size: 4 },
  DoubleProperty: { kind: "double", size: 8 },
};

const STRING_KINDS: Record<string, SavePropKind> = {
  StrProperty: "str",
  NameProperty: "name",
  ObjectProperty: "object",
};

function isKnownPropType(type: string): boolean {
  return (
    type in NUMERIC_KINDS ||
    type === "BoolProperty" || type === "ByteProperty" || type === "EnumProperty" ||
    type in STRING_KINDS ||
    type === "SoftObjectProperty" || type === "InterfaceProperty" ||
    type === "StructProperty" || type === "ArrayProperty" || type === "SetProperty" ||
    type === "MapProperty"
  );
}

// ---------------------------------------------------------------------------
// okuma: header + property agaci
// ---------------------------------------------------------------------------

function readHeader(r: Reader, decodeUtf8: boolean): SaveGameHeader {
  const start = r.pos;
  const magic = r.bytes(4);
  if (!magic.equals(GVAS_MAGIC)) throw fail(start, "GVAS imzasi yok");

  const fileVersion = r.i32();
  if (fileVersion < 0 || fileVersion > 100) {
    throw fail(start + 4, `saveGameFileVersion beklenmedik: ${fileVersion}`);
  }
  const ue4Version = r.i32();
  const ue5Version = fileVersion >= 3 ? r.i32() : undefined;

  const engineMajor = r.u16();
  const engineMinor = r.u16();
  const enginePatch = r.u16();
  const changelist = r.u32();
  const branchRead = readFString(r, decodeUtf8);

  const customVersionFormat = r.i32();
  const cvCount = r.i32();
  if (cvCount < 0 || cvCount > 1024) {
    throw fail(r.pos - 4, `customVersionCount beklenmedik: ${cvCount}`);
  }
  const customVersions: SaveGameCustomVersion[] = [];
  for (let i = 0; i < cvCount; i++) {
    const guid = hexToGuid(r.bytes(16));
    const version = r.i32();
    customVersions.push({ guid, version });
  }

  const classNameRead = readFString(r, decodeUtf8);
  return {
    fileVersion,
    ue4Version,
    ue5Version,
    engineMajor,
    engineMinor,
    enginePatch,
    changelist,
    branch: branchRead.text,
    branchRawHex: branchRead.rawHex || undefined,
    customVersionFormat,
    customVersions,
    className: classNameRead.text,
    classNameRawHex: classNameRead.rawHex || undefined,
  };
}

/** tag govdesini okur (name zaten okunmus); bilinmeyen tip -> opaque */
function readTagAndBody(r: Reader, name: string, type: string, size: number, tagStart: number, decodeUtf8: boolean): SavePropNode {
  const base = (over: Partial<SavePropNode>): SavePropNode => ({
    kind: "opaque",
    name,
    type,
    offset: tagStart,
    size: 0,
    sizeRaw: size,
    ...over,
  });

  // --- tip extras (tag icinde) ---
  let node: SavePropNode | null = null;

  if (type in NUMERIC_KINDS) {
    const spec = NUMERIC_KINDS[type]!;
    const tail = readTagTail(r);
    let value: number;
    switch (spec.kind) {
      case "int": value = r.i32(); break;
      case "int64": value = r.i64(); break;
      case "int16": value = r.i16(); break;
      case "int8": value = r.i8(); break;
      case "uint32": value = r.u32(); break;
      case "uint64": value = r.u64(); break;
      case "uint16": value = r.u16(); break;
      case "float": value = r.f32(); break;
      case "double": value = r.f64(); break;
      default: throw fail(r.pos, "bilinmeyen sayisal tip");
    }
    // UE sayisal tipler govde sonunda 1 dolgu baytasi tasir (uesave-rs padding)
    const pad = r.u8();
    node = base({
      kind: spec.kind,
      tagTailHex: tail,
      value,
      padHex: pad.toString(16).padStart(2, "0"),
    });
  } else if (type === "BoolProperty") {
    const boolVal = r.u8();
    const tail = readTagTail(r);
    node = base({ kind: "bool", tagTailHex: tail, value: boolVal !== 0 });
  } else if (type === "ByteProperty" || type === "EnumProperty") {
    // once tag kuyrugu (hasPropertyGuid), sonra govde: enumName + deger (UE/uesave semantigi)
    const tail = readTagTail(r);
    if (type === "ByteProperty") {
      // enum'suz ByteProperty govdesi tek bayttir (Size==1)
      const enumName = size !== 1 ? readFString(r, decodeUtf8).text : undefined;
      const value = r.u8();
      node = base({ kind: "byte", enumName, tagTailHex: tail, value });
    } else {
      const enumName = readFString(r, decodeUtf8).text;
      const val = readFString(r, decodeUtf8);
      node = base({ kind: "enum", enumName, tagTailHex: tail, value: val.text, rawStringBytes: val.rawHex });
    }
  } else if (type in STRING_KINDS) {
    const tail = readTagTail(r);
    const val = readFString(r, decodeUtf8);
    node = base({ kind: STRING_KINDS[type]!, tagTailHex: tail, value: val.text, rawStringBytes: val.rawHex });
  } else if (type === "SoftObjectProperty" || type === "InterfaceProperty") {
    const tail = readTagTail(r);
    const path = readFString(r, decodeUtf8);
    const sub = readFString(r, decodeUtf8);
    const pathNode: SavePropNode = { kind: "str", name: "SourcePath", type: "FString", value: path.text, rawStringBytes: path.rawHex, offset: 0, size: 0 };
    const subNode: SavePropNode = { kind: "str", name: "SubPath", type: "FString", value: sub.text, rawStringBytes: sub.rawHex, offset: 0, size: 0 };
    node = base({ kind: "softobject", tagTailHex: tail, value: path.text, children: [pathNode, subNode] });
  } else if (type === "StructProperty") {
    const structType = readFString(r, decodeUtf8).text;
    const structGuid = hexToGuid(r.bytes(16));
    const tail = readTagTail(r);
    const children = readTaggedProps(r, decodeUtf8);
    node = base({ kind: "struct", structType, structGuid, tagTailHex: tail, children });
  } else if (type === "ArrayProperty" || type === "SetProperty") {
    // once tag kuyrugu, sonra govde: innerType + count + ogeler
    const tail = readTagTail(r);
    const innerType = readFString(r, decodeUtf8).text;
    if (!isKnownPropType(innerType)) {
      // bilinmeyen ic tip: govde kalanini ham al, tum tag'i opaque yap
      return finishOpaque(r, node, size, tagStart);
    }
    const count = r.i32();
    if (count < 0 || count > r.remaining()) {
      throw fail(r.pos - 4, `array oge sayisi gecersiz: ${count}`);
    }
    const children: SavePropNode[] = [];
    if (innerType === "StructProperty") {
      for (let i = 0; i < count; i++) {
        const elStart = r.pos;
        const elChildren = readTaggedProps(r, decodeUtf8);
        children.push({
          kind: "struct",
          name: "",
          type: "StructProperty",
          structType: "",
          children: elChildren,
          offset: elStart,
          size: r.pos - elStart,
        });
      }
    } else {
      for (let i = 0; i < count; i++) {
        children.push(readBodyOnly(r, innerType, decodeUtf8));
      }
    }
    node = base({ kind: type === "ArrayProperty" ? "array" : "set", innerType, tagTailHex: tail, children });
  } else if (type === "MapProperty") {
    // once tag kuyrugu, sonra govde: keyType + valueType + count + ciftler
    const tail = readTagTail(r);
    const keyType = readFString(r, decodeUtf8).text;
    const valueType = readFString(r, decodeUtf8).text;
    if (!isKnownPropType(keyType) || !isKnownPropType(valueType)) {
      return finishOpaque(r, node, size, tagStart);
    }
    const count = r.i32();
    if (count < 0 || count > r.remaining()) {
      throw fail(r.pos - 4, `map cift sayisi gecersiz: ${count}`);
    }
    const pairs: { key: SavePropNode; value: SavePropNode }[] = [];
    for (let i = 0; i < count; i++) {
      const key = readFullProp(r, decodeUtf8);
      const value = readFullProp(r, decodeUtf8);
      pairs.push({ key, value });
    }
    node = base({ kind: "map", keyType, valueType, tagTailHex: tail, pairs });
  } else {
    // bilinmeyen tip: govde = tag.size bayt; tum tag opaque olarak saklanir
    return finishOpaque(r, node, size, tagStart);
  }

  node!.size = r.pos - tagStart;
  return node!;
}

/** hasPropertyGuid bayti (+1 ise 16B guid); byte-perfect icin hex olarak korunur */
function readTagTail(r: Reader): string | undefined {
  const flag = r.u8();
  if (flag === 0) return undefined;
  if (flag === 1) {
    const guid = r.bytes(16);
    return Buffer.concat([Buffer.from([flag]), guid]).toString("hex");
  }
  // bozuk bayrak: yine de koru
  return Buffer.from([flag]).toString("hex");
}

/** okunan tag+govde araligini opaque node'a cevirir */
function finishOpaque(r: Reader, partial: SavePropNode | null, size: number, tagStart: number): SavePropNode {
  if (size < 0 || size > r.remaining()) {
    throw fail(r.pos, `opaque govde boyu dosya disinda (${size})`);
  }
  const body = r.bytes(size);
  const base: SavePropNode = partial ?? {
    kind: "opaque",
    name: "",
    type: "",
    offset: tagStart,
    size: 0,
  };
  return {
    ...base,
    kind: "opaque",
    opaqueBytes: r.slice(tagStart, r.pos).toString("hex"),
    size: body.length + (r.pos - tagStart - body.length),
  };
}

/** tag'siz tek deger (array/set ogeleri icin) */
function readBodyOnly(r: Reader, innerType: string, decodeUtf8: boolean): SavePropNode {
  const start = r.pos;
  if (innerType in NUMERIC_KINDS) {
    const spec = NUMERIC_KINDS[innerType]!;
    let value: number;
    switch (spec.kind) {
      case "int": value = r.i32(); break;
      case "int64": value = r.i64(); break;
      case "int16": value = r.i16(); break;
      case "int8": value = r.i8(); break;
      case "uint32": value = r.u32(); break;
      case "uint64": value = r.u64(); break;
      case "uint16": value = r.u16(); break;
      case "float": value = r.f32(); break;
      case "double": value = r.f64(); break;
      default: throw fail(start, "bilinmeyen sayisal ic tip");
    }
    // dizi/set ogelerinde de dolgu baytasi var
    const pad = r.u8();
    return {
      kind: spec.kind,
      name: "",
      type: innerType,
      value,
      padHex: pad.toString(16).padStart(2, "0"),
      offset: start,
      size: r.pos - start,
    };
  }
  if (innerType === "ByteProperty") {
    return { kind: "byte", name: "", type: innerType, value: r.u8(), offset: start, size: r.pos - start };
  }
  if (innerType === "EnumProperty" || innerType in STRING_KINDS) {
    const val = readFString(r, decodeUtf8);
    return {
      kind: innerType === "EnumProperty" ? "enum" : STRING_KINDS[innerType]!,
      name: "",
      type: innerType,
      value: val.text,
      rawStringBytes: val.rawHex,
      offset: start,
      size: r.pos - start,
    };
  }
  if (innerType === "SoftObjectProperty" || innerType === "InterfaceProperty") {
    const path = readFString(r, decodeUtf8);
    const sub = readFString(r, decodeUtf8);
    return {
      kind: "softobject",
      name: "",
      type: innerType,
      value: path.text,
      children: [
        { kind: "str", name: "SourcePath", type: "FString", value: path.text, rawStringBytes: path.rawHex, offset: 0, size: 0 },
        { kind: "str", name: "SubPath", type: "FString", value: sub.text, rawStringBytes: sub.rawHex, offset: 0, size: 0 },
      ],
      offset: start,
      size: r.pos - start,
    };
  }
  throw fail(start, `bilinmeyen array ic tipi: ${innerType}`);
}

/** tam property tag'i okur: name + type + size + extras + tail + govde (map ciftleri icin) */
function readFullProp(r: Reader, decodeUtf8: boolean): SavePropNode {
  const tagStart = r.pos;
  const name = readFString(r, decodeUtf8).text;
  const type = readFString(r, decodeUtf8).text;
  const size = r.i64();
  if (size < 0 || size > r.remaining()) {
    throw fail(r.pos - 8, `property boyu dosya disinda (${name}: ${size})`);
  }
  return readTagAndBody(r, name, type, size, tagStart, decodeUtf8);
}

/** "None" ile biten tagged prop listesi (kok seviyesi + struct govdesi + array struct ogeleri) */
function readTaggedProps(r: Reader, decodeUtf8: boolean): SavePropNode[] {
  const out: SavePropNode[] = [];
  for (;;) {
    const tagStart = r.pos;
    const name = readFString(r, decodeUtf8).text;
    if (name === "None") return out;
    const type = readFString(r, decodeUtf8).text;
    const size = r.i64();
    if (size < 0 || size > r.remaining()) {
      throw fail(r.pos - 8, `property boyu dosya disinda (${name}: ${size})`);
    }
    out.push(readTagAndBody(r, name, type, size, tagStart, decodeUtf8));
  }
}

// ---------------------------------------------------------------------------
// yazim: header + property agaci (+ boyut hesabi)
// ---------------------------------------------------------------------------

function writeHeader(w: Writer, h: SaveGameHeader): void {
  w.raw(GVAS_MAGIC);
  w.i32(h.fileVersion);
  w.i32(h.ue4Version);
  if (h.fileVersion >= 3) w.i32(h.ue5Version ?? 0);
  w.u16(h.engineMajor);
  w.u16(h.engineMinor);
  w.u16(h.enginePatch);
  w.u32(h.changelist);
  if (h.branchRawHex) {
    writeFStringOf(w, h.branch, h.branchRawHex);
  } else {
    writeAsciiFString(w, h.branch);
  }
  w.i32(h.customVersionFormat ?? 3);
  w.i32(h.customVersions.length);
  for (const cv of h.customVersions) {
    w.raw(guidToBytes(cv.guid));
    w.i32(cv.version);
  }
  if (h.classNameRawHex) {
    writeFStringOf(w, h.className, h.classNameRawHex);
  } else {
    writeAsciiFString(w, h.className);
  }
}

/** yazim sirasinda tag kuyrugu (hasPropertyGuid + guid) */
function writeTagTail(w: Writer, node: SavePropNode): void {
  if (node.tagTailHex && node.tagTailHex.length > 0) {
    w.raw(Buffer.from(node.tagTailHex, "hex"));
  } else {
    w.u8(0);
  }
}

function tagSizeOf(node: SavePropNode): number {
  let n = asciiFStringSize(node.name) + asciiFStringSize(node.type) + 8;
  if (node.type === "StructProperty") n += asciiFStringSize(node.structType ?? "") + 16;
  else if (node.type === "BoolProperty") n += 1; // bool degeri tag icinde
  n += node.tagTailHex ? node.tagTailHex.length / 2 : 1;
  return n;
}

function bodySizeOf(node: SavePropNode): number {
  switch (node.kind) {
    // sayisal tipler + 1 dolgu baytasi (UE padding)
    case "int": case "float": case "uint32": return 5;
    case "int64": case "uint64": case "double": return 9;
    case "int16": case "uint16": return 3;
    case "int8": return 2;
    case "byte": return node.enumName ? asciiFStringSize(node.enumName) + 1 : 1;
    case "bool": return 0;
    case "enum":
      return asciiFStringSize(node.enumName ?? "") + fstringEncodedSize(String(node.value ?? ""), node.rawStringBytes);
    case "str": case "name": case "object":
      return fstringEncodedSize(String(node.value ?? ""), node.rawStringBytes);
    case "softobject": {
      const kids = node.children ?? [];
      const a = kids[0];
      const b = kids[1];
      return (
        fstringEncodedSize(String(a?.value ?? ""), a?.rawStringBytes) +
        fstringEncodedSize(String(b?.value ?? ""), b?.rawStringBytes)
      );
    }
    case "struct": {
      let n = NONE_SIZE;
      for (const c of node.children ?? []) n += propSizeOf(c);
      return n;
    }
    case "array": case "set": {
      let n = asciiFStringSize(node.innerType ?? "") + 4;
      for (const el of node.children ?? []) {
        if ((node.innerType ?? "") === "StructProperty" && el.kind === "struct") {
          n += NONE_SIZE;
          for (const c of el.children ?? []) n += propSizeOf(c);
        } else {
          n += bodySizeOf(el);
        }
      }
      return n;
    }
    case "map": {
      let n = asciiFStringSize(node.keyType ?? "") + asciiFStringSize(node.valueType ?? "") + 4;
      for (const p of node.pairs ?? []) n += propSizeOf(p.key) + propSizeOf(p.value);
      return n;
    }
    case "opaque":
      return (node.opaqueBytes?.length ?? 0) / 2;
    default:
      return 0;
  }
}

/** Size alani: degistirilmemis dugumlerde orijinal deger, duzenlendiyse yeniden hesap */
function bodySizeEffective(node: SavePropNode): number {
  if (!node.edited && node.sizeRaw !== undefined && node.sizeRaw >= 0) return node.sizeRaw;
  return bodySizeOf(node);
}

function propSizeOf(node: SavePropNode): number {
  if (node.kind === "opaque") return (node.opaqueBytes?.length ?? 0) / 2;
  return tagSizeOf(node) + bodySizeEffective(node);
}

/** dolgu baytasi (varsayilan 0x00) */
function padByteOf(node: SavePropNode): number {
  const n = parseInt(node.padHex ?? "00", 16);
  return Number.isFinite(n) ? n : 0;
}

function writeBody(w: Writer, node: SavePropNode): void {
  switch (node.kind) {
    // isaretsiz turler kendi yazicilarindan gecer (u32/u64/u16) — buyuk
    // degerlerde i32/i64 kesme hatasi olmasin (byte-perfect yazim)
    case "int": w.i32(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "uint32": w.u32(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "int64": w.i64(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "uint64": w.u64(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "int16": w.i16(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "uint16": w.u16(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "int8": w.i8(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "float": w.f32(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "double": w.f64(Number(node.value ?? 0)); w.u8(padByteOf(node)); break;
    case "bool": break; // deger tag icinde yazildi
    case "byte":
      if (node.enumName) writeAsciiFString(w, node.enumName);
      w.u8(Number(node.value ?? 0) & 0xff);
      break;
    case "enum":
      writeAsciiFString(w, node.enumName ?? "");
      writeFStringOf(w, String(node.value ?? ""), node.rawStringBytes);
      break;
    case "str":
    case "name":
    case "object":
      writeFStringOf(w, String(node.value ?? ""), node.rawStringBytes);
      break;
    case "softobject": {
      const kids = node.children ?? [];
      writeFStringOf(w, String(kids[0]?.value ?? ""), kids[0]?.rawStringBytes);
      writeFStringOf(w, String(kids[1]?.value ?? ""), kids[1]?.rawStringBytes);
      break;
    }
    case "struct":
      writeTaggedProps(w, node.children ?? []);
      break;
    case "array":
    case "set": {
      writeAsciiFString(w, node.innerType ?? "");
      const kids = node.children ?? [];
      w.i32(kids.length);
      for (const el of kids) {
        if ((node.innerType ?? "") === "StructProperty" && el.kind === "struct") {
          writeTaggedProps(w, el.children ?? []);
        } else {
          writeBody(w, el);
        }
      }
      break;
    }
    case "map": {
      writeAsciiFString(w, node.keyType ?? "");
      writeAsciiFString(w, node.valueType ?? "");
      const pairs = node.pairs ?? [];
      w.i32(pairs.length);
      for (const p of pairs) {
        writeProp(w, p.key);
        writeProp(w, p.value);
      }
      break;
    }
    case "opaque":
      w.raw(Buffer.from(node.opaqueBytes ?? "", "hex"));
      break;
    default:
      break;
  }
}

/** tek property: tag (header+extras+tail) + govde; opaque ise ham baytlar */
function writeProp(w: Writer, node: SavePropNode): void {
  if (node.kind === "opaque") {
    w.raw(Buffer.from(node.opaqueBytes ?? "", "hex"));
    return;
  }
  writeAsciiFString(w, node.name);
  writeAsciiFString(w, node.type);
  // Size: degistirilmemis dugumlerde orijinal deger korunur (byte-perfect)
  w.i64(bodySizeEffective(node));
  if (node.type === "StructProperty") {
    writeAsciiFString(w, node.structType ?? "");
    w.raw(node.structGuid ? guidToBytes(node.structGuid) : Buffer.alloc(16));
  } else if (node.type === "BoolProperty") {
    w.u8(node.value ? 1 : 0);
  }
  writeTagTail(w, node);
  writeBody(w, node);
}

function writeTaggedProps(w: Writer, children: SavePropNode[]): void {
  for (const c of children) writeProp(w, c);
  w.raw(NONE_FSTRING);
}

// ---------------------------------------------------------------------------
// sifreleme (UE FAES stili AES-256)
// ---------------------------------------------------------------------------

function parseKeyHex(keyHex: string, what: string): Buffer {
  const clean = keyHex.trim().toLowerCase().replace(/\s+/g, "");
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`${what}: keyHex gecersiz - 32 bayt (64 hex karakter) bekleniyor`);
  }
  return Buffer.from(clean, "hex");
}

function parseIvHex(ivHex: string | undefined, what: string): Buffer {
  if (ivHex === undefined) return Buffer.alloc(16);
  const clean = ivHex.trim().toLowerCase().replace(/\s+/g, "");
  if (!/^[0-9a-f]{32}$/.test(clean)) {
    throw new Error(`${what}: ivHex gecersiz - 16 bayt (32 hex karakter) bekleniyor`);
  }
  return Buffer.from(clean, "hex");
}

function pkcsPad(data: Buffer): Buffer {
  const pad = 16 - (data.length % 16);
  return Buffer.concat([data, Buffer.alloc(pad, pad)]);
}

function pkcsValid(data: Buffer): number {
  if (data.length === 0 || data.length % 16 !== 0) return 0;
  const n = data[data.length - 1]!;
  if (n < 1 || n > 16) return 0;
  for (let i = data.length - n; i < data.length; i++) {
    if (data[i] !== n) return 0;
  }
  return n;
}

function blockPad(data: Buffer, usePkcs: boolean): Buffer {
  if (usePkcs) return pkcsPad(data);
  const rem = data.length % 16;
  return rem === 0 ? data : Buffer.concat([data, Buffer.alloc(16 - rem)]);
}

interface DecryptedPlain {
  data: Buffer;
  pkcsPadding: boolean;
  ivHex?: string;
}

function decryptPlain(buf: Buffer, keyHex: string, cipher: SaveCipher, opts: { ivHex?: string } = {}): DecryptedPlain {
  const key = parseKeyHex(keyHex, "SaveGame AES");
  if (buf.length === 0 || buf.length % 16 !== 0) {
    throw new Error(`SaveGame AES: sifreli veri 16 baytin kati olmali (mevcut: ${buf.length})`);
  }

  const tryDecrypt = (ct: Buffer, iv: Buffer): Buffer => {
    const d = crypto.createDecipheriv(cipher === "aes-256-cbc" ? "aes-256-cbc" : "aes-256-ecb", key, cipher === "aes-256-cbc" ? iv : null);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(ct), d.final()]);
  };

  const plausible = (b: Buffer): boolean => looksGvas(b) || looksZlib(b);

  let plain: Buffer;
  let usedIvHex: string | undefined;
  if (cipher === "aes-256-cbc") {
    const iv = parseIvHex(opts.ivHex, "SaveGame AES-CBC");
    plain = tryDecrypt(buf, iv);
    usedIvHex = opts.ivHex ? iv.toString("hex") : undefined;
    if (!plausible(plain) && !opts.ivHex && buf.length >= 32) {
      // IV dosyanin basinda gomulu olabilir: ilk 16 bayt IV, kalan ciphertext
      const embeddedIv = buf.subarray(0, 16);
      plain = tryDecrypt(buf.subarray(16), embeddedIv);
      usedIvHex = embeddedIv.toString("hex");
    }
  } else {
    plain = tryDecrypt(buf, Buffer.alloc(0));
  }

  if (!plausible(plain)) {
    const stripped = pkcsValid(plain);
    if (stripped > 0 && plausible(plain.subarray(0, plain.length - stripped))) {
      plain = plain.subarray(0, plain.length - stripped);
    } else {
      throw new Error(
        `SaveGame AES-256 ${cipher === "aes-256-cbc" ? "CBC" : "ECB"} cozumleme basarisiz: ilk blok GVAS/zlib imzasi tasimiyor (anahtar hatali olabilir)`,
      );
    }
  }

  const pkcs = pkcsValid(plain);
  return {
    data: pkcs > 0 ? plain.subarray(0, plain.length - pkcs) : plain,
    pkcsPadding: pkcs > 0,
    ivHex: usedIvHex,
  };
}

function encryptPlain(buf: Buffer, keyHex: string, cipher: SaveCipher, opts: { ivHex?: string; pkcsPadding?: boolean } = {}): Buffer {
  const key = parseKeyHex(keyHex, "SaveGame AES");
  const padded = blockPad(buf, opts.pkcsPadding === true);
  if (cipher === "aes-256-cbc") {
    const iv = parseIvHex(opts.ivHex, "SaveGame AES-CBC");
    const c = crypto.createCipheriv("aes-256-cbc", key, iv);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(padded), c.final()]);
  }
  const c = crypto.createCipheriv("aes-256-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(padded), c.final()]);
}

/** Standalone AES cozumleme (parseSaveGame (c) adimi). Turkce hata firlatir. */
export function decryptSaveGame(buf: Buffer, keyHex: string, cipher: SaveCipher = "aes-256-ecb", opts: { ivHex?: string } = {}): Buffer {
  return decryptPlain(buf, keyHex, cipher, opts).data;
}

/** Standalone AES sifreleme (serializeSaveGame tersi). */
export function encryptSaveGame(buf: Buffer, keyHex: string, cipher: SaveCipher = "aes-256-ecb", opts: { ivHex?: string; pkcsPadding?: boolean } = {}): Buffer {
  return encryptPlain(buf, keyHex, cipher, opts);
}

// ---------------------------------------------------------------------------
// parse / serialize
// ---------------------------------------------------------------------------

export function parseSaveGame(buf: Buffer, opts: ParseSaveGameOpts = {}): SaveGameDoc {
  const meta: SaveGameMeta = {
    originalSize: buf.length,
    encrypted: false,
    compressed: false,
    inflated: false,
    propCount: 0,
  };
  let work = buf;

  if (looksGvas(work)) {
    // duz dosya
  } else if (looksZlib(work)) {
    try {
      work = zlib.inflateSync(work);
    } catch (e) {
      throw new Error(`SaveGame zlib acma hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }
    meta.compressed = true;
    meta.inflated = true;
    if (!looksGvas(work)) {
      throw new Error("SaveGame: zlib akisi acildi ancak icerik GVAS imzasi tasimiyor");
    }
  } else if (opts.keyHex) {
    const cipher = opts.cipher ?? "aes-256-ecb";
    const dec = decryptPlain(buf, opts.keyHex, cipher, { ivHex: opts.ivHex });
    meta.encrypted = true;
    meta.cipher = cipher;
    meta.decryptedFrom = `${cipher}${dec.pkcsPadding ? "+pkcs7" : ""}`;
    meta.pkcsPadding = dec.pkcsPadding || undefined;
    meta.ivHex = dec.ivHex;
    work = dec.data;
    if (looksZlib(work)) {
      try {
        work = zlib.inflateSync(work);
      } catch (e) {
        throw new Error(`SaveGame zlib acma hatasi (sifreleme sonrasi): ${e instanceof Error ? e.message : String(e)}`);
      }
      meta.compressed = true;
      meta.inflated = true;
    }
    if (!looksGvas(work)) {
      throw new Error("SaveGame: AES cozumleme sonrasi GVAS imzasi bulunamadi");
    }
  } else {
    throw new Error(
      "SaveGame okunamadi: GVAS imzasi yok ve zlib akisi degil. Dosya AES ile sifreli olabilir - keyHex (32 bayt hex) secenegini verin.",
    );
  }

  const r = new Reader(work);
  const header = readHeader(r, opts.decodeUtf8 === true);
  const props = readTaggedProps(r, opts.decodeUtf8 === true);
  meta.propCount = countProps(props);
  return { header, props, meta };
}

function countProps(nodes: SavePropNode[]): number {
  let n = 0;
  const walk = (list: SavePropNode[]): void => {
    for (const nd of list) {
      n++;
      if (nd.children) walk(nd.children);
      if (nd.pairs) {
        for (const p of nd.pairs) {
          walk([p.key]);
          walk([p.value]);
        }
      }
    }
  };
  walk(nodes);
  return n;
}

export function serializeSaveGame(doc: SaveGameDoc, opts: SerializeSaveGameOpts = {}): Buffer {
  const w = new Writer();
  writeHeader(w, doc.header);
  for (const p of doc.props) writeProp(w, p);
  w.raw(NONE_FSTRING);
  let plain = w.toBuffer();

  if (doc.meta.compressed) {
    plain = zlib.deflateSync(plain);
  }
  if (doc.meta.encrypted) {
    const cipher = opts.cipher ?? doc.meta.cipher ?? "aes-256-ecb";
    if (!opts.keyHex) {
      throw new Error("Sifreli save game kaydedilemedi: sifreli dosya icin keyHex gerekli");
    }
    plain = encryptPlain(plain, opts.keyHex, cipher, {
      ivHex: opts.ivHex ?? doc.meta.ivHex,
      pkcsPadding: doc.meta.pkcsPadding === true,
    });
  }
  return plain;
}

// ---------------------------------------------------------------------------
// duzenleme (path: "PlayerState.Health", "Inventory[1].Name", "Loot[key=3]")
// ---------------------------------------------------------------------------

const NUMERIC_RANGES: Record<string, [number, number]> = {
  int: [-2147483648, 2147483647],
  uint32: [0, 4294967295],
  int16: [-32768, 32767],
  uint16: [0, 65535],
  int8: [-128, 127],
  byte: [0, 255],
};

function applyIndex(node: SavePropNode, idx: string, path: string): SavePropNode {
  if (node.kind === "array" || node.kind === "set") {
    const m = /^\d+$/.exec(idx);
    if (!m) throw new Error(`dizi indeksi gecersiz: [${idx}] (dizi icin sayi kullanin)`);
    const i = parseInt(idx, 10);
    const kids = node.children ?? [];
    if (i >= kids.length) throw new Error(`dizi indeksi sinir disinda: ${path} (uzunluk ${kids.length})`);
    return kids[i]!;
  }
  if (node.kind === "map") {
    const keyMatch = /^key=(.*)$/s.exec(idx);
    const pairs = node.pairs ?? [];
    if (keyMatch) {
      const wanted = keyMatch[1]!;
      const found = pairs.find((p) => stringifyKey(p.key) === wanted || (isNumericKind(p.key.kind) && Number(p.key.value) === Number(wanted)));
      if (!found) throw new Error(`map anahtari bulunamadi: [${idx}]`);
      return found.value;
    }
    if (/^\d+$/.test(idx)) {
      const i = parseInt(idx, 10);
      if (i >= pairs.length) throw new Error(`map cift indeksi sinir disinda: ${path} (${pairs.length} cift)`);
      return pairs[i]!.value;
    }
    throw new Error(`map indeksi gecersiz: [${idx}] (map icin [key=deger] kullanin)`);
  }
  if (node.kind === "struct" && /^\d+$/.test(idx)) {
    const i = parseInt(idx, 10);
    const kids = node.children ?? [];
    if (i >= kids.length) throw new Error(`struct indeksi sinir disinda: ${path}`);
    return kids[i]!;
  }
  throw new Error(`indeks yalnizca dizi/set/map icin kullanilir: ${path}`);
}

function isNumericKind(k: SavePropKind): boolean {
  return k === "int" || k === "int64" || k === "int16" || k === "int8" ||
    k === "uint32" || k === "uint64" || k === "uint16" || k === "float" ||
    k === "double" || k === "byte";
}

function stringifyKey(node: SavePropNode): string {
  if (node.value === null || node.value === undefined) return "";
  if (typeof node.value === "boolean") return node.value ? "true" : "false";
  return String(node.value);
}

function childListOf(node: SavePropNode): SavePropNode[] {
  if (node.kind === "struct" || node.kind === "array" || node.kind === "set") return node.children ?? [];
  return [];
}

function resolvePath(doc: SaveGameDoc, path: string, chain?: SavePropNode[]): SavePropNode {
  const segments = path.split(".").map((s) => s.trim()).filter((s) => s.length > 0);
  if (segments.length === 0) throw new Error("bos yol");

  let current: SavePropNode | undefined;
  let list: SavePropNode[] = doc.props;

  for (const seg of segments) {
    const m = /^([^\[\]]*)(?:\[([^\]]*)\])?$/.exec(seg);
    if (!m) throw new Error(`yol parcasi cozulemedi: "${seg}"`);
    const base = m[1] ?? "";
    const idx = m[2];

    if (current === undefined) {
      if (!base) throw new Error(`ilk yol parcasi bir property adi olmali: "${seg}"`);
      const found = list.find((n) => n.name === base);
      if (!found) throw new Error(`kok property bulunamadi: "${base}"`);
      current = found;
    } else if (base) {
      if (current.kind === "map") {
        throw new Error(`"${seg}": map alt anahtarlari [key=...] ile erisilir`);
      }
      const kids = childListOf(current);
      const found = kids.find((n) => n.name === base);
      if (!found) throw new Error(`property bulunamadi: "${seg}" (ebeveyn: ${current.name || current.kind})`);
      current = found;
    }

    if (idx !== undefined) {
      if (current === undefined) throw new Error(`indeks icin hedef yok: "${seg}"`);
      current = applyIndex(current, idx, seg);
    }
    if (chain && current) chain.push(current);
  }

  if (current === undefined) throw new Error(`yol cozulemedi: ${path}`);
  return current;
}

function setNodeValue(node: SavePropNode, raw: string, path: string): void {
  const v = String(raw);
  switch (node.kind) {
    case "int": case "uint32": case "int16": case "uint16": case "int8": case "byte": {
      const n = Number(v.trim());
      if (!Number.isFinite(n) || !Number.isInteger(n)) {
        throw new Error(`"${v}" tamsayiya cevrilemedi`);
      }
      const range = NUMERIC_RANGES[node.kind]!;
      if (n < range[0] || n > range[1]) {
        throw new Error(`deger aralik disinda (${node.kind}: ${range[0]}..${range[1]}): ${n}`);
      }
      node.value = n;
      break;
    }
    case "int64": case "uint64": {
      const n = Number(v.trim());
      if (!Number.isFinite(n) || !Number.isInteger(n)) {
        throw new Error(`"${v}" tamsayiya cevrilemedi`);
      }
      if (Math.abs(n) >= Number.MAX_SAFE_INTEGER) {
        throw new Error(`deger 2^53 sinirinin disinda (JS sayi hassasiyeti): ${v}`);
      }
      node.value = n;
      break;
    }
    case "float": case "double": {
      const n = Number(v.trim());
      if (!Number.isFinite(n)) throw new Error(`"${v}" sayiya cevrilemedi`);
      node.value = n;
      break;
    }
    case "bool": {
      const t = v.trim().toLowerCase();
      if (t === "true" || t === "1") node.value = true;
      else if (t === "false" || t === "0") node.value = false;
      else throw new Error(`"${v}" bool'a cevrilemedi (true/false bekleniyor)`);
      break;
    }
    case "enum":
    case "str":
    case "name":
    case "object":
      node.value = v;
      node.rawStringBytes = undefined; // yeniden kodla
      break;
    case "softobject": {
      const kids = node.children ?? [];
      if (kids[0]) {
        kids[0].value = v;
        kids[0].rawStringBytes = undefined;
      }
      node.value = v;
      break;
    }
    case "struct":
    case "array":
    case "set":
    case "map":
      throw new Error(`hedef bir yaprak degil (${node.kind}) - yaprak property secin`);
    case "opaque":
      throw new Error("opak (bilinmeyen tip) property duzenlenemez");
    default:
      throw new Error(`bilinmeyen hedef tip: ${node.kind}`);
  }
}

export function applyEdits(doc: SaveGameDoc, edits: { path: string; value: string }[]): { applied: number; errors: string[] } {
  const errors: string[] = [];
  let applied = 0;
  for (const e of edits) {
    try {
      const chain: SavePropNode[] = [];
      const target = resolvePath(doc, e.path, chain);
      setNodeValue(target, e.value, e.path);
      // boyut yeniden hesabi icin yoldaki tum dugumleri "edited" isaretle
      for (const nd of chain) nd.edited = true;
      applied++;
    } catch (err) {
      errors.push(`${e.path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { applied, errors };
}

// ---------------------------------------------------------------------------
// canli yazma dogrulamasi (yazim sonrasi dosya yeniden okunurken kullanilir)
// ---------------------------------------------------------------------------

/** Dugumun mevcut degeri, edit'in beklenen degeriyle uyusuyor mu? */
function valueMatches(node: SavePropNode, raw: string): boolean {
  const cur = node.value;
  switch (node.kind) {
    case "float": {
      const a = Number(cur);
      const b = Number(raw);
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      // f32 round-trip yuvarlamasi icin goreli tolerans (f32 eps ~1.2e-7)
      return Math.abs(a - b) <= Math.max(Math.abs(b) * 1e-6, 1e-9);
    }
    case "double": {
      const a = Number(cur);
      const b = Number(raw);
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      return Math.abs(a - b) <= Math.max(Math.abs(b) * 1e-12, 1e-15);
    }
    case "int": case "int64": case "int16": case "int8":
    case "uint32": case "uint64": case "uint16": case "byte":
      return Number(cur) === Number(raw);
    case "bool": {
      const t = raw.trim().toLowerCase();
      const expected = t === "true" || t === "1";
      return cur === expected;
    }
    case "str": case "name": case "enum": case "object": case "softobject":
      return String(cur ?? "") === String(raw);
    // struct/array/set/map/opaque: deger alanlari duzenlenemez (applyEdits
    // zaten reddeder); yol cozulduyse dogrulama sayilir
    default:
      return true;
  }
}

/**
 * Canli yazma dogrulamasi: diskten yeniden okunan dokumda her edit'in hedefi
 * beklenen degeri tasiyor mu? (kalicilik kontrolu)
 */
export function verifyEdits(doc: SaveGameDoc, edits: { path: string; value: string }[]): { verified: boolean; errors: string[] } {
  const errors: string[] = [];
  for (const e of edits) {
    try {
      const target = resolvePath(doc, e.path);
      if (!valueMatches(target, e.value)) {
        errors.push(
          `${e.path}: deger kalicilasmadi (dosyada "${String(target.value ?? "")}", beklenen "${e.value}")`,
        );
      }
    } catch (err) {
      errors.push(`${e.path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { verified: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// ozet
// ---------------------------------------------------------------------------

function engineVersionString(h: SaveGameHeader): string {
  const base = `${h.engineMajor}.${h.engineMinor}.${h.enginePatch}-${h.changelist}`;
  return h.branch ? `${base}+${h.branch}` : base;
}

export function summarizeSaveGame(doc: SaveGameDoc): SaveGameSummary {
  let structCount = 0;
  let arrayCount = 0;
  let mapCount = 0;
  let opaqueCount = 0;
  const stringSample: string[] = [];

  const pushStr = (s: string): void => {
    if (stringSample.length < 16 && s && stringSample.indexOf(s) === -1) stringSample.push(s);
  };

  const walk = (list: SavePropNode[]): void => {
    for (const nd of list) {
      if (nd.kind === "struct") structCount++;
      else if (nd.kind === "array") arrayCount++;
      else if (nd.kind === "map") mapCount++;
      else if (nd.kind === "opaque") opaqueCount++;
      if (nd.kind === "str" || nd.kind === "name" || nd.kind === "enum" || nd.kind === "object") {
        pushStr(String(nd.value ?? ""));
      } else if (nd.kind === "softobject") {
        pushStr(String(nd.value ?? ""));
      }
      if (nd.children) walk(nd.children);
      if (nd.pairs) {
        for (const p of nd.pairs) {
          walk([p.key]);
          walk([p.value]);
        }
      }
    }
  };
  walk(doc.props);
  pushStr(doc.header.className);

  return {
    fileVersion: doc.header.fileVersion,
    ue4Version: doc.header.ue4Version,
    ue5Version: doc.header.ue5Version,
    engineVersion: engineVersionString(doc.header),
    className: doc.header.className,
    propCount: countProps(doc.props),
    structCount,
    arrayCount,
    mapCount,
    opaqueCount,
    stringSample,
    encrypted: doc.meta.encrypted,
    compressed: doc.meta.compressed,
  };
}
