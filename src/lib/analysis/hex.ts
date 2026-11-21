// ----------------------------------------------------------------------------
// DumperPro Online - Hex/Byte/AOB goruntuleme, arama, yama, kaydet sistemi
//
// Ilham: Il2CppDumper/UE hata ayiklama akisi (hex gorunum + AOB tarama) ve
// DumperPro C++ HexTool.cpp. LEECHCORE mantigiyla calisir: dosya = bayt
// alani; PE yuklendiyse off<->RVA/VA cevrimi sunulur.
//
// Akis: GET /api/uploads/[id]/hex (gorunum) -> POST .../hex/search (AOB) ->
// POST .../hex/patch (yamalari .dpr yan dosyasina yazar) -> POST .../hex/save
// (yamali kopyayi yeni yukleme olarak kaydeder + analiz eder).
// ----------------------------------------------------------------------------

export interface HexRow {
  off: number;
  hex: string[];
  ascii: string;
}

export interface HexView {
  size: number;
  off: number;
  len: number;
  rows: HexRow[];
  rva?: string; // PE ise: off -> RVA
  va?: string;
  note?: string;
}

export interface AobMatch {
  off: number;
  rva?: number;
  va?: number;
  hex: string;
}

/** "48 8B ?? 89" / "488B??89" / "48 8B * 89" desenini (number|null)[] yapar. */
export function parseAobPattern(pattern: string): { bytes: (number | null)[]; error?: string } {
  const clean = pattern.replace(/0x/gi, " ").replace(/,/g, " ").trim();
  if (!clean) return { bytes: [], error: "bos desen" };
  const tokens = clean.split(/\s+/).flatMap((t) => (t.length > 2 ? chunk2(t) : [t]));
  const bytes: (number | null)[] = [];
  for (const t of tokens) {
    if (t === "??" || t === "*" || t === "?") bytes.push(null);
    else if (/^[0-9a-fA-F]{2}$/.test(t)) bytes.push(parseInt(t, 16));
    else return { bytes: [], error: `gecersiz token: "${t}"` };
  }
  if (bytes.length === 0 || bytes.length > 4096) return { bytes: [], error: "desen uzunlugu gecersiz" };
  return { bytes };
}

function chunk2(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += 2) out.push(s.slice(i, i + 2));
  return out;
}

export function hexView(buf: Buffer, off: number, len: number, bytesPerRow = 16, pe?: { imageBase: number; rvaOf(off: number): number | null }): HexView {
  const clampedOff = Math.max(0, Math.min(off, buf.length));
  const clampedLen = Math.max(0, Math.min(len, buf.length - clampedOff, 16 * 1024));
  const rows: HexRow[] = [];
  for (let r = 0; r < clampedLen; r += bytesPerRow) {
    const start = clampedOff + r;
    const end = Math.min(start + bytesPerRow, clampedOff + clampedLen);
    const slice = buf.subarray(start, end);
    const hex: string[] = [];
    let ascii = "";
    for (let i = 0; i < bytesPerRow; i++) {
      if (i < slice.length) {
        const b = slice[i];
        hex.push(b.toString(16).padStart(2, "0"));
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
      } else {
        hex.push("  ");
        ascii += " ";
      }
    }
    rows.push({ off: start, hex, ascii });
  }
  const view: HexView = { size: buf.length, off: clampedOff, len: clampedLen, rows };
  if (pe) {
    const rva = pe.rvaOf(clampedOff);
    if (rva !== null) {
      view.rva = `0x${rva.toString(16).toUpperCase()}`;
      view.va = `0x${(pe.imageBase + rva).toString(16).toUpperCase()}`;
    }
  }
  return view;
}

export function aobSearch(
  buf: Buffer,
  bytes: (number | null)[],
  opts: { off?: number; len?: number; limit?: number; imageBase?: number; rvaOf?: (off: number) => number | null } = {},
): { matches: AobMatch[]; scanned: number; truncated: boolean } {
  const start = Math.max(0, opts.off ?? 0);
  const end = Math.min(buf.length, start + (opts.len ?? buf.length - start), start + 128 * 1024 * 1024);
  const limit = Math.min(opts.limit ?? 256, 1024);
  const matches: AobMatch[] = [];
  const plen = bytes.length;
  const first = bytes.findIndex((b) => b !== null);
  if (first === -1 || plen === 0 || end - start < plen) return { matches, scanned: end - start, truncated: false };
  const data = buf.subarray(start, end);
  let idx = -1;
  let truncated = false;
  for (;;) {
    idx = data.indexOf(bytes[first]!, idx + 1);
    if (idx === -1 || idx + plen > data.length) break;
    let ok = true;
    for (let k = 0; k < plen; k++) {
      const p = bytes[k];
      if (p === null) continue;
      if (data[idx + k] !== p) { ok = false; break; }
    }
    if (ok) {
      if (matches.length >= limit) { truncated = true; break; }
      const abs = start + idx;
      const rva = opts.rvaOf ? opts.rvaOf(abs) : null;
      matches.push({
        off: abs,
        rva: rva ?? undefined,
        va: rva !== null && rva !== undefined && opts.imageBase !== undefined
          ? opts.imageBase + rva
          : undefined,
        hex: data.subarray(idx, idx + Math.min(plen, 32)).toString("hex"),
      });
    }
  }
  return { matches, scanned: data.length, truncated };
}

// ---------------------------------------------------------------------------
// yama saklama (.dpr = DumperPro Patch Record; JSON yan dosyasi)
// ---------------------------------------------------------------------------

export interface HexPatch {
  off: number;
  bytes: number[]; // YENI degerler
  orig: number[]; // eski degerler (otomatik)
  note?: string;
}

export interface PatchRecord {
  version: 1;
  baseFile: string;
  patches: HexPatch[];
  updatedAt: string;
}

export function applyPatches(buf: Buffer, patches: HexPatch[]): { buf: Buffer; applied: number; skipped: string[] } {
  const out = Buffer.from(buf);
  const skipped: string[] = [];
  let applied = 0;
  for (const p of patches) {
    if (p.off < 0 || p.off + p.bytes.length > out.length) {
      skipped.push(`0x${p.off.toString(16)}: aralik dosya disinda`);
      continue;
    }
    for (let i = 0; i < p.bytes.length; i++) {
      out[p.off + i] = p.bytes[i] & 0xff;
    }
    applied++;
  }
  return { buf: out, applied, skipped };
}

export function parsePatchJson(text: string): PatchRecord | null {
  try {
    const rec = JSON.parse(text) as PatchRecord;
    if (rec.version !== 1 || !Array.isArray(rec.patches)) return null;
    return rec;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// veri tipi kayit sistemi: bayt -> deger yorumlama (little-endian)
//
// DumperPro C++ DataType modulu (src/core/DataType.h) ile hizali tip seti.
// Cheat Engine / ReClass benzeri: tamsayilar, float/double, bool, bit,
// ASCII + UTF-16 string, pointer, float vektorler.
// ---------------------------------------------------------------------------

export type DataType =
  | "i8"
  | "u8"
  | "i16"
  | "u16"
  | "i32"
  | "u32"
  | "i64"
  | "u64"
  | "f32"
  | "f64"
  | "bool"
  | "bit"
  | "str"
  | "str16"
  | "ptr"
  | "vec2"
  | "vec3"
  | "vec4";

export interface DataTypeMeta {
  label: string;
  /** sabit bayt boyutu; str/str16 -> 0 (NUL'a kadar degisken) */
  size: number;
  group: "int" | "float" | "bool" | "text" | "other";
  /** C++ DumperPro tip adi (alias'larin dayandigi kanonik ad) */
  cpp: string;
}

export const DATA_TYPE_META: Record<DataType, DataTypeMeta> = {
  i8: { label: "int8 (1 B)", size: 1, group: "int", cpp: "i8" },
  u8: { label: "uint8 / byte (1 B)", size: 1, group: "int", cpp: "u8" },
  i16: { label: "int16 / short (2 B)", size: 2, group: "int", cpp: "i16" },
  u16: { label: "uint16 / word (2 B)", size: 2, group: "int", cpp: "u16" },
  i32: { label: "int32 / int (4 B)", size: 4, group: "int", cpp: "i32" },
  u32: { label: "uint32 / dword (4 B)", size: 4, group: "int", cpp: "u32" },
  i64: { label: "int64 (8 B)", size: 8, group: "int", cpp: "i64" },
  u64: { label: "uint64 / qword (8 B)", size: 8, group: "int", cpp: "u64" },
  f32: { label: "float (4 B)", size: 4, group: "float", cpp: "f32" },
  f64: { label: "double (8 B)", size: 8, group: "float", cpp: "f64" },
  bool: { label: "bool (1 B, 0/1)", size: 1, group: "bool", cpp: "bool" },
  bit: { label: "bit (1 B icinde)", size: 1, group: "bool", cpp: "bit" },
  str: { label: "string ASCII (NUL'a kadar)", size: 0, group: "text", cpp: "str" },
  str16: { label: "string UTF-16LE (NUL'a kadar)", size: 0, group: "text", cpp: "str16" },
  ptr: { label: "pointer (8 B, hex)", size: 8, group: "other", cpp: "ptr" },
  vec2: { label: "vec2 float (8 B)", size: 8, group: "float", cpp: "vec2" },
  vec3: { label: "vec3 float / FVector (12 B)", size: 12, group: "float", cpp: "vec3" },
  vec4: { label: "vec4 float (16 B)", size: 16, group: "float", cpp: "vec4" },
};

/** UI secim listesi icin gruplu tip sirasi */
export const DATA_TYPE_GROUPS: { label: string; types: DataType[] }[] = [
  { label: "Tam sayi", types: ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"] },
  { label: "Kayan nokta / vektor", types: ["f32", "f64", "vec2", "vec3", "vec4"] },
  { label: "Boolean / bit", types: ["bool", "bit"] },
  { label: "Metin", types: ["str", "str16"] },
  { label: "Diger", types: ["ptr"] },
];

/** C++ DataType alias tablosuyla ayni cozumleme (byte -> u8, int -> i32, ...) */
const DATA_TYPE_ALIASES: Record<string, DataType> = {
  int8: "i8", sbyte: "i8",
  byte: "u8", uint8: "u8",
  short: "i16", int16: "i16",
  ushort: "u16", word: "u16", uint16: "u16",
  int: "i32", int32: "i32", dword: "i32",
  uint: "u32", uint32: "u32",
  longlong: "i64", int64: "i64",
  qword: "u64", uint64: "u64",
  float: "f32", float32: "f32",
  double: "f64", float64: "f64",
  boolean: "bool",
  string: "str", ascii: "str",
  utf16: "str16", wide: "str16", wstring: "str16",
  pointer: "ptr",
  vector2: "vec2", vector2d: "vec2", fvector2d: "vec2",
  vector3: "vec3", vector3d: "vec3", fvector: "vec3", frotator: "vec3",
  vector4: "vec4", vector4d: "vec4", fvector4: "vec4",
};

/** tip adi/alias -> DataType; bilinmiyorsa null */
export function resolveDataType(name: string): DataType | null {
  const k = name.trim().toLowerCase();
  if (k in DATA_TYPE_META) return k as DataType;
  return DATA_TYPE_ALIASES[k] ?? null;
}

export interface DecodedValue {
  ok: boolean;
  value: string;
  /** tuketilen baytlar (sonlandirici dahil; string taramasi icin) */
  bytes: number[];
  error?: string;
  note?: string;
}

/** little-endian float gorunumu: gereksiz sifirlari kirp, NaN/Inf korunur */
function fmtFloat(v: number, sig: number): string {
  if (Number.isNaN(v)) return "NaN";
  if (!Number.isFinite(v)) return v > 0 ? "Inf" : "-Inf";
  return String(parseFloat(v.toPrecision(sig)));
}

function isPrintable(b: number): boolean {
  return b >= 0x20 && b < 0x7f;
}

/**
 * buf[off..] baytlarini tip olarak yorumlar (little-endian).
 * bit: (bayt >> bitIndex) & 1, bitIndex 0..7 (0 = LSB).
 * str: NUL'a kadar ASCII; str16: 0x0000'a kadar UTF-16LE.
 */
export function decodeValue(
  buf: Buffer,
  off: number,
  type: DataType,
  opts: { bitIndex?: number; maxChars?: number } = {},
): DecodedValue {
  if (off < 0 || off >= buf.length) {
    return { ok: false, value: "", bytes: [], error: "ofset dosya disinda" };
  }
  const meta = DATA_TYPE_META[type];
  const bitIndex = Math.max(0, Math.min(7, opts.bitIndex ?? 0));
  const maxChars = Math.max(1, Math.min(256, opts.maxChars ?? 96));

  if (meta.size > 0 && off + meta.size > buf.length) {
    return { ok: false, value: "", bytes: [], error: `eksik bayt (gerekli ${meta.size})` };
  }

  const take = (n: number): number[] => Array.from(buf.subarray(off, off + n));

  switch (type) {
    case "i8":
      return { ok: true, value: String(buf.readInt8(off)), bytes: take(1) };
    case "u8":
      return { ok: true, value: String(buf.readUInt8(off)), bytes: take(1) };
    case "i16":
      return { ok: true, value: String(buf.readInt16LE(off)), bytes: take(2) };
    case "u16":
      return { ok: true, value: String(buf.readUInt16LE(off)), bytes: take(2) };
    case "i32":
      return { ok: true, value: String(buf.readInt32LE(off)), bytes: take(4) };
    case "u32":
      return { ok: true, value: String(buf.readUInt32LE(off)), bytes: take(4) };
    case "i64":
      return { ok: true, value: buf.readBigInt64LE(off).toString(), bytes: take(8) };
    case "u64":
      return { ok: true, value: buf.readBigUInt64LE(off).toString(), bytes: take(8) };
    case "f32":
      return { ok: true, value: fmtFloat(buf.readFloatLE(off), 6), bytes: take(4) };
    case "f64":
      return { ok: true, value: fmtFloat(buf.readDoubleLE(off), 12), bytes: take(8) };
    case "bool":
      return { ok: true, value: buf.readUInt8(off) ? "true" : "false", bytes: take(1) };
    case "bit": {
      const b = buf.readUInt8(off);
      const bit = (b >> bitIndex) & 1;
      return {
        ok: true,
        value: bit ? "true" : "false",
        bytes: take(1),
        note: `bit ${bitIndex}/0-7`,
      };
    }
    case "str": {
      const out: number[] = [];
      let value = "";
      let truncated = false;
      const cap = Math.min(buf.length - off, maxChars * 4);
      for (let i = 0; i < cap; i++) {
        const b = buf[off + i];
        out.push(b);
        if (b === 0) break;
        if (isPrintable(b)) value += String.fromCharCode(b);
        else value += "?";
        if (out.length >= maxChars && (i + 1 >= cap || buf[off + i + 1] !== 0)) {
          truncated = true;
          break;
        }
      }
      const dec: DecodedValue = { ok: true, value, bytes: out };
      if (truncated || (out.length > 0 && out[out.length - 1] !== 0 && off + out.length >= buf.length)) {
        dec.note = "NUL bulunamadi, kisaltildi";
      }
      return dec;
    }
    case "str16": {
      const out: number[] = [];
      let value = "";
      const cap = Math.min(buf.length - off, maxChars * 4);
      for (let i = 0; i + 1 < cap; i += 2) {
        const lo = buf[off + i];
        const hi = buf[off + i + 1];
        out.push(lo, hi);
        const ch = lo | (hi << 8);
        if (ch === 0) break;
        // BMP + surrogate ciftleri
        if (ch >= 0xd800 && ch <= 0xdbff && i + 3 < cap) {
          const lo2 = buf[off + i + 2];
          const hi2 = buf[off + i + 3];
          const ch2 = lo2 | (hi2 << 8);
          if (ch2 >= 0xdc00 && ch2 <= 0xdfff) {
            const cp = 0x10000 + ((ch - 0xd800) << 10) + (ch2 - 0xdc00);
            value += String.fromCodePoint(cp);
            out.push(lo2, hi2);
            i += 2;
            continue;
          }
        }
        value += String.fromCharCode(ch);
        if (out.length >= maxChars * 2) {
          return { ok: true, value, bytes: out, note: "NUL bulunamadi, kisaltildi" };
        }
      }
      return { ok: true, value, bytes: out };
    }
    case "ptr":
      return {
        ok: true,
        value: `0x${buf.readBigUInt64LE(off).toString(16).toUpperCase()}`,
        bytes: take(8),
      };
    case "vec2":
    case "vec3":
    case "vec4": {
      const n = meta.size / 4;
      const parts: string[] = [];
      for (let i = 0; i < n; i++) parts.push(fmtFloat(buf.readFloatLE(off + i * 4), 6));
      return { ok: true, value: parts.join(", "), bytes: take(meta.size) };
    }
    default:
      return { ok: false, value: "", bytes: [], error: "bilinmeyen tip" };
  }
}

/**
 * Kullanici girdisini tipin little-endian bayt desenine cevirir (deger arama).
 * Tam sayilar: "42" "-7" "0x2A"; float: "3.14"; bool: 1/0/true/false;
 * str: ASCII; str16: karakter basina 2 bayt LE; ptr: hex;
 * vecN: "1 2 3" veya "1, 2, 3"; bit: desteklenmez (bool kullanin).
 */
export function encodeValue(type: DataType, text: string): { ok: boolean; bytes: number[]; error?: string } {
  const s = text.trim();
  if (!s) return { ok: false, bytes: [], error: "bos deger" };
  const meta = DATA_TYPE_META[type];

  if (["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"].includes(type)) {
    let v: bigint | number;
    if (type.startsWith("u")) {
      if (s.startsWith("-")) return { ok: false, bytes: [], error: "isaretsiz tip negatif kabul etmez" };
      const m = /^0x[0-9a-fA-F]+$|^[0-9]+$/.test(s);
      if (!m) return { ok: false, bytes: [], error: `gecersiz tamsayi: "${s}"` };
      v = BigInt(s);
      const max = type === "u8" ? 0xffn : type === "u16" ? 0xffffn : type === "u32" ? 0xffffffffn : 0xffffffffffffffffn;
      if (v > max) return { ok: false, bytes: [], error: `${meta.cpp} araligi 0..${max}` };
    } else {
      const m = /^-?0x[0-9a-fA-F]+$|^-?[0-9]+$/.test(s);
      if (!m) return { ok: false, bytes: [], error: `gecersiz tamsayi: "${s}"` };
      v = BigInt(s);
      const b = type === "i8" ? 8 : type === "i16" ? 16 : type === "i32" ? 32 : 64;
      const min = -(2n ** BigInt(b - 1));
      const max = 2n ** BigInt(b - 1) - 1n;
      if (v < min || v > max) return { ok: false, bytes: [], error: `${meta.cpp} araligi ${min}..${max}` };
    }
    const size = meta.size;
    const out: number[] = [];
    let big = BigInt(v);
    for (let i = 0; i < size; i++) {
      out.push(Number(big & 0xffn));
      big >>= 8n;
    }
    return { ok: true, bytes: out };
  }

  switch (type) {
    case "f32": {
      const v = Number(s);
      if (!Number.isFinite(v)) return { ok: false, bytes: [], error: `gecersiz float: "${s}"` };
      const b = Buffer.alloc(4);
      b.writeFloatLE(v);
      return { ok: true, bytes: Array.from(b) };
    }
    case "f64": {
      const v = Number(s);
      if (!Number.isFinite(v)) return { ok: false, bytes: [], error: `gecersiz double: "${s}"` };
      const b = Buffer.alloc(8);
      b.writeDoubleLE(v);
      return { ok: true, bytes: Array.from(b) };
    }
    case "bool": {
      const l = s.toLowerCase();
      if (["1", "true", "on", "yes"].includes(l)) return { ok: true, bytes: [0x01] };
      if (["0", "false", "off", "no"].includes(l)) return { ok: true, bytes: [0x00] };
      return { ok: false, bytes: [], error: "bool girdisi: 1/0/true/false" };
    }
    case "bit":
      return { ok: false, bytes: [], error: "bit aramasi tek bayt icinde anlamli degildir; bool kullanin" };
    case "str":
      return { ok: true, bytes: Array.from(Buffer.from(s, "latin1")) };
    case "str16": {
      if (s.length < 2) return { ok: false, bytes: [], error: "str16 en az 2 karakter gerekli" };
      const b = Buffer.alloc(s.length * 2);
      for (let i = 0; i < s.length; i++) {
        b[i * 2] = s.charCodeAt(i) & 0xff;
        b[i * 2 + 1] = 0;
      }
      return { ok: true, bytes: Array.from(b) };
    }
    case "ptr": {
      if (!/^0x[0-9a-fA-F]{1,16}$|^[0-9]{1,20}$/.test(s)) {
        return { ok: false, bytes: [], error: `gecersiz pointer: "${s}" (0x...)` };
      }
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(BigInt(s));
      return { ok: true, bytes: Array.from(b) };
    }
    case "vec2":
    case "vec3":
    case "vec4": {
      const parts = s.split(/[\s,;]+/).filter(Boolean);
      const n = meta.size / 4;
      if (parts.length !== n) {
        return { ok: false, bytes: [], error: `${meta.cpp} icin ${n} float gerekli ("1 2 3")` };
      }
      const b = Buffer.alloc(meta.size);
      for (let i = 0; i < n; i++) {
        const f = Number(parts[i]);
        if (!Number.isFinite(f)) return { ok: false, bytes: [], error: `gecersiz float: "${parts[i]}"` };
        b.writeFloatLE(f, i * 4);
      }
      return { ok: true, bytes: Array.from(b) };
    }
    default:
      return { ok: false, bytes: [], error: "tip encode desteklemiyor" };
  }
}

/**
 * Tipli deger aramasi: girdiyi bayt desenine cevirip aobSearch calistirir.
 * Donus sekli aobSearch ile aynidir + opsiyonel error/encoded alanlari.
 */
export function valueSearch(
  buf: Buffer,
  type: DataType,
  text: string,
  opts: { off?: number; len?: number; limit?: number; imageBase?: number; rvaOf?: (off: number) => number | null } = {},
): { matches: AobMatch[]; scanned: number; truncated: boolean; error?: string; encoded?: string } {
  const enc = encodeValue(type, text);
  if (!enc.ok) return { matches: [], scanned: 0, truncated: false, error: enc.error };
  const res = aobSearch(buf, enc.bytes, opts);
  return { ...res, encoded: enc.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ") };
}
