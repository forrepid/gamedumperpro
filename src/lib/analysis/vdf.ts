// ----------------------------------------------------------------------------
// DumperPro Online - Steam VDF (Valve Data Format) modulu
//
// Iki varyant:
//   1) Metin VDF  : Steam cloud config, localconfig.vdf, loginusers.vdf...
//      Tokenizer: quote'lu / quote'suz anahtar-deger, "{}" bloklari,
//      "//" ve "/* */" yorumlari, escape (\t \n \" \\).
//   2) Ikili VDF  : shortcuts.vdf, remotecache.vdf (SteamKit2 BinKV semantigi)
//      Kayit: TIPLERI ADI bayti once gelir, ardindan anahtar FString'i, sonra
//      deger. Tipler:
//        0x00 blok (alt anahtarlar ... 0x08 ile biter)
//        0x01 string (latin1 FString)
//        0x02 int32   0x03 float   0x04 pointer(u64)
//        0x05 widestring (utf16 FString)   0x06 color(int32)
//        0x07 uint64   0x08 blok sonu
//
// Kaynak/teyit: SteamKit2 BinKV reader semantigi + ValveDataFormat dokumantasyonu.
// Byte-perfect geri yazim icin ikili varyant tip bilgisi (t) korunur;
// metin varyantta yorumlar/girinti korunmaz (bilinen kisit - UI'da belirtilir).
// ----------------------------------------------------------------------------

// --- agac dugumu -----------------------------------------------------------

export type VdfType = "block" | "str" | "wstr" | "int" | "float" | "ptr" | "color" | "u64";

export interface VdfNode {
  /** ikili vdf'te orijinal tip (byte-perfect geri yazim icin); metinde "str" */
  t: VdfType;
  /** deger (metin olarak; int/float da string tutulur - byte-perfect) */
  v: string;
  /** alt agac (blok) */
  c?: Record<string, VdfNode>;
}

export interface VdfDoc {
  kind: "text" | "binary";
  /** kok blok (kokte tek anonim blok vardir) */
  root: Record<string, VdfNode>;
  meta: {
    size: number;
    keyCount: number;
    maxDepth: number;
    /** ikili vdf'te tip dagilimi */
    typeCounts: Record<string, number>;
  };
}

// --- yardimcilar -----------------------------------------------------------

function isWs(b: number): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0d || b === 0x0a;
}

function statsOf(root: Record<string, VdfNode>): { keyCount: number; maxDepth: number; types: Record<string, number> } {
  const types: Record<string, number> = {};
  let keyCount = 0;
  let maxDepth = 0;
  const walk = (node: VdfNode, depth: number): void => {
    keyCount++;
    maxDepth = Math.max(maxDepth, depth);
    types[node.t] = (types[node.t] ?? 0) + 1;
    if (node.c) for (const k of Object.keys(node.c)) walk(node.c[k]!, depth + 1);
  };
  for (const k of Object.keys(root)) walk(root[k]!, 1);
  return { keyCount, maxDepth, types };
}

// --- metin VDF -------------------------------------------------------------

export function parseVdfText(buf: Buffer): Record<string, VdfNode> {
  const s = buf.toString("latin1");
  let i = 0;
  const n = s.length;

  const skipWs = (): void => {
    for (;;) {
      while (i < n && isWs(s.charCodeAt(i))) i++;
      if (i + 1 < n && s[i] === "/" && s[i + 1] === "/") {
        while (i < n && s[i] !== "\n") i++;
        continue;
      }
      if (i + 1 < n && s[i] === "/" && s[i + 1] === "*") {
        i += 2;
        while (i + 1 < n && !(s[i] === "*" && s[i + 1] === "/")) i++;
        i += 2;
        continue;
      }
      break;
    }
  };

  const readToken = (): string => {
    skipWs();
    if (i >= n) throw new Error("VDF: beklenmedik dosya sonu");
    if (s[i] === '"') {
      i++;
      let out = "";
      while (i < n && s[i] !== '"') {
        if (s[i] === "\\" && i + 1 < n) {
          const c = s[i + 1];
          out += c === "n" ? "\n" : c === "t" ? "\t" : c === "r" ? "\r" : c;
          i += 2;
          continue;
        }
        out += s[i];
        i++;
      }
      if (i >= n) throw new Error("VDF: kapanis tirnagi yok");
      i++; // kapanis tirnagi
      return out;
    }
    let out = "";
    while (i < n && !isWs(s.charCodeAt(i)) && s[i] !== "{") out += s[i++];
    return out;
  };

  const readBlock = (): Record<string, VdfNode> => {
    const obj: Record<string, VdfNode> = {};
    for (;;) {
      skipWs();
      if (i >= n) throw new Error("VDF: blok kapanmadan dosya bitti");
      if (s[i] === "}") {
        i++;
        return obj;
      }
      const key = readToken();
      skipWs();
      if (i >= n) throw new Error(`VDF: '${key}' icin deger yok`);
      if (s[i] === "{") {
        i++;
        obj[key] = { t: "block", v: "", c: readBlock() };
      } else {
        obj[key] = { t: "str", v: readToken() };
      }
    }
  };

  skipWs();
  const root: Record<string, VdfNode> = {};
  for (;;) {
    skipWs();
    if (i >= n) break;
    if (s[i] === "{") {
      i++;
      root[""] = { t: "block", v: "", c: readBlock() };
      continue;
    }
    const key = readToken();
    skipWs();
    if (i < n && s[i] === "{") {
      i++;
      root[key] = { t: "block", v: "", c: readBlock() };
    } else {
      root[key] = { t: "str", v: readToken() };
    }
  }
  return root;
}

function quoteVdf(v: string): string {
  let out = '"';
  for (const ch of v) {
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\t") out += "\\t";
    else out += ch;
  }
  return out + '"';
}

function serializeVdfBlock(obj: Record<string, VdfNode>, depth: number): string {
  const pad = "  ".repeat(depth);
  const lines: string[] = [];
  for (const k of Object.keys(obj)) {
    const node = obj[k]!;
    if (node.c) {
      lines.push(`${pad}${quoteVdf(k)}`);
      lines.push(`${pad}{`);
      lines.push(serializeVdfBlock(node.c, depth + 1));
      lines.push(`${pad}}`);
    } else {
      lines.push(`${pad}${quoteVdf(k)}  ${quoteVdf(node.v)}`);
    }
  }
  return lines.join("\n");
}

export function serializeVdfText(root: Record<string, VdfNode>): string {
  return serializeVdfBlock(root, 0) + "\n";
}

// --- ikili VDF (SteamKit2 BinKV semantigi) ----------------------------------

const T_BLOCK = 0x00;
const T_STRING = 0x01;
const T_INT32 = 0x02;
const T_FLOAT = 0x03;
const T_POINTER = 0x04;
const T_WIDESTRING = 0x05;
const T_COLOR = 0x06;
const T_UINT64 = 0x07;
const T_END = 0x08;

const TYPE_BYTE_OF: Record<VdfType, number> = {
  block: T_BLOCK,
  str: T_STRING,
  wstr: T_WIDESTRING,
  int: T_INT32,
  float: T_FLOAT,
  ptr: T_POINTER,
  color: T_COLOR,
  u64: T_UINT64,
};

// NOT: hesaplanan sayisal anahtarli nesne ({ [T_BLOCK]: ... }) Turbopack
// derlemesinde sunucu surecini cokertiyor - dizi esleme kullanilir.
const TYPE_OF_BYTE_LIST: [number, VdfType][] = [
  [T_BLOCK, "block"],
  [T_STRING, "str"],
  [T_WIDESTRING, "wstr"],
  [T_INT32, "int"],
  [T_FLOAT, "float"],
  [T_POINTER, "ptr"],
  [T_COLOR, "color"],
  [T_UINT64, "u64"],
];
function typeOfByte(b: number): VdfType | null {
  for (const [k, t] of TYPE_OF_BYTE_LIST) if (k === b) return t;
  return null;
}

function readBinFString(buf: Buffer, pos: { p: number }): string {
  if (pos.p + 4 > buf.length) throw new Error("VDF binary: FString uzunlugu dosya disinda");
  const len = buf.readInt32LE(pos.p);
  pos.p += 4;
  if (len === 0) return "";
  if (len < 0) {
    const chars = -len;
    if (pos.p + chars * 2 > buf.length) throw new Error("VDF binary: utf16 string dosya disinda");
    const raw = buf.subarray(pos.p, pos.p + chars * 2);
    pos.p += chars * 2;
    return chars > 1 ? raw.subarray(0, (chars - 1) * 2).toString("utf16le") : "";
  }
  if (pos.p + len > buf.length) throw new Error("VDF binary: string dosya disinda");
  const raw = buf.subarray(pos.p, pos.p + len);
  pos.p += len;
  return raw.subarray(0, Math.max(0, len - 1)).toString("latin1");
}

function writeBinFString(w: Buffer[], s: string, utf16: boolean): void {
  if (utf16) {
    const body = Buffer.concat([Buffer.from(s, "utf16le"), Buffer.from([0, 0])]);
    const len = Buffer.alloc(4);
    len.writeInt32LE(-(s.length + 1));
    w.push(len, body);
  } else {
    const body = Buffer.concat([Buffer.from(s, "latin1"), Buffer.from([0])]);
    const len = Buffer.alloc(4);
    len.writeInt32LE(body.length);
    w.push(len, body);
  }
}

function readBinBlock(buf: Buffer, pos: { p: number }): Record<string, VdfNode> {
  const obj: Record<string, VdfNode> = {};
  for (;;) {
    if (pos.p >= buf.length) throw new Error("VDF binary: blok kapanmadan dosya bitti");
    const type = buf[pos.p]!;
    if (type === T_END) {
      pos.p++;
      return obj;
    }
    const t = typeOfByte(type);
    if (!t) throw new Error(`VDF binary: bilinmeyen tip bayti 0x${type.toString(16)} @${pos.p}`);
    pos.p++;
    const key = readBinFString(buf, pos);
    if (t === "block") {
      obj[key] = { t: "block", v: "", c: readBinBlock(buf, pos) };
    } else if (t === "str" || t === "wstr") {
      obj[key] = { t, v: readBinFString(buf, pos) };
    } else {
      obj[key] = readBinScalar(buf, pos, t);
    }
  }
}

function readBinScalar(buf: Buffer, pos: { p: number }, t: VdfType): VdfNode {
  switch (t) {
    case "int":
    case "color": {
      if (pos.p + 4 > buf.length) throw new Error("VDF binary: int32 dosya disinda");
      const v = buf.readInt32LE(pos.p);
      pos.p += 4;
      return { t, v: String(v) };
    }
    case "float": {
      if (pos.p + 4 > buf.length) throw new Error("VDF binary: float dosya disinda");
      const v = buf.readFloatLE(pos.p);
      pos.p += 4;
      return { t, v: String(v) };
    }
    case "ptr":
    case "u64": {
      if (pos.p + 8 > buf.length) throw new Error("VDF binary: u64 dosya disinda");
      const v = buf.readBigUInt64LE(pos.p);
      pos.p += 8;
      return { t, v: v.toString() };
    }
    default:
      throw new Error(`VDF binary: beklenmeyen skaler tip ${t}`);
  }
}

function writeBinBlock(w: Buffer[], obj: Record<string, VdfNode>): void {
  for (const k of Object.keys(obj)) {
    const node = obj[k]!;
    if (node.c) {
      w.push(Buffer.from([T_BLOCK]));
      writeBinFString(w, k, false);
      writeBinBlock(w, node.c);
      w.push(Buffer.from([T_END]));
      continue;
    }
    w.push(Buffer.from([TYPE_BYTE_OF[node.t] ?? T_STRING]));
    writeBinFString(w, k, false);
    switch (node.t) {
      case "str":
        writeBinFString(w, node.v, false);
        break;
      case "wstr":
        writeBinFString(w, node.v, true);
        break;
      case "int":
      case "color": {
        const b = Buffer.alloc(4);
        b.writeInt32LE(Number(node.v) | 0);
        w.push(b);
        break;
      }
      case "float": {
        const b = Buffer.alloc(4);
        b.writeFloatLE(Number(node.v));
        w.push(b);
        break;
      }
      case "ptr":
      case "u64": {
        const b = Buffer.alloc(8);
        let big: bigint;
        try {
          big = BigInt(node.v || "0");
        } catch {
          big = 0n;
        }
        b.writeBigUInt64LE(big);
        w.push(b);
        break;
      }
      default:
        writeBinFString(w, node.v, false);
    }
  }
}

export function serializeVdfBinary(root: Record<string, VdfNode>): Buffer {
  const w: Buffer[] = [];
  writeBinBlock(w, root);
  w.push(Buffer.from([T_END])); // kok blogun sonu
  return Buffer.concat(w);
}

// --- tespit + genel API ----------------------------------------------------

export function detectVdf(buf: Buffer): "text" | "binary" | null {
  if (buf.length < 4) return null;
  // ikili vdf ilk bayt bir tip baytidir (0x00..0x07)
  const first = buf[0]!;
  if (first <= 0x07 && typeOfByte(first)) {
    try {
      // kesin tespit: binary parse denemesi
      const pos = { p: 0 };
      readBinBlock(buf, pos);
      if (pos.p === buf.length) return "binary";
    } catch {
      // metin deneriz
    }
  }
  const head = buf.subarray(0, Math.min(buf.length, 4096)).toString("latin1");
  if (head.includes('"') && (head.includes("{") || head.includes("}"))) return "text";
  return null;
}

export function parseVdf(buf: Buffer): VdfDoc {
  const kind = detectVdf(buf);
  if (!kind) {
    throw new Error("VDF: format taninamadi (metin veya ikili VDF degil)");
  }
  const root = kind === "binary" ? parseVdfBinaryStrict(buf) : parseVdfText(buf);
  const st = statsOf(root);
  return {
    kind,
    root,
    meta: { size: buf.length, keyCount: st.keyCount, maxDepth: st.maxDepth, typeCounts: st.types },
  };
}

function parseVdfBinaryStrict(buf: Buffer): Record<string, VdfNode> {
  const pos = { p: 0 };
  const root = readBinBlock(buf, pos);
  return root;
}

export function serializeVdf(doc: VdfDoc): Buffer {
  return doc.kind === "binary" ? serializeVdfBinary(doc.root) : Buffer.from(serializeVdfText(doc.root), "latin1");
}

/** yol duzenlemesi: "UserConfig.games.name" tarzi nokta ayraci */
export function applyVdfEdits(
  doc: VdfDoc,
  edits: { path: string; value: string }[],
): { applied: number; errors: string[] } {
  const errors: string[] = [];
  let applied = 0;
  for (const e of edits) {
    try {
      const segs = e.path.split(".").map((s) => s.trim()).filter(Boolean);
      if (segs.length === 0) throw new Error("bos yol");
      let block = doc.root;
      for (let i = 0; i < segs.length - 1; i++) {
        const next = block[segs[i]!];
        if (!next) throw new Error(`anahtar bulunamadi: ${segs.slice(0, i + 1).join(".")}`);
        if (!next.c) throw new Error(`aradaki anahtar blok degil: ${segs.slice(0, i + 1).join(".")}`);
        block = next.c;
      }
      const last = segs[segs.length - 1]!;
      const target = block[last];
      if (!target) throw new Error(`anahtar bulunamadi: ${e.path}`);
      target.v = e.value;
      applied++;
    } catch (err) {
      errors.push(`${e.path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { applied, errors };
}

/** UI icin ozet */
export function summarizeVdf(doc: VdfDoc): { keyCount: number; maxDepth: number; sampleKeys: string[] } {
  const sampleKeys: string[] = [];
  const walk = (obj: Record<string, VdfNode>): void => {
    for (const k of Object.keys(obj)) {
      if (sampleKeys.length < 24 && k) sampleKeys.push(k);
      const nd = obj[k]!;
      if (nd.c) walk(nd.c);
    }
  };
  walk(doc.root);
  return { keyCount: doc.meta.keyCount, maxDepth: doc.meta.maxDepth, sampleKeys };
}
