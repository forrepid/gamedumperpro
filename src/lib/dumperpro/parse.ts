// ----------------------------------------------------------------------------
// DumperPro ice aktarma - sonuc dosyasi normalizasyon katmani (sifir bagimlilik)
//
// DumperPro.exe (Windows C++ araci) su ciktilari uretir:
//   names.json     {"format":"dumperpro-names","count":N,"names":[{index,name}]}
//   objects.json   {"format":"dumperpro-objects","count":N,"objects":[...]}
//   functions.json {"format":"dumperpro-functions","version":1,"functions":[...]}
//   result.json    manifest (arac, oyun, UE, modul, status, counts, artifacts)
//   Names.txt      "0x0000012A: SomeName" satirlari
//   Objects.txt    "[123] Class Name /Path/Here 0x7FF..." satirlari
//   funcs.txt      "Class::Func [ufunction] RVA 0x... VA 0x... ParamsSize 0x..." satirlari
//
// Tum adres/offset/size/flags alanlari HEX DIZESIDIR ("0x..."); sayisal
// ihtiyac halinde parseInt(x, 16) kullanin (bkz. hexToNum). Normalize edilen
// veri DumperProImport kaydina JSON dizesi olarak yazilir; ham dosyalar
// storage/dumperpro/<id>/ altinda korunur.
// ----------------------------------------------------------------------------

import { parseZipCentralDirectory, extractZipEntry } from "@/lib/analysis/zipapk";

// ---------------------------------------------------------------------------
// tipler (frontend ile paylasilir)
// ---------------------------------------------------------------------------

export interface DpName {
  index: number;
  name: string;
}

export interface DpObject {
  index: number;
  cls: string; // obje sinifi (Class / Function / ScriptStruct ...)
  name: string;
  path: string; // "/Script/Engine.Actor" veya ""
  address: string; // hex dize, yoksa "0x0"
  invalid: boolean;
}

export interface DpParam {
  name: string;
  type: string;
  offset: string; // hex dize
  size: string; // hex dize
  flags: string; // hex dize
  target?: string; // struct hedefi (StructProperty icin)
}

export interface DpFunction {
  cls: string;
  pkg: string;
  name: string;
  rva: string; // hex dize
  va: string; // hex dize
  ufunction: string; // hex dize ("0x0" olabilir)
  native: string; // hex dize ("0x0" = BP-only)
  paramsSize: string; // hex dize
  flags: string; // hex dize
  params: DpParam[];
  ret?: DpParam;
}

export interface DpMeta {
  toolVersion: string | null; // "DumperPro 0.5.0"
  mode: string | null; // result.target.mode ("device" ...)
  target: string | null; // result.target.detail
  game: string | null;
  ueVersion: string | null;
  moduleName: string | null;
  moduleBase: string | null;
  status: "full" | "names-only";
  generated: string | null; // result.generated (insan okur damga)
}

export interface DpParsedImport {
  names: DpName[];
  objects: DpObject[];
  functions: DpFunction[];
  meta: DpMeta;
  /** bulunan/parse edilen kaynak dosya adlari */
  sources: string[];
  /** result.json artifacts listesi (varsa) */
  artifacts: string[];
}

export interface DpSourceFile {
  /** diskte korunacak guvenli ad */
  name: string;
  data: Buffer;
}

// ---------------------------------------------------------------------------
// yardimcilar
// ---------------------------------------------------------------------------

const HEX_RE = /^0x[0-9a-fA-F]+$/;

/** "0x1A2B3C" -> 1715004 | gecersiz ise 0. */
export function hexToNum(s: string | undefined | null): number {
  if (!s) return 0;
  const t = String(s).trim();
  if (HEX_RE.test(t)) return parseInt(t, 16) || 0;
  const n = Number(t);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

/** Sayiyi standart hex dizesine cevirir ("0x1a2b3c" kucuk harf). */
export function numToHex(n: number): string {
  return `0x${Math.max(0, Math.floor(n)).toString(16)}`;
}

function asHex(v: unknown, fallback = "0x0"): string {
  if (typeof v === "string" && HEX_RE.test(v.trim())) return v.trim().toLowerCase();
  if (typeof v === "number" && Number.isFinite(v) && v >= 0) return numToHex(v);
  return fallback;
}

function asStr(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

function safeJsonParse(buf: Buffer): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(buf.toString("utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// JSON normalizatorleri (tolerant)
// ---------------------------------------------------------------------------

export function parseNamesJson(buf: Buffer): DpName[] {
  const root = safeJsonParse(buf);
  if (!root) {
    // tip: duz dize dizisi ["None","ByteProperty"] da kabul edilir
    try {
      const arr: unknown = JSON.parse(buf.toString("utf8"));
      if (Array.isArray(arr)) {
        return arr
          .map((s, i) => ({ index: i, name: typeof s === "string" ? s : String(s ?? "") }))
          .filter((n) => n.name.length > 0);
      }
    } catch {
      // JSON degil
    }
    return [];
  }
  const list = Array.isArray(root.names) ? root.names : [];
  const out: DpName[] = [];
  let next = 0;
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const o = raw as Record<string, unknown>;
    const name = asStr(o.name ?? o.Name ?? o.n);
    if (!name) continue;
    const idxRaw = o.index ?? o.i;
    let index = next;
    if (typeof idxRaw === "number" && Number.isFinite(idxRaw) && idxRaw >= 0) index = Math.floor(idxRaw);
    else if (typeof idxRaw === "string" && HEX_RE.test(idxRaw.trim())) index = parseInt(idxRaw.trim(), 16);
    next = index + 1;
    out.push({ index, name });
  }
  return out;
}

export function parseObjectsJson(buf: Buffer): DpObject[] {
  const root = safeJsonParse(buf);
  if (!root) return [];
  const list = Array.isArray(root.objects) ? root.objects : [];
  const out: DpObject[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const o = raw as Record<string, unknown>;
    const index =
      typeof o.index === "number" && Number.isFinite(o.index) ? Math.floor(o.index) : hexToNum(asStr(o.index, "0x0"));
    const invalid = o.invalid === true;
    const cls = asStr(o.class ?? o.cls ?? o.type);
    const name = asStr(o.name);
    const objPath = asStr(o.path ?? o.fullPath);
    const address = asHex(o.address ?? o.addr);
    if (!invalid && !cls && !name) continue;
    out.push({ index, cls, name, path: objPath, address, invalid });
  }
  return out;
}

function normalizeParam(raw: unknown): DpParam | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const name = asStr(o.name);
  const type = asStr(o.type ?? o.propType);
  if (!name && !type) return null;
  const p: DpParam = {
    name: name || "Param",
    type: type || "Unknown",
    offset: asHex(o.offset),
    size: asHex(o.size),
    flags: asHex(o.flags),
  };
  const target = asStr(o.target);
  if (target) p.target = target;
  return p;
}

export function parseFunctionsJson(buf: Buffer): { functions: DpFunction[]; meta: Partial<DpMeta> } {
  const root = safeJsonParse(buf);
  const empty = { functions: [] as DpFunction[], meta: {} as Partial<DpMeta> };
  if (!root) return empty;

  const meta: Partial<DpMeta> = {};
  const game = asStr(root.game);
  if (game) meta.game = game;
  const ue = asStr(root.ue);
  if (ue) meta.ueVersion = ue;
  const mod = root.module;
  if (mod && typeof mod === "object") {
    const m = mod as Record<string, unknown>;
    const modName = asStr(m.name);
    if (modName) meta.moduleName = modName;
    const modBase = asStr(m.base);
    if (modBase) meta.moduleBase = asHex(modBase);
  }

  const list = Array.isArray(root.functions) ? root.functions : [];
  const functions: DpFunction[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const o = raw as Record<string, unknown>;
    const name = asStr(o.name);
    if (!name) continue;
    const fn: DpFunction = {
      cls: asStr(o.cls ?? o.class),
      pkg: asStr(o.pkg ?? o.package),
      name,
      rva: asHex(o.rva),
      va: asHex(o.va),
      ufunction: asHex(o.ufunction),
      native: asHex(o.native),
      paramsSize: asHex(o.paramsSize ?? o.paramSize),
      flags: asHex(o.flags),
      params: Array.isArray(o.params)
        ? o.params.map(normalizeParam).filter((p): p is DpParam => p !== null)
        : [],
    };
    const ret = normalizeParam(o.ret);
    if (ret) fn.ret = ret;
    functions.push(fn);
  }
  return { functions, meta };
}

// ---------------------------------------------------------------------------
// manifest (result.json)
// ---------------------------------------------------------------------------

export function parseResultJson(
  buf: Buffer,
): Partial<DpMeta> & {
  counts?: { names: number; objects: number; functions: number };
  artifacts?: string[];
} {
  const root = safeJsonParse(buf);
  const out: Partial<DpMeta> & {
    counts?: { names: number; objects: number; functions: number };
    artifacts?: string[];
  } = {};
  if (!root) return out;
  const tool = asStr(root.tool);
  if (tool) out.toolVersion = tool;
  const generated = asStr(root.generated);
  if (generated) out.generated = generated;
  const tgt = root.target;
  if (tgt && typeof tgt === "object") {
    const t = tgt as Record<string, unknown>;
    const mode = asStr(t.mode);
    if (mode) out.mode = mode;
    const detail = asStr(t.detail);
    if (detail) out.target = detail;
  }
  const game = asStr(root.game);
  if (game) out.game = game;
  const ue = asStr(root.ue);
  if (ue) out.ueVersion = ue;
  const mod = root.module;
  if (mod && typeof mod === "object") {
    const m = mod as Record<string, unknown>;
    const modName = asStr(m.name);
    if (modName) out.moduleName = modName;
    const modBase = asStr(m.base);
    if (modBase) out.moduleBase = asHex(modBase);
  }
  const status = asStr(root.status);
  if (status === "full" || status === "names-only") out.status = status;
  const counts = root.counts;
  if (counts && typeof counts === "object") {
    const c = counts as Record<string, unknown>;
    out.counts = {
      names: typeof c.names === "number" ? Math.floor(c.names) : hexToNum(asStr(c.names)),
      objects: typeof c.objects === "number" ? Math.floor(c.objects) : hexToNum(asStr(c.objects)),
      functions: typeof c.functions === "number" ? Math.floor(c.functions) : hexToNum(asStr(c.functions)),
    };
  }
  if (Array.isArray(root.artifacts)) {
    out.artifacts = root.artifacts.filter((a): a is string => typeof a === "string");
  }
  return out;
}

// ---------------------------------------------------------------------------
// yedek metin formatlari (Names.txt / Objects.txt / funcs.txt)
// ---------------------------------------------------------------------------

/** "0x0000012A: SomeName" veya "298: SomeName" satirlari. */
export function parseNamesTxt(buf: Buffer): DpName[] {
  const text = buf.toString("utf8");
  const out: DpName[] = [];
  const seen = new Set<number>();
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:0x([0-9a-fA-F]+)|(\d+))\s*:\s*(.+?)\s*$/.exec(line);
    if (!m) continue;
    const index = m[1] !== undefined ? parseInt(m[1], 16) : parseInt(m[2] ?? "", 10);
    const name = m[3] ?? "";
    if (!Number.isFinite(index) || !name) continue;
    if (seen.has(index)) continue; // ilk goren kazanir
    seen.add(index);
    out.push({ index, name });
  }
  return out;
}

/** "[123] Actor /Script/Engine 0x7FF..." -> index, cls, name, path?, address? */
export function parseObjectsTxt(buf: Buffer): DpObject[] {
  const text = buf.toString("utf8");
  const out: DpObject[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*\[(\d+)\]\s+(\S+)\s+(\S+)(?:\s+(\/\S+))?(?:\s+(0x[0-9a-fA-F]+))?\s*$/.exec(line);
    if (!m) continue;
    out.push({
      index: parseInt(m[1] ?? "0", 10),
      cls: m[2] ?? "",
      name: m[3] ?? "",
      path: m[4] ?? "",
      address: m[5] ? m[5].toLowerCase() : "0x0",
      invalid: false,
    });
  }
  return out;
}

/**
 * SDK funcs.txt satirlari:
 *   "Class::Func [ufunction] RVA 0x1A2B3C VA 0x7FF... ParamsSize 0x58 UFunction 0x7FF..."
 * Kose parantezli etiketler ([vtable>Foo], [pattern], [ufunction]) opsiyonel ve
 * degiskendir; eksik alanlara toleransli.
 */
export function parseFuncsTxt(buf: Buffer): DpFunction[] {
  const text = buf.toString("utf8");
  const out: DpFunction[] = [];
  const kv = (line: string, key: string): string | undefined =>
    new RegExp(`${key}\\s+(0x[0-9a-fA-F]+)`, "i").exec(line)?.[1];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//") || line.startsWith("#")) continue;
    // kose parantezlerinden onceki kisim = cls::name (etiketler opsiyonel)
    const bracketStart = line.indexOf("[");
    const head = (bracketStart >= 0 ? line.slice(0, bracketStart) : line).trim();
    if (!head) continue;

    const sep = head.lastIndexOf("::");
    const cls = sep >= 0 ? head.slice(0, sep).trim() : "";
    const name = sep >= 0 ? head.slice(sep + 2).trim() : head;
    if (!name) continue;

    out.push({
      cls,
      pkg: "",
      name,
      rva: (kv(line, "RVA") ?? "0x0").toLowerCase(),
      va: (kv(line, "VA") ?? "0x0").toLowerCase(),
      ufunction: (kv(line, "UFunction") ?? "0x0").toLowerCase(),
      native: (kv(line, "Native") ?? "0x0").toLowerCase(),
      paramsSize: (kv(line, "ParamsSize") ?? "0x0").toLowerCase(),
      flags: (kv(line, "Flags") ?? "0x0").toLowerCase(),
      params: [],
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// kayit alanlari: normalize edilmis JSON dizelerinden dizi okuma
// ---------------------------------------------------------------------------

/** namesJson alanindan DpName dizisi (bozuk/eksik JSON -> bos dizi). */
export function parseNamesField(json: string | null | undefined): DpName[] {
  if (!json) return [];
  try {
    const root: unknown = JSON.parse(json);
    if (root && typeof root === "object" && Array.isArray((root as { names?: unknown }).names)) {
      return (root as { names: DpName[] }).names;
    }
  } catch {
    // bozuk JSON - bos don
  }
  return [];
}

/** objectsJson alanindan DpObject dizisi (bozuk/eksik JSON -> bos dizi). */
export function parseObjectsField(json: string | null | undefined): DpObject[] {
  if (!json) return [];
  try {
    const root: unknown = JSON.parse(json);
    if (root && typeof root === "object" && Array.isArray((root as { objects?: unknown }).objects)) {
      return (root as { objects: DpObject[] }).objects;
    }
  } catch {
    // bozuk JSON - bos don
  }
  return [];
}

/** functionsJson alanindan DpFunction dizisi (bozuk/eksik JSON -> bos dizi). */
export function parseFunctionsField(json: string | null | undefined): DpFunction[] {
  if (!json) return [];
  try {
    const root: unknown = JSON.parse(json);
    if (root && typeof root === "object" && Array.isArray((root as { functions?: unknown }).functions)) {
      return (root as { functions: DpFunction[] }).functions;
    }
  } catch {
    // bozuk JSON - bos don
  }
  return [];
}

// ---------------------------------------------------------------------------
// dosya siniflandirma + zip demeti
// ---------------------------------------------------------------------------

export type DpFileKind = "result" | "names" | "objects" | "functions" | "funcs" | "unknown";

/** Basit ada gore tur tespiti (.basename tabanli, kaba; anahtar kelime dosya adinin herhangi bir yerinde olabilir). */
export function classifyFileName(name: string): DpFileKind {
  const base = name.split(/[/\\]/).pop() ?? name;
  const lower = base.toLowerCase();
  if (lower.includes("result") && lower.endsWith(".json")) return "result";
  if (lower.includes("function") && lower.endsWith(".json")) return "functions";
  if (lower.includes("funcs") || (lower.includes("function") && !lower.endsWith(".json"))) return "funcs";
  if (lower.includes("gnames") || lower.includes("names")) return "names";
  if (lower.includes("objects") || lower.includes("object")) return "objects";
  return "unknown";
}

/** ZIP icindeki sonuc dosyalarini cikarir (STORE + DEFLATE, zipapk yardimcileri). */
export function extractDumperProZip(buf: Buffer): DpSourceFile[] {
  let entries;
  try {
    entries = parseZipCentralDirectory(buf);
  } catch {
    return [];
  }
  const out: DpSourceFile[] = [];
  for (const entry of entries) {
    const kind = classifyFileName(entry.name);
    if (kind === "unknown") continue;
    const extracted = extractZipEntry(buf, entry);
    if (!extracted) continue;
    const base = entry.name.split(/[/\\]/).pop() ?? entry.name;
    out.push({ name: sanitizeDpFileName(base), data: extracted.data });
  }
  return out;
}

/** storage icin guvenli dosya adi (storage.ts.sanitizeFileName ile ayni mantik). */
export function sanitizeDpFileName(name: string): string {
  const base = (name.split(/[/\\]/).pop() ?? name).replace(/[^A-Za-z0-9._-]/g, "_");
  return base.slice(0, 120) || "dosya.bin";
}

// ---------------------------------------------------------------------------
// tumlestirici: kaynak dosya listesi -> DpParsedImport
// ---------------------------------------------------------------------------

function mergeMeta(target: DpMeta, patch: Partial<DpMeta>): void {
  if (patch.toolVersion && !target.toolVersion) target.toolVersion = patch.toolVersion;
  if (patch.mode && !target.mode) target.mode = patch.mode;
  if (patch.target && !target.target) target.target = patch.target;
  if (patch.game && !target.game) target.game = patch.game;
  if (patch.ueVersion && !target.ueVersion) target.ueVersion = patch.ueVersion;
  if (patch.moduleName && !target.moduleName) target.moduleName = patch.moduleName;
  if (patch.moduleBase && !target.moduleBase) target.moduleBase = patch.moduleBase;
  if (patch.generated && !target.generated) target.generated = patch.generated;
}

function defaultMeta(): DpMeta {
  return {
    toolVersion: null,
    mode: null,
    target: null,
    game: null,
    ueVersion: null,
    moduleName: null,
    moduleBase: null,
    status: "names-only",
    generated: null,
  };
}

/**
 * Tum kaynak dosyalari ayristirip tek normalize edilmis sonuc uretir.
 * Meta onceligi: result.json > functions.json basligi > varsayilanlar.
 * Ayni turden birden fazla dosya birlestirilir (names/objects indekse gore
 * tekillestirilir, fonksiyonlar cls::name@rva anahtariyla tekillestirilir).
 */
export function parseDumperProFiles(files: DpSourceFile[]): DpParsedImport {
  const meta = defaultMeta();
  const names = new Map<number, DpName>();
  const objects = new Map<number, DpObject>();
  const functions: DpFunction[] = [];
  const fnSeen = new Set<string>();
  const sources: string[] = [];
  let manifestStatus: "full" | "names-only" | undefined;
  let artifacts: string[] = [];

  for (const file of files) {
    const kind = classifyFileName(file.name);
    if (kind === "unknown") continue;
    sources.push(file.name);

    if (kind === "result") {
      const m = parseResultJson(file.data);
      mergeMeta(meta, m);
      if (m.status) manifestStatus = m.status;
      if (m.artifacts && artifacts.length === 0) artifacts = m.artifacts;
      continue;
    }

    if (kind === "names") {
      // once JSON, bos donerse tolerant metin parser
      let parsed = parseNamesJson(file.data);
      if (parsed.length === 0) parsed = parseNamesTxt(file.data);
      for (const n of parsed) {
        if (!names.has(n.index)) names.set(n.index, n);
      }
      continue;
    }

    if (kind === "objects") {
      let parsed = parseObjectsJson(file.data);
      if (parsed.length === 0) parsed = parseObjectsTxt(file.data);
      for (const o of parsed) {
        if (!objects.has(o.index)) objects.set(o.index, o);
      }
      continue;
    }

    if (kind === "functions" || kind === "funcs") {
      // JSON ise schema v1 parser, degilse funcs.txt satir parser
      const root = safeJsonParse(file.data);
      let fns: DpFunction[];
      if (root && Array.isArray(root.functions)) {
        const j = parseFunctionsJson(file.data);
        fns = j.functions;
        mergeMeta(meta, j.meta);
      } else {
        fns = parseFuncsTxt(file.data);
      }
      for (const f of fns) {
        const key = `${f.cls}::${f.name}@${f.rva}`;
        if (!fnSeen.has(key)) {
          fnSeen.add(key);
          functions.push(f);
        }
      }
      continue;
    }
  }

  const namesArr = [...names.values()].sort((a, b) => a.index - b.index);
  const objectsArr = [...objects.values()].sort((a, b) => a.index - b.index);

  // meta tamamla: eksikler icin varsayilanlar
  if (!meta.game) meta.game = "Bilinmeyen";
  if (!meta.ueVersion) meta.ueVersion = "—";
  if (!meta.mode) meta.mode = "—";
  if (!meta.target) meta.target = "—";
  if (!meta.moduleName) meta.moduleName = "—";
  if (!meta.moduleBase) meta.moduleBase = "—";

  // durum: manifest > turetilmis (fonksiyon/obje verisi varsa full)
  meta.status = manifestStatus ?? (functions.length > 0 || objectsArr.length > 0 ? "full" : "names-only");

  return {
    names: namesArr,
    objects: objectsArr,
    functions,
    meta,
    sources,
    artifacts,
  };
}
