// ----------------------------------------------------------------------------
// DumperPro Online - cok dilli kod uretici (codegen)
//
// AnalysisResult icindeki fonksiyon/struct/enum/dize verisini, kullanicinin
// sectigi dilde (cpp/csharp/python/rust/typescript/java/lua/json) sozdizimsel
// olarak dogru iskeletlere dokar. Her fonksiyon icin RVA/VA/boyut + prologue
// baytlarindan AOB deseni uretilir: son 4 bayt ve RIP-goreli pointer load /
// E8-E9 rel32 alanlari "??" joker yapilir (ASLR -> adres gecici).
//
// Fonksiyon adlari: etiket yoksa sub_<RVA8hex> (cikti kodunda ve yorumda).
// Cikti dosya adlari: <kind>_<language>.<ext> (h/cs/py/rs/ts/java/lua/json).
// Tum ciktilar arastirma amaclidir; offsetler statik kurtarma (tahmini).
// ----------------------------------------------------------------------------

import type {
  AnalysisResult,
  FunctionEntry,
  InterestingString,
  RecoveredEnum,
  RecoveredStruct,
  StructField,
} from "./types";

// ---------------------------------------------------------------------------
// public tipler
// ---------------------------------------------------------------------------

export type CodegenLanguage = "cpp" | "csharp" | "python" | "rust" | "typescript" | "java" | "lua" | "json";

export interface CodegenOptions {
  language: CodegenLanguage;
  kind: "functions" | "structs" | "enums" | "strings" | "all";
  limit?: number; // varsayilan 500
  filter?: string; // ad icinde buyuk/kucuk harf duyarsiz arama
  imageBase?: number; // verildiyse VA = imageBase + RVA
}

export interface CodegenOutput {
  language: CodegenLanguage;
  kind: string;
  filename: string;
  content: string;
  stats: { items: number; truncated?: boolean };
  notes: string[];
}

export const CODEGEN_LANGUAGES: CodegenLanguage[] = [
  "cpp", "csharp", "python", "rust", "typescript", "java", "lua", "json",
];

export const CODEGEN_KINDS: NonNullable<CodegenOptions["kind"]>[] = [
  "functions", "structs", "enums", "strings", "all",
];

// ---------------------------------------------------------------------------
// kucuk yardimcilar
// ---------------------------------------------------------------------------

const EXT: Record<CodegenLanguage, string> = {
  cpp: "h", csharp: "cs", python: "py", rust: "rs", typescript: "ts",
  java: "java", lua: "lua", json: "json",
};

const COMMENT: Record<CodegenLanguage, string> = {
  cpp: "//", csharp: "//", python: "#", rust: "//", typescript: "//",
  java: "//", lua: "--", json: "",
};

function hx(n: number): string {
  return `0x${Math.max(0, Math.floor(n)).toString(16).toUpperCase()}`;
}

function hxl(n: number): string {
  return `0x${Math.max(0, Math.floor(n)).toString(16)}`;
}

/** Dil anahtar sozcukleriyle cakismayi hassasiyetle birakiriz; yalnizca
 *  gecersiz karakterleri guvenli tanimlayiciya cevirir. */
function safeIdent(name: string): string {
  const clean = (name ?? "").replace(/[^A-Za-z0-9_]/g, "_");
  if (!clean) return "unnamed";
  return /^[0-9]/.test(clean) ? `_${clean}` : clean;
}

/** Ayni tanimlayicinin iki kez uretilmesini engeller (yeniden tanim hatasi). */
function makeNamer(): (base: string) => string {
  const seen = new Map<string, number>();
  return (base: string): string => {
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return n === 0 ? base : `${base}_${n + 1}`;
  };
}

/**
 * Alanlar arasindaki bosluklari (ve toplam boyuta kadar son dolguyu) uint8
 * dolgu alanlariyla doldurur; boylece cpp static_assert / python _pack_ = 1 /
 * rust repr(C) yerlesimi gercek offsetlerle birebir eslesir.
 */
function fieldsWithPadding(fields: StructField[], totalSize?: number): StructField[] {
  const out: StructField[] = [];
  let cursor = 0;
  const sorted = [...fields].sort((a, b) => a.offset - b.offset);
  for (const f of sorted) {
    if (f.offset > cursor) {
      out.push({ name: `pad_0x${cursor.toString(16)}`, offset: cursor, size: f.offset - cursor, type: `uint8[${f.offset - cursor}]`, reads: 0 });
    }
    out.push(f);
    cursor = Math.max(cursor, f.offset + f.size);
  }
  if (totalSize !== undefined && totalSize > cursor) {
    out.push({ name: `pad_0x${cursor.toString(16)}`, offset: cursor, size: totalSize - cursor, type: `uint8[${totalSize - cursor}]`, reads: 0 });
  }
  return out;
}

/** Tum dillerde paylasilan kacis karakteri: kontrol karakterleri -> '.', \\ ve " kacirilir. */
function escStr(s: string): string {
  let out = "";
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (code < 0x20 || code === 0x7f) out += ".";
    else out += ch;
  }
  return out;
}

// ---------------------------------------------------------------------------
// fonksiyon adlandirma + AOB
// ---------------------------------------------------------------------------

/** Etiket yoksa (ya da etiket ordinal/adres ise) sub_<RVA8hex> uretir. */
export function functionNameOf(f: FunctionEntry): string {
  const label = (f.label ?? "").trim();
  if (label && !/^(0x[0-9a-f]+|\d+|Ordinal_?\d+)$/i.test(label)) return label;
  return `sub_${f.rva.toString(16).padStart(8, "0").toUpperCase()}`;
}

/** Dekorlu etiketten (MSVC ?fn@Cls@@ / Itanium _ZN...) okunabilir ad cikarir;
 *  etiket zaten duz ise aynen dondurur, ordinal/adres ise "" dondurur. */
function readableName(label: string): string {
  const s = (label ?? "").trim();
  if (!s || /^(0x[0-9a-f]+|\d+|Ordinal_?\d+)$/i.test(s)) return "";
  if (s.startsWith("?")) {
    const m = s.match(/^\?([A-Za-z_$][A-Za-z0-9_$]*)@/);
    if (m) return m[1]!;
    return s.replace(/[?@].*$/, "");
  }
  if (s.startsWith("_Z") || s.startsWith("__Z")) {
    const names = [...s.matchAll(/(?:^|[^A-Za-z0-9_])(\d{1,4})([A-Za-z_$][A-Za-z0-9_$]{2,})/g)].map((m) => m[2]!);
    if (names.length > 0) return names[names.length - 1]!;
  }
  return s;
}

/**
 * Prologue baytlarindan AOB deseni uretir.
 * - anlamsiz baytlar (parse edilemeyen) -> ??
 * - son 4 bayt her zaman ?? (rel32/imm32 alani)
 * - RIP-goreli pointer load (48/4C/49 + 8B/8D/... + mod=00 rm=101) sonrasi 4 bayt ??
 * - E8/E9 rel32 cagri/atlama sonrasi 4 bayt ??
 * Desen: "48 89 5C 24 ?? 57" (boslukla ayrilmis, joker ??).
 */
export function buildAobPattern(prologue: string): string {
  const raw = (prologue ?? "").trim();
  if (!raw || raw === "-") return "";
  const tokens = raw.split(/\s+/).map((t) => (/^[0-9a-fA-F]{2}$/.test(t) ? t.toUpperCase() : null));
  if (tokens.length === 0) return "";
  const bytes: (number | null)[] = tokens.map((t) => (t === null ? null : parseInt(t, 16)));
  const wild = new Array<boolean>(tokens.length).fill(false);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === null) wild[i] = true;
  }
  // son 4 bayt: rel32 cagri hedefi / 32-bit immediate
  for (let i = Math.max(0, bytes.length - 4); i < bytes.length; i++) wild[i] = true;
  // RIP-goreli pointer load + E8/E9 rel32
  for (let i = 0; i + 3 < bytes.length; i++) {
    const b0 = bytes[i];
    if (b0 === null) continue;
    if (b0 === 0xe8 || b0 === 0xe9) {
      for (let k = i + 1; k < Math.min(i + 5, bytes.length); k++) wild[k] = true;
      continue;
    }
    if (i + 3 >= bytes.length) continue;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    if (b1 === null || b2 === null) continue;
    const isRex = b0 === 0x48 || b0 === 0x4c || b0 === 0x49;
    const ripOp = b1 === 0x8b || b1 === 0x8d || b1 === 0x63 || b1 === 0x03 || b1 === 0x2b || b1 === 0x3b;
    if (isRex && ripOp && (b2 & 0xc7) === 0x05) {
      for (let k = i + 3; k < Math.min(i + 7, bytes.length); k++) wild[k] = true;
    }
  }
  return bytes.map((_, i) => (wild[i] ? "??" : tokens[i]!)).join(" ");
}

// ---------------------------------------------------------------------------
// secim (filter + limit)
// ---------------------------------------------------------------------------

interface Selection<T> {
  items: T[];
  total: number; // filtre sonrasi toplam
  truncated: boolean;
}

function pick<T>(all: T[], filter: string | undefined, limit: number, nameOf: (t: T) => string): Selection<T> {
  let list = all;
  if (filter) {
    const q = filter.toLowerCase();
    list = list.filter((x) => nameOf(x).toLowerCase().includes(q));
  }
  return { items: list.slice(0, limit), total: list.length, truncated: list.length > limit };
}

// ---------------------------------------------------------------------------
// uretim baglami
// ---------------------------------------------------------------------------

interface FnMeta {
  name: string; // etiket ya da sub_<RVA8hex> (ham; json/lua/python anahtarlari)
  identBase: string; // tanimlayici tabani (dekor temizlenmis; cpp/csharp/rust/ts/java/python def)
  rva: number;
  va: number;
  size: number;
  aob: string;
  section: string;
  strings: string[];
  apiCalls: string[];
  callsOut: number;
  xrefsIn: number;
  label: string;
}

interface SelCounts {
  functions: number;
  structs: number;
  enums: number;
  strings: number;
}

interface EmitCtx {
  r: AnalysisResult;
  kind: NonNullable<CodegenOptions["kind"]>;
  limit: number;
  filter?: string;
  imageBase?: number;
  want: { functions: boolean; structs: boolean; enums: boolean; strings: boolean };
  fns: FnMeta[];
  structs: RecoveredStruct[];
  enums: RecoveredEnum[];
  strings: InterestingString[];
  counts: SelCounts;
}

type Emitter = (ctx: EmitCtx) => string[];

function fnMeta(f: FunctionEntry, imageBase?: number): FnMeta {
  const name = functionNameOf(f);
  return {
    name,
    identBase: readableName(f.label ?? "") || name,
    rva: f.rva,
    va: imageBase !== undefined ? imageBase + f.rva : f.va,
    size: f.size,
    aob: buildAobPattern(f.prologue),
    section: f.section,
    strings: f.strings ?? [],
    apiCalls: f.apiCalls ?? [],
    callsOut: f.callsOut ?? 0,
    xrefsIn: f.xrefsIn ?? 0,
    label: f.label ?? "",
  };
}

function fnHeaderLines(pre: string, f: FnMeta): string[] {
  const L: string[] = [];
  L.push(`${pre} RVA: ${hx(f.rva)} | VA: ${hx(f.va)} | SIZE: ${hx(f.size)} | SEC: ${f.section}${f.label ? ` | etiket: ${escStr(f.label)}` : ""}`);
  L.push(`${pre} AOB: ${f.aob || "-"}`);
  if (f.strings.length > 0) L.push(`${pre} strings: ${f.strings.map((s) => `"${escStr(s)}"`).join(", ")}`);
  if (f.apiCalls.length > 0) L.push(`${pre} api: ${f.apiCalls.join(", ")}`);
  return L;
}

function headerLines(pre: string, ctx: EmitCtx, filename: string): string[] {
  const L: string[] = [];
  const bar = `${pre} ===========================================================================`;
  L.push(bar);
  L.push(`${pre} DumperPro Online - kod uretimi (${ctx.kind} / ${ctx.r.file.name})`);
  L.push(`${pre} Cikti dosyasi: ${filename}`);
  L.push(`${pre} Secim: fonksiyon ${ctx.counts.functions} | struct ${ctx.counts.structs} | enum ${ctx.counts.enums} | dize ${ctx.counts.strings}`);
  if (ctx.filter) L.push(`${pre} Filtre: "${escStr(ctx.filter)}" (buyuk/kucuk harf duyarsiz)`);
  if (ctx.imageBase !== undefined) L.push(`${pre} VA = imageBase (${hx(ctx.imageBase)}) + RVA olarak hesaplandi`);
  L.push(`${pre} NOT: offsetler/adresler statik kurtarmadir (tahmini); canli modda dogrulanmali.`);
  L.push(`${pre} AOB: "??" jokerleri rel32/imm32 alanlaridir (ASLR -> adres gecici).`);
  L.push(bar);
  L.push("");
  return L;
}

// ---------------------------------------------------------------------------
// tip esleyicileri
// ---------------------------------------------------------------------------

function parseType(t: string): { base: string; count: number | null } {
  const m = (t ?? "").match(/^([A-Za-z0-9_]+)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]$/);
  if (m) {
    const n = m[2]!.startsWith("0x") ? parseInt(m[2]!, 16) : parseInt(m[2]!, 10);
    return { base: m[1]!, count: n };
  }
  return { base: t ?? "uint8", count: null };
}

const CPP_TYPES: Record<string, string> = {
  uint8: "uint8_t", uint16: "uint16_t", uint32: "uint32_t", uint64: "uint64_t",
  int8: "int8_t", int16: "int16_t", int32: "int32_t", int64: "int64_t",
  float: "float", double: "double", bool: "bool", vptr: "void*", "void*": "void*",
};

function cppFieldType(t: string): string {
  const { base } = parseType(t);
  if (CPP_TYPES[base]) return CPP_TYPES[base]!;
  const um = base.match(/^uint(\d+)$/);
  if (um) return `uint${um[1]!}_t`;
  const im = base.match(/^int(\d+)$/);
  if (im) return `int${im[1]!}_t`;
  return "uint8_t"; // bilinmeyen tur -> bayt guvenli varsayim
}

const CS_TYPES: Record<string, string> = {
  uint8: "byte", uint16: "ushort", uint32: "uint", uint64: "ulong",
  int8: "sbyte", int16: "short", int32: "int", int64: "long",
  float: "float", double: "double", bool: "bool", vptr: "IntPtr", "void*": "IntPtr",
};

function csFieldType(t: string): string {
  const { base, count } = parseType(t);
  const mapped = CS_TYPES[base] ?? (base.startsWith("uint") || base.startsWith("int") ? "byte" : "byte");
  return count !== null ? `${mapped}[]` : mapped;
}

const PY_TYPES: Record<string, string> = {
  uint8: "ctypes.c_uint8", uint16: "ctypes.c_uint16", uint32: "ctypes.c_uint32",
  uint64: "ctypes.c_uint64", int8: "ctypes.c_int8", int16: "ctypes.c_int16",
  int32: "ctypes.c_int32", int64: "ctypes.c_int64", float: "ctypes.c_float",
  double: "ctypes.c_double", bool: "ctypes.c_bool", vptr: "ctypes.c_void_p",
  "void*": "ctypes.c_void_p",
};

function pyFieldType(t: string, size: number): string {
  const { base, count } = parseType(t);
  const known = PY_TYPES[base];
  if (count !== null) {
    const elem = known ?? "ctypes.c_ubyte";
    return `${elem} * ${count}`;
  }
  if (known) return known;
  if (size > 0) return `ctypes.c_ubyte * ${size}`; // bilinmeyen tur -> bayt dizisi
  return "ctypes.c_void_p";
}

const RS_TYPES: Record<string, string> = {
  uint8: "u8", uint16: "u16", uint32: "u32", uint64: "u64",
  int8: "i8", int16: "i16", int32: "i32", int64: "i64",
  float: "f32", double: "f64", bool: "bool", vptr: "*mut core::ffi::c_void", "void*": "*mut core::ffi::c_void",
};

function rsFieldType(t: string): string {
  const { base, count } = parseType(t);
  const mapped = RS_TYPES[base] ?? "u8";
  return count !== null ? `[${mapped}; ${count}]` : mapped;
}

function tsFieldType(t: string): string {
  const { base, count } = parseType(t);
  const is64 = base === "uint64" || base === "int64";
  const isPtr = base === "vptr" || base === "void*";
  const isBool = base === "bool";
  let single = "number";
  if (is64) single = "bigint";
  else if (isPtr) single = "number | null";
  else if (isBool) single = "boolean";
  return count !== null ? `${single}[]` : single;
}

const JAVA_TYPES: Record<string, string> = {
  uint8: "byte", uint16: "short", uint32: "int", uint64: "long",
  int8: "byte", int16: "short", int32: "int", int64: "long",
  float: "float", double: "double", bool: "boolean", vptr: "long", "void*": "long",
};

function javaFieldType(t: string): string {
  const { base, count } = parseType(t);
  const mapped = JAVA_TYPES[base] ?? "byte";
  return count !== null ? `${mapped}[]` : mapped;
}

// ---------------------------------------------------------------------------
// cpp emitter
// ---------------------------------------------------------------------------

function emitCpp(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.cpp;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_cpp.h`));
  L.push("#pragma once");
  L.push("#include <cstdint>");
  L.push("#include <cstddef>");
  L.push("");

  if (ctx.want.functions) {
    L.push(`// ------------------------- fonksiyonlar (${ctx.fns.length}) -------------------------`);
    if (ctx.fns.length === 0) L.push("// (fonksiyon verisi yok)");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const name = nm(safeIdent(f.identBase));
      L.push(...fnHeaderLines(pre, f));
      L.push(`void ${name}();`);
      L.push("");
    }
  }

  if (ctx.want.structs) {
    L.push(`// ------------------------- structlar (${ctx.structs.length}) -------------------------`);
    if (ctx.structs.length === 0) L.push("// (struct verisi yok)");
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      const laid = fieldsWithPadding(s.fields, s.size);
      L.push(`struct ${sname} {`);
      if (laid.length === 0) L.push("    // (alan yok)");
      for (const fld of laid) {
        const t = cppFieldType(fld.type);
        const { count } = parseType(fld.type);
        const decl = count !== null ? `${t} ${safeIdent(fld.name)}[${count}]` : `${t} ${safeIdent(fld.name)}`;
        const isPad = fld.reads === 0 && fld.name.startsWith("pad_");
        L.push(`    ${decl}; // ${hx(fld.offset)} (boyut ${hx(fld.size)}, erisim ${fld.reads} fn)${isPad ? " // dolgu" : ""}`);
      }
      const extra: string[] = [`kaynak: ${s.source}`];
      if (s.size !== undefined) extra.push(`boyut: ${hx(s.size)}`);
      if (s.vftableRva !== undefined) extra.push(`vftable RVA: ${hx(s.vftableRva)}`);
      L.push(`}; // ${extra.join(" | ")}`);
      L.push("");
      for (const fld of laid) {
        L.push(`static_assert(offsetof(${sname}, ${safeIdent(fld.name)}) == ${hx(fld.offset)}, "${sname}.${escStr(fld.name)} offset dogrulamasi");`);
      }
      if (laid.length > 0) L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`// ------------------------- enumlar (${ctx.enums.length}) -------------------------`);
    if (ctx.enums.length === 0) L.push("// (enum verisi yok)");
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push(`enum class ${ename} : int32_t {`);
      if (e.members.length === 0) L.push("    // (uye yok)");
      for (const m of e.members) {
        L.push(`    ${safeIdent(m.name)} = ${m.value},`);
      }
      L.push(`}; // kaynak: ${e.source}`);
      L.push("");
    }
  }

  if (ctx.want.strings) {
    L.push(`// ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    if (ctx.strings.length === 0) L.push("// (dize verisi yok)");
    for (let i = 0; i < ctx.strings.length; i++) {
      const s = ctx.strings[i]!;
      if (s.kind === "utf16") L.push(`static const char16_t* STR_${String(i).padStart(3, "0")} = u"${escStr(s.value)}"; // utf16`);
      else L.push(`static const char* STR_${String(i).padStart(3, "0")} = "${escStr(s.value)}"; // ascii`);
    }
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// csharp emitter (Dumper-7 stili)
// ---------------------------------------------------------------------------

function emitCSharp(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.csharp;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_csharp.cs`));
  L.push("using System;");
  L.push("using System.Runtime.InteropServices;");
  L.push("");

  if (ctx.want.functions) {
    L.push("// Dumper-7 stili Address attribute tanimi");
    L.push("public class AddressAttribute : Attribute");
    L.push("{");
    L.push("    public string RVA;");
    L.push("    public string Offset;");
    L.push("    public string VA;");
    L.push("}");
    L.push("");
    L.push(`// ------------------------- fonksiyonlar (${ctx.fns.length}) -------------------------`);
    L.push("public class DumperFunctions");
    L.push("{");
    if (ctx.fns.length === 0) L.push("    // (fonksiyon verisi yok)");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const name = nm(safeIdent(f.identBase));
      L.push(...fnHeaderLines(pre, f).map((l) => `    ${l.slice(3)}`));
      L.push(`    [Address(RVA = "${hx(f.rva)}", Offset = "${hx(f.rva)}", VA = "${hx(f.va)}")]`);
      L.push(`    public void ${name}() { }`);
      L.push("");
    }
    L.push("}");
    L.push("");
  }

  if (ctx.want.structs) {
    L.push(`// ------------------------- structlar (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      L.push(`// kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}${s.size !== undefined ? ` | boyut: ${hx(s.size)}` : ""}`);
      L.push("[StructLayout(LayoutKind.Explicit)]");
      L.push(`public partial struct ${sname}`);
      L.push("{");
      if (s.fields.length === 0) L.push("    // (alan yok)");
      for (const fld of s.fields) {
        L.push(`    [FieldOffset(${hx(fld.offset)})] public ${csFieldType(fld.type)} ${safeIdent(fld.name)}; // erisim ${fld.reads} fn`);
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`// ------------------------- enumlar (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push(`public enum ${ename}`);
      L.push("{");
      if (e.members.length === 0) L.push("    // (uye yok)");
      for (const m of e.members) {
        L.push(`    ${safeIdent(m.name)} = ${m.value},`);
      }
      L.push(`} // kaynak: ${e.source}`);
      L.push("");
    }
  }

  if (ctx.want.strings) {
    L.push(`// ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    L.push("public static class DumperStrings");
    L.push("{");
    if (ctx.strings.length === 0) L.push("    // (dize verisi yok)");
    for (let i = 0; i < ctx.strings.length; i++) {
      const s = ctx.strings[i]!;
      L.push(`    public const string STR_${String(i).padStart(3, "0")} = "${escStr(s.value)}"; // ${s.kind}`);
    }
    L.push("}");
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// python emitter (ctypes)
// ---------------------------------------------------------------------------

function emitPython(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.python;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_python.py`));
  L.push("import ctypes");
  L.push("from enum import IntEnum");
  L.push("");

  if (ctx.want.functions) {
    L.push(`# ------------------------- fonksiyonlar (${ctx.fns.length}) -------------------------`);
    L.push("ADDRESSES = {");
    if (ctx.fns.length === 0) L.push("    # (fonksiyon verisi yok)");
    for (const f of ctx.fns) {
      L.push(`    "${escStr(f.name)}": {"rva": ${hxl(f.rva)}, "va": ${hxl(f.va)}, "size": ${hxl(f.size)}, "aob": "${f.aob || "-"}"}, # SEC: ${escStr(f.section)}`);
    }
    L.push("}");
    L.push("");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const defName = nm(safeIdent(f.identBase));
      L.push(`def ${defName}():`);
      L.push(`    """RVA: ${hx(f.rva)} | VA: ${hx(f.va)} | SIZE: ${hx(f.size)} | AOB: ${f.aob || "-"}"""`);
      L.push("    ...");
      L.push("");
    }
  }

  if (ctx.want.structs) {
    L.push(`# ------------------------- structlar (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      const laid = fieldsWithPadding(s.fields, s.size);
      L.push(`# kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}${s.size !== undefined ? ` | boyut: ${hx(s.size)}` : ""}`);
      L.push(`class ${sname}(ctypes.Structure):`);
      L.push("    _pack_ = 1 # pakli yerlesim (offset dogrulamasi icin)");
      L.push("    _fields_ = [");
      if (laid.length === 0) L.push("        # (alan yok)");
      for (const fld of laid) {
        const t = pyFieldType(fld.type, fld.size);
        const { base } = parseType(fld.type);
        const known = PY_TYPES[base] !== undefined;
        const isPad = fld.reads === 0 && fld.name.startsWith("pad_");
        const note = isPad ? " # dolgu" : known ? "" : ` # tur tahmini: ${escStr(fld.type)}`;
        L.push(`        ("${escStr(fld.name)}", ${t}), # ${hx(fld.offset)}${note}`);
      }
      L.push("    ]");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`# ------------------------- enumlar (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push(`class ${ename}(IntEnum): # kaynak: ${e.source}`);
      if (e.members.length === 0) L.push("    pass # (uye yok)");
      for (const m of e.members) {
        L.push(`    ${safeIdent(m.name)} = ${m.value}`);
      }
      L.push("");
    }
  }

  if (ctx.want.strings) {
    L.push(`# ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    if (ctx.strings.length === 0) L.push("# (dize verisi yok)");
    L.push("STRINGS = [");
    for (const s of ctx.strings) {
      L.push(`    {"value": "${escStr(s.value)}", "kind": "${s.kind}"},`);
    }
    L.push("]");
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// rust emitter
// ---------------------------------------------------------------------------

function emitRust(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.rust;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_rust.rs`));
  L.push("#![allow(non_snake_case, dead_code)]");
  L.push("");

  if (ctx.want.functions) {
    L.push(`// ------------------------- fonksiyonlar (${ctx.fns.length}) -------------------------`);
    L.push("pub const FUNCTION_ADDRESSES: &[(&str, u64)] = &[");
    if (ctx.fns.length === 0) L.push("    // (fonksiyon verisi yok)");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const name = nm(safeIdent(f.identBase));
      L.push(`    // RVA: ${hx(f.rva)} | VA: ${hx(f.va)} | SIZE: ${hx(f.size)} | SEC: ${escStr(f.section)} | AOB: ${f.aob || "-"}`);
      L.push(`    ("${escStr(name)}", ${hxl(f.rva)}),`);
    }
    L.push("];");
    L.push("");
    L.push(`extern "system" { // RVA yorumlari FUNCTION_ADDRESSES tablosundadir`);
    const nm2 = makeNamer();
    for (const f of ctx.fns) {
      const name = nm2(safeIdent(f.identBase));
      L.push(`    // AOB: ${f.aob || "-"}`);
      L.push(`    fn ${name}();`);
    }
    L.push("}");
    L.push("");
  }

  if (ctx.want.structs) {
    L.push(`// ------------------------- structlar (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      const laid = fieldsWithPadding(s.fields, s.size);
      L.push(`// kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}${s.size !== undefined ? ` | boyut: ${hx(s.size)}` : ""}`);
      L.push("#[repr(C)]");
      L.push(`pub struct ${sname} {`);
      if (laid.length === 0) L.push("    // (alan yok)");
      for (const fld of laid) {
        const isPad = fld.reads === 0 && fld.name.startsWith("pad_");
        L.push(`    pub ${safeIdent(fld.name)}: ${rsFieldType(fld.type)}, // ${hx(fld.offset)} (erisim ${fld.reads} fn)${isPad ? " // dolgu" : ""}`);
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`// ------------------------- enumlar (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push("#[repr(i32)]");
      L.push(`pub enum ${ename} { // kaynak: ${e.source}`);
      if (e.members.length === 0) L.push("    // (uye yok)");
      for (const m of e.members) {
        L.push(`    ${safeIdent(m.name)} = ${m.value},`);
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.strings) {
    L.push(`// ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    if (ctx.strings.length === 0) L.push("// (dize verisi yok)");
    for (let i = 0; i < ctx.strings.length; i++) {
      const s = ctx.strings[i]!;
      L.push(`pub static STR_${String(i).padStart(3, "0")}: &str = "${escStr(s.value)}"; // ${s.kind}`);
    }
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// typescript emitter
// ---------------------------------------------------------------------------

function emitTypeScript(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.typescript;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_typescript.ts`));

  if (ctx.want.functions) {
    L.push(`// ------------------------- fonksiyon adres tablosu (${ctx.fns.length}) -------------------------`);
    L.push("export const functionOffsets = {");
    if (ctx.fns.length === 0) L.push("    // (fonksiyon verisi yok)");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const name = nm(safeIdent(f.identBase));
      L.push(`    // RVA: ${hx(f.rva)} | VA: ${hx(f.va)} | SIZE: ${hx(f.size)} | SEC: ${escStr(f.section)} | AOB: ${f.aob || "-"}`);
      L.push(`    ${name}: ${hxl(f.rva)},`);
    }
    L.push("} as const;");
    L.push("");
  }

  if (ctx.want.structs) {
    L.push(`// ------------------------- interface + offset tablolari (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      L.push(`// kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}${s.size !== undefined ? ` | boyut: ${hx(s.size)}` : ""}`);
      L.push(`export interface ${sname} {`);
      if (s.fields.length === 0) L.push("    // (alan yok)");
      for (const fld of s.fields) {
        L.push(`    ${safeIdent(fld.name)}: ${tsFieldType(fld.type)}; // ${hx(fld.offset)} (${escStr(fld.type)}, erisim ${fld.reads} fn)`);
      }
      L.push("}");
      L.push("");
      L.push(`export const ${sname}Offsets = {`);
      for (const fld of s.fields) {
        L.push(`    ${safeIdent(fld.name)}: ${hxl(fld.offset)},`);
      }
      L.push("} as const;");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`// ------------------------- enum benzeri sabit nesneler (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push(`export const ${ename} = { // kaynak: ${e.source}`);
      if (e.members.length === 0) L.push("    // (uye yok)");
      for (const m of e.members) {
        L.push(`    ${safeIdent(m.name)}: ${m.value},`);
      }
      L.push("} as const;");
      L.push(`export type ${ename} = typeof ${ename}[keyof typeof ${ename}];`);
      L.push("");
    }
  }

  if (ctx.want.strings) {
    L.push(`// ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    if (ctx.strings.length === 0) L.push("// (dize verisi yok)");
    L.push("export const interestingStrings = [");
    for (const s of ctx.strings) {
      L.push(`    "${escStr(s.value)}", // ${s.kind}`);
    }
    L.push("] as const;");
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// java emitter
// ---------------------------------------------------------------------------

function emitJava(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.java;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_java.java`));

  if (ctx.want.structs) {
    L.push(`// ------------------------- siniflar (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      L.push(`public class ${sname} { // kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}`);
      if (s.fields.length === 0) L.push("    // (alan yok)");
      for (const fld of s.fields) {
        L.push(`    public ${javaFieldType(fld.type)} ${safeIdent(fld.name)}; // ${hx(fld.offset)} (${escStr(fld.type)}, erisim ${fld.reads} fn)`);
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`// ------------------------- enumlar (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      L.push(`public enum ${ename} { // kaynak: ${e.source}`);
      if (e.members.length === 0) L.push("    // (uye yok)");
      else {
        L.push(`    ${e.members.map((m) => `${safeIdent(m.name)}(${m.value})`).join(", ")};`);
        L.push("");
        L.push("    private final int value;");
        L.push("");
        L.push(`    ${ename}(int value) {`);
        L.push("        this.value = value;");
        L.push("    }");
        L.push("");
        L.push("    public int getValue() {");
        L.push("        return value;");
        L.push("    }");
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.functions) {
    L.push(`// ------------------------- fonksiyon adres tablosu (${ctx.fns.length}) -------------------------`);
    L.push("public class FunctionAddresses {");
    if (ctx.fns.length === 0) L.push("    // (fonksiyon verisi yok)");
    const nm = makeNamer();
    for (const f of ctx.fns) {
      const name = nm(safeIdent(f.identBase));
      L.push(...fnHeaderLines(pre, f).map((l) => `    ${l.slice(3)}`));
      L.push(`    public static final long ${name} = ${hxl(f.rva)}L;`);
      L.push("");
    }
    L.push("}");
    L.push("");
  }

  if (ctx.want.strings) {
    L.push(`// ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    L.push("public class StringTable {");
    if (ctx.strings.length === 0) L.push("    // (dize verisi yok)");
    for (let i = 0; i < ctx.strings.length; i++) {
      const s = ctx.strings[i]!;
      L.push(`    public static final String STR_${String(i).padStart(3, "0")} = "${escStr(s.value)}"; // ${s.kind}`);
    }
    L.push("}");
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// lua emitter
// ---------------------------------------------------------------------------

function emitLua(ctx: EmitCtx): string[] {
  const L: string[] = [];
  const pre = COMMENT.lua;
  L.push(...headerLines(pre, ctx, `${ctx.kind}_lua.lua`));

  if (ctx.want.structs) {
    L.push(`-- ------------------------- struct tablolari (${ctx.structs.length}) -------------------------`);
    const nm = makeNamer();
    for (const s of ctx.structs) {
      const sname = nm(safeIdent(s.name));
      L.push(`${sname} = { -- kaynak: ${s.source}${s.vftableRva !== undefined ? ` | vftable RVA: ${hx(s.vftableRva)}` : ""}${s.size !== undefined ? ` | boyut: ${hx(s.size)}` : ""}`);
      if (s.fields.length === 0) L.push("    -- (alan yok)");
      for (const fld of s.fields) {
        L.push(`    ["${escStr(fld.name)}"] = { off = ${hxl(fld.offset)}, type = "${escStr(fld.type)}" }, -- erisim ${fld.reads} fn`);
      }
      L.push("}");
      L.push("");
    }
  }

  if (ctx.want.enums) {
    L.push(`-- ------------------------- enum tablolari (${ctx.enums.length}) -------------------------`);
    const nm = makeNamer();
    for (const e of ctx.enums) {
      const ename = nm(safeIdent(e.name));
      if (e.members.length <= 8) {
        const body = e.members.map((m) => `["${escStr(m.name)}"] = ${m.value}`).join(", ");
        L.push(`${ename} = { ${body || "-- (uye yok)"} } -- kaynak: ${e.source}`);
      } else {
        L.push(`${ename} = { -- kaynak: ${e.source}`);
        for (const m of e.members) {
          L.push(`    ["${escStr(m.name)}"] = ${m.value},`);
        }
        L.push("}");
      }
      L.push("");
    }
  }

  if (ctx.want.functions) {
    L.push(`-- ------------------------- fonksiyon adres tablosu (${ctx.fns.length}) -------------------------`);
    L.push("FunctionAddresses = {");
    if (ctx.fns.length === 0) L.push("    -- (fonksiyon verisi yok)");
    for (const f of ctx.fns) {
      L.push(`    -- RVA: ${hx(f.rva)} | VA: ${hx(f.va)} | SIZE: ${hx(f.size)} | SEC: ${escStr(f.section)} | AOB: ${f.aob || "-"}`);
      L.push(`    ["${escStr(f.name)}"] = ${hxl(f.rva)},`);
    }
    L.push("}");
    L.push("");
  }

  if (ctx.want.strings) {
    L.push(`-- ------------------------- dizeler (${ctx.strings.length}) -------------------------`);
    if (ctx.strings.length === 0) L.push("-- (dize verisi yok)");
    L.push("Strings = {");
    for (const s of ctx.strings) {
      L.push(`    { value = "${escStr(s.value)}", kind = "${s.kind}" },`);
    }
    L.push("}");
    L.push("");
  }

  return L;
}

// ---------------------------------------------------------------------------
// json emitter (makine okunabilir ozet)
// ---------------------------------------------------------------------------

interface JsonOut {
  meta: Record<string, unknown>;
  functions?: unknown[];
  structs?: unknown[];
  enums?: unknown[];
  strings?: unknown[];
}

function emitJson(ctx: EmitCtx): string[] {
  const out: JsonOut = {
    meta: {
      generator: "DumperPro Online codegen",
      kind: ctx.kind,
      language: "json",
      targetFile: ctx.r.file.name,
      targetSize: ctx.r.file.size,
      imageBase: ctx.imageBase !== undefined ? hx(ctx.imageBase) : undefined,
      filter: ctx.filter,
      limit: ctx.limit,
      counts: ctx.counts,
      note: "offsetler/adresler statik kurtarma (tahmini); AOB jokerleri rel32/imm32 alanlaridir",
    },
  };
  if (ctx.want.functions) {
    out.functions = ctx.fns.map((f) => ({
      name: f.name,
      label: f.label || undefined,
      rva: hx(f.rva),
      va: hx(f.va),
      size: f.size,
      section: f.section,
      aob: f.aob || undefined,
      callsOut: f.callsOut,
      xrefsIn: f.xrefsIn,
      strings: f.strings,
      apiCalls: f.apiCalls,
    }));
  }
  if (ctx.want.structs) {
    out.structs = ctx.structs.map((s) => ({
      name: s.name,
      kind: s.kind,
      size: s.size,
      base: s.base,
      vftableRva: s.vftableRva !== undefined ? hx(s.vftableRva) : undefined,
      vftableVa: s.vftableVa !== undefined ? hx(s.vftableVa) : undefined,
      methodCount: s.methodCount,
      source: s.source,
      fields: s.fields.map((f: StructField) => ({
        name: f.name,
        offset: hx(f.offset),
        size: f.size,
        type: f.type,
        reads: f.reads,
      })),
    }));
  }
  if (ctx.want.enums) {
    out.enums = ctx.enums.map((e) => ({
      name: e.name,
      source: e.source,
      members: e.members,
    }));
  }
  if (ctx.want.strings) {
    out.strings = ctx.strings;
  }
  return [JSON.stringify(out, null, 2)];
}

// ---------------------------------------------------------------------------
// ana giris: generateCode
// ---------------------------------------------------------------------------

const EMITTERS: Record<CodegenLanguage, Emitter> = {
  cpp: emitCpp,
  csharp: emitCSharp,
  python: emitPython,
  rust: emitRust,
  typescript: emitTypeScript,
  java: emitJava,
  lua: emitLua,
  json: emitJson,
};

export function generateCode(result: AnalysisResult, opts: CodegenOptions): CodegenOutput {
  if (!CODEGEN_LANGUAGES.includes(opts.language)) {
    throw new Error(`gecersiz dil: ${String(opts.language)}`);
  }
  if (!CODEGEN_KINDS.includes(opts.kind)) {
    throw new Error(`gecersiz kind: ${String(opts.kind)}`);
  }
  const limit = Math.max(1, Math.min(opts.limit ?? 500, 5000));
  const filter = opts.filter && opts.filter.trim() ? opts.filter.trim() : undefined;
  const imageBase = opts.imageBase;

  const want = {
    functions: opts.kind === "all" || opts.kind === "functions",
    structs: opts.kind === "all" || opts.kind === "structs",
    enums: opts.kind === "all" || opts.kind === "enums",
    strings: opts.kind === "all" || opts.kind === "strings",
  };

  const rawFns = want.functions ? result.functions?.functions ?? [] : [];
  const rawStructs = want.structs ? result.structs?.structs ?? [] : [];
  const rawEnums = want.enums ? result.enums?.enums ?? [] : [];
  const rawStrings = want.strings ? result.strings ?? [] : [];

  const selFns = pick(rawFns, filter, limit, (f) => `${f.label ?? ""} ${functionNameOf(f)}`);
  const selStructs = pick(rawStructs, filter, limit, (s) => s.name);
  const selEnums = pick(rawEnums, filter, limit, (e) => `${e.name} ${e.members.map((m) => m.name).join(" ")}`);
  const selStrings = pick(rawStrings, filter, limit, (s) => s.value);

  const ctx: EmitCtx = {
    r: result,
    kind: opts.kind,
    limit,
    filter,
    imageBase,
    want,
    fns: selFns.items.map((f) => fnMeta(f, imageBase)),
    structs: selStructs.items,
    enums: selEnums.items,
    strings: selStrings.items,
    counts: {
      functions: selFns.items.length,
      structs: selStructs.items.length,
      enums: selEnums.items.length,
      strings: selStrings.items.length,
    },
  };

  const lines = EMITTERS[opts.language]!(ctx);
  const filename = `${opts.kind}_${opts.language}.${EXT[opts.language]}`;

  const items = ctx.counts.functions + ctx.counts.structs + ctx.counts.enums + ctx.counts.strings;
  const truncated = selFns.truncated || selStructs.truncated || selEnums.truncated || selStrings.truncated;

  // notlar
  const notes: string[] = [];
  notes.push("Offsetler/adresler statik kurtarmadir (tahmini); canli modda dogrulanmali.");
  if (imageBase !== undefined) notes.push(`VA = imageBase (${hx(imageBase)}) + RVA ile hesaplandi.`);
  if (want.functions) {
    notes.push('AOB deseninde "??" jokerleri rel32 cagri hedefleri / 32-bit immediates ve RIP-goreli pointer load alanlaridir.');
    if (result.functions?.note) notes.push(String(result.functions.note));
  }
  if (filter) notes.push(`Filtre "${filter}" uygulandi (buyuk/kucuk harf duyarsiz).`);
  if (selFns.truncated) notes.push(`Limit ${limit} uygulandi: fonksiyon ${selFns.total} kayittan ${selFns.items.length} yazildi.`);
  if (selStructs.truncated) notes.push(`Limit ${limit} uygulandi: struct ${selStructs.total} kayittan ${selStructs.items.length} yazildi.`);
  if (selEnums.truncated) notes.push(`Limit ${limit} uygulandi: enum ${selEnums.total} kayittan ${selEnums.items.length} yazildi.`);
  if (selStrings.truncated) notes.push(`Limit ${limit} uygulandi: dize ${selStrings.total} kayittan ${selStrings.items.length} yazildi.`);
  if (want.functions && result.functions === undefined) notes.push("Analiz sonucunda fonksiyon verisi bulunamadi.");
  if (want.structs && result.structs === undefined) notes.push("Analiz sonucunda struct verisi bulunamadi.");
  if (want.enums && result.enums === undefined) notes.push("Analiz sonucunda enum verisi bulunamadi.");
  if (want.strings && (result.strings ?? []).length === 0) notes.push("Analiz sonucunda dize verisi bulunamadi.");
  if (opts.language === "java") notes.push("Java: tek dosyada birden fazla public top-level sinif olabilir; javac dosya adi siniri icin ayri dosyalara bolunmesi gerekebilir.");
  if (opts.language === "python") notes.push("Python: struct siniflari _pack_ = 1 ile pakli yerlesim kullanir; bilinmeyen alan turleri c_ubyte dizisine indirgenir.");
  if (opts.language === "json") notes.push("JSON ciktisi yorum icermez; ust veri meta alanindadir.");

  return {
    language: opts.language,
    kind: opts.kind,
    filename,
    content: lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n",
    stats: { items, truncated },
    notes,
  };
}
