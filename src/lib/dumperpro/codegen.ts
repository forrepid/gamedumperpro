// ----------------------------------------------------------------------------
// DumperPro ice aktarma - kod uretici (saf fonksiyon, sunucu rotasindan cagrilir)
//
// Kaynak veri DumperPro functions.json normalize edilmis DpFunction listesidir.
// Motor ciktisinda opcode yoktur; burada da OPCODE URETILMEZ - yalnizca aracin
// raporladigi RVA/VA/UFunction/Native/ParamsSize/Flags adresleri ve parametre
// tablolari dil sozdizimine dokulur.
//
// Desteklenen diller: cpp | csharp | python | rust | typescript | java | lua | json
// Turler: all | functions | structs | enums (v1: structs/enums bos + aciklama)
// ----------------------------------------------------------------------------

import type { DpFunction } from "./parse";

// ---------------------------------------------------------------------------
// tipler
// ---------------------------------------------------------------------------

export type DpCodegenLang = "cpp" | "csharp" | "python" | "rust" | "typescript" | "java" | "lua" | "json";
export type DpCodegenKind = "all" | "functions" | "structs" | "enums";

export interface DpCodegenMeta {
  tool: string; // "DumperPro 0.5.0"
  game: string;
  ue: string;
  moduleName: string;
  moduleBase: string;
  status: string; // full | names-only
}

export interface DpCodegenInput {
  meta: DpCodegenMeta;
  functions: DpFunction[];
}

export interface DpCodegenOutput {
  text: string;
  filename: string;
  itemCount: number;
}

export const DP_CODEGEN_LANGS: DpCodegenLang[] = [
  "cpp",
  "csharp",
  "python",
  "rust",
  "typescript",
  "java",
  "lua",
  "json",
];

export const DP_CODEGEN_KINDS: DpCodegenKind[] = ["all", "functions", "structs", "enums"];

// ---------------------------------------------------------------------------
// yardimcilar
// ---------------------------------------------------------------------------

const COMMENT_PREFIX: Record<DpCodegenLang, string> = {
  cpp: "//",
  csharp: "//",
  python: "#",
  rust: "//",
  typescript: "//",
  java: "//",
  lua: "--",
  json: "",
};

const FILENAME_BY_LANG: Record<DpCodegenLang, string> = {
  cpp: "dumperpro_functions.cpp",
  csharp: "DumperProFunctions.cs",
  python: "dumperpro_functions.py",
  rust: "dumperpro_functions.rs",
  typescript: "dumperpro_functions.ts",
  java: "DumperProFunctions.java",
  lua: "dumperpro_functions.lua",
  json: "dumperpro_functions.json",
};

/** "ACharacter::ServerMovePacked" -> "ACharacter_ServerMovePacked" (guv. tanimlayici). */
function identOf(fn: DpFunction): string {
  const raw = `${fn.cls || "Global"}_${fn.name}`.replace(/[^A-Za-z0-9_]/g, "_");
  const safe = /^[0-9]/.test(raw) ? `F_${raw}` : raw;
  return safe || "F_Anonymous";
}

function commentBlock(lang: DpCodegenLang, lines: string[]): string {
  const prefix = COMMENT_PREFIX[lang];
  if (!prefix) return ""; // json: yorum yok (_meta kullanilir)
  return lines.map((l) => `${prefix} ${l}`).join("\n");
}

// ---------------------------------------------------------------------------
// dil sekicileri (fonksiyon basina bir sabit/adres kaydi)
// ---------------------------------------------------------------------------

function cppEntry(fn: DpFunction, ident: string, comment: string): string {
  const lines: string[] = [];
  lines.push(comment);
  lines.push(`static constexpr unsigned long long ${ident}_RVA = ${fn.rva || "0x0"};`);
  lines.push(`static constexpr unsigned long long ${ident}_VA = ${fn.va || "0x0"};`);
  return lines.join("\n");
}

function csharpEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `public const ulong ${ident}_RVA = ${fn.rva || "0x0"};`,
    `public const ulong ${ident}_VA = ${fn.va || "0x0"};`,
  ].join("\n");
}

function rustEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `pub const ${ident.toUpperCase()}_RVA: u64 = ${fn.rva || "0x0"};`,
    `pub const ${ident.toUpperCase()}_VA: u64 = ${fn.va || "0x0"};`,
  ].join("\n");
}

function tsEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `export const ${ident}_RVA = ${fn.rva || "0x0"};`,
    `export const ${ident}_VA = ${fn.va || "0x0"};`,
  ].join("\n");
}

function javaEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `public static final long ${ident.toUpperCase()}_RVA = ${fn.rva || "0x0"}L;`,
    `public static final long ${ident.toUpperCase()}_VA = ${fn.va || "0x0"}L;`,
  ].join("\n");
}

function pythonEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `"${ident}": {"rva": "${fn.rva || "0x0"}", "va": "${fn.va || "0x0"}"},`,
  ].join("\n");
}

function luaEntry(fn: DpFunction, ident: string, comment: string): string {
  return [
    comment,
    `    ${ident} = { rva = "${fn.rva || "0x0"}", va = "${fn.va || "0x0"}" },`,
  ].join("\n");
}

// ---------------------------------------------------------------------------
// ana uretici
// ---------------------------------------------------------------------------

export function generateDumperProCode(input: DpCodegenInput, lang: DpCodegenLang, kind: DpCodegenKind): DpCodegenOutput {
  const { meta } = input;
  const filename = FILENAME_BY_LANG[lang];
  const isJson = lang === "json";
  const wantFunctions = kind === "all" || kind === "functions";

  if (isJson) {
    // JSON: gecerli belge - bilgiyi _meta icinde tasiyoruz (yorum yok)
    const payload = {
      _meta: {
        format: "dumperpro-codegen",
        tool: meta.tool,
        game: meta.game,
        ue: meta.ue,
        module: meta.moduleName,
        moduleBase: meta.moduleBase,
        status: meta.status,
        kind,
        count: wantFunctions ? input.functions.length : 0,
        note:
          kind === "structs" || kind === "enums"
            ? "v1: structs/enums verisi functions.json semasinda yok"
            : "opcode yok; yalnizca DumperPro rapor adresleri",
      },
      ...(wantFunctions
        ? {
            functions: input.functions.map((f) => ({
              cls: f.cls,
              pkg: f.pkg,
              name: f.name,
              rva: f.rva,
              va: f.va,
              ufunction: f.ufunction,
              native: f.native,
              paramsSize: f.paramsSize,
              flags: f.flags,
              params: f.params,
              ...(f.ret ? { ret: f.ret } : {}),
            })),
          }
        : {}),
    };
    return {
      text: JSON.stringify(payload, null, 2),
      filename,
      itemCount: wantFunctions ? input.functions.length : 0,
    };
  }

  const lines: string[] = [];
  const prefix = COMMENT_PREFIX[lang];

  // baslik yorumlari: arac, oyun, ue, adet
  lines.push(
    ...commentBlock(lang, [
      `DumperPro ice aktarma kod uretimi (${kind})`,
      `Arac: ${meta.tool}`,
      `Oyun: ${meta.game}`,
      `UE surumu: ${meta.ue}`,
      `Modul: ${meta.moduleName} (base ${meta.moduleBase})`,
      `Fonksiyon sayisi: ${input.functions.length} | durum: ${meta.status}`,
      `Opcode icermez - yalnizca DumperPro rapor adresleri (RVA/VA/UFunction/Native)`,
    ]).split("\n"),
  );
  lines.push("");

  if (kind === "structs" || kind === "enums") {
    lines.push(
      ...commentBlock(lang, [
        "v1 notu: functions.json semasi struct/enum tanimi tasimaz;",
        "bu tur icin cikarilacak veri yok. fonksiyon turunu kullanin.",
      ]).split("\n"),
    );
    return { text: lines.join("\n"), filename, itemCount: 0 };
  }

  const fns = input.functions;

  if (lang === "cpp") {
    lines.push("#include <cstdint>");
    lines.push("");
    lines.push("namespace DumperPro {");
    for (const f of fns) {
      lines.push(cppEntry(f, identOf(f), functionComment(lang, f)));
    }
    lines.push("}");
  } else if (lang === "csharp") {
    lines.push("namespace DumperPro {");
    lines.push("    public static class FunctionOffsets {");
    for (const f of fns) {
      lines.push(indent(csharpEntry(f, identOf(f), functionComment(lang, f)), 8));
    }
    lines.push("    }");
    lines.push("}");
  } else if (lang === "rust") {
    for (const f of fns) {
      lines.push(rustEntry(f, identOf(f), functionComment(lang, f)));
    }
  } else if (lang === "typescript") {
    lines.push("export const DumperProFunctionOffsets = {");
    for (const f of fns) {
      lines.push(indent(tsEntry(f, identOf(f), functionComment(lang, f)), 2));
    }
    lines.push("} as const;");
  } else if (lang === "java") {
    lines.push("public final class DumperProFunctions {");
    for (const f of fns) {
      lines.push(indent(javaEntry(f, identOf(f), functionComment(lang, f)), 4));
    }
    lines.push("}");
  } else if (lang === "python") {
    lines.push("DUMPERPRO_FUNCTIONS = {");
    for (const f of fns) {
      lines.push(indent(pythonEntry(f, identOf(f), functionComment(lang, f)), 4));
    }
    lines.push("}");
  } else if (lang === "lua") {
    lines.push("local DumperProFunctions = {");
    for (const f of fns) {
      lines.push(luaEntry(f, identOf(f), functionComment(lang, f)));
    }
    lines.push("}");
  }

  return { text: lines.join("\n"), filename, itemCount: fns.length };
}

/** Fonksiyon basina yorum blogu: RVA 0x... VA 0x... + param/ret tablosu. */
function functionComment(lang: DpCodegenLang, f: DpFunction): string {
  const prefix = COMMENT_PREFIX[lang];
  const head = `${f.cls ? `${f.cls}::` : ""}${f.name}${f.pkg ? ` [pkg: ${f.pkg}]` : ""}`;
  const addr = `RVA ${f.rva || "0x0"} VA ${f.va || "0x0"} UFunction ${f.ufunction || "0x0"} Native ${f.native || "0x0"} ParamsSize ${f.paramsSize || "0x0"} Flags ${f.flags || "0x0"}`;
  const out: string[] = [head, addr];
  for (const p of f.params) {
    out.push(
      `param ${p.name}: ${p.type} @${p.offset || "0x0"} size ${p.size || "0x0"}${p.target ? ` -> ${p.target}` : ""}`,
    );
  }
  if (f.ret) {
    out.push(
      `ret ${f.ret.name}: ${f.ret.type} @${f.ret.offset || "0x0"} size ${f.ret.size || "0x0"}`,
    );
  }
  if (!prefix) return "";
  return out.map((l) => `${prefix} ${l}`).join("\n");
}

function indent(block: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return block
    .split("\n")
    .map((l) => (l.length > 0 ? pad + l : l))
    .join("\n");
}
