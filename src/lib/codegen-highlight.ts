// ----------------------------------------------------------------------------
// DumperPro Online - codegen cikti vurgulayici (sifir bagimlilik)
//
// Kod Uretici panelindeki uretilen kodu satir satir renklendirir. Amac
// ozellikle YORUM satirlarinin (RVA/OFF/VA/AOB/opcodes meta bilgileri) silik
// italik gorunmesi ve hex sayilar ile dizelerin ayristirilmasidir.
// Diller: cpp/csharp/rust/typescript/java (//), python (#), lua (--), json.
// ----------------------------------------------------------------------------

import type { Token } from "@/lib/highlight";

/** Dil -> yorum oneki (json yorum desteklemez). */
const COMMENT_PREFIX: Record<string, string> = {
  cpp: "//",
  csharp: "//",
  rust: "//",
  typescript: "//",
  java: "//",
  python: "#",
  lua: "--",
};

const KEYWORDS = new Set([
  // ortak
  "public", "private", "protected", "static", "const", "class", "struct", "enum",
  "interface", "namespace", "using", "void", "return", "new", "partial", "readonly",
  "override", "virtual", "extern", "unsafe", "fixed", "export", "import", "type",
  "declare", "function", "def", "local", "end", "nil", "true", "false", "null",
  "pub", "mut", "fn", "impl", "let", "match", "self", "repr", "allow", "crate",
  "pragma", "include", "define", "elif", "endif", "once", "from", "as", "in", "if",
  "else", "elif", "while", "for", "try", "catch", "finally", "with", "lambda",
  "long", "int", "short", "byte", "float", "double", "boolean", "final", "throws",
]);

/**
 * Tek satiri vurgu belirteclerine boler. Yorum oneki verildiyse satirin
 * dize disindaki ilk yorum noktasindan sonrasi yorum olarak renklendirilir.
 */
export function tokenizeCodegenLine(line: string, language: string): Token[] {
  const commentToken = COMMENT_PREFIX[language];
  const tokens: Token[] = [];

  // tamamen yorum satiri (json'da yorum yok)
  if (commentToken) {
    const trimmed = line.trimStart();
    if (trimmed.startsWith(commentToken)) {
      return [{ text: line, cls: "text-zinc-500 italic" }];
    }
  }

  // kod kismini tarayici: dize/hex/sayi/tanimlayici/yorum
  let buf = "";
  let i = 0;
  const flush = (): void => {
    if (!buf) return;
    tokens.push(...tokenizePlain(buf));
    buf = "";
  };
  while (i < line.length) {
    const ch = line[i]!;
    // yorum baslangici (dize icinde degilken)
    if (commentToken && line.startsWith(commentToken, i)) {
      flush();
      tokens.push({ text: line.slice(i), cls: "text-zinc-500 italic" });
      return tokens;
    }
    // dize
    if (ch === '"' || ch === "'") {
      flush();
      let j = i + 1;
      while (j < line.length && line[j] !== ch) {
        if (line[j] === "\\") j++;
        j++;
      }
      j = Math.min(j + 1, line.length);
      tokens.push({ text: line.slice(i, j), cls: "text-lime-300" });
      i = j;
      continue;
    }
    buf += ch;
    i++;
  }
  flush();
  return tokens;
}

/** Yorum/dize disindaki duz kod parcasini hex/sayi/anahtar kelime olarak boler. */
function tokenizePlain(code: string): Token[] {
  const out: Token[] = [];
  const re = /(0[xX][0-9a-fA-F]+|\b\d+(?:\.\d+)?[uUlLfF]*\b)|([A-Za-z_][A-Za-z0-9_]*)|(\s+)|(.)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const text = m[0];
    if (m[1]) out.push({ text, cls: "text-amber-300" });
    else if (m[2]) {
      if (KEYWORDS.has(text)) out.push({ text, cls: "text-fuchsia-300" });
      else if (/^[A-Z][A-Za-z0-9_]*$/.test(text)) out.push({ text, cls: "text-emerald-200" });
      else out.push({ text, cls: null });
    } else out.push({ text, cls: null });
  }
  return out;
}
