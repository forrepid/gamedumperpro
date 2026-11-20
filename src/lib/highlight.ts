// Lightweight syntax highlighter for the code viewer.
// Zero dependencies - tokenizer tuned for C/C++/CMake + INI + Markdown.

export interface Token {
  text: string;
  cls: string | null;
}

export interface HighlightState {
  inBlockComment: boolean;
}

const CPP_KEYWORDS = new Set([
  "alignas","alignof","and","asm","auto","bool","break","case","catch","char",
  "class","compl","const","consteval","constexpr","constinit","const_cast",
  "continue","decltype","default","delete","do","double","dynamic_cast","else",
  "enum","explicit","export","extern","false","float","for","friend","goto",
  "if","inline","int","long","mutable","namespace","new","noexcept","not",
  "nullptr","operator","or","private","protected","public","register",
  "reinterpret_cast","return","short","signed","sizeof","static",
  "static_assert","static_cast","struct","switch","template","this","throw",
  "true","try","typedef","typeid","typename","union","unsigned","using",
  "virtual","void","volatile","wchar_t","while","xor",
]);

const CPP_TYPES = new Set([
  "u8","u16","u32","u64","i8","i16","i32","i64","usize","size_t","uint8_t",
  "uint16_t","uint32_t","uint64_t","int8_t","int16_t","int32_t","int64_t",
  "uintptr_t","intptr_t","HANDLE","DWORD","WORD","BOOL","BOOLEAN","NTSTATUS",
  "PEPROCESS","KAPC_STATE","std","vector","string","map","set","optional",
  "uintptr_t","SOCKET","IOCTL","UINT64","UINT32","PVOID","BOOLEAN","IRP","PIRP",
  "Process","ModuleInfo","MemRange","Pattern","Offsets","NameDb","ObjectDb",
  "Ini","Driver","SigRecord","StructInfo","EnumInfo","PropertyInfo",
  "FunctionInfo","ResolvedFunc","SdkOptions","SdkGenerator","ClassParser",
  "VTableResolver","Progress","UEVersion","FUObjectItem","OffsetEntry",
  "FNameValue","PeSection","ProcEntry","ZipEntry","Token",
]);

const CPP_TOKEN_RE =
  /("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|(#\s*\w+)|(\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?[uUlLfF]*\b)|(\b[A-Za-z_]\w*\b)|(\s+)|(.)/g;

export function tokenizeCppLine(line: string, state: HighlightState): Token[] {
  const tokens: Token[] = [];

  // Block comment continuation across lines.
  if (state.inBlockComment) {
    const end = line.indexOf("*/");
    if (end === -1) {
      return [{ text: line, cls: "text-zinc-500 italic" }];
    }
    tokens.push({ text: line.slice(0, end + 2), cls: "text-zinc-500 italic" });
    state.inBlockComment = false;
    line = line.slice(end + 2);
  }

  let m: RegExpExecArray | null;
  CPP_TOKEN_RE.lastIndex = 0;
  while ((m = CPP_TOKEN_RE.exec(line)) !== null) {
    const text = m[0];
    if (m[1] || m[2]) {
      tokens.push({ text, cls: "text-lime-300" });
    } else if (m[3]) {
      tokens.push({ text, cls: "text-rose-300" });
    } else if (m[4]) {
      tokens.push({ text, cls: "text-amber-300" });
    } else if (m[5]) {
      const t = text;
      if (CPP_KEYWORDS.has(t)) tokens.push({ text, cls: "text-fuchsia-300" });
      else if (CPP_TYPES.has(t)) tokens.push({ text, cls: "text-emerald-300" });
      else if (/^[A-Z][A-Za-z0-9_]*$/.test(t))
        tokens.push({ text, cls: "text-emerald-200" });
      else tokens.push({ text, cls: null });
    } else {
      tokens.push({ text, cls: null });
    }
  }
  return tokens;
}

const INI_TOKEN_RE =
  /(\s+)|((?:^|(?<=\s))[;#].*$)|(\[.*\])|((?:^|(?<=\s))0[xX][0-9a-fA-F]+\b|\b\d+\b)|([A-Za-z_][\w.]*)|(.)/g;

export function tokenizeIniLine(line: string): Token[] {
  const tokens: Token[] = [];
  let m: RegExpExecArray | null;
  INI_TOKEN_RE.lastIndex = 0;
  while ((m = INI_TOKEN_RE.exec(line)) !== null) {
    const text = m[0];
    if (m[2]) tokens.push({ text, cls: "text-zinc-500 italic" });
    else if (m[3]) tokens.push({ text, cls: "text-rose-300" });
    else if (m[4]) tokens.push({ text, cls: "text-amber-300" });
    else if (m[5]) tokens.push({ text, cls: "text-emerald-300" });
    else tokens.push({ text, cls: null });
  }
  return tokens;
}

const MD_TOKEN_RE = /(\s+)|(^\s*#{1,6}\s.*$)|(`[^`]*`)|(\*\*[^*]+\*\*)|(\[.*\]\(.*\))|(.)/g;

export function tokenizeMdLine(line: string): Token[] {
  const tokens: Token[] = [];
  let m: RegExpExecArray | null;
  MD_TOKEN_RE.lastIndex = 0;
  while ((m = MD_TOKEN_RE.exec(line)) !== null) {
    const text = m[0];
    if (m[2]) tokens.push({ text, cls: "text-fuchsia-300 font-semibold" });
    else if (m[3]) tokens.push({ text, cls: "text-lime-300" });
    else if (m[4]) tokens.push({ text, cls: "text-emerald-300 font-semibold" });
    else if (m[5]) tokens.push({ text, cls: "text-amber-300 underline" });
    else tokens.push({ text, cls: null });
  }
  return tokens;
}

export function tokenizeCodeLine(
  line: string,
  lang: string,
  state: HighlightState,
): Token[] {
  if (lang === "cpp" || lang === "c") return tokenizeCppLine(line, state);
  if (lang === "ini") return tokenizeIniLine(line);
  if (lang === "md") return tokenizeMdLine(line);
  return [{ text: line, cls: null }];
}
