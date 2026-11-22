// ----------------------------------------------------------------------------
// DumperPro Online - Pattern Visual Scanner motoru
//
// C++ motorundaki src/core/Pattern.{h,cpp} web portu:
//   - IDA tarzı desen ayrıştırma ("48 8B 05 ?? ?? ?? ??")
//   - nibble kısmi maske ("4?" hi-nibble literal, "?8" lo-nibble literal)
//   - FindAll / FindFirst (Buffer.indexOf hızlandırıcılı)
//   - BuildExtendedSig portu: eşleşme çevresinden otomatik imza çıkarma
//     (maske seçenekleri: match bölgesini koru / pattern jokerlerini aktar)
//   - desen istatistikleri (özgüllük: rastgele veride beklenen eşleşme aralığı)
// ----------------------------------------------------------------------------

export type PatToken =
  | { kind: "exact"; value: number } // FF  (mask 0xFF)
  | { kind: "hi"; hi: number } //     4?  (mask 0xF0 - C++ PatByte ile birebir)
  | { kind: "lo"; lo: number } //     ?8  (mask 0x0F)
  | { kind: "wild" }; //              ??  (mask 0x00)

export interface CompileResult {
  ok: boolean;
  tokens: PatToken[];
  error?: string;
  /** token kopyalarının okunur gösterimi: "48 8B 05 ??" */
  rendered: string;
}

/** IDA tarzı deseni token'lara ayrıştırır; hataları Türkçe döner.
 *  Leksik geçiş: bitişik girişleri de doğru ayırır ("488B05?????????" veya "4?8B" gibi). */
export function compilePattern(input: string): CompileResult {
  const raw = (input ?? "").trim();
  if (!raw) {
    return { ok: false, tokens: [], error: "Desen boş olamaz.", rendered: "" };
  }
  const s = raw.replace(/\\x/gi, " ");
  const tokens: PatToken[] = [];
  let i = 0;
  const isHexChar = (c: string | undefined) =>
    c !== undefined && /[0-9A-Fa-f]/.test(c);
  while (i < s.length) {
    const c = s[i]!;
    if (/\s/.test(c) || c === "," || c === "." || c === "_" || c === "|") {
      i++;
      continue;
    }
    if (c === "?") {
      if (s[i + 1] === "?") {
        tokens.push({ kind: "wild" });
        i += 2;
      } else if (isHexChar(s[i + 1])) {
        tokens.push({ kind: "lo", lo: parseInt(s[i + 1]!, 16) });
        i += 2;
      } else {
        tokens.push({ kind: "wild" }); // tek ? = joker
        i++;
      }
      continue;
    }
    if (isHexChar(c)) {
      if (s[i + 1] === "?") {
        tokens.push({ kind: "hi", hi: parseInt(c, 16) });
        i += 2;
      } else if (isHexChar(s[i + 1])) {
        tokens.push({ kind: "exact", value: parseInt(c + s[i + 1]!, 16) });
        i += 2;
      } else {
        return bad(c + "?" /* tek hex + bitmeyen girdi */);
      }
      continue;
    }
    return bad(c);
  }
  if (tokens.length === 0) {
    return { ok: false, tokens: [], error: "Ayrıştırılabilir token yok.", rendered: "" };
  }
  if (tokens.length > 512) {
    return { ok: false, tokens: [], error: "Desen çok uzun (en fazla 512 bayt).", rendered: "" };
  }
  if (tokens.every((t) => t.kind === "wild")) {
    return { ok: false, tokens: [], error: "Desen tamamen joker olamaz (en az 1 literal bayt gerekli).", rendered: "" };
  }
  return { ok: true, tokens, rendered: renderTokens(tokens) };
}

function bad(tok: string): CompileResult {
  return {
    ok: false,
    tokens: [],
    error: `Geçersiz token: "${tok}" — hex bayt (48), joker (??) veya nibble maskesi (4? / ?8) bekleniyor.`,
    rendered: "",
  };
}

export function renderTokens(tokens: PatToken[]): string {
  return tokens.map(tokenString).join(" ");
}

function tokenString(t: PatToken): string {
  switch (t.kind) {
    case "exact":
      return t.value.toString(16).toUpperCase().padStart(2, "0");
    case "hi":
      return `${t.hi.toString(16).toUpperCase()}?`;
    case "lo":
      return `?${t.lo.toString(16).toUpperCase()}`;
    default:
      return "??";
  }
}

/** Tek baytı token'a göre test eder. */
export function matchByte(t: PatToken, b: number): boolean {
  switch (t.kind) {
    case "exact":
      return b === t.value;
    case "hi":
      return (b >> 4) === t.hi;
    case "lo":
      return (b & 0x0f) === t.lo;
    default:
      return true;
  }
}

// ---------------------------------------------------------------------------
// tarama
// ---------------------------------------------------------------------------

export interface PatMatch {
  off: number;
  rva?: number;
  va?: number;
  section?: string;
  /** eşleşen bölgenin hex'i (kopyalamak için) */
  hex: string;
}

export interface ScanOptions {
  start?: number;
  end?: number;
  limit?: number;
  imageBase?: number;
  rvaOf?: (off: number) => number | null;
  sectionOf?: (off: number) => string | undefined;
}

export interface ScanResult {
  matches: PatMatch[];
  scanned: number;
  truncated: boolean;
}

const MAX_SCAN = 128 * 1024 * 1024; // aobSearch ile aynı üst sınır

export function findPatternMatches(
  buf: Buffer,
  tokens: PatToken[],
  opts: ScanOptions = {},
): ScanResult {
  const start = Math.max(0, opts.start ?? 0);
  const end = Math.min(buf.length, start + (opts.end ?? buf.length - start), start + MAX_SCAN);
  const limit = Math.min(opts.limit ?? 64, 256);
  const matches: PatMatch[] = [];
  const plen = tokens.length;
  if (plen === 0 || end - start < plen) {
    return { matches, scanned: Math.max(0, end - start), truncated: false };
  }
  const data = buf.subarray(start, end);

  // ilk literal token'a sabitlenip Buffer.indexOf ile ilerle (hiz).
  // ilerleme garantisi: arama konumu her adimda en az 1 bayt artar.
  const anchorIdx = tokens.findIndex((t) => t.kind === "exact");
  const anchorVal = anchorIdx >= 0 ? tokens[anchorIdx]!.value : -1;
  const dataLen = data.length;
  let searchPos = 0;
  let truncated = false;
  for (;;) {
    let anchorHit: number;
    if (anchorIdx >= 0) {
      anchorHit = data.indexOf(anchorVal, searchPos);
      if (anchorHit === -1) break;
      if (anchorHit + (plen - anchorIdx) > dataLen) break; // anchor'la desen tasmaz
    } else {
      // nibble-only desen: anchor yok, her pozisyon denenir (nadir)
      if (searchPos + plen > dataLen) break;
      anchorHit = searchPos;
    }
    const startIdx = anchorHit - anchorIdx; // anchor yoksa == anchorHit
    if (startIdx < 0) {
      searchPos = anchorHit + 1;
      continue;
    }
    let ok = true;
    for (let k = 0; k < plen; k++) {
      if (!matchByte(tokens[k]!, data[startIdx + k]!)) {
        ok = false;
        break;
      }
    }
    if (ok) {
      if (matches.length >= limit) {
        truncated = true;
        break;
      }
      const abs = start + startIdx;
      const rva = opts.rvaOf ? opts.rvaOf(abs) : null;
      matches.push({
        off: abs,
        rva: rva ?? undefined,
        va: rva != null && opts.imageBase !== undefined ? opts.imageBase + rva : undefined,
        section: opts.sectionOf ? opts.sectionOf(abs) : undefined,
        hex: data.subarray(startIdx, startIdx + plen).toString("hex"),
      });
    }
    // bir sonraki adim: her zaman en az 1 bayt ilerle (sonsuz dongu guard)
    searchPos = Math.max(startIdx + 1, anchorHit + 1);
  }
  return { matches, scanned: dataLen, truncated };
}

// ---------------------------------------------------------------------------
// istatistik / özgüllük
// ---------------------------------------------------------------------------

export interface PatternStats {
  length: number; // token (bayt) sayısı
  exact: number;
  nibble: number;
  wild: number;
  /** rastgele veride 1 eşleşme için beklenen bayt aralığı (1/p) */
  specificityBytes: number;
  /** insan-okur özgüllük etiketi */
  specificityLabel: "zayıf" | "orta" | "iyi" | "güçlü";
}

export function patternStats(tokens: PatToken[]): PatternStats {
  let exact = 0;
  let nibble = 0;
  let wild = 0;
  for (const t of tokens) {
    if (t.kind === "exact") exact++;
    else if (t.kind !== "wild") nibble++;
    else wild++;
  }
  // p = (1/256)^exact * (1/16)^nibble  -> 1/p = 256^exact * 16^nibble
  // (2^53 ustunu cap'le: Number guvenli tamsayi araligi)
  const specificityBytes = Math.min(
    Math.pow(256, exact) * Math.pow(16, nibble),
    2 ** 53,
  );
  let label: PatternStats["specificityLabel"] = "zayıf";
  if (specificityBytes >= 1 << 30) label = "güçlü";
  else if (specificityBytes >= 1 << 20) label = "iyi";
  else if (specificityBytes >= 1 << 12) label = "orta";
  return { length: tokens.length, exact, nibble, wild, specificityBytes, specificityLabel: label };
}

// ---------------------------------------------------------------------------
// sig çıkarıcı (C++ BuildExtendedSig portu)
// ---------------------------------------------------------------------------

export type MaskMode = "keep" | "pattern";

export interface ExtractResult {
  ok: boolean;
  error?: string;
  off: number; // sig başlangıcı (dosya ofseti)
  length: number; // sig bayt uzunluğu
  bytes: number[]; // ham baytlar
  /** token dizisi: sig bölgesi + maskeleme uygulanmış */
  tokens: PatToken[];
  formats: {
    /** IDA / Cheat Engine / x64dbg klasik: "48 8B 05 ?? ?? ?? ??" */
    ida: string;
    /** x64dbg mask satırı: bytes hex + mask string */
    x64dbg: string;
    /** C++: değer + maske dizileri */
    cpp: string;
    /** Python: b"\x48\x8b..." + mask notu */
    py: string;
  };
}

/**
 * `off` konumuna çakılan eşleşmenin çevresinden IDA tarzı imza çıkarır.
 * - before/after: eşleşme dışında kaç bayt bağlam eklensin
 * - pattern (varsa) + maskMode="pattern": eşleşme bölgesinde desenin joker
 *   token'ları çıktıda ?? olarak korunur (rel32/imm32 hayatta kalır)
 * - maskMode="keep": eşleşme bölgesi gerçek bayt değeriyle yazılır
 */
export function extractSignature(
  buf: Buffer,
  off: number,
  before: number,
  after: number,
  opts: { pattern?: PatToken[]; maskMode?: MaskMode } = {},
): ExtractResult {
  const patternLen = opts.pattern?.length ?? 0;
  const startOff = Math.max(0, off - Math.max(0, before));
  const matchEnd = off + patternLen;
  const endOff = Math.min(buf.length, matchEnd + Math.max(0, after));
  if (endOff <= startOff) {
    return { ok: false, off, length: 0, bytes: [], tokens: [], formats: { ida: "", x64dbg: "", cpp: "", py: "" }, error: "Geçersiz bağlam aralığı." };
  }
  if (endOff - startOff > 512) {
    return { ok: false, off, length: 0, bytes: [], tokens: [], formats: { ida: "", x64dbg: "", cpp: "", py: "" }, error: "Çıkarılacak imza çok uzun (en fazla 512 bayt)." };
  }
  const bytes: number[] = [];
  const tokens: PatToken[] = [];
  const maskMode = opts.maskMode ?? "pattern";
  for (let i = startOff; i < endOff; i++) {
    const b = buf[i]!;
    bytes.push(b);
    const inMatch = patternLen > 0 && i >= off && i < matchEnd;
    const k = inMatch ? i - off : -1;
    const t = inMatch ? opts.pattern![k]! : undefined;
    // yalnizca gerçek joker konumlar ?? kalir; hi/lo nibble bayt degeriyle
    // somutlasir (REX vb. korunur) -> rel32/imm32 disp32 hayatta kalir
    const masked = inMatch && maskMode === "pattern" && t && t.kind === "wild";
    if (masked) {
      tokens.push({ kind: "wild" });
    } else if (t && t.kind === "hi") {
      tokens.push({ kind: "hi", hi: b >> 4 });
    } else if (t && t.kind === "lo") {
      tokens.push({ kind: "lo", lo: b & 0x0f });
    } else {
      tokens.push({ kind: "exact", value: b });
    }
  }
  return {
    ok: true,
    off: startOff,
    length: bytes.length,
    bytes,
    tokens,
    formats: formatVariants(tokens),
  };
}

export function formatVariants(tokens: PatToken[]): ExtractResult["formats"] {
  const ida = tokens.map(tokenString).join(" ");
  // x64dbg: bayt düzeyi hex + mask (nibble bayt düzeyinde joker'e düşer)
  let xbytes = "";
  let xmask = "";
  let nibbleDown = false;
  for (const t of tokens) {
    if (t.kind === "exact") {
      xbytes += t.value.toString(16).padStart(2, "0").toUpperCase() + " ";
      xmask += "x";
    } else if (t.kind === "wild") {
      xbytes += "00 ";
      xmask += "?";
    } else {
      xbytes += "00 ";
      xmask += "?";
      nibbleDown = true;
    }
  }
  const x64dbg = `${xbytes.trim()} / mask: ${xmask}${nibbleDown ? "  (nibble maske bayt joker'ine düştü)" : ""}`;
  // C++: değer + maske dizileri
  const vals: string[] = [];
  const masks: string[] = [];
  for (const t of tokens) {
    if (t.kind === "exact") {
      vals.push(`0x${t.value.toString(16).padStart(2, "0").toUpperCase()}`);
      masks.push("0xFF");
    } else if (t.kind === "wild") {
      vals.push("0x00");
      masks.push("0x00");
    } else if (t.kind === "hi") {
      vals.push("0x00");
      masks.push("0xF0");
    } else {
      vals.push("0x00");
      masks.push("0x0F");
    }
  }
  const cpp = `bytes[] = { ${vals.join(", ")} }\nmask[]  = { ${masks.join(", ")} }`;
  // Python: literal bayt dizisi + mask notu
  let py = "";
  let litOk = true;
  for (const t of tokens) {
    if (t.kind !== "exact") {
      litOk = false;
      break;
    }
  }
  if (litOk) {
    py = `pattern = b"${tokens.map((t) => `\\x${(t as { value: number }).value.toString(16).padStart(2, "0")}`).join("")}"`;
  } else {
    py = `# joker/maske var: bytes + mask çiftini kullan\nbytes = [${vals.join(", ")}]\nmask  = [${masks.join(", ")}]  # 0xFF exact, 0xF0/0x0F nibble, 0x00 joker`;
  }
  return { ida, x64dbg, cpp, py };
}

/** Bağlam şeridi için ham bayt dizisini token'lara (tümü exact) çevirir. */
export function bytesToExactTokens(bytes: number[]): PatToken[] {
  return bytes.map((b) => ({ kind: "exact" as const, value: b }));
}
