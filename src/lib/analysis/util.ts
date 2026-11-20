// ----------------------------------------------------------------------------
// DumperPro Online - ortak yardimcilar (entropy, string tarama, needle sayma)
// Sifir bagimlilik: yalnizca node:built-in (Buffer, zlib, crypto).
// ----------------------------------------------------------------------------

/** Shannon entropy 0..8 (bayt basina bit). Orneginde hizli hesap icin ornekleme. */
export function entropy(buf: Buffer, maxSample = 1024 * 1024): number {
  const len = buf.length;
  if (len === 0) return 0;
  const step = Math.max(1, Math.floor(len / maxSample));
  const hist = new Float64Array(256);
  let total = 0;
  for (let i = 0; i < len; i += step) {
    hist[buf[i]]++;
    total++;
  }
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (hist[i] === 0) continue;
    const p = hist[i] / total;
    e -= p * Math.log2(p);
  }
  return Math.round(e * 100) / 100;
}

/** Buffer uzerinde literal needle sayisi (Buffer.indexOf ile hizli). */
export function countNeedle(buf: Buffer, needle: Buffer, cap = 1_000_000): number {
  let count = 0;
  let idx = buf.indexOf(needle);
  while (idx !== -1 && count < cap) {
    count++;
    idx = buf.indexOf(needle, idx + 1);
  }
  return count;
}

export interface RawVersionHit {
  raw: string;
  engine: "UE4" | "UE5";
  branch: string;
  version: string;
}

/**
 * UE surum stringlerini bulur. UnrealBuildTool uretimi ornek:
 *   ++UE4+Release-4.27.2-CL-0-Windows
 *   ++UE5+Release-5.3.2-CL-0-Windows
 * Custom dallar: ++UE5+Main, ++UE4+Licensor-...
 * Hem ASCII hem UTF-16LE kodlamasi taranir.
 */
export function findUeVersionStrings(buf: Buffer, cap = 24): RawVersionHit[] {
  const out: RawVersionHit[] = [];
  const seen = new Set<string>();
  const push = (raw: string) => {
    const m = raw.match(/^\+\+(UE4|UE5)\+([A-Za-z0-9_.-]+?)-(\d+\.\d+(?:\.\d+)?)/);
    if (!m) return;
    const key = m[0];
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ raw: key, engine: m[1] as "UE4" | "UE5", branch: m[2], version: m[3] });
  };

  const base = Buffer.from("++UE", "latin1");
  let idx = buf.indexOf(base);
  while (idx !== -1 && out.length < cap) {
    // etrafindaki yazilabilir baytlari al (en fazla 96)
    let end = idx;
    while (end < buf.length && end - idx < 96) {
      const b = buf[end];
      if ((b >= 0x20 && b < 0x7f) || b === 0x2b) end++;
      else break;
    }
    push(buf.subarray(idx, end).toString("latin1"));
    idx = buf.indexOf(base, idx + 4);
  }

  // UTF-16LE taramasi
  const base16 = Buffer.from("++UE", "utf16le");
  idx = buf.indexOf(base16);
  while (idx !== -1 && out.length < cap) {
    let end = idx;
    while (end + 1 < buf.length && end - idx < 192) {
      const b = buf[end];
      if ((b >= 0x20 && b < 0x7f) || b === 0x2b) end += 2;
      else break;
    }
    const slice = buf.subarray(idx, Math.min(end, buf.length));
    // UTF-16 -> latin1 daralt
    let s = "";
    for (let i = 0; i + 1 < slice.length; i += 2) s += String.fromCharCode(slice[i]);
    push(s);
    idx = buf.indexOf(base16, idx + 4);
  }
  return out;
}

/** ASCII yazilabilir stringleri cikarir (tarama penceresi sinirlidir). */
export function extractAsciiStrings(
  buf: Buffer,
  minLen = 6,
  cap = 2500,
  window = 96 * 1024 * 1024,
): string[] {
  const limit = Math.min(buf.length, window);
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i < limit; i++) {
    const b = buf[i];
    const printable = (b >= 0x20 && b <= 0x7e) || b === 0x09;
    if (printable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen && out.length < cap) {
        out.push(buf.subarray(start, i).toString("latin1"));
      }
      start = -1;
    }
    if (out.length >= cap) break;
  }
  return out;
}

/** Buyuk/kucuk harf duyarsiz alt-dize aramasi (latin1 varsayimi). */
export function ciContains(hay: string, needle: string): boolean {
  return hay.toLowerCase().includes(needle.toLowerCase());
}
