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
