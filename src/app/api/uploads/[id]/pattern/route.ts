// ----------------------------------------------------------------------------
// /api/uploads/[id]/pattern - Pattern Visual Scanner
//   POST { action: "scan", pattern, maxHits?, start?, end?, section? }
//       -> nibble-mask destekli AOB tarama + desen istatistikleri
//   POST { action: "extract", off, before?, after?, pattern?, maskMode? }
//       -> eslesme cevresinden IDA tarzi imza cikarma (BuildExtendedSig portu)
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";

import { db } from "@/lib/db";
import {
  compilePattern,
  findPatternMatches,
  patternStats,
  extractSignature,
  renderTokens,
  type MaskMode,
  type PatToken,
} from "@/lib/analysis/pattern";
import type { PeInfo } from "@/lib/analysis/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

async function loadRow(id: string) {
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) return null;
  let buf: Buffer;
  try {
    buf = fs.readFileSync(row.savedPath);
  } catch {
    return null;
  }
  return { row, buf };
}

async function getPeInfo(id: string): Promise<PeInfo | undefined> {
  const a = await db.analysis.findUnique({ where: { uploadId: id } });
  if (!a) return undefined;
  try {
    const summary = JSON.parse(a.summary) as { pe?: PeInfo };
    return summary.pe;
  } catch {
    return undefined;
  }
}

function rvaResolver(pe: PeInfo | undefined): ((off: number) => number | null) | undefined {
  if (!pe) return undefined;
  return (off: number): number | null => {
    for (const s of pe.sections) {
      if (off >= s.rawPointer && off < s.rawPointer + s.rawSize) {
        return s.virtualAddress + (off - s.rawPointer);
      }
    }
    return null;
  };
}

function sectionResolver(pe: PeInfo | undefined): ((off: number) => string | undefined) | undefined {
  if (!pe) return undefined;
  return (off: number): string | undefined => {
    for (const s of pe.sections) {
      if (off >= s.rawPointer && off < s.rawPointer + s.rawSize) return s.name;
    }
    return undefined;
  };
}

/** bolum adi -> [dosya-baslangic, dosya-bitisi] araligi (taramayi kisitlamak icin) */
function sectionRange(pe: PeInfo | undefined, name: string | undefined): { start?: number; end?: number } {
  if (!pe || !name || name === "all") return {};
  const s = pe.sections.find((x) => x.name === name);
  if (!s || s.rawSize === 0) return {};
  return { start: s.rawPointer, end: s.rawPointer + s.rawSize };
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const loaded = await loadRow(id);
  if (!loaded) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });
  const { buf } = loaded;

  let body: {
    action?: string;
    pattern?: string;
    maxHits?: number;
    start?: number;
    end?: number;
    section?: string;
    off?: number;
    before?: number;
    after?: number;
    maskMode?: MaskMode;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govde" }, { status: 400 });
  }

  const pe = await getPeInfo(id);
  const rvaOf = rvaResolver(pe);
  const sectionOf = sectionResolver(pe);

  // --- tarama ---
  if (body.action === "scan") {
    const compiled = compilePattern(body.pattern ?? "");
    if (!compiled.ok) {
      return NextResponse.json({ ok: false, error: compiled.error }, { status: 400 });
    }
    const range = sectionRange(pe, body.section);
    const maxHits = Math.max(1, Math.min(body.maxHits ?? 16, 128));
    const res = findPatternMatches(buf, compiled.tokens, {
      start: range.start,
      end: range.end,
      limit: maxHits,
      imageBase: pe?.imageBase,
      rvaOf,
      sectionOf,
    });
    // gorsel serit icin eslesme cevresi baytlar (once/sonra 8 bayt hex)
    const plen = compiled.tokens.length;
    const matches = res.matches.map((m) => ({
      ...m,
      contextBefore: buf.subarray(Math.max(0, m.off - 8), m.off).toString("hex"),
      contextAfter: buf
        .subarray(m.off + plen, Math.min(buf.length, m.off + plen + 8))
        .toString("hex"),
    }));
    return NextResponse.json({
      ok: true,
      pattern: body.pattern,
      rendered: renderTokens(compiled.tokens),
      stats: patternStats(compiled.tokens),
      total: res.matches.length,
      truncated: res.truncated,
      scanned: res.scanned,
      matches,
    });
  }

  // --- sig cikarici ---
  if (body.action === "extract") {
    const off = Math.max(0, Math.min(body.off ?? 0, buf.length));
    const before = Math.max(0, Math.min(body.before ?? 8, 64));
    const after = Math.max(0, Math.min(body.after ?? 8, 64));
    let patternTokens: PatToken[] | undefined;
    if (body.pattern) {
      const c = compilePattern(body.pattern);
      if (c.ok) patternTokens = c.tokens;
    }
    const maskMode: MaskMode = body.maskMode === "keep" ? "keep" : "pattern";
    const res = extractSignature(buf, off, before, after, { pattern: patternTokens, maskMode });
    if (!res.ok) {
      return NextResponse.json({ ok: false, error: res.error }, { status: 400 });
    }
    const rva = rvaOf ? rvaOf(res.off) : null;
    return NextResponse.json({
      ok: true,
      off: res.off,
      rva: rva ?? undefined,
      va: rva != null && pe ? pe.imageBase + rva : undefined,
      section: sectionOf ? sectionOf(res.off) : undefined,
      length: res.length,
      bytes: res.bytes,
      rendered: renderTokens(res.tokens),
      formats: res.formats,
      stats: patternStats(res.tokens),
    });
  }

  return NextResponse.json({ ok: false, error: "Bilinmeyen islem (scan|extract)" }, { status: 400 });
}
