// ----------------------------------------------------------------------------
// /api/uploads/[id]/hex - Hex/AOB sistemi
//   GET  ?off=&len=            -> hex gorunum (satirlar + RVA/VA)
//   POST { action: "search", pattern, off?, len? }   -> AOB tarama (?? joker)
//   POST { action: "patch",  patches: [{off, bytes}] } -> yamalari .dpr'a yaz
//   POST { action: "save",   name }  -> yamali kopyayi yeni yukleme olarak kaydet
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";
import fs from "node:fs";

import { db } from "@/lib/db";
import { saveBuffer } from "@/lib/storage";
import { runAnalysis } from "@/lib/analysis/queue";
import { hexView, parseAobPattern, aobSearch, applyPatches, parsePatchJson, type HexPatch, type PatchRecord } from "@/lib/analysis/hex";
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

function patchPathFor(savedPath: string): string {
  return `${savedPath}.dpr`;
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const loaded = await loadRow(id);
  if (!loaded) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });
  const url = new URL(req.url);
  const off = Math.max(0, parseInt(url.searchParams.get("off") ?? "0", 10) || 0);
  const len = Math.max(16, Math.min(parseInt(url.searchParams.get("len") ?? "512", 10) || 512, 16 * 1024));
  const pe = await getPeInfo(id);
  const view = hexView(loaded.buf, off, len, 16, pe ? { imageBase: pe.imageBase, rvaOf: rvaResolver(pe)! } : undefined);
  let rec: PatchRecord | null = null;
  try {
    rec = parsePatchJson(fs.readFileSync(patchPathFor(loaded.row.savedPath), "utf8"));
  } catch {
    // yama dosyasi yok
  }
  return NextResponse.json({
    ok: true,
    ...view,
    patchCount: rec?.patches.length ?? 0,
    patches: rec?.patches ?? [],
  });
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const loaded = await loadRow(id);
  if (!loaded) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });
  const { row, buf } = loaded;

  let body: {
    action?: string;
    pattern?: string;
    off?: number;
    len?: number;
    patches?: { off: number; bytes: number[] }[];
    name?: string;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govde" }, { status: 400 });
  }

  const pe = await getPeInfo(id);
  const rvaOf = rvaResolver(pe);

  // --- AOB arama ---
  if (body.action === "search") {
    const { bytes, error } = parseAobPattern(body.pattern ?? "");
    if (error) return NextResponse.json({ ok: false, error }, { status: 400 });
    const res = aobSearch(buf, bytes, { off: body.off, len: body.len, limit: 256, imageBase: pe?.imageBase, rvaOf });
    return NextResponse.json({
      ok: true,
      pattern: body.pattern,
      total: res.matches.length,
      truncated: res.truncated,
      scanned: res.scanned,
      matches: res.matches,
    });
  }

  // --- yama yaz ---
  if (body.action === "patch") {
    if (!body.patches || !Array.isArray(body.patches) || body.patches.length === 0) {
      return NextResponse.json({ ok: false, error: "'patches' alani gerekli" }, { status: 400 });
    }
    const pPath = patchPathFor(row.savedPath);
    let rec: PatchRecord = { version: 1, baseFile: row.fileName, patches: [], updatedAt: new Date().toISOString() };
    try {
      const existing = parsePatchJson(fs.readFileSync(pPath, "utf8"));
      if (existing) rec = existing;
    } catch {
      // yeni kayit
    }
    let applied = 0;
    for (const p of body.patches.slice(0, 4096)) {
      if (!Number.isInteger(p.off) || !Array.isArray(p.bytes)) continue;
      if (p.off < 0 || p.off + p.bytes.length > buf.length) continue;
      const orig = Array.from(buf.subarray(p.off, p.off + p.bytes.length));
      const existingIdx = rec.patches.findIndex((x) => x.off === p.off);
      const entry: HexPatch = { off: p.off, bytes: p.bytes.map((b) => b & 0xff), orig };
      if (existingIdx >= 0) rec.patches[existingIdx] = entry;
      else rec.patches.push(entry);
      applied++;
    }
    rec.updatedAt = new Date().toISOString();
    fs.writeFileSync(pPath, JSON.stringify(rec), "utf8");
    return NextResponse.json({ ok: true, applied, totalPatches: rec.patches.length });
  }

  // --- yamali kopyayi kaydet + analiz et ---
  if (body.action === "save") {
    const pPath = patchPathFor(row.savedPath);
    let rec: PatchRecord | null = null;
    try {
      rec = parsePatchJson(fs.readFileSync(pPath, "utf8"));
    } catch {
      // yama yok
    }
    let out = buf;
    let patchCount = 0;
    if (rec && rec.patches.length > 0) {
      const res = applyPatches(buf, rec.patches);
      out = res.buf;
      patchCount = res.applied;
    }
    if (patchCount === 0) {
      return NextResponse.json({ ok: false, error: "Kaydedilecek yama yok (once patch yapin)" }, { status: 400 });
    }
    const safeName = (body.name ?? `${row.fileName.replace(/\.[^.]+$/, "")}.patched.bin`).slice(0, 120);
    const newId = crypto.randomUUID();
    const saved = saveBuffer(newId, safeName, out);
    await db.upload.create({
      data: {
        id: newId,
        fileName: safeName,
        savedPath: saved.savedPath,
        size: out.length,
        mime: "application/octet-stream",
        source: "patch",
        parentId: id,
        status: "analyzing",
      },
    });
    try {
      const analysis = await runAnalysis(newId, out, safeName);
      if (!analysis) {
        const row = await db.upload.findUnique({ where: { id: newId }, select: { error: true } });
        return NextResponse.json({ ok: true, id: newId, status: "error", error: row?.error ?? "analiz hatasi" });
      }
      return NextResponse.json({ ok: true, id: newId, patches: patchCount, kind: analysis.result.kind });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      await db.upload.update({ where: { id: newId }, data: { status: "error", error: msg } });
      return NextResponse.json({ ok: true, id: newId, status: "error", error: msg });
    }
  }

  return NextResponse.json({ ok: false, error: "Bilinmeyen islem (search|patch|save)" }, { status: 400 });
}
