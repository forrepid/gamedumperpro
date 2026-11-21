// ----------------------------------------------------------------------------
// /api/uploads/[id]/mem - bellek dump islemleri (LeechCore/MemProcFS benzeri)
//   POST { action: "search", pattern }              -> bellek icinde AOB
//   POST { action: "search", type, value }          -> tipli deger arama (LE)
//   POST { action: "dump", base, size?, name? }     -> PE kurtar -> yeni analiz
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import { saveBuffer } from "@/lib/storage";
import { runAnalysis } from "@/lib/analysis/queue";
import { analyzeMemoryDump, searchMemory, recoverModulePe } from "@/lib/analysis/mem";
import { parseAobPattern, resolveDataType, encodeValue } from "@/lib/analysis/hex";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

interface MemSummary {
  mem?: { modules: { name: string; base: number; size: number; recoverable: boolean }[] };
}

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

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const loaded = await loadRow(id);
  if (!loaded) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });
  const { row, buf } = loaded;

  let body: { action?: string; pattern?: string; base?: number; size?: number; name?: string; type?: string; value?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govde" }, { status: 400 });
  }

  // cihazi kur (memmap eslesmesi yukleme eslemlerinden gelebilir)
  const a = await db.analysis.findUnique({ where: { uploadId: id } });
  let memmapText: string | undefined;
  if (a) {
    try {
      const summary = JSON.parse(a.summary) as { notes?: string[] };
      void summary;
    } catch {
      // yoksay
    }
  }
  // bagli memmap yuklemesi (parent/sibling aramasi upload rotasinda kayitli)
  const linkedMemmap = await db.upload.findFirst({
    where: { AND: [{ parentId: id }, { fileName: { contains: ".memmap" } }] },
  });
  if (linkedMemmap) {
    try {
      memmapText = fs.readFileSync(linkedMemmap.savedPath, "utf8");
    } catch {
      // yoksay
    }
  }
  // yukleme rotasinin 24 saatlik eslesme penceresiyle ayni davranis:
  // ayri yuklenen *.memmap tanim dosyasini son yuklemeden bul
  if (!memmapText) {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentMap = await db.upload.findFirst({
      where: { createdAt: { gte: since }, fileName: { contains: ".memmap" }, id: { not: id } },
      orderBy: { createdAt: "desc" },
    });
    if (recentMap) {
      try {
        memmapText = fs.readFileSync(recentMap.savedPath, "utf8");
      } catch {
        // yoksay
      }
    }
  }
  // ters yonde: bu kayit bir memmap ise ve raw dump kardesi varsa
  if (!memmapText && row.parentId) {
    const parent = await db.upload.findUnique({ where: { id: row.parentId } });
    if (parent && /\.bin$|\.raw$|\.mem$/i.test(parent.fileName)) {
      // raw dump eslemesi bu rota uzerinden degil; yoksay
    }
  }

  const mres = analyzeMemoryDump(buf, row.fileName, { memmapText });
  if (!mres) {
    return NextResponse.json({ ok: false, error: "Bellek cihazi kurulamadi (minidump/memmap eslesmesi yok)" }, { status: 400 });
  }
  const { device, minidump } = mres;

  // --- bellek icinde AOB / tipli deger ---
  if (body.action === "search") {
    let bytes: (number | null)[];
    let label = body.pattern ?? "";
    let encoded: string | undefined;
    if (body.type) {
      const t = resolveDataType(body.type);
      if (!t) {
        return NextResponse.json({ ok: false, error: `bilinmeyen veri tipi: "${body.type}"` }, { status: 400 });
      }
      const enc = encodeValue(t, body.value ?? body.pattern ?? "");
      if (!enc.ok) return NextResponse.json({ ok: false, error: enc.error }, { status: 400 });
      bytes = enc.bytes;
      label = `${body.type}: ${body.value ?? body.pattern ?? ""}`;
      encoded = enc.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    } else {
      const parsed = parseAobPattern(body.pattern ?? "");
      if (!parsed.bytes.length || parsed.error) {
        return NextResponse.json({ ok: false, error: parsed.error ?? "bos desen" }, { status: 400 });
      }
      bytes = parsed.bytes;
    }
    const hits = searchMemory(device, bytes, 256);
    // modul etiketi
    const modules = (a ? (JSON.parse(a.summary) as MemSummary).mem?.modules : undefined) ?? minidump?.modules.map((m) => ({ name: m.name, base: m.base, size: m.size, recoverable: false })) ?? [];
    const labeled = hits.map((h) => {
      const mod = modules.find((m) => h.va >= m.base && h.va < m.base + m.size);
      return { ...h, module: mod ? mod.name : undefined, rva: mod ? h.va - mod.base : undefined };
    });
    return NextResponse.json({ ok: true, total: labeled.length, matches: labeled, scannedBytes: device.totalBytes, pattern: label, encoded });
  }

  // --- PE kurtar + yeni analiz ---
  if (body.action === "dump") {
    const base = body.base;
    if (typeof base !== "number" || !Number.isFinite(base) || base <= 0) {
      return NextResponse.json({ ok: false, error: "'base' gerekli" }, { status: 400 });
    }
    const modInfo = minidump?.modules.find((m) => m.base === base);
    const size = body.size ?? modInfo?.size ?? 0;
    const name = (body.name ?? modInfo?.name?.split(/[\\/]/).pop() ?? `modul_${base.toString(16)}.dll`).slice(0, 120);
    const notes: string[] = [];
    const recovered = recoverModulePe(device, base, size, notes);
    if (!recovered) {
      return NextResponse.json({ ok: false, error: notes.join("; ") || "PE kurtarma basarisiz" }, { status: 400 });
    }
    const newId = crypto.randomUUID();
    const saved = saveBuffer(newId, name, recovered);
    await db.upload.create({
      data: {
        id: newId,
        fileName: name,
        savedPath: saved.savedPath,
        size: recovered.length,
        mime: "application/octet-stream",
        source: "memdump",
        parentId: id,
        status: "analyzing",
      },
    });
    try {
      const analysis = await runAnalysis(newId, recovered, name);
      if (!analysis) {
        const row = await db.upload.findUnique({ where: { id: newId }, select: { error: true } });
        return NextResponse.json({ ok: true, id: newId, status: "error", error: row?.error ?? "analiz hatasi" });
      }
      return NextResponse.json({ ok: true, id: newId, name, notes, kind: analysis.result.kind, engine: analysis.result.engine.detected });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      await db.upload.update({ where: { id: newId }, data: { status: "error", error: msg } });
      return NextResponse.json({ ok: true, id: newId, status: "error", error: msg });
    }
  }

  return NextResponse.json({ ok: false, error: "Bilinmeyen islem (search|dump)" }, { status: 400 });
}
