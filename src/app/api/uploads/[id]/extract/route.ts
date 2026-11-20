// ----------------------------------------------------------------------------
// POST /api/uploads/[id]/extract - APK/ZIP icinden dosya cikarip yeni analiz
// body: { "entry": "lib/arm64-v8a/libUE4.so" }
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";

import { db } from "@/lib/db";
import { saveBuffer, MAX_UPLOAD_BYTES } from "@/lib/storage";
import { runAnalysis } from "@/lib/analysis/queue";
import { parseZipCentralDirectory, extractZipEntry, ZipParseError } from "@/lib/analysis/zipapk";
import fs from "node:fs";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Ana kayit bulunamadi" }, { status: 404 });
  }

  let body: { entry?: string };
  try {
    body = (await req.json()) as { entry?: string };
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govde" }, { status: 400 });
  }
  const entryPath = body.entry;
  if (!entryPath || typeof entryPath !== "string") {
    return NextResponse.json({ ok: false, error: "'entry' alani gerekli" }, { status: 400 });
  }

  let buf: Buffer;
  try {
    buf = fs.readFileSync(row.savedPath);
  } catch {
    return NextResponse.json({ ok: false, error: "Arsiv dosyasi diskte bulunamadi" }, { status: 404 });
  }

  let entries;
  try {
    entries = parseZipCentralDirectory(buf);
  } catch (e) {
    const msg = e instanceof ZipParseError ? e.message : "arsiv okunamadi";
    return NextResponse.json({ ok: false, error: msg }, { status: 400 });
  }

  const target = entries.find((e) => e.name === entryPath);
  if (!target) {
    return NextResponse.json({ ok: false, error: "Kayit arsivde bulunamadi" }, { status: 404 });
  }
  if (target.size > MAX_UPLOAD_BYTES) {
    return NextResponse.json({ ok: false, error: "Kayit cok buyuk (300 MB siniri)" }, { status: 413 });
  }

  const extracted = extractZipEntry(buf, target);
  if (!extracted) {
    return NextResponse.json(
      { ok: false, error: "Kayit acilamadi (desteklenmeyen sikistirma yontemi veya bozuk veri)" },
      { status: 400 },
    );
  }

  const newId = crypto.randomUUID();
  const outName = target.name.split("/").pop() || "extracted.bin";
  const saved = saveBuffer(newId, outName, extracted.data);

  await db.upload.create({
    data: {
      id: newId,
      fileName: outName,
      savedPath: saved.savedPath,
      size: extracted.data.length,
      mime: "application/octet-stream",
      source: "extract",
      parentId: id,
      relPath: target.name,
      status: "analyzing",
    },
  });

  try {
    const analysis = await runAnalysis(newId, extracted.data, outName);
    if (!analysis) {
      const row = await db.upload.findUnique({ where: { id: newId }, select: { error: true } });
      return NextResponse.json({ ok: true, id: newId, status: "error", error: row?.error ?? "analiz hatasi" });
    }
    return NextResponse.json({ ok: true, id: newId, kind: analysis.result.kind, engine: analysis.result.engine.detected });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await db.upload.update({ where: { id: newId }, data: { status: "error", error: msg } });
    return NextResponse.json({ ok: true, id: newId, status: "error", error: msg });
  }
}
