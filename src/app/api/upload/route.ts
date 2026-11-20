// ----------------------------------------------------------------------------
// POST /api/upload  - dosya yukle (multipart/form-data, alan: "file")
//
// Akis: dosya diske yazilir + Upload satiri olusur -> istek HEMEN doner
// ("analyzing"); agir analiz arka planda (lib/analysis/queue) calisir.
// Ilerleme: GET /api/uploads/[id]/progress - bittiginde Analysis satiri yazilir.
//
// Senkron mod (eski davranis, testler icin): ?sync=1 -> analiz bitene kadar bekle.
//
// Cift eslestirmeler (lib/analysis/queue.computePairOpts):
//   - global-metadata.dat <-> GameAssembly.dll/libil2cpp.so
//   - *.memmap/*.map      <-> raw bellek dump (LeechCore memmap:// eslemesi)
//   - *.pdb               <-> debugPdb adina eslesen PE (sembol cikarma)
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";

import { db } from "@/lib/db";
import { saveBuffer, MAX_UPLOAD_BYTES } from "@/lib/storage";
import {
  computePairOpts,
  dispatchUploadJob,
  runAnalysis,
} from "@/lib/analysis/queue";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return NextResponse.json(
      { ok: false, error: "Gecersiz istek - multipart/form-data bekleniyor" },
      { status: 400 },
    );
  }

  const file = form.get("file");
  if (!file || typeof file === "string") {
    return NextResponse.json(
      { ok: false, error: "'file' alani bulunamadi - bir dosya secin" },
      { status: 400 },
    );
  }

  // klasor grup yuklemesi: opsiyonel ust klasor kaydi + goreceli yol
  const parentIdRaw = form.get("parentId");
  const relPathRaw = form.get("relPath");
  const parentId = typeof parentIdRaw === "string" && parentIdRaw.trim() ? parentIdRaw.trim() : null;
  const relPath =
    typeof relPathRaw === "string" && relPathRaw.trim()
      ? relPathRaw.trim().replace(/\\/g, "/").slice(0, 400)
      : null;

  let parentRow: { id: string; source: string } | null = null;
  if (parentId) {
    parentRow = await db.upload.findUnique({
      where: { id: parentId },
      select: { id: true, source: true },
    });
    if (!parentRow) {
      return NextResponse.json(
        { ok: false, error: "parentId bulunamadi - once POST /api/upload/folder ile klasor kaydi acin" },
        { status: 400 },
      );
    }
  }

  if (file.size > MAX_UPLOAD_BYTES) {
    return NextResponse.json(
      {
        ok: false,
        error: `Dosya cok buyuk: ${(file.size / 1024 / 1024).toFixed(1)} MB (sinir ${MAX_UPLOAD_BYTES / 1024 / 1024} MB)`,
      },
      { status: 413 },
    );
  }

  const id = crypto.randomUUID();
  const fileName = file.name || "dosya.bin";
  const buf = Buffer.from(await file.arrayBuffer());

  // 1) dosyayi diske yaz + kayit olustur
  let savedPath = "";
  try {
    const saved = saveBuffer(id, fileName, buf);
    savedPath = saved.savedPath;
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: `Dosya kaydedilemedi: ${e instanceof Error ? e.message : String(e)}` },
      { status: 500 },
    );
  }

  await db.upload.create({
    data: {
      id,
      fileName,
      savedPath,
      size: buf.length,
      mime: file.type || null,
      source: "upload",
      parentId: parentRow ? parentRow.id : null,
      relPath,
      status: "analyzing",
    },
  });

  // klasor grup toplamlarini guncelle (boyut + durum)
  if (parentRow) {
    try {
      const agg = await db.upload.aggregate({
        where: { parentId: parentRow.id },
        _sum: { size: true },
        _count: { _all: true },
      });
      await db.upload.update({
        where: { id: parentRow.id },
        data: {
          size: agg._sum.size ?? 0,
          status: "done", // en az 1 dosya eklendi
        },
      });
    } catch {
      // toplamlar kritik degil
    }
  }

  // 2) eslestirme secenekleri (24 saat pencere; hizli DB sorgulari)
  const opts = await computePairOpts(id, fileName, buf);
  const syncMode = req.nextUrl.searchParams.get("sync") === "1";

  if (syncMode) {
    // eski senkron davranis - test uyumlulugu
    const analysis = await runAnalysis(id, buf, fileName, opts);
    if (!analysis) {
      const row = await db.upload.findUnique({ where: { id }, select: { error: true } });
      return NextResponse.json({ ok: true, id, status: "error", error: row?.error ?? "analiz hatasi" });
    }
    return NextResponse.json({
      ok: true,
      id,
      status: "done",
      kind: analysis.result.kind,
      engine: analysis.result.engine.detected,
      engineVersion: analysis.result.engine.version,
      parentId: parentId ?? undefined,
      relPath: relPath ?? undefined,
    });
  }

  // 3) arka plan analizi - istek hemen doner; isi worker havuzu yurutur
  //    (ANALYSIS_WORKERS adet worker_threads; paket yoksa ayni surec)
  dispatchUploadJob(id, fileName, buf, opts);

  return NextResponse.json({
    ok: true,
    id,
    status: "analyzing",
    parentId: parentId ?? undefined,
    relPath: relPath ?? undefined,
  });
}
