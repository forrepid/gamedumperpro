// ----------------------------------------------------------------------------
// GET    /api/uploads/[id] - tam analiz sonucu
// DELETE /api/uploads/[id] - kayit + disk dosyasini sil (klasor ise alt dosyalar dahil)
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({
    where: { id },
    include: { analysis: true },
  });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }

  // klasor grubu ise alt dosyalari da bildir
  const childCount =
    row.source === "folder"
      ? await db.upload.count({ where: { parentId: row.id } })
      : undefined;

  return NextResponse.json({
    ok: true,
    upload: {
      id: row.id,
      fileName: row.fileName,
      size: row.size,
      mime: row.mime,
      source: row.source,
      parentId: row.parentId,
      relPath: row.relPath,
      status: row.status,
      error: row.error,
      createdAt: row.createdAt,
      childCount,
    },
    analysis: row.analysis
      ? {
          id: row.analysis.id,
          kind: row.analysis.kind,
          engine: row.analysis.engine,
          engineVersion: row.analysis.engineVersion,
          result: JSON.parse(row.analysis.summary) as unknown,
          report: row.analysis.report,
        }
      : null,
  });
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }

  // klasor grubu: alt dosyalari da sil (disk + db, kaskad analiz silmesi)
  const children = await db.upload.findMany({ where: { parentId: id } });
  for (const child of children) {
    try {
      if (child.savedPath && child.savedPath !== "-") fs.unlinkSync(child.savedPath);
    } catch {
      // dosya zaten yok - sorun degil
    }
    await db.upload.delete({ where: { id: child.id } }); // analysis cascade
  }

  try {
    if (row.savedPath && row.savedPath !== "-") fs.unlinkSync(row.savedPath);
  } catch {
    // dosya zaten yok - sorun degil
  }
  // yan dosyalari da temizle: .dpr (patch kaydi) + sdk klasoru
  if (row.savedPath && row.savedPath !== "-") {
    try {
      fs.unlinkSync(`${row.savedPath}.dpr`);
    } catch {
      // yan dosya yok
    }
  }
  try {
    const sdkDir = path.join(process.cwd(), "storage", "uploads", "sdk", row.id);
    fs.rmSync(sdkDir, { recursive: true, force: true });
  } catch {
    // sdk klasoru yok
  }
  await db.upload.delete({ where: { id } }); // analysis cascade

  return NextResponse.json({ ok: true, deletedChildren: children.length });
}
