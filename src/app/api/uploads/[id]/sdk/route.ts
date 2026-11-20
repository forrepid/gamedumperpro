// ----------------------------------------------------------------------------
// GET /api/uploads/[id]/sdk       - SDK cikti manifest (dosya listesi)
// GET /api/uploads/[id]/sdk/[name] - tek SDK dosyasini indir
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import { SDK_DIR } from "@/lib/storage";

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
  if (!row?.analysis) {
    return NextResponse.json({ ok: false, error: "Analiz bulunamadi" }, { status: 404 });
  }

  // manifest: diskte var olanlar listele (kaynak gercekler)
  const dir = SDK_DIR(id);
  let files: { name: string; kind: string; size: number }[] = [];
  try {
    if (fs.existsSync(dir)) {
      files = fs
        .readdirSync(dir)
        .map((name) => {
          const st = fs.statSync(path.join(dir, name));
          const kind = name.endsWith(".h") ? (name.includes("classes") ? "classes.h" : name.includes("structs") ? "structs.h" : name.includes("enums") ? "enums.h" : "header") : name.endsWith(".cs") ? (name.includes("enums") ? "enums.cs" : "dump.cs") : name.endsWith(".hpp") ? "SDK.hpp" : name.replace(".txt", ".txt");
          return { name, kind, size: st.size };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
    }
  } catch {
    // disk okunamadi - analizdeki manifest ile devam
  }

  if (files.length === 0) {
    const fromResult = row.analysis.summary
      ? (JSON.parse(row.analysis.summary) as { sdk?: { files?: { name: string; kind: string; size: number }[] } }).sdk?.files
      : undefined;
    files = fromResult ?? [];
  }

  return NextResponse.json({ ok: true, files });
}
