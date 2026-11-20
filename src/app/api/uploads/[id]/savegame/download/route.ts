// ----------------------------------------------------------------------------
// GET /api/uploads/[id]/savegame/download - duzenlenen save kopyasini indir
// (duzenleme yoksa orijinal dosya gonderilir)
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
    include: { analysis: { select: { kind: true } } },
  });
  if (!row) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });

  const isVdf = row.analysis?.kind === "vdf" || /\.vdf$/i.test(row.fileName);
  const ep = `${row.savedPath}.edited${isVdf ? ".vdf" : ".sav"}`;
  const filePath = fs.existsSync(ep) ? ep : row.savedPath;
  const isEdited = filePath === ep;

  let buf: Buffer;
  try {
    buf = fs.readFileSync(filePath);
  } catch {
    return NextResponse.json({ ok: false, error: "Disk dosyasi okunamadi" }, { status: 410 });
  }

  const base = path.basename(row.fileName).replace(/\.[^.]+$/, "");
  const ext = isVdf ? ".vdf" : ".sav";
  const downloadName = `${base}${isEdited ? "_edited" : ""}${ext}`;

  return new NextResponse(new Uint8Array(buf), {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${downloadName}"`,
      "Content-Length": String(buf.length),
      "X-Edited": isEdited ? "1" : "0",
    },
  });
}
