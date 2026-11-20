// ----------------------------------------------------------------------------
// GET /api/uploads/[id]/report?format=txt|json - rapor indirme
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";

import { db } from "@/lib/db";
import { sanitizeFileName } from "@/lib/storage";

export const dynamic = "force-dynamic";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const format = req.nextUrl.searchParams.get("format") === "json" ? "json" : "txt";

  const row = await db.upload.findUnique({
    where: { id },
    include: { analysis: true },
  });
  if (!row?.analysis) {
    return NextResponse.json({ ok: false, error: "Analiz bulunamadi" }, { status: 404 });
  }

  const base = sanitizeFileName(row.fileName.replace(/\.[^.]+$/, ""));
  if (format === "json") {
    const json = JSON.stringify(JSON.parse(row.analysis.summary), null, 2);
    return new NextResponse(json, {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="${base}_analiz.json"`,
        "Cache-Control": "no-store",
      },
    });
  }

  return new NextResponse(row.analysis.report, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${base}_analiz.txt"`,
      "Cache-Control": "no-store",
    },
  });
}
