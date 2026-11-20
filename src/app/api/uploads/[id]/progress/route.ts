// ----------------------------------------------------------------------------
// GET /api/uploads/[id]/progress - arka plan analiz ilerlemesi
// { ok, id, status, stage, percent, error? }
//   status: "analyzing" | "done" | "error" (DB) ; stage/percent: is haritasi
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";

import { db } from "@/lib/db";
import { getJobState } from "@/lib/analysis/queue";

export const dynamic = "force-dynamic";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({
    where: { id },
    select: { id: true, status: true, error: true, fileName: true },
  });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }
  const job = getJobState(id);
  const done =
    row.status === "done"
      ? { stage: "tamamlandi", percent: 100 }
      : null;
  return NextResponse.json({
    ok: true,
    id: row.id,
    fileName: row.fileName,
    status: row.status,
    error: row.error ?? undefined,
    stage: job?.stage ?? done?.stage ?? (row.status === "analyzing" ? "kuyrukta" : undefined),
    percent: job?.percent ?? done?.percent ?? (row.status === "analyzing" ? 0 : undefined),
  });
}
