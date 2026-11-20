// ----------------------------------------------------------------------------
// GET /api/uploads - yukleme gecmisi (son 100 ust + klasor gruplari)
// ----------------------------------------------------------------------------

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getJobState } from "@/lib/analysis/queue";

export const dynamic = "force-dynamic";

export async function GET() {
  const rows = await db.upload.findMany({
    orderBy: { createdAt: "desc" },
    take: 100,
    include: {
      analysis: {
        select: { kind: true, engine: true, engineVersion: true },
      },
    },
  });

  // klasor grup alt sayilari (tek sorgu)
  const groupCounts = await db.upload.groupBy({
    by: ["parentId"],
    _count: { _all: true },
  });
  const countByParent = new Map<string, number>();
  for (const g of groupCounts) {
    if (g.parentId) countByParent.set(g.parentId, g._count._all);
  }

  return NextResponse.json({
    ok: true,
    uploads: rows.map((r) => ({
      id: r.id,
      fileName: r.fileName,
      size: r.size,
      source: r.source,
      parentId: r.parentId,
      relPath: r.relPath,
      status: r.status,
      error: r.error,
      createdAt: r.createdAt,
      childCount: countByParent.get(r.id) ?? 0,
      // arka plan analiz ilerlemesi (yalnizca hala calisan islerde)
      progress:
        r.status === "analyzing"
          ? (() => {
              const j = getJobState(r.id);
              return { stage: j?.stage ?? "kuyrukta", percent: j?.percent ?? 0 };
            })()
          : undefined,
      analysis: r.analysis
        ? { kind: r.analysis.kind, engine: r.analysis.engine, engineVersion: r.analysis.engineVersion }
        : null,
    })),
  });
}
