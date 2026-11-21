// ----------------------------------------------------------------------------
// GET /api/dumperpro/imports - DumperPro ice aktarma kayitlari (yeni -> eski, 100)
// ----------------------------------------------------------------------------

import { NextResponse } from "next/server";

import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  const rows = await db.dumperProImport.findMany({
    orderBy: { createdAt: "desc" },
    take: 100,
    select: {
      id: true,
      label: true,
      game: true,
      ueVersion: true,
      status: true,
      namesCount: true,
      objectsCount: true,
      functionsCount: true,
      toolVersion: true,
      createdAt: true,
    },
  });

  return NextResponse.json({ ok: true, imports: rows });
}
