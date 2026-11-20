// ----------------------------------------------------------------------------
// GET /api/uploads/[id]/sdk/[name]        - tek SDK cikti dosyasini indir
// GET /api/uploads/[id]/sdk/[name]?raw=1  - canli goruntuleme (JSON icerik)
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import { SDK_DIR } from "@/lib/storage";

export const dynamic = "force-dynamic";

const MIME: Record<string, string> = {
  ".h": "text/plain; charset=utf-8",
  ".hpp": "text/plain; charset=utf-8",
  ".cs": "text/plain; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; name: string }> },
) {
  const { id, name } = await params;

  // yol gezinmesini engelle
  const safe = path.basename(name);
  if (safe !== name || safe.includes("..") || safe.length > 128) {
    return NextResponse.json({ ok: false, error: "Gecersiz dosya adi" }, { status: 400 });
  }

  const filePath = path.join(SDK_DIR(id), safe);
  if (!fs.existsSync(filePath)) {
    return NextResponse.json({ ok: false, error: "SDK dosyasi bulunamadi" }, { status: 404 });
  }

  const content = fs.readFileSync(filePath, "utf8");

  // canli goruntuleme modu: JSON olarak dondur (panel icinde hizli acilis)
  if (req.nextUrl.searchParams.get("raw") === "1") {
    return NextResponse.json(
      { ok: true, name: safe, size: Buffer.byteLength(content, "utf8"), content },
      { headers: { "Cache-Control": "no-store" } },
    );
  }

  const ext = path.extname(safe).toLowerCase();
  return new NextResponse(content, {
    headers: {
      "Content-Type": MIME[ext] ?? "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${safe}"`,
      "Cache-Control": "no-store",
    },
  });
}
