// ----------------------------------------------------------------------------
// POST /api/uploads/[id]/dumperpro - gercek C++ DumperPro ikilisini calistir
//   `DumperPro --file <upload> --json --out /tmp/...`
// Ciktilar SDK klasorune CLI_ onekiyle kopyalanir (SDK sekmesinde gorunur).
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";

import { db } from "@/lib/db";
import { runDumperProCli } from "@/lib/cppbridge";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }
  if (!row.savedPath || row.savedPath === "-") {
    return NextResponse.json({ ok: false, error: "Bu kayit disk dosyasi icermiyor (klasor grubu)" }, { status: 400 });
  }
  try {
    fs.accessSync(row.savedPath);
  } catch {
    return NextResponse.json({ ok: false, error: "Disk dosyasi bulunamadi" }, { status: 410 });
  }

  const res = await runDumperProCli(id, row.savedPath, row.fileName);
  if (!res.ok) {
    return NextResponse.json(
      {
        ok: false,
        error: res.error ?? "DumperPro ikilisi calistirilamadi",
        binary: res.binary,
        timedOut: res.timedOut,
        stderr: res.stderr,
      },
      { status: 500 },
    );
  }
  return NextResponse.json({
    ok: true,
    binary: res.binary,
    outFiles: res.outFiles,
    sdkCopied: res.sdkCopied,
    stdoutTail: res.stdout?.split("\n").slice(-12).join("\n"),
  });
}
