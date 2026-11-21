// ----------------------------------------------------------------------------
// GET /api/dumperpro/imports/[id]/codegen?lang=cpp|...&kind=all|functions|structs|enums
// Saklanan normalize edilmis fonksiyon verisinden kaynak metin uretir.
// Opcode URETILMEZ - motor ciktisinde olmadigi icin yalnizca rapor adresleri.
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";

import { db } from "@/lib/db";
import {
  DP_CODEGEN_KINDS,
  DP_CODEGEN_LANGS,
  generateDumperProCode,
  type DpCodegenKind,
  type DpCodegenLang,
} from "@/lib/dumperpro/codegen";
import { parseFunctionsField } from "@/lib/dumperpro/parse";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const row = await db.dumperProImport.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }

  const sp = req.nextUrl.searchParams;
  const lang = (sp.get("lang") ?? "cpp").toLowerCase() as DpCodegenLang;
  const kind = (sp.get("kind") ?? "all").toLowerCase() as DpCodegenKind;

  if (!DP_CODEGEN_LANGS.includes(lang)) {
    return NextResponse.json(
      { ok: false, error: `Gecersiz lang - ${DP_CODEGEN_LANGS.join(", ")} bekleniyor` },
      { status: 400 },
    );
  }
  if (!DP_CODEGEN_KINDS.includes(kind)) {
    return NextResponse.json(
      { ok: false, error: `Gecersiz kind - ${DP_CODEGEN_KINDS.join(", ")} bekleniyor` },
      { status: 400 },
    );
  }

  const functions = parseFunctionsField(row.functionsJson);
  const out = generateDumperProCode(
    {
      meta: {
        tool: row.toolVersion ?? "DumperPro",
        game: row.game ?? "Bilinmeyen",
        ue: row.ueVersion ?? "—",
        moduleName: row.moduleName ?? "—",
        moduleBase: row.moduleBase ?? "—",
        status: row.status,
      },
      functions,
    },
    lang,
    kind,
  );

  return NextResponse.json({
    ok: true,
    lang,
    kind,
    text: out.text,
    filename: out.filename,
    count: out.itemCount,
    totalFunctions: functions.length,
  });
}
