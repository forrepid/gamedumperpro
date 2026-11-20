// ----------------------------------------------------------------------------
// POST /api/uploads/[id]/codegen - cok dilli kod uretimi (Kod Uretici sekmesi)
//   govde: { language, kind: "functions"|"structs"|"enums"|"strings"|"all",
//            filter?, limit? }
//   GET  -> desteklenen dil/tur listesi
// Analiz sonucu DB'den okunur; codegen.ts dil bazli cikti uretir.
// Yuklenen dosya diskte acilir ve readAt bayt-okuyucu olarak verilir: boylece
// her fonksiyon icin opcode onizlemesi (ilk N bayt) ciktiya eklenir. Dosya
// okunamazsa uretim opcodes alanlari olmadan ayni sekilde devam eder.
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { db } from "@/lib/db";
import { generateCode, CODEGEN_LANGUAGES, CODEGEN_KINDS, type CodegenLanguage } from "@/lib/analysis/codegen";
import type { AnalysisResult } from "@/lib/analysis/types";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ ok: true, languages: CODEGEN_LANGUAGES, kinds: CODEGEN_KINDS });
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({ where: { id }, include: { analysis: true } });
  if (!row || !row.analysis) {
    return NextResponse.json({ ok: false, error: "Analiz sonucu bulunamadi - once dosyayi yukleyin" }, { status: 404 });
  }

  let body: { language?: string; kind?: string; filter?: string; limit?: number };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govdesi" }, { status: 400 });
  }

  const language = (body.language ?? "cpp") as CodegenLanguage;
  if (!CODEGEN_LANGUAGES.includes(language)) {
    return NextResponse.json(
      { ok: false, error: `Desteklenmeyen dil: ${language} (gecerli: ${CODEGEN_LANGUAGES.join(", ")})` },
      { status: 400 },
    );
  }
  const kind: string = body.kind ?? "all";
  if (!(CODEGEN_KINDS as readonly string[]).includes(kind)) {
    return NextResponse.json(
      { ok: false, error: `Desteklenmeyen tur: ${kind} (gecerli: ${CODEGEN_KINDS.join(", ")})` },
      { status: 400 },
    );
  }

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.analysis.summary) as AnalysisResult;
  } catch {
    return NextResponse.json({ ok: false, error: "Analiz ozeti bozuk (JSON parse hatasi)" }, { status: 500 });
  }

  // --- opcode onizlemesi icin bayt okuyucu (hataya toleransli) ---
  // Dosya acilamazsa readAt tanimsiz kalir; kod uretimi opcodes olmadan surer.
  let opened: number | null = null;
  let fileSize = 0;
  try {
    if (row.savedPath && row.savedPath !== "-") {
      opened = fs.openSync(row.savedPath, "r");
      fileSize = fs.fstatSync(opened).size;
    }
  } catch {
    opened = null;
  }
  const handle = opened; // const: closure icinde dogru tip daralmasi icin

  const readAt =
    handle !== null
      ? (fileOffset: number, length: number): Buffer | null => {
          try {
            if (fileOffset < 0 || fileOffset >= fileSize) return null;
            const want = Math.min(length, fileSize - fileOffset);
            if (want <= 0) return null;
            const buf = Buffer.alloc(want);
            const read = fs.readSync(handle, buf, 0, want, fileOffset);
            return read > 0 ? buf.subarray(0, read) : null;
          } catch {
            return null;
          }
        }
      : undefined;

  try {
    const out = generateCode(result, {
      language,
      kind: kind as "functions" | "structs" | "enums" | "strings" | "all",
      filter: body.filter,
      limit: typeof body.limit === "number" ? body.limit : undefined,
      imageBase: result.pe?.imageBase,
      readAt,
    });
    return NextResponse.json({ ok: true, ...out });
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: `Kod uretimi hatasi: ${e instanceof Error ? e.message : String(e)}` },
      { status: 500 },
    );
  } finally {
    if (handle !== null) {
      try {
        fs.closeSync(handle);
      } catch {
        // kapatma hatasi yoksayilir
      }
    }
  }
}
