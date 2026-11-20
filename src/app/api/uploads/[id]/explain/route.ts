// ----------------------------------------------------------------------------
// POST /api/uploads/[id]/explain - semantik aciklama (heuristic + AI)
//   govde: {
//     type: "function"|"field"|"struct"|"enum"|"string"|"name",
//     artifact: { ... tiye gore alanlar },
//     useAi?: boolean  -> z-ai-web-dev-sdk ile Turkce derin aciklama
//   }
// Yanit: { ok, heuristic: SemanticInfo, ai?: string }
// ----------------------------------------------------------------------------
//
// Heuristic katman her zaman doner (semantics.ts sozlugu - cevrimdisi).
// useAi=true ise backend'de z-ai-web-dev-sdk calistirilir (istemcide ASLA).

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  explainFunction,
  explainField,
  explainStruct,
  explainEnum,
  explainString,
  explainName,
  type SemanticInfo,
} from "@/lib/analysis/semantics";
import type { FunctionEntry, RecoveredStruct, RecoveredEnum } from "@/lib/analysis/types";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

function buildHeuristic(type: string, artifact: Record<string, unknown>): SemanticInfo {
  switch (type) {
    case "function":
      return explainFunction(artifact as unknown as FunctionEntry, {
        strings: (artifact.strings as string[]) ?? undefined,
        apiCalls: (artifact.apiCalls as string[]) ?? undefined,
      });
    case "field":
      return explainField(String(artifact.name ?? ""), String(artifact.type ?? ""), artifact.structName ? String(artifact.structName) : undefined);
    case "struct":
      return explainStruct(artifact as unknown as RecoveredStruct);
    case "enum":
      return explainEnum(artifact as unknown as RecoveredEnum);
    case "string":
      return explainString(String(artifact.value ?? ""));
    default:
      return explainName(String(artifact.name ?? artifact.value ?? ""));
  }
}

function buildPrompt(type: string, artifact: Record<string, unknown>, heuristic: SemanticInfo): { system: string; user: string } {
  const system =
    "Sen bir oyun/bellek analiz uzmanisin. Kullaniciya TURKCE, kisa (en fazla 8 madde), net ve teknik " +
    "bir aciklama ver. Format: once 1 cumlelik ozet, ardindan '- ' ile baslayan maddeler. " +
    "Maddelerde sunlari anlat: ne is yapar, ne hesaplar, hangi veriye/structure yazabilir, oyun baglaminda " +
    "kategorisi (karakter/silah/para/konum/fizik/gorsel/ag vb), guven seviyesi ve varsa kullaniciya pratik not. " +
    "Kesin bilgi yoksa 'olasilik' dili kullan; ASLA emin gibi konusma. Markdown kullanma, duz metin yaz.";
  const data = JSON.stringify(artifact).slice(0, 4000);
  const user =
    `Analiz tipi: ${type}\n` +
    `Heuristic tahmin: kategori=${heuristic.category}, guven=${heuristic.confidence}, ` +
    `ozet="${heuristic.summary}", hesaplar="${heuristic.computes}", yazim hedefi="${heuristic.writes}"\n` +
    `Ham veri: ${data}\n` +
    `Bu veriyi derinlemesine acikla (Turkce).`;
  return { system, user };
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });
  }

  let body: { type?: string; artifact?: Record<string, unknown>; useAi?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govdesi" }, { status: 400 });
  }
  const type = body.type ?? "name";
  const artifact = body.artifact ?? {};
  const heuristic = buildHeuristic(type, artifact);

  const res: { ok: true; heuristic: SemanticInfo; ai?: string; aiError?: string } = { ok: true, heuristic };

  if (body.useAi === true) {
    try {
      const { default: ZAI } = await import("z-ai-web-dev-sdk");
      const zai = await ZAI.create();
      const { system, user } = buildPrompt(type, artifact, heuristic);
      const completion = await zai.chat.completions.create({
        messages: [
          { role: "assistant", content: system },
          { role: "user", content: user },
        ],
        thinking: { type: "disabled" },
      });
      const content = completion.choices[0]?.message?.content;
      res.ai = typeof content === "string" && content.trim() ? content.trim() : undefined;
      if (!res.ai) res.aiError = "AI bos yanit dondu";
    } catch (e) {
      res.aiError = e instanceof Error ? e.message : String(e);
    }
  }

  return NextResponse.json(res);
}
