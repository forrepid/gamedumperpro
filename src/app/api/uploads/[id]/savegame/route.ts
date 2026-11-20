// ----------------------------------------------------------------------------
// /api/uploads/[id]/savegame - UE/Steam save editor backend
//   GET  ?keyHex=&cipher=      -> save agaci (GVAS props / VDF agaci)
//   PUT  { edits, keyHex?, cipher? } -> duzenlemeleri uygula, .edited kopyasi yaz
// Download: GET /api/uploads/[id]/savegame/download
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import {
  parseSaveGame,
  serializeSaveGame,
  applyEdits,
  summarizeSaveGame,
  type SaveCipher,
} from "@/lib/analysis/savegame";
import { parseVdf, serializeVdf, applyVdfEdits } from "@/lib/analysis/vdf";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** 20 MB uzeri agac cevabin kisaltilir (DB/JSON sismesin) */
const TREE_CAP = 20 * 1024 * 1024;

function editedPathFor(savedPath: string, kind: "savegame" | "vdf"): string {
  return `${savedPath}.edited${kind === "savegame" ? ".sav" : ".vdf"}`;
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({
    where: { id },
    include: { analysis: { select: { kind: true } } },
  });
  if (!row) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });

  const url = new URL(req.url);
  const keyHex = url.searchParams.get("keyHex") ?? undefined;
  const cipher = (url.searchParams.get("cipher") as SaveCipher | null) ?? undefined;

  // once duzenlenen kopya, yoksa orijinal
  const isVdf = row.analysis?.kind === "vdf" || /\.vdf$/i.test(row.fileName);
  let filePath = row.savedPath;
  let fromEdited = false;
  const ep = editedPathFor(row.savedPath, isVdf ? "vdf" : "savegame");
  if (fs.existsSync(ep)) {
    filePath = ep;
    fromEdited = true;
  }

  let buf: Buffer;
  try {
    buf = fs.readFileSync(filePath);
  } catch {
    return NextResponse.json({ ok: false, error: "Disk dosyasi okunamadi" }, { status: 410 });
  }

  try {
    if (isVdf) {
      const doc = parseVdf(buf);
      const big = buf.length > TREE_CAP;
      return NextResponse.json({
        ok: true,
        type: "vdf",
        editedFile: fromEdited,
        meta: { ...doc.meta, kind: doc.kind },
        root: big ? undefined : doc.root,
        summary: doc.meta,
        truncated: big,
      });
    }
    const doc = parseSaveGame(buf, { keyHex, cipher });
    const big = buf.length > TREE_CAP;
    return NextResponse.json({
      ok: true,
      type: "savegame",
      editedFile: fromEdited,
      header: doc.header,
      meta: { ...doc.meta, keyHex: keyHex ? `${keyHex.slice(0, 4)}...` : undefined },
      props: big ? undefined : doc.props,
      summary: summarizeSaveGame(doc),
      truncated: big,
    });
  } catch (e) {
    return NextResponse.json(
      {
        ok: false,
        error: e instanceof Error ? e.message : String(e),
        hint: "Sifreli save dosyalari icin keyHex (32 bayt / 64 hex) ve cipher (aes-256-ecb/aes-256-cbc) verin",
      },
      { status: 422 },
    );
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const row = await db.upload.findUnique({
    where: { id },
    include: { analysis: { select: { kind: true } } },
  });
  if (!row) return NextResponse.json({ ok: false, error: "Yukleme bulunamadi" }, { status: 404 });

  let body: { edits?: { path: string; value: string }[]; keyHex?: string; cipher?: SaveCipher; ivHex?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govdesi" }, { status: 400 });
  }
  if (!Array.isArray(body.edits) || body.edits.length === 0) {
    return NextResponse.json({ ok: false, error: "edits dizisi gerekli (path + value)" }, { status: 400 });
  }

  const isVdf = row.analysis?.kind === "vdf" || /\.vdf$/i.test(row.fileName);
  let buf: Buffer;
  try {
    buf = fs.readFileSync(row.savedPath);
  } catch {
    return NextResponse.json({ ok: false, error: "Orijinal dosya okunamadi" }, { status: 410 });
  }

  try {
    if (isVdf) {
      const doc = parseVdf(buf);
      const res = applyVdfEdits(doc, body.edits);
      const out = serializeVdf(doc);
      const ep = editedPathFor(row.savedPath, "vdf");
      fs.mkdirSync(path.dirname(ep), { recursive: true });
      fs.writeFileSync(ep, out);
      return NextResponse.json({
        ok: true,
        type: "vdf",
        applied: res.applied,
        errors: res.errors,
        editedSize: out.length,
        downloadUrl: `/api/uploads/${id}/savegame/download`,
      });
    }

    const doc = parseSaveGame(buf, { keyHex: body.keyHex, cipher: body.cipher, ivHex: body.ivHex });
    const res = applyEdits(doc, body.edits);
    const out = serializeSaveGame(doc, { keyHex: body.keyHex, cipher: body.cipher, ivHex: body.ivHex });
    const ep = editedPathFor(row.savedPath, "savegame");
    fs.mkdirSync(path.dirname(ep), { recursive: true });
    fs.writeFileSync(ep, out);
    return NextResponse.json({
      ok: true,
      type: "savegame",
      applied: res.applied,
      errors: res.errors,
      editedSize: out.length,
      encrypted: doc.meta.encrypted,
      downloadUrl: `/api/uploads/${id}/savegame/download`,
    });
  } catch (e) {
    return NextResponse.json(
      {
        ok: false,
        error: e instanceof Error ? e.message : String(e),
        hint: "Sifreli dosyada once GET ?keyHex= ile dogrulayin; ayni anahtar PUT isteginde de gonderilmeli",
      },
      { status: 422 },
    );
  }
}
