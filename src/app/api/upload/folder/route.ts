// ----------------------------------------------------------------------------
// POST /api/upload/folder - klasor (grup) yukleme kaydi olustur
//
// Frontend klasor yuklediginde (webkitdirectory) once buraya bir "klasor"
// ust kaydi acar; ardindan her dosya POST /api/upload ile parentId=klasorId
// + relPath=goreceli yol gonderilir. Boylece gecmis listesi
// "dizin > dosya" agac gorunumunde gruplanir.
//
// body: { "name": "MyGameBundle", "count": 12 }
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";

import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  let body: { name?: string; count?: number };
  try {
    body = (await req.json()) as { name?: string; count?: number };
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govde" }, { status: 400 });
  }

  const rawName = (body.name ?? "").trim();
  if (!rawName) {
    return NextResponse.json({ ok: false, error: "'name' alani gerekli" }, { status: 400 });
  }

  // yol gezinmesini engelle + temiz ad
  const name =
    rawName
      .replace(/[\\/]+/g, "_")
      .replace(/[^A-Za-z0-9._ -]/g, "")
      .trim()
      .slice(0, 120) || "Klasor";

  const id = crypto.randomUUID();

  await db.upload.create({
    data: {
      id,
      fileName: name,
      savedPath: "-", // klasorun diske dosyasi yoktur
      size: 0, // dosyalar eklendikce guncellenir
      mime: null,
      source: "folder",
      status: "analyzing",
    },
  });

  return NextResponse.json({
    ok: true,
    id,
    name,
    hint: `Dosyalari POST /api/upload ile parentId=${id} ve relPath alanlarina gonderin`,
  });
}
