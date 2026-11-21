// ----------------------------------------------------------------------------
// POST /api/dumperpro/import - DumperPro.exe cikti dosyalarini ice aktar
//
// multipart/form-data, alan: "files" (birden fazla) veya "file" (tek).
// Kabul: names.json, objects.json, functions.json, result.json (JSON) +
// Names.txt / Objects.txt / funcs.txt (metin) + .zip demetleri (icindekiler
// zipapk yardimcilariyla acilir).
//
// Akis: ham dosyalar storage/dumperpro/<id>/ altina yazilir, normalize edilmis
// JSON dizeleri DumperProImport kaydina konur. Hicbir sey ayristirilamazsa 400.
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import {
  classifyFileName,
  extractDumperProZip,
  parseDumperProFiles,
  sanitizeDpFileName,
  type DpSourceFile,
} from "@/lib/dumperpro/parse";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

const MAX_FILE_BYTES = 300 * 1024 * 1024; // 300 MB / dosya
const DP_DIR = (id: string): string => path.join(process.cwd(), "storage", "dumperpro", id);

export async function POST(req: NextRequest) {
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return NextResponse.json(
      { ok: false, error: "Gecersiz istek - multipart/form-data bekleniyor" },
      { status: 400 },
    );
  }

  const rawFiles = [...form.getAll("files"), ...form.getAll("file")].filter(
    (f): f is File => f instanceof File,
  );
  if (rawFiles.length === 0) {
    return NextResponse.json(
      { ok: false, error: "'files' alani bulunamadi - en az bir dosya secin" },
      { status: 400 },
    );
  }

  // 1) tum yuklemeleri oku; zip demetlerini ac; ham dosyalari derle
  const sources: DpSourceFile[] = [];
  const rawToSave: DpSourceFile[] = [];
  let skipped = 0;

  for (const file of rawFiles) {
    if (file.size > MAX_FILE_BYTES) {
      return NextResponse.json(
        {
          ok: false,
          error: `Dosya cok buyuk: ${file.name || "dosya"} (${(file.size / 1024 / 1024).toFixed(1)} MB, sinir 300 MB)`,
        },
        { status: 413 },
      );
    }
    const buf = Buffer.from(await file.arrayBuffer());
    const lower = (file.name || "").toLowerCase();
    rawToSave.push({ name: sanitizeDpFileName(file.name || "dosya.bin"), data: buf });

    if (lower.endsWith(".zip")) {
      const extracted = extractDumperProZip(buf);
      if (extracted.length === 0) skipped++;
      sources.push(...extracted);
    } else if (classifyFileName(file.name || "") !== "unknown") {
      sources.push({ name: sanitizeDpFileName(file.name || "dosya.txt"), data: buf });
    } else {
      skipped++;
    }
  }

  if (sources.length === 0) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "Ayristirilabilir DumperPro ciktisi bulunamadi - names/objects/functions/result JSON veya Names.txt/Objects.txt/funcs.txt bekleniyor",
      },
      { status: 400 },
    );
  }

  // 2) normalize et
  const parsed = parseDumperProFiles(sources);
  if (parsed.names.length === 0 && parsed.objects.length === 0 && parsed.functions.length === 0) {
    return NextResponse.json(
      { ok: false, error: "Dosyalar okundu ama gecerli names/objects/functions verisi cikarilamadi" },
      { status: 400 },
    );
  }

  // 3) kayit etiketi: result target.detail > game > zaman damgali varsayilan
  const stamp = new Date().toISOString().replace("T", " ").slice(0, 19);
  const targetLabel =
    parsed.meta.target && parsed.meta.target !== "—" ? parsed.meta.target : null;
  const gameLabel =
    parsed.meta.game && parsed.meta.game !== "Bilinmeyen" ? parsed.meta.game : null;
  const label = targetLabel ?? gameLabel ?? `DumperPro ice aktarim ${stamp}`;

  const id = crypto.randomUUID();

  // 4) ham dosyalari storage/dumperpro/<id>/ altina yaz (ayni adda cakisma: -2, -3)
  try {
    const dir = DP_DIR(id);
    fs.mkdirSync(dir, { recursive: true });
    const used = new Set<string>();
    for (const rf of rawToSave) {
      let name = rf.name;
      let n = 0;
      while (used.has(name.toLowerCase())) {
        n++;
        const ext = path.extname(rf.name);
        const stem = path.basename(rf.name, ext);
        name = `${stem}-${n}${ext}`;
      }
      used.add(name.toLowerCase());
      fs.writeFileSync(path.join(dir, name), rf.data);
    }
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: `Ham dosyalar kaydedilemedi: ${e instanceof Error ? e.message : String(e)}` },
      { status: 500 },
    );
  }

  // 5) normalize edilmis JSON dizelerini kaydet
  const namesJson =
    parsed.names.length > 0
      ? JSON.stringify({ format: "dumperpro-names", count: parsed.names.length, names: parsed.names })
      : null;
  const objectsJson =
    parsed.objects.length > 0
      ? JSON.stringify({ format: "dumperpro-objects", count: parsed.objects.length, objects: parsed.objects })
      : null;
  const functionsJson =
    parsed.functions.length > 0
      ? JSON.stringify({
          format: "dumperpro-functions",
          version: 1,
          game: parsed.meta.game,
          ue: parsed.meta.ueVersion,
          module: { name: parsed.meta.moduleName, base: parsed.meta.moduleBase },
          count: parsed.functions.length,
          functions: parsed.functions,
        })
      : null;

  try {
    await db.dumperProImport.create({
      data: {
        id,
        label,
        toolVersion: parsed.meta.toolVersion,
        mode: parsed.meta.mode,
        target: parsed.meta.target,
        game: parsed.meta.game,
        ueVersion: parsed.meta.ueVersion,
        moduleName: parsed.meta.moduleName,
        moduleBase: parsed.meta.moduleBase,
        status: parsed.meta.status,
        namesJson,
        objectsJson,
        functionsJson,
        namesCount: parsed.names.length,
        objectsCount: parsed.objects.length,
        functionsCount: parsed.functions.length,
      },
    });
  } catch (e) {
    // DB kaydi olusturulamadi - yazilan ham dosyalari da temizle
    try {
      fs.rmSync(DP_DIR(id), { recursive: true, force: true });
    } catch {
      // temizlik basarisiz olsa da yanit don
    }
    return NextResponse.json(
      { ok: false, error: `Kayit olusturulamadi: ${e instanceof Error ? e.message : String(e)}` },
      { status: 500 },
    );
  }

  return NextResponse.json({
    ok: true,
    id,
    label,
    status: parsed.meta.status,
    counts: {
      names: parsed.names.length,
      objects: parsed.objects.length,
      functions: parsed.functions.length,
    },
    sources: parsed.sources,
    skipped,
  });
}
