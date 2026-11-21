// ----------------------------------------------------------------------------
// GET    /api/dumperpro/imports/[id] - bolum bazli okuma (sunucu tarafi dilimleme)
//   ?section=meta|names|functions|objects&search=&cls=&limit=200&offset=0
// DELETE /api/dumperpro/imports/[id] - kayit + storage/dumperpro/<id> sil
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import {
  parseFunctionsField,
  parseNamesField,
  parseObjectsField,
} from "@/lib/dumperpro/parse";

export const dynamic = "force-dynamic";

const DP_DIR = (id: string): string => path.join(process.cwd(), "storage", "dumperpro", id);

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const row = await db.dumperProImport.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }

  const sp = req.nextUrl.searchParams;
  const section = (sp.get("section") ?? "meta").toLowerCase();
  const search = (sp.get("search") ?? "").trim().toLowerCase();
  const clsFilter = (sp.get("cls") ?? "").trim();
  const limit = Math.min(Math.max(Number(sp.get("limit") ?? 200) || 200, 1), 2000);
  const offset = Math.max(Number(sp.get("offset") ?? 0) || 0, 0);

  const meta = {
    id: row.id,
    label: row.label,
    toolVersion: row.toolVersion,
    mode: row.mode,
    target: row.target,
    game: row.game,
    ueVersion: row.ueVersion,
    moduleName: row.moduleName,
    moduleBase: row.moduleBase,
    status: row.status,
    createdAt: row.createdAt,
  };
  const counts = {
    names: row.namesCount,
    objects: row.objectsCount,
    functions: row.functionsCount,
  };

  if (section === "meta") {
    return NextResponse.json({
      ok: true,
      section: "meta",
      meta,
      counts,
      hasNames: row.namesJson !== null,
      hasObjects: row.objectsJson !== null,
      hasFunctions: row.functionsJson !== null,
    });
  }

  if (section === "names") {
    const names = parseNamesField(row.namesJson);
    const filtered = search
      ? names.filter((n) => n.name.toLowerCase().includes(search))
      : names;
    return NextResponse.json({
      ok: true,
      section: "names",
      total: filtered.length,
      offset,
      limit,
      items: filtered.slice(offset, offset + limit),
    });
  }

  if (section === "functions") {
    const functions = parseFunctionsField(row.functionsJson);
    // sinif filtresi: tam eslesme (dropdown icin)
    const afterCls = clsFilter ? functions.filter((f) => f.cls === clsFilter) : functions;
    // arama: cls/name/pkg uzerinde kaba harf duyarsiz alt dize
    const filtered = search
      ? afterCls.filter(
          (f) =>
            f.name.toLowerCase().includes(search) ||
            f.cls.toLowerCase().includes(search) ||
            f.pkg.toLowerCase().includes(search),
        )
      : afterCls;
    // sinif listesi: tum fonksiyonlardan (filtreden once, dropdown stabil)
    const classes = [...new Set(functions.map((f) => f.cls).filter((c) => c.length > 0))]
      .sort((a, b) => a.localeCompare(b))
      .slice(0, 500);
    return NextResponse.json({
      ok: true,
      section: "functions",
      total: filtered.length,
      offset,
      limit,
      classes,
      items: filtered.slice(offset, offset + limit),
    });
  }

  if (section === "objects") {
    const objects = parseObjectsField(row.objectsJson);
    const filtered = search
      ? objects.filter(
          (o) =>
            o.name.toLowerCase().includes(search) ||
            o.cls.toLowerCase().includes(search) ||
            o.path.toLowerCase().includes(search),
        )
      : objects;
    return NextResponse.json({
      ok: true,
      section: "objects",
      total: filtered.length,
      offset,
      limit,
      items: filtered.slice(offset, offset + limit),
    });
  }

  return NextResponse.json(
    { ok: false, error: "Gecersiz section - meta|names|functions|objects bekleniyor" },
    { status: 400 },
  );
}

export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const row = await db.dumperProImport.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ ok: false, error: "Kayit bulunamadi" }, { status: 404 });
  }

  try {
    fs.rmSync(DP_DIR(id), { recursive: true, force: true });
  } catch {
    // klasor yok - sorun degil
  }
  await db.dumperProImport.delete({ where: { id } });

  return NextResponse.json({ ok: true, id });
}
