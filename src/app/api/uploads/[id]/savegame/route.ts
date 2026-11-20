// ----------------------------------------------------------------------------
// /api/uploads/[id]/savegame - UE/Steam save editor backend (editor-writer)
//   GET  ?keyHex=&cipher=      -> save agaci (GVAS props / VDF agaci)
//   PUT  { edits, keyHex?, cipher?, ivHex?, live? }
//        live yok/false (VARSAYILAN): duzenlemeler .edited KOPYAYA yazilir,
//        orijinal dosya korunur; indirme: GET /savegame/download
//        live: true  -> CANLI YAZMA: once otomatik yedek (storage/uploads/
//        backups/<id>__<ad>.bak-<YYYYMMDD-HHMMSS>), sonra orijinal dosya
//        uzerine yazim, ardindan diskten yeniden okuyup dogrulama. Dogrulama
//        basarisizsa yedekten otomatik geri yukleme yapilir.
// Download: GET /api/uploads/[id]/savegame/download
// ----------------------------------------------------------------------------

import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

import { db } from "@/lib/db";
import { createBackup, type BackupInfo } from "@/lib/storage";
import {
  parseSaveGame,
  serializeSaveGame,
  applyEdits,
  verifyEdits,
  summarizeSaveGame,
  type SaveCipher,
} from "@/lib/analysis/savegame";
import { parseVdf, serializeVdf, applyVdfEdits, verifyVdfEdits } from "@/lib/analysis/vdf";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** 20 MB uzeri agac cevabin kisaltilir (DB/JSON sismesin) */
const TREE_CAP = 20 * 1024 * 1024;

function editedPathFor(savedPath: string, kind: "savegame" | "vdf"): string {
  return `${savedPath}.edited${kind === "savegame" ? ".sav" : ".vdf"}`;
}

/** storage/uploads/<id>__<safeName> -> <safeName> (yedek adi icin) */
function safeNameOf(id: string, savedPath: string): string {
  const base = path.basename(savedPath);
  return base.startsWith(`${id}__`) ? base.slice(id.length + 2) : base;
}

// --- canli yazma yardimcilari ----------------------------------------------

interface PutEdit { path: string; value: string }

interface LiveOk {
  ok: true;
  backup: BackupInfo;
  sizeBefore: number;
  sizeAfter: number;
}

interface LiveFail {
  ok: false;
  status: number;
  payload: Record<string, unknown>;
}

/**
 * Ortak canli yazma akisi: yedek -> uzerine yaz -> diskten dogrula ->
 * dogrulama basarisizsa yedekten geri yukle. Cagiran taraf cevabi sekillendirir.
 */
function liveWrite(args: {
  savedPath: string;
  id: string;
  safeName: string;
  out: Buffer;
  /** diskten taze okunan baytlar uzerinde kalicilik dogrulamasi */
  verify: (fresh: Buffer) => { verified: boolean; errors: string[] };
}): LiveOk | LiveFail {
  const { savedPath, id, safeName, out, verify } = args;

  const sizeBefore = fs.statSync(savedPath).size;

  // 1) otomatik yedek (yazmadan ONCE)
  let backup: BackupInfo;
  try {
    backup = createBackup(id, safeName, savedPath);
  } catch (e) {
    return {
      ok: false,
      status: 500,
      payload: {
        error: `Canli yazma yedegi alinamadi - dosyaya dokunulmadi: ${e instanceof Error ? e.message : String(e)}`,
      },
    };
  }

  const restore = (): boolean => {
    try {
      fs.writeFileSync(savedPath, fs.readFileSync(backup.backupPath));
      return true;
    } catch {
      return false;
    }
  };

  // 2) orijinal dosya uzerine yaz
  try {
    fs.writeFileSync(savedPath, out);
  } catch (e) {
    const restored = restore();
    return {
      ok: false,
      status: 500,
      payload: {
        error: `Canli yazma basarisiz (dosya yazilamadi): ${e instanceof Error ? e.message : String(e)}`,
        restored,
        verified: false,
        backup: { ...backup },
      },
    };
  }

  // 3) diskten yeniden oku ve editlerin kaliciligini dogrula
  let verified = false;
  let verifyErrors: string[] = [];
  try {
    const fresh = fs.readFileSync(savedPath);
    const v = verify(fresh);
    verified = v.verified;
    verifyErrors = v.errors;
  } catch (e) {
    verifyErrors = [e instanceof Error ? e.message : String(e)];
  }

  if (!verified) {
    // 4) dogrulama basarisiz -> otomatik geri yukleme
    const restored = restore();
    return {
      ok: false,
      status: 500,
      payload: {
        error: "Canli yazma dogrulamasi basarisiz - orijinal dosya yedekten geri yuklendi",
        restored,
        verified: false,
        verifyErrors,
        backup: { ...backup },
      },
    };
  }

  return { ok: true, backup, sizeBefore, sizeAfter: out.length };
}

/** Canli yazma sonrasi DB boyutunu guncelle (kritik degil, hata yutulur). */
async function syncUploadSize(id: string, size: number): Promise<void> {
  try {
    await db.upload.update({ where: { id }, data: { size } });
  } catch {
    // boyut senkronu kritik degil
  }
}

/** Canli yazma sonrasi bayat .edited kopyasini kaldir (orijinal artik guncel). */
function removeStaleEditedCopy(savedPath: string, kind: "savegame" | "vdf"): boolean {
  try {
    const ep = editedPathFor(savedPath, kind);
    if (fs.existsSync(ep)) {
      fs.unlinkSync(ep);
      return true;
    }
  } catch {
    // temizlik kritik degil
  }
  return false;
}

// --- handler'lar ------------------------------------------------------------

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

  let body: {
    edits?: PutEdit[];
    keyHex?: string;
    cipher?: SaveCipher;
    ivHex?: string;
    live?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Gecersiz JSON govdesi" }, { status: 400 });
  }
  if (!Array.isArray(body.edits) || body.edits.length === 0) {
    return NextResponse.json({ ok: false, error: "edits dizisi gerekli (path + value)" }, { status: 400 });
  }
  const edits: PutEdit[] = body.edits;
  const live = body.live === true;
  const downloadUrl = `/api/uploads/${id}/savegame/download`;

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
      const res = applyVdfEdits(doc, edits);
      const out = serializeVdf(doc);

      if (!live) {
        // MEVCUT DAVRANIS (aynen korunur): duzenlenen .edited kopyaya yaz
        const ep = editedPathFor(row.savedPath, "vdf");
        fs.mkdirSync(path.dirname(ep), { recursive: true });
        fs.writeFileSync(ep, out);
        return NextResponse.json({
          ok: true,
          type: "vdf",
          applied: res.applied,
          errors: res.errors,
          editedSize: out.length,
          downloadUrl,
        });
      }

      // CANLI: tum editler uygulanamadiysa hic dokunma (all-or-nothing)
      if (res.errors.length > 0) {
        return NextResponse.json(
          {
            ok: false,
            type: "vdf",
            live: true,
            applied: res.applied,
            errors: res.errors,
            error: "Canli yazma iptal edildi - gecersiz duzenleme var, orijinal dosya degistirilmedi",
          },
          { status: 422 },
        );
      }

      const outcome = liveWrite({
        savedPath: row.savedPath,
        id,
        safeName: safeNameOf(id, row.savedPath),
        out,
        verify: (fresh) => verifyVdfEdits(parseVdf(fresh), edits),
      });
      if (!outcome.ok) {
        return NextResponse.json(
          { ok: false, type: "vdf", live: true, applied: res.applied, errors: [], ...outcome.payload },
          { status: outcome.status },
        );
      }
      await syncUploadSize(id, out.length);
      const removedEditedCopy = removeStaleEditedCopy(row.savedPath, "vdf");
      return NextResponse.json({
        ok: true,
        type: "vdf",
        live: true,
        applied: res.applied,
        errors: [],
        verified: true,
        verifyErrors: [],
        backup: { ...outcome.backup },
        sizeBefore: outcome.sizeBefore,
        sizeAfter: outcome.sizeAfter,
        removedEditedCopy,
        downloadUrl,
      });
    }

    // --- GVAS savegame ---
    const doc = parseSaveGame(buf, { keyHex: body.keyHex, cipher: body.cipher, ivHex: body.ivHex });
    const res = applyEdits(doc, edits);
    const out = serializeSaveGame(doc, { keyHex: body.keyHex, cipher: body.cipher, ivHex: body.ivHex });

    if (!live) {
      // MEVCUT DAVRANIS (aynen korunur): duzenlenen .edited kopyaya yaz
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
        downloadUrl,
      });
    }

    // CANLI: tum editler uygulanamadiysa hic dokunma (all-or-nothing)
    if (res.errors.length > 0) {
      return NextResponse.json(
        {
          ok: false,
          type: "savegame",
          live: true,
          applied: res.applied,
          errors: res.errors,
          error: "Canli yazma iptal edildi - gecersiz duzenleme var, orijinal dosya degistirilmedi",
          hint: "Canli modda tum duzenlemeler birlikte uygulanir (all-or-nothing); kopya modunda kismi uygulama yapilir",
        },
        { status: 422 },
      );
    }

    const outcome = liveWrite({
      savedPath: row.savedPath,
      id,
      safeName: safeNameOf(id, row.savedPath),
      out,
      verify: (fresh) =>
        verifyEdits(
          parseSaveGame(fresh, { keyHex: body.keyHex, cipher: body.cipher, ivHex: body.ivHex }),
          edits,
        ),
    });
    if (!outcome.ok) {
      return NextResponse.json(
        { ok: false, type: "savegame", live: true, applied: res.applied, errors: [], ...outcome.payload },
        { status: outcome.status },
      );
    }
    await syncUploadSize(id, out.length);
    const removedEditedCopy = removeStaleEditedCopy(row.savedPath, "savegame");
    return NextResponse.json({
      ok: true,
      type: "savegame",
      live: true,
      applied: res.applied,
      errors: [],
      verified: true,
      verifyErrors: [],
      backup: { ...outcome.backup },
      sizeBefore: outcome.sizeBefore,
      sizeAfter: outcome.sizeAfter,
      encrypted: doc.meta.encrypted,
      removedEditedCopy,
      downloadUrl,
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
