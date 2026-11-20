// ----------------------------------------------------------------------------
// storage-doctor.ts - yukleme deposu <-> DB tutarlilik doktoru (Gorev 6)
//
// Tutarlilik sorunlari (zamanla birikir):
//   1. Yetim disk dosyalari : storage/uploads/<id>__<ad> ama DB'de Upload yok
//   2. Kayip disk dosyalari : DB'de Upload var ama dosya diskte yok
//   3. Yetim .dpr yan dosyalari (patch kayitlari) - sahibi silinmis
//   4. Yetim sdk klasorleri : storage/uploads/sdk/<id> ama Upload yok
//
// Kullanim: bun scripts/storage-doctor.ts [--fix]
//   --fix : yetim dosya/klasorleri siler, kayip dosyali kayitlari error isaretler
//   siz  : yalnizca rapor yazdirir (varsayilan)
// ----------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";

import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();
const STORAGE_DIR = path.join(process.cwd(), "storage", "uploads");
const SDK_DIR = path.join(STORAGE_DIR, "sdk");

const FIX = process.argv.includes("--fix");

function listUploadFiles(): Map<string, string> {
  const out = new Map<string, string>();
  for (const ent of fs.readdirSync(STORAGE_DIR, { withFileTypes: true })) {
    if (!ent.isFile()) continue;
    // dosya adi formati: <uuid>__<safeName>
    const m = ent.name.match(/^([0-9a-fA-F-]{36})__/);
    if (!m) continue;
    out.set(m[1], path.join(STORAGE_DIR, ent.name));
  }
  return out;
}

function listPatchSidecars(): string[] {
  return fs
    .readdirSync(STORAGE_DIR, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".dpr"))
    .map((e) => path.join(STORAGE_DIR, e.name));
}

async function main() {
  const rows = await db.upload.findMany({
    select: { id: true, fileName: true, savedPath: true, status: true },
  });
  const diskFiles = listUploadFiles();
  const dbIds = new Set(rows.map((r) => r.id));

  console.log(`DB kayitlari   : ${rows.length}`);
  console.log(`Disk dosyalari : ${diskFiles.size}`);

  // 1) yetim disk dosyalari
  let orphanFiles = 0;
  for (const [id, p] of diskFiles) {
    if (!dbIds.has(id)) {
      orphanFiles++;
      console.log(`  [yetim dosya] ${path.basename(p)}`);
      if (FIX) {
        try {
          fs.unlinkSync(p);
          console.log(`      -> silindi`);
        } catch (e) {
          console.log(`      -> silinemedi: ${e instanceof Error ? e.message : e}`);
        }
      }
    }
  }

  // 2) kayip disk dosyalari (klasor gruplari savedPath="-" ayridir)
  let missingFiles = 0;
  for (const r of rows) {
    if (!r.savedPath || r.savedPath === "-") continue;
    if (!fs.existsSync(r.savedPath)) {
      missingFiles++;
      console.log(`  [kayip dosya] ${r.fileName} (${r.id}) status=${r.status}`);
      if (FIX && r.status !== "error") {
        await db.upload.update({ where: { id: r.id }, data: { status: "error", error: "disk dosyasi kayip" } });
        console.log(`      -> status=error isaretlendi`);
      }
    }
  }

  // 3) yetim .dpr yan dosyalari
  let orphanDpr = 0;
  for (const p of listPatchSidecars()) {
    const base = path.basename(p, ".dpr");
    const m = base.match(/^([0-9a-fA-F-]{36})__/);
    if (!m || !dbIds.has(m[1])) {
      orphanDpr++;
      console.log(`  [yetim .dpr] ${path.basename(p)}`);
      if (FIX) {
        try {
          fs.unlinkSync(p);
          console.log(`      -> silindi`);
        } catch (e) {
          console.log(`      -> silinemedi: ${e instanceof Error ? e.message : e}`);
        }
      }
    }
  }

  // 4) yetim sdk klasorleri
  let orphanSdk = 0;
  try {
    for (const ent of fs.readdirSync(SDK_DIR, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      if (!dbIds.has(ent.name)) {
        orphanSdk++;
        console.log(`  [yetim sdk] ${ent.name}`);
        if (FIX) {
          try {
            fs.rmSync(path.join(SDK_DIR, ent.name), { recursive: true, force: true });
            console.log(`      -> silindi`);
          } catch (e) {
            console.log(`      -> silinemedi: ${e instanceof Error ? e.message : e}`);
          }
        }
      }
    }
  } catch {
    // sdk klasoru yok olabilir
  }

  console.log("");
  console.log(`Ozet: yetim dosya=${orphanFiles} kayip dosya=${missingFiles} yetim .dpr=${orphanDpr} yetim sdk=${orphanSdk}`);
  if (!FIX && (orphanFiles || missingFiles || orphanDpr || orphanSdk)) {
    console.log("Duzeltmek icin: bun scripts/storage-doctor.ts --fix");
  }
  await db.$disconnect();
}

void main();
