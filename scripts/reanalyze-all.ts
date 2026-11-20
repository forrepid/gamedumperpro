// Mevcut yuklemeleri yeni derin analiz motoruyla yeniden analiz eder.
// - DB'deki tum Upload kayitlarini gez
// - disk dosyasini oku, analyzeBuffer calistir
// - SDK dosyalarini storage/sdk/<id>/ altina yaz
// - Analysis satirini guncelle (upsert)
// Kullanim: npx tsx scripts/reanalyze-all.ts [uploadId]
import fs from "node:fs";
import path from "node:path";

async function main(): Promise<void> {
  const { PrismaClient } = await import("@prisma/client");
  const { analyzeBuffer } = await import("../src/lib/analysis/index");
  const { STORAGE_DIR } = await import("../src/lib/storage");

  const db = new PrismaClient();
  const onlyId = process.argv[2];

  const uploads = await db.upload.findMany({
    where: onlyId ? { id: onlyId } : undefined,
    orderBy: { createdAt: "desc" },
  });

  console.log(`${uploads.length} kayit yeniden analiz edilecek`);

  for (const u of uploads) {
    try {
      if (!fs.existsSync(u.savedPath)) {
        console.log(`  SKIP (dosya yok): ${u.fileName}`);
        continue;
      }
      const buf = fs.readFileSync(u.savedPath);
      const t0 = Date.now();
      const { result, report, sdkContents } = analyzeBuffer(buf, u.fileName);
      const ms = Date.now() - t0;

      // SDK dosyalarini yaz
      if (sdkContents.length > 0) {
        const sdkDir = path.join(STORAGE_DIR, "sdk", u.id);
        fs.mkdirSync(sdkDir, { recursive: true });
        for (const f of sdkContents) {
          fs.writeFileSync(path.join(sdkDir, f.name), f.content, "utf8");
        }
      }

      await db.analysis.upsert({
        where: { uploadId: u.id },
        create: {
          uploadId: u.id,
          kind: result.kind,
          engine: result.engine.detected === "Bilinmiyor" ? null : result.engine.detected,
          engineVersion: result.engine.version ?? null,
          summary: JSON.stringify(result),
          report,
        },
        update: {
          kind: result.kind,
          engine: result.engine.detected === "Bilinmiyor" ? null : result.engine.detected,
          engineVersion: result.engine.version ?? null,
          summary: JSON.stringify(result),
          report,
        },
      });
      await db.upload.update({ where: { id: u.id }, data: { status: "done", error: null } });
      console.log(
        `  OK: ${u.fileName} -> ${result.engine.detected} | fn=${result.functions?.total ?? 0} struct=${result.structs?.total ?? 0} enum=${result.enums?.total ?? 0} sdk=${sdkContents.length} (${ms}ms)`,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`  HATA: ${u.fileName}: ${msg}`);
      await db.upload.update({ where: { id: u.id }, data: { status: "error", error: msg } }).catch(() => undefined);
    }
  }

  await db.$disconnect();
}

void main();
