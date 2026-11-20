// ----------------------------------------------------------------------------
// DumperPro Online - arka plan analiz kuyrugu
//
// POST /api/upload artik dosyayi kaydedip HEMEN doner; agir analiz burada
// arka planda (ayni sunucu sureci icinde) calisir. Isteyen rotalar
// `await runAnalysis(...)` ile senkron modu kullanmaya devam edebilir
// (hex/save, mem/dump, extract gibi kucuk cocuk analizleri).
//
// Ilerleme:
//   - bellek ici harita: getJobState(id) -> { stage, percent }
//   - GET /api/uploads/[id]/progress
//   - GET /api/uploads listesi de "analyzing" satirlara progress ekler
//
// Eslestirmeler (Il2CppDumper / LeechCore mantigi):
//   - global-metadata.dat <-> GameAssembly/libil2cpp  (il2cppMetadata opt)
//   - *.memmap/*.map     <-> raw bellek dump          (memmapText opt)
//   - *.pdb              <-> debugPdb yolu eslesen PE  (pdbBuffer opt)
// Ters yonde eslestirme (metadata/memmap sonradan geldi -> onceki yuklemeyi
// yeniden analiz) processUploadJob icinde otomatik yapilir.
// ----------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { Worker } from "node:worker_threads";

import { db } from "@/lib/db";
import { saveBuffer, STORAGE_DIR } from "@/lib/storage";
// NOT: agir analiz grafigi dinamik yuklenir. Turbopack dev derlemesi bu
// sandbox'in ~1.65 GB cgroup bellek limitinde tepe yapiyor; hafif rotalarin
// (/api/uploads, progress, hex, mem, extract) derleme grafigi kucuk kalsin
// diye analyzeBuffer/extractDex ilk analiz cagrisinda chunk olarak yuklenir.
import type { AnalyzeOptions, FullAnalysis } from "@/lib/analysis";

export type { AnalyzeOptions };

// ---- bellek ici is durumu ---------------------------------------------------

export interface AnalysisJobState {
  stage: string;
  percent: number; // 0..100, -1 = hata
  updatedAt: number;
}

const jobs = new Map<string, AnalysisJobState>();

export function getJobState(id: string): AnalysisJobState | null {
  const s = jobs.get(id);
  if (!s) return null;
  return { ...s };
}

// ---- worker_threads destegi (coklu is parcasi) -----------------------------
//
// ANALYSIS_WORKERS env ile ka adet analiz is parcasi calisacagi belirlenir
// (varsayilan: min(4, cpu) ve bu sandbox'ta bellek dostu 2). Isler
// dispatchUploadJob ile kuyruga alinir; her is ayr bir worker_threads
// Worker'i icinde processUploadJob calistirir. Ilerleme stageHook uzerinden
// ana is parcasiya postMessage ile tasir (bellek ici job haritasi ana
// surecte kalir; /api/uploads progress boylece calismaya devam eder).
// Worker paketi yoksa (storage/bin/analysis-worker.js) davranis eski ayni
// surec ici yola duser - geri uyumlu.

type StageHook = (id: string, stage: string, percent: number) => void;
let stageHook: StageHook | null = null;

/** Sadece worker girisi kullanir: stage olaylarini ana surece tasir. */
export function setStageHook(fn: StageHook | null): void {
  stageHook = fn;
}

function setStage(id: string, stage: string, percent: number) {
  jobs.set(id, { stage, percent, updatedAt: Date.now() });
  try {
    stageHook?.(id, stage, percent);
  } catch {
    // hook hatasi isi engellememeli
  }
}

const MAX_WORKERS = Math.max(1, Math.min(4, Number(process.env.ANALYSIS_WORKERS ?? Math.min(2, os.availableParallelism?.() ?? 2))));

interface QueuedJob {
  id: string;
  fileName: string;
  buf: Buffer;
  opts: AnalyzeOptions;
}

const workerQueue: QueuedJob[] = [];
const activeWorkers = new Map<string, Worker>();

function workerBundlePath(): string {
  return path.join(process.cwd(), "storage", "bin", "analysis-worker.js");
}

function startWorker(job: QueuedJob): boolean {
  const wPath = workerBundlePath();
  if (!fs.existsSync(wPath)) return false;
  try {
    const w = new Worker(wPath, {
      workerData: { job: { id: job.id, fileName: job.fileName, buf: job.buf, opts: job.opts } },
      stdout: true,
      stderr: true,
    });
    w.on("message", (m: { type?: string; id?: string; stage?: string; percent?: number }) => {
      if (m?.type === "stage" && m.id && typeof m.stage === "string" && typeof m.percent === "number") {
        setStage(m.id, m.stage, m.percent);
      }
    });
    w.on("error", (e: Error) => {
      setStage(job.id, "hata", -1);
      void db.upload
        .update({ where: { id: job.id }, data: { status: "error", error: `worker hatasi: ${e.message.slice(0, 300)}` } })
        .catch(() => undefined);
      activeWorkers.delete(job.id);
      pumpQueue();
    });
    w.on("exit", () => {
      activeWorkers.delete(job.id);
      pumpQueue();
    });
    activeWorkers.set(job.id, w);
    setStage(job.id, `worker is parcasi #${w.threadId} alindi`, 2);
    console.log(`[queue] worker thread #${w.threadId} -> ${job.fileName} (${job.id.slice(0, 8)})`);
    return true;
  } catch {
    return false;
  }
}

function pumpQueue(): void {
  while (activeWorkers.size < MAX_WORKERS && workerQueue.length > 0) {
    const job = workerQueue.shift()!;
    if (!startWorker(job)) {
      // worker paketi yok: eski davranis - ayni surec icinde calistir
      console.log(`[queue] ayni surec ici yedek -> ${job.fileName} (${job.id.slice(0, 8)})`);
      void processUploadJob(job.id, job.fileName, job.buf, job.opts).catch(() => undefined);
    }
  }
}

/**
 * POST /api/upload'in arka plan girisi: isi worker kuyruguna atar ve HEMEN
 * doner. Coklu is yuklendiginde MAX_WORKERS kadarisi paralel is parcasi-
 * larda calisir, kalanlar kuyrukte bekler (Il2CppDumper eslestirmeleri
 * tetiklemek icin processUploadJob yine tam akisi yurutur).
 */
export function dispatchUploadJob(id: string, fileName: string, buf: Buffer, opts: AnalyzeOptions): void {
  workerQueue.push({ id, fileName, buf, opts });
  setStage(id, "kuyruya alindi", 1);
  pumpQueue();
}

function clearJobLater(id: string) {
  setTimeout(
    () => {
      const s = jobs.get(id);
      if (s && (s.percent === 100 || s.percent < 0)) jobs.delete(id);
    },
    60_000,
  ).unref();
}

// ---- eslestirme yardimcilari -------------------------------------------------

export async function readUploadBuffer(id: string): Promise<Buffer | null> {
  const row = await db.upload.findUnique({ where: { id } });
  if (!row) return null;
  try {
    return fs.readFileSync(row.savedPath);
  } catch {
    return null;
  }
}

const PAIR_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Yeni yuklenmis dosya icin cift eslestirme secenekleri hesaplar (24 saat pencere). */
export async function computePairOpts(id: string, fileName: string, buf: Buffer): Promise<AnalyzeOptions> {
  const opts: AnalyzeOptions = {};
  const lowName = fileName.toLowerCase();
  const isIl2cppBin = lowName.includes("gameassembly") || lowName.includes("libil2cpp");
  const isMetadata = lowName.includes("global-metadata");
  const isMemmap = /\.(memmap|map)$/.test(lowName);
  const isPdb = /\.pdb$/i.test(lowName);
  const since = new Date(Date.now() - PAIR_WINDOW_MS);

  try {
    // a) IL2CPP binary -> son metadata yuklemesini bagla
    if (isIl2cppBin) {
      const recentMeta = await db.upload.findFirst({
        where: { createdAt: { gte: since }, analysis: { kind: "metadata" }, id: { not: id } },
        orderBy: { createdAt: "desc" },
      });
      if (recentMeta) {
        const mb = await readUploadBuffer(recentMeta.id);
        if (mb) opts.il2cppMetadata = mb;
      }
    }
    // b) raw dump -> son memmap tanimini bagla
    if (!isMetadata && !isMemmap && !isIl2cppBin && !isPdb && buf.length > 1024 * 1024) {
      const recentMap = await db.upload.findFirst({
        where: { createdAt: { gte: since }, fileName: { contains: ".memmap" }, id: { not: id } },
        orderBy: { createdAt: "desc" },
      });
      if (recentMap) {
        try {
          opts.memmapText = fs.readFileSync(recentMap.savedPath, "utf8");
        } catch {
          // yoksay
        }
      }
    }
    // c) PE -> ayni adli .pdb yuklemesini bagla (sem bolma: ROB RUN.pdb <-> ROB RUN.exe)
    if (isPdb) {
      const stem = fileName.replace(/\.pdb$/i, "").toLowerCase();
      const recentPe = await db.upload.findFirst({
        where: { createdAt: { gte: since }, id: { not: id }, analysis: { kind: "pe" } },
        orderBy: { createdAt: "desc" },
      });
      const candidates = await db.upload.findMany({
        where: { createdAt: { gte: since }, id: { not: id }, analysis: { kind: "pe" } },
        orderBy: { createdAt: "desc" },
        take: 25,
      });
      const stemBase = stem.split(/[\\/]/).pop() ?? stem;
      const match = [recentPe, ...candidates].find((r) => {
        if (!r) return false;
        const base = r.fileName.replace(/\.[^.]+$/, "").toLowerCase();
        return base === stemBase || stemBase.includes(base) || base.includes(stemBase);
      });
      if (match) {
        const pb = await readUploadBuffer(match.id);
        if (pb) opts.pdbBuffer = pb;
      }
    } else if (!isMetadata && !isMemmap && !isIl2cppBin) {
      // PE yuklendi -> adina uyan son .pdb'i bagla (ters yon b)
      const stem = fileName.replace(/\.[^.]+$/, "").toLowerCase();
      if (stem && buf.length > 0) {
        const recentPdb = await db.upload.findFirst({
          where: { createdAt: { gte: since }, fileName: { contains: ".pdb" }, id: { not: id } },
          orderBy: { createdAt: "desc" },
          take: 10,
        });
        if (recentPdb) {
          const pdbStem = recentPdb.fileName.replace(/\.pdb$/i, "").toLowerCase().split(/[\\/]/).pop() ?? "";
          if (pdbStem && (pdbStem === stem || stem.includes(pdbStem) || pdbStem.includes(stem))) {
            const pb = await readUploadBuffer(recentPdb.id);
            if (pb) opts.pdbBuffer = pb;
          }
        }
      }
    }
  } catch {
    // eslestirme opsiyonel; hata analizi engellememeli
  }
  return opts;
}

/** Pair notlari (kullaniciya gorunur) uret. */
export function describePairs(fileName: string, opts: AnalyzeOptions): string[] {
  const notes: string[] = [];
  if (opts.il2cppMetadata) notes.push(`Eslestirme: metadata bu binary'ye baglandi - dump.cs + script.json uretilecek`);
  if (opts.memmapText) notes.push("Eslestirme: memmap tanimi bu bellek dump'ina baglandi (LeechCore memmap:// semantigi)");
  if (opts.pdbBuffer) notes.push(`Eslestirme: eslesen .pdb bu PE'ye baglandi - semboller (S_PUB32/S_UDT) cikarilacak`);
  void fileName;
  return notes;
}

// ---- cekirdek analiz akisi ---------------------------------------------------

/** Tek yukleme icin tam analiz: analiz + SDK yazimi + Analysis satiri + durum. */
export async function runAnalysis(
  id: string,
  buf: Buffer,
  fileName: string,
  opts: AnalyzeOptions = {},
): Promise<FullAnalysis | null> {
  setStage(id, "analiz basliyor", 5);
  try {
    setStage(id, "format tespiti + derin analiz", 20);
    const { analyzeBuffer } = await import("@/lib/analysis");
    const analysis = analyzeBuffer(buf, fileName, opts);
    if (opts && (opts.il2cppMetadata || opts.memmapText || opts.pdbBuffer)) {
      const pairNotes = describePairs(fileName, opts);
      if (pairNotes.length) analysis.result.notes.unshift(...pairNotes);
    }

    // savegame/vdf ozet zenginlestirmesi (agir olmayan moduller dinamik)
    try {
      if (analysis.result.kind === "savegame") {
        const sg = await import("@/lib/analysis/savegame");
        const doc = sg.parseSaveGame(buf);
        const sum = sg.summarizeSaveGame(doc);
        analysis.result.savegame = {
          magic: true,
          fileVersion: sum.fileVersion,
          ue4Version: sum.ue4Version,
          ue5Version: sum.ue5Version,
          className: sum.className,
          propCount: sum.propCount,
          totalPropBytes: doc.props.reduce((a, p) => a + p.size, 0),
          encrypted: sum.encrypted,
          compressed: sum.compressed,
          engineVersion: sum.engineVersion,
        };
        analysis.result.notes.push(
          `UE save game (GVAS) tanindi: ${sum.className} - ${sum.propCount} property` +
            (sum.encrypted ? " (sifreli)" : "") +
            (sum.compressed ? " (zlib sikistirilmis)" : "") +
            " - Save Editor sekmesinden duzenlenebilir",
        );
      } else if (analysis.result.kind === "vdf") {
        const vdf = await import("@/lib/analysis/vdf");
        const doc = vdf.parseVdf(buf);
        const sum = vdf.summarizeVdf(doc);
        analysis.result.vdf = { kind: doc.kind, keyCount: sum.keyCount, maxDepth: sum.maxDepth, sampleKeys: sum.sampleKeys };
        analysis.result.notes.push(
          `Steam VDF (${doc.kind}) tanindi: ${sum.keyCount} anahtar, ${sum.maxDepth} derinlik - Save Editor sekmesinden duzenlenebilir`,
        );
      }
    } catch (e) {
      analysis.result.errors.push(`Save editor ozeti hatasi: ${e instanceof Error ? e.message : String(e)}`);
    }

    setStage(id, "SDK ciktilari yaziliyor", 70);
    if (analysis.sdkContents.length > 0) {
      const sdkDir = path.join(STORAGE_DIR, "sdk", id);
      fs.mkdirSync(sdkDir, { recursive: true });
      for (const f of analysis.sdkContents) {
        fs.writeFileSync(path.join(sdkDir, f.name), f.content, "utf8");
      }
    }

    setStage(id, "rapor kaydediliyor", 90);
    const data = {
      kind: analysis.result.kind,
      engine: analysis.result.engine.detected === "Bilinmiyor" ? null : analysis.result.engine.detected,
      engineVersion: analysis.result.engine.version ?? null,
      summary: JSON.stringify(analysis.result),
      report: analysis.report,
    };
    const existing = await db.analysis.findUnique({ where: { uploadId: id } });
    if (existing) {
      await db.analysis.update({ where: { uploadId: id }, data });
    } else {
      await db.analysis.create({ data: { uploadId: id, ...data } });
    }
    await db.upload.update({ where: { id }, data: { status: "done" } });
    setStage(id, "tamamlandi", 100);
    clearJobLater(id);
    return analysis;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await db.upload
      .update({ where: { id }, data: { status: "error", error: msg } })
      .catch(() => undefined);
    setStage(id, "hata", -1);
    clearJobLater(id);
    return null;
  }
}

/**
 * Onceki bir yuklemeyi yeni esleme verisiyle yeniden analiz eder
 * (metadata/memmap/pdb sonradan geldiginde). Analysis satiri + SDK guncellenir.
 */
export async function reanalyzeUpload(
  id: string,
  fileName: string,
  buf: Buffer,
  opts: AnalyzeOptions,
): Promise<string | null> {
  const analysis = await runAnalysis(id, buf, fileName, opts);
  if (!analysis) return "yeniden analiz hatasi";
  const pairNote = describePairs(fileName, opts)[0];
  return pairNote ?? "yeniden analiz tamam";
}

/**
 * ART VDEX/OAT icerisindeki DEX'leri ayri cocuk yukleme olarak kaydeder ve
 * analiz eder (history agacinda dizin>dosya seklinde gorunur).
 */
async function spawnArtDexChildren(
  uploadId: string,
  fileName: string,
  buf: Buffer,
  art: NonNullable<FullAnalysis["result"]["art"]>,
): Promise<void> {
  const base = fileName.replace(/\.[^.]+$/, "");
  for (const e of art.dexes.slice(0, 8)) {
    try {
      const { extractDex } = await import("@/lib/analysis/vdex");
      const slice = extractDex(buf, { index: e.index, offset: e.offset, size: e.size });
      if (slice.length < 64) continue;
      const childId = crypto.randomUUID();
      const childName = `${base}_dex${e.index}.dex`;
      const saved = saveBuffer(childId, childName, slice);
      await db.upload.create({
        data: {
          id: childId,
          fileName: childName,
          savedPath: saved.savedPath,
          size: slice.length,
          mime: "application/octet-stream",
          source: "artdex",
          parentId: uploadId,
          relPath: childName,
          status: "analyzing",
        },
      });
      void runAnalysis(childId, slice, childName).catch(() => undefined);
    } catch {
      // tek dex basarisizligi digerlerini engellememeli
    }
  }
}

/**
 * POST /api/upload isinin tam arka plan akisi:
 * 1) kendi analizini yap  2) ters yonde esle (metadata/memmap/pdb -> onceki yukleme)
 * 3) ART VDEX/OAT ise gomulu DEX'leri cocuk yukleme olarak cikar
 */
export async function processUploadJob(id: string, fileName: string, buf: Buffer, opts: AnalyzeOptions): Promise<void> {
  const lowName = fileName.toLowerCase();
  const isMetadata = lowName.includes("global-metadata");
  const isMemmap = /\.(memmap|map)$/.test(lowName);
  const isIl2cppBin = lowName.includes("gameassembly") || lowName.includes("libil2cpp");
  const isPdb = /\.pdb$/i.test(lowName);
  const since = new Date(Date.now() - PAIR_WINDOW_MS);

  await runAnalysis(id, buf, fileName, opts);
  if (getJobState(id)?.percent === 100) setStage(id, "ters eslestirme kontrolu", 98);

  // ART VDEX/OAT ise gomulu DEX'leri cocuk olarak cikar
  try {
    const mainAnalysis = await db.analysis.findUnique({
      where: { uploadId: id },
      select: { summary: true },
    });
    if (mainAnalysis) {
      const summary = JSON.parse(mainAnalysis.summary) as { art?: NonNullable<FullAnalysis["result"]["art"]> };
      if (summary.art && summary.art.dexes.length > 0) {
        setStage(id, "gomulu DEX cikarma", 99);
        await spawnArtDexChildren(id, fileName, buf, summary.art);
      }
    }
  } catch {
    // dex cocuklari opsiyonel
  }

  try {
    if (isMetadata) {
      const recentBin = await db.upload.findFirst({
        where: {
          createdAt: { gte: since },
          id: { not: id },
          OR: [{ fileName: { contains: "GameAssembly" } }, { fileName: { contains: "libil2cpp" } }],
        },
        orderBy: { createdAt: "desc" },
      });
      if (recentBin) {
        const bb = await readUploadBuffer(recentBin.id);
        if (bb) await reanalyzeUpload(recentBin.id, recentBin.fileName, bb, { il2cppMetadata: buf });
      }
    }
    if (isMemmap) {
      const recentRaw = await db.upload.findFirst({
        where: {
          createdAt: { gte: since },
          id: { not: id },
          size: { gt: 1024 * 1024 },
          analysis: { kind: { in: ["minidump", "unknown"] } },
        },
        orderBy: { createdAt: "desc" },
      });
      if (recentRaw) {
        const rb = await readUploadBuffer(recentRaw.id);
        if (rb) await reanalyzeUpload(recentRaw.id, recentRaw.fileName, rb, { memmapText: buf.toString("utf8") });
      }
    }
    if (isPdb) {
      // eslesen PE'yi pdb ile yeniden analiz et
      const stem = fileName.replace(/\.pdb$/i, "").toLowerCase().split(/[\\/]/).pop() ?? "";
      const pes = await db.upload.findMany({
        where: { createdAt: { gte: since }, id: { not: id }, analysis: { kind: "pe" } },
        orderBy: { createdAt: "desc" },
        take: 25,
      });
      const match = pes.find((r) => {
        const base = r.fileName.replace(/\.[^.]+$/, "").toLowerCase();
        return stem && (base === stem || stem.includes(base) || base.includes(stem));
      });
      if (match) {
        const pb = await readUploadBuffer(match.id);
        if (pb) await reanalyzeUpload(match.id, match.fileName, pb, { pdbBuffer: buf });
      }
    }
  } catch {
    // ters eslestirme opsiyonel
  }
  setStage(id, "tamamlandi", 100);
  clearJobLater(id);
}
