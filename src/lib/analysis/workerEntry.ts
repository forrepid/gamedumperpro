// ----------------------------------------------------------------------------
// DumperPro Online - analiz is parcasi girisi (worker_threads)
//
// Bu dosya ALAŞTIĞINDA tek basina calismaz: `bun run worker:build` ile
// storage/bin/analysis-worker.js olarak paketlenir ve queue.ts'in worker
// havuzu (dispatchUploadJob) tarafindan node:worker_threads ile acilir.
//
// Akis: parent -> workerData.job {id, fileName, buf, opts} ->
// processUploadJob (tam analiz + eslestirme + ART cocuklari) ->
// her setStage postMessage ile ana surece -> parent bellek ici job haritasini
// gunceller -> /api/uploads/[id]/progress aynen calisir.
// ----------------------------------------------------------------------------

import { workerData, parentPort } from "node:worker_threads";

import { processUploadJob, setStageHook, type AnalyzeOptions } from "./queue";

interface WorkerJobData {
  job: {
    id: string;
    fileName: string;
    buf: Buffer;
    opts: AnalyzeOptions;
  };
}

const data = workerData as WorkerJobData;
const { id, fileName, opts } = data.job;
// Yapısal klonlama Buffer'i Uint8Array'e dusurebilir - Buffer'a geri sar
// (kopyasiz: ayni bellek araligi uzerinden)
const raw = data.job.buf as unknown as Uint8Array;
const buf =
  Buffer.isBuffer(raw)
    ? raw
    : Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);

const port = parentPort;

if (port) {
  setStageHook((stageId, stage, percent) => {
    port.postMessage({ type: "stage", id: stageId, stage, percent });
  });

  processUploadJob(id, fileName, buf, opts)
    .then(() => {
      port.postMessage({ type: "stage", id, stage: "tamamlandi", percent: 100 });
    })
    .catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e);
      port.postMessage({ type: "stage", id, stage: "hata", percent: -1 });
      port.postMessage({ type: "error", id, error: msg.slice(0, 500) });
    });
}
