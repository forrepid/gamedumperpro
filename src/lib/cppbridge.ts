// ----------------------------------------------------------------------------
// DumperPro Online - C++ ikili koprusu (Gorev 5)
//
// Web analiz hatti TS portlariyla calisir; bu modul gerekliyse GERCEK
// DumperPro C++ ikilisini (UE SDK/gen, vtable cozumleme, imza taramasi)
// cagirir: `DumperPro --file <upload> --json --out <tmpdir>`.
//
// Ikili konumu (sirayla):
//   1) env DUMPERPRO_BIN
//   2) storage/bin/DumperPro            (bu projenin Linux derlemesi)
//   3) DumperPro/build_test/DumperPro   (gelistirme derlemesi)
//   4) DumperPro/bin/DumperPro(.exe)    (Windows yanina konmus ikili)
//
// Ciktilar storage/uploads/sdk/<id>/ altina "CLI_" onekiyle kopyalanir;
// SDK manifest'i (GET /api/uploads/[id]/sdk) onlari otomatik listeler.
// ----------------------------------------------------------------------------

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

import { STORAGE_DIR } from "@/lib/storage";

const execFileAsync = promisify(execFile);

export interface CliRunResult {
  ok: boolean;
  binary?: string;
  exitCode?: number;
  timedOut?: boolean;
  stdout?: string;
  stderr?: string;
  outFiles?: { name: string; size: number }[];
  sdkCopied?: string[];
  error?: string;
}

const TIMEOUT_MS = 120_000;

export function findDumperProBinary(): string | null {
  const candidates = [
    process.env.DUMPERPRO_BIN,
    path.join(STORAGE_DIR, "..", "bin", "DumperPro"),
    path.join(process.cwd(), "storage", "bin", "DumperPro"),
    path.join(process.cwd(), "DumperPro", "build_test", "DumperPro"),
    path.join(process.cwd(), "DumperPro", "bin", "DumperPro"),
    path.join(process.cwd(), "DumperPro", "bin", "DumperPro.exe"), // Windows sunucu senaryosu
  ].filter((p): p is string => !!p);
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      // yoksay
    }
  }
  return null;
}

/** SDK klasorune kopyalanacak CLI cikti dosyalari (kilavuz: yalniz bilinen desenler). */
const CLI_COPY_PATTERNS = [
  /^SDK\/SDK\.hpp$/i,
  /^SDK\/_basics\.hpp$/i,
  /^SDK\/.*_classes\.h$/i,
  /^SDK\/.*_structs\.h$/i,
  /^SDK\/.*_enums\.h$/i,
  /^SDK\/funcs\.txt$/i,
  /^names\.json$/i,
  /^objects\.json$/i,
  /^Names\.txt$/i,
  /^Objects\.txt$/i,
  /^offsets\.txt$/i,
  /^signatures\.txt$/i,
  /^.*_sigs\.txt$/i,
  /^vtable_funcs\.txt$/i,
  /^analysis_report\.txt$/i,
  /^analysis_report\.json$/i,
];

/** Bir yukleme icin C++ DumperPro ikilisini calistirir. */
export async function runDumperProCli(
  uploadId: string,
  savedPath: string,
  fileName: string,
): Promise<CliRunResult> {
  const binary = findDumperProBinary();
  if (!binary) {
    return {
      ok: false,
      error:
        "DumperPro ikilisi bulunamadi - storage/bin/DumperPro ya da DUMPERPRO_BIN env ile konum verin (DumperPro/ klasorunde: g++ -std=c++20 -O2 -I src -o ../storage/bin/DumperPro src/*.cpp src/*/*.cpp -lpthread)",
    };
  }

  const workDir = fs.mkdtempSync(path.join("/tmp", "dumperpro-cli-"));
  const args = ["--file", savedPath, "--json", "--out", workDir];

  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      timeout: TIMEOUT_MS,
      maxBuffer: 8 * 1024 * 1024,
    });
    return collectCliOutputs(uploadId, stdout, stderr, workDir);
  } catch (e) {
    const err = e as { code?: number | string; killed?: boolean; stdout?: string; stderr?: string; message?: string };
    const timedOut = err.killed === true;
    const out = err.stdout ?? "";
    // UE olmayan PE: C++ hat GNames/GObjects bulamayip kod 4 ile cikar - yumusak durum
    if (!timedOut && (out.includes("GNames not found") || out.includes("GObjects not found"))) {
      return {
        ok: false,
        binary,
        exitCode: typeof err.code === "number" ? err.code : undefined,
        error:
          "C++ ikilisi UE motor verisi bulamadi (GNames/GObjects yok) - bu dosya UE dump'i degil (Unity/IL2CPP/diger). Web TS analizi bu dosya icin zaten tamamlandı; UE hedeflerde ikili tam SDK uretir.",
        stdout: out.slice(-4000),
        stderr: err.stderr?.slice(-2000),
      };
    }
    // kismi ciktilar yazilmis olabilir - topla
    const partial = collectCliOutputs(uploadId, out, err.stderr ?? "", workDir, true);
    if (partial.outFiles && partial.outFiles.length > 0) return partial;
    return {
      ok: false,
      binary,
      exitCode: typeof err.code === "number" ? err.code : undefined,
      timedOut,
      stdout: out.slice(-4000),
      stderr: err.stderr?.slice(-2000),
      error: timedOut
        ? `ikili zaman asimi (${TIMEOUT_MS / 1000} sn)`
        : `ikili hatayla cikti${typeof err.code === "number" ? ` (kod ${err.code})` : ""}: ${err.message?.slice(0, 300)}`,
    };
  } finally {
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      // temizlik kritik degil
    }
  }
}

/** CLI cikti klasorunu tarar, SDK desenine uyanlari kopyalar. */
function collectCliOutputs(
  uploadId: string,
  stdout: string,
  stderr: string,
  workDir: string,
  soft = false,
): CliRunResult {
  const outFiles: { name: string; size: number }[] = [];
  const sdkDir = path.join(STORAGE_DIR, "sdk", uploadId);
  const copied: string[] = [];
  const walk = (dir: string, rel: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      const relPath = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        walk(full, relPath);
        continue;
      }
      const st = fs.statSync(full);
      outFiles.push({ name: relPath, size: st.size });
      if (CLI_COPY_PATTERNS.some((re) => re.test(relPath)) && st.size < 4 * 1024 * 1024) {
        try {
          fs.mkdirSync(sdkDir, { recursive: true });
          const target = path.join(sdkDir, `CLI_${relPath.replace(/[\\/]/g, "_")}`);
          fs.copyFileSync(full, target);
          copied.push(`CLI_${relPath.replace(/[\\/]/g, "_")}`);
        } catch {
          // kopyalama kritik degil
        }
      }
    }
  };
  try {
    walk(workDir, "");
  } catch {
    // cikti klasoru bos/olmayabilir
  }
  if (!soft && outFiles.length === 0) {
    return {
      ok: false,
      error: "ikili cikti uretmedi",
      stdout: stdout.slice(-4000),
      stderr: stderr.slice(-2000),
    };
  }
  return {
    ok: true,
    exitCode: 0,
    stdout: stdout.slice(-4000),
    stderr: stderr.slice(-2000),
    outFiles,
    sdkCopied: copied,
  };
}

/** Kolaylik icin: sdk klasorune yazilan dosya adlarini dondur. */
export function sdkFileList(uploadId: string): { name: string; size: number }[] {
  const sdkDir = path.join(STORAGE_DIR, "sdk", uploadId);
  try {
    return fs
      .readdirSync(sdkDir, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => ({ name: e.name, size: fs.statSync(path.join(sdkDir, e.name)).size }));
  } catch {
    return [];
  }
}
