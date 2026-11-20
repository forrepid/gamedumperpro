// ----------------------------------------------------------------------------
// DumperPro Online - yukleme deposu (storage/uploads)
// ----------------------------------------------------------------------------

import fs from "fs";
import path from "path";

export const STORAGE_DIR = path.join(process.cwd(), "storage", "uploads");
export const MAX_UPLOAD_BYTES = 300 * 1024 * 1024; // 300 MB

export function ensureStorage(): void {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

/** Yol gezinmesini engelleyen guvenli dosya adi. */
export function sanitizeFileName(name: string): string {
  const base = path.basename(name).replace(/[^A-Za-z0-9._-]/g, "_");
  return base.slice(0, 120) || "dosya.bin";
}

export function savedPathFor(id: string, safeName: string): string {
  return path.join(STORAGE_DIR, `${id}__${safeName}`);
}

export function saveBuffer(id: string, fileName: string, buf: Buffer): { savedPath: string; safeName: string } {
  ensureStorage();
  const safeName = sanitizeFileName(fileName);
  const savedPath = savedPathFor(id, safeName);
  fs.writeFileSync(savedPath, buf);
  return { savedPath, safeName };
}

/** SDK cikti dizini: storage/sdk/<uploadId> (Dumper-7 / Il2CppDumper stili dosyalar). */
export const SDK_DIR = (id: string): string => path.join(STORAGE_DIR, "sdk", id);

// ----------------------------------------------------------------------------
// Canli yazma (live edit) yedekleri: storage/uploads/backups/
// Orijinal dosya uzerine yazmadan once otomatik yedek buraya alinir.
// ----------------------------------------------------------------------------

export const BACKUPS_DIR = path.join(STORAGE_DIR, "backups");

/** YYYYMMDD-HHMMSS (yerel saat) - yedek dosya adi damgasi. */
export function backupStamp(d: Date = new Date()): string {
  const p = (n: number): string => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
    `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  );
}

export interface BackupInfo {
  backupPath: string;
  fileName: string;
  /** STORAGE_DIR'e gore goreceli yol: "backups/<id>__<ad>.bak-<damga>" */
  rel: string;
  size: number;
}

/** Orijinal dosyayi yedekler; ayni saniyede cakisma olursa -1, -2... ekler. */
export function createBackup(id: string, safeName: string, savedPath: string): BackupInfo {
  ensureStorage();
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  const stamp = backupStamp();
  let target = path.join(BACKUPS_DIR, `${id}__${safeName}.bak-${stamp}`);
  let n = 0;
  while (fs.existsSync(target)) {
    n++;
    target = path.join(BACKUPS_DIR, `${id}__${safeName}.bak-${stamp}-${n}`);
  }
  fs.copyFileSync(savedPath, target);
  return {
    backupPath: target,
    fileName: path.basename(target),
    rel: path.relative(STORAGE_DIR, target),
    size: fs.statSync(target).size,
  };
}
