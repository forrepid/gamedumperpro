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
