import { NextRequest, NextResponse } from "next/server";
import {
  getProjectFiles,
  readProjectFileBuffer,
} from "@/lib/project-files";
import { createZip, type ZipEntry } from "@/lib/zip";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const single = req.nextUrl.searchParams.get("path");

  if (single) {
    const buf = readProjectFileBuffer(single);
    if (!buf) {
      return NextResponse.json({ error: "dosya bulunamadi" }, { status: 404 });
    }
    const name = single.split("/").pop() ?? "file.txt";
    return new NextResponse(new Uint8Array(buf), {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${name}"`,
        "Cache-Control": "no-store",
      },
    });
  }

  // Full source archive
  const files = getProjectFiles();
  const entries: ZipEntry[] = files.map((f) => ({
    path: `UnrealDumperX/${f.path}`,
    data: readProjectFileBuffer(f.path) ?? Buffer.alloc(0),
  }));
  const zip = createZip(entries);
  return new NextResponse(new Uint8Array(zip), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": 'attachment; filename="UnrealDumperX_src.zip"',
      "Cache-Control": "no-store",
    },
  });
}
